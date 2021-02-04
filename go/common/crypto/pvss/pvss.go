// Package pvss implements a PVSS backed commit-reveal scheme loosely
// based on the Scalable Randomness Attested by Public Entities
// protocol by Casudo and David.
//
// In practice this implementation omits the things that make SCRAPE
// scalable/fast, and is just a consensus backed PVSS based beacon.
// The differences are as follows:
//
//  * The coding theory based share verification mechanism is not
//    implemented.  The check is as in Schoenmakers' paper.  This
//    could be added at a future date for a performance gain.
//
//  * The commit/reveal based fast path that skips having to recover
//    each participant's secret if they submitted a protocol level
//    reveal is omitted.  It is possible to game the system by
//    publishing shares for one secret and a commitment for another
//    secret, and then choosing to reveal or not after everyone else
//    has revealed.  While this behavior is detectable, it either
//    involves having to recover the secret from the shares anyway
//    rendering the optimization moot, or having a userbase that
//    understands that slashing is integral to the security of the
//    system.
//
// See: https://eprint.iacr.org/2017/216.pdf
package pvss

import (
	"fmt"
	"math"
	"sort"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/share/pvss"
)

const maxRetries = 3

var (
	// Yes, this uses the NIST P-256 curve, due to vastly superior
	// performance compared to kyber's Ed25519 implementation.  In
	// theory Ed25519 should be faster, but the runtime library's
	// P-256 scalar multiply is optimized, and kyber's Ed25519
	// is basically ref10.
	suite = nist.NewBlakeSHA256P256()

	basePoint     = suite.Point().Pick(suite.XOF([]byte("oasis-core/pvss: base point")))
	errVerifyOnly = fmt.Errorf("pvss: instance is verify only")
)

type dealerState struct {
	scalar kyber.Scalar
	point  kyber.Point
	index  int
}

// Config is the configuration for an execution of the PVSS protocol.
type Config struct {
	// PrivateKey is the scalar to use as the private key.
	PrivateKey *Scalar

	// Participants is the vector of public keys of all participants
	// in the protocol.
	//
	// Note: This must be in consistent order across all participants,
	// and include the public point generated from `PrivateKey`, if
	// this config is for a participant.
	Participants []Point

	// Threshold is the threshold to use for specifying the
	// minimum number of commits and reveals required for the
	// protocol to proceed.  This value is also used as the threshold
	// for the underling PVSS scheme.
	Threshold int
}

// Instance is an instance of the PVSS protocol.
type Instance struct {
	Participants    []Point                      `json:"participants"`
	Commits         map[int]*CommitState         `json:"commits"`
	Reveals         map[int]*Reveal              `json:"reveals"`
	DecryptedShares map[int]map[int]*PubVerShare `json:"decrypted_shares"`
	Threshold       int                          `json:"threshold"`

	dealerState        *dealerState
	cachedParticipants []kyber.Point
}

// SetScalar sets the private scalar belonging to an instance.  Under
// most circumstances this will be handled by the constructor.
func (inst *Instance) SetScalar(privateKey *Scalar) error {
	if privateKey == nil {
		return fmt.Errorf("pvss: privateKey is nil")
	}
	if err := privateKey.isWellFormed(); err != nil {
		return fmt.Errorf("pvss: invalid private key: %w", err)
	}
	if inst.dealerState != nil {
		return fmt.Errorf("pvss: private key for dealer already set")
	}

	var (
		scalar  = privateKey.Inner()
		point   = suite.Point().Mul(scalar, nil)
		selfIdx = -1
	)
	for idx, publicKey := range inst.participants() {
		if publicKey.Equal(point) {
			selfIdx = idx
			break
		}
	}
	if selfIdx < 0 {
		return fmt.Errorf("pvss: privateKey's point not in participant list")
	}

	inst.dealerState = &dealerState{
		scalar: scalar,
		point:  point,
		index:  selfIdx,
	}

	return nil
}

// Commit executes the commit phase of the protocol, generating a commitment
// message to be broadcasted to all participants.
func (inst *Instance) Commit() (*Commit, error) {
	if inst.isVerifyOnly() {
		return nil, errVerifyOnly
	}

	// Generate the secret scalar.
	secret, _, err := NewKeyPair()
	if err != nil {
		return nil, fmt.Errorf("pvss/commit: failed to generate secret: %w", err)
	}

	// Generate the encrypted shares for the PVSS commitment.
	encShares, pubPoly, err := pvss.EncShares(
		suite,
		basePoint,
		inst.participants(),
		secret.Inner(),
		inst.Threshold,
	)
	if err != nil {
		return nil, fmt.Errorf("pvss/commit: failed to encrypt shares: %w", err)
	}

	commit := &Commit{
		Index: inst.dealerState.index,
		Shares: commitSharesFromKyber(
			pubPoly.Shares(len(inst.Participants)),
			encShares,
		),
	}

	// Handle our own encrypted share.
	if err = inst.OnCommit(commit); err != nil {
		return nil, fmt.Errorf("pvss/commit: failed to process own commit: %w", err)
	}

	return commit, nil
}

// OnCommit processes a commitment message received from a participant.
//
// Note: This assumes that the commit is authentic and attributable.
func (inst *Instance) OnCommit(commit *Commit) error {
	onlyVerify := inst.isVerifyOnly()

	numParticipants := len(inst.Participants)
	if numS := len(commit.Shares); numS != numParticipants {
		return fmt.Errorf("pvss/commit: invalid number of shares: %d", numS)
	}

	commitIdx := commit.Index
	if commitIdx < 0 || commitIdx >= numParticipants {
		return fmt.Errorf("pvss/commit: invalid commit index: %d", commitIdx)
	}
	if inst.Commits[commitIdx] != nil {
		return fmt.Errorf("pvss/commit: received multiple commits for participant: %d", commitIdx)
	}

	var (
		polyShares []*share.PubShare
		encShares  []*pvss.PubVerShare
	)
	for idx, share := range commit.Shares {
		if share == nil {
			return fmt.Errorf("pvss/commit: missing share: %d", idx)
		}
		if err := share.isWellFormed(); err != nil {
			return fmt.Errorf("pvss/commit: share %d malformed: %w", idx, err)
		}

		polyShare, encShare := share.toKyber(idx)
		polyShares = append(polyShares, polyShare)
		encShares = append(encShares, encShare)
	}

	publicPoly, err := share.RecoverPubPoly(suite, polyShares, inst.Threshold, numParticipants)
	if err != nil {
		return fmt.Errorf("pvss/commit: failed to recover public polynomial: %w", err)
	}

	// Note: In theory this is overly strict since the PVSS algorithm
	// can recover the secret even if shares are malformed.  But the
	// assumption is that anything that submits a commit that has
	// malformed entries is evil.
	//
	// The coding theory checks would go here, if we ever decide to
	// implement such a thing.
	cs := &CommitState{
		Commit: commit,
	}
	for idx, share := range encShares {
		sH := publicPoly.Eval(idx).V
		switch {
		case !onlyVerify && idx == inst.dealerState.index:
			// Verify and decrypt the share that is intended for us.
			ds, err := pvss.DecShare(
				suite,
				basePoint,
				inst.dealerState.point,
				sH,
				inst.dealerState.scalar,
				share,
			)
			if err != nil {
				return fmt.Errorf("pvss/commit: failed to decrypt share: %w", err)
			}

			// Only store this if the all of the shares check out.
			cs.DecryptedShare = pubVerShareFromKyber(ds)
		default:
			// Verify the encrypted share that is intended for another.
			if err := pvss.VerifyEncShare(
				suite,
				basePoint,
				inst.participants()[idx],
				sH,
				share,
			); err != nil {
				return fmt.Errorf("pvss/commit: failed to verify encrypted share (%d:%d): %w", commitIdx, idx, err)
			}
		}
	}

	inst.Commits[commitIdx] = cs

	return nil
}

// MayReveal returns true iff it is possible to proceed to the reveal
// step, and the total number of distinct valid commitments received.
func (inst *Instance) MayReveal() (bool, int) {
	totalCommits := len(inst.Commits)
	return totalCommits >= inst.Threshold, totalCommits
}

// Reveal executes the reveal phase of the protocol, generating a reveal
// message to be broadcasted to all participants.
func (inst *Instance) Reveal() (*Reveal, error) {
	if inst.isVerifyOnly() {
		return nil, errVerifyOnly
	}

	if ok, _ := inst.MayReveal(); !ok {
		return nil, fmt.Errorf("pvss/reveal: insufficient valid commits")
	}

	reveal := &Reveal{
		Index:           inst.dealerState.index,
		DecryptedShares: make(map[int]*PubVerShare),
	}
	for idx, cs := range inst.Commits {
		reveal.DecryptedShares[idx] = cs.DecryptedShare
	}

	// Handle our own reveal.
	if err := inst.OnReveal(reveal); err != nil {
		return nil, fmt.Errorf("pvss/reveal: failed to process own reveal: %w", err)
	}

	return reveal, nil
}

// OnReveal processes a reveal message received from a participant.
//
// Note: This assumes that the reveal is authentic and attributable.
func (inst *Instance) OnReveal(reveal *Reveal) error {
	revealIdx := reveal.Index

	if revealIdx < 0 || revealIdx >= len(inst.Participants) {
		return fmt.Errorf("pvss/reveal: invalid reveal index: %d", revealIdx)
	}
	if inst.Reveals[revealIdx] != nil {
		return fmt.Errorf("pvss/reveal: received multiple reveals for participant: %d", revealIdx)
	}
	if numDs := len(reveal.DecryptedShares); numDs != len(inst.Commits) {
		return fmt.Errorf("pvss/reveal: invalid number of decrypted shares: %d", numDs)
	}

	decShares := make(map[int]*pvss.PubVerShare)
	for idx, share := range reveal.DecryptedShares {
		if share == nil {
			return fmt.Errorf("pvss/reveal: missing share: %d", idx)
		}
		if err := share.isWellFormed(); err != nil {
			return fmt.Errorf("pvss/reveal: share %d malformed: %w", idx, err)
		}

		decShares[idx] = share.toKyber(revealIdx)
	}

	g := suite.Point().Base()
	for idx, ds := range decShares {
		cs := inst.Commits[idx]
		if cs == nil {
			return fmt.Errorf("pvss/reveal: reveal for missing commit: %d", idx)
		}

		_, es := cs.Commit.Shares[revealIdx].toKyber(idx)

		if err := pvss.VerifyDecShare(
			suite,
			g,
			inst.participants()[revealIdx],
			es,
			ds,
		); err != nil {
			return fmt.Errorf("pvss/reveal: failed to verify decrypted share (%d:%d): %w", revealIdx, idx, err)
		}
	}

	// Store the reveal and all of the decrypted shares.
	inst.Reveals[revealIdx] = reveal
	for idx := range decShares {
		m := inst.DecryptedShares[idx]
		if m == nil {
			m = make(map[int]*PubVerShare)
			inst.DecryptedShares[idx] = m
		}

		// This works because decShares and reveal.DecryptedShares
		// have the same reveals in the same places.
		m[revealIdx] = reveal.DecryptedShares[idx]
	}

	return nil
}

// MayRecover returns true iff it is possible to proceed to the recovery
// step, and the total number of distinct valid reveals received.
func (inst *Instance) MayRecover() (bool, int) {
	var goodInstances int
	for i := 0; i < len(inst.Participants); i++ {
		decShares := inst.DecryptedShares[i]
		if len(decShares) >= inst.Threshold {
			goodInstances++
		}
	}

	return goodInstances >= inst.Threshold, len(inst.Reveals)
}

// Recover executes the recovery phase of the protocol, returning the resulting
// composite entropy and the indexes of the participants that contributed fully.
func (inst *Instance) Recover() ([]byte, []int, error) {
	if ok, _ := inst.MayRecover(); !ok {
		return nil, nil, fmt.Errorf("pvss/recover: insufficient valid reveals")
	}

	// Iterate over each participant's PVSS instance.
	points := make([]kyber.Point, 0, len(inst.DecryptedShares))
	for i := 0; i < len(inst.Participants); i++ {
		// All of the shares in `inst.DecryptedShares` are valid.
		decShares := inst.DecryptedShares[i]
		if len(decShares) < inst.Threshold {
			continue
		}

		// Note: This uses `share.RecoverCommit` instead of
		// `pvss.RecoverSecret` because `Instance.OnReveal` calls
		// `pvss.VerifyDecShare`.
		shares := make([]*share.PubShare, 0, len(decShares))
		for idx, decShare := range decShares {
			ds := decShare.toKyber(idx)
			shares = append(shares, &ds.S)
		}
		point, err := share.RecoverCommit(
			suite,
			shares,
			inst.Threshold,
			len(inst.Participants),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("pvss/recover: failed to recover secret (%d): %w", i, err)
		}

		points = append(points, point)
	}

	// This should NEVER happen, but check anyway.
	if numPoints := len(points); numPoints < inst.Threshold {
		return nil, nil, fmt.Errorf("pvss/recover: insufficient recovered points: %d", numPoints)
	}

	// Produce the final entropy based on all of the points.
	h := suite.Hash()
	_, _ = h.Write([]byte("oasis-core/pvss: Hash points"))
	for _, point := range points {
		b, err := point.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("pvss/recover: failed to marshal point: %w", err)
		}
		_, _ = h.Write(b)
	}

	// Credit everyone that submitted a valid reveal.
	contributors := make([]int, 0, len(inst.DecryptedShares))
	for idx := range inst.Reveals {
		contributors = append(contributors, idx)
	}
	sort.Ints(contributors)

	return h.Sum(nil), contributors, nil
}

// New creates a new protocol instance with the provided configuration.
func New(cfg *Config) (*Instance, error) {
	numParticipants := len(cfg.Participants)
	if numParticipants < 2 {
		return nil, fmt.Errorf("pvss/new: insufficient participants: %d", numParticipants)
	}
	if numParticipants > math.MaxInt32 {
		// Enforcing this constraint, in combination with explicit
		// checks in `OnCommit` and `OnReveal`, ensures that using
		// signed integers in the serialized types will not cause
		// issues regardless of the underlying architecture.
		//
		// That said, 32 bit platforms aren't supported by
		// tendermint anyway, and our use of this uses CBOR (all
		// integers are 64 bits), so it is a bit of a moot point.
		return nil, fmt.Errorf("pvss/new: too many participants: %d", numParticipants)
	}
	if cfg.Threshold <= 0 || cfg.Threshold > numParticipants {
		return nil, fmt.Errorf("pvss/new: insufficient threshold: %d", cfg.Threshold)
	}

	var participants []kyber.Point
	for idx, participant := range cfg.Participants {
		if err := participant.isWellFormed(); err != nil {
			return nil, fmt.Errorf("pvss/new: invalid point for participant %d: %w", idx, err)
		}
		participants = append(participants, participant.Inner())
	}

	inst := &Instance{
		Participants:       cfg.Participants,
		Commits:            make(map[int]*CommitState),
		Reveals:            make(map[int]*Reveal),
		DecryptedShares:    make(map[int]map[int]*PubVerShare),
		Threshold:          cfg.Threshold,
		cachedParticipants: participants,
	}

	if cfg.PrivateKey != nil {
		if err := inst.SetScalar(cfg.PrivateKey); err != nil {
			return nil, err
		}
	}

	return inst, nil
}

func (inst *Instance) participants() []kyber.Point {
	if len(inst.cachedParticipants) == 0 {
		var participants []kyber.Point
		for _, participant := range inst.Participants {
			participants = append(participants, participant.Inner())
		}
		inst.cachedParticipants = participants
	}

	return inst.cachedParticipants
}

func (inst *Instance) isVerifyOnly() bool {
	return inst.dealerState == nil
}

// NewKeyPair creates a new scalar/point pair for use with a PVSS instance.
func NewKeyPair() (*Scalar, *Point, error) {
	for i := 0; i < maxRetries; i++ {
		scalarInner := suite.Scalar().Pick(suite.RandomStream())
		scalar := scalarFromKyber(scalarInner)
		point := scalar.Point()

		if pointIsValid(point.Inner()) {
			return &scalar, &point, nil
		}
	}

	return nil, nil, fmt.Errorf("pvss: failed to generate scalar")
}

// Commit is a PVSS commit.
type Commit struct {
	Index  int            `json:"index"`
	Shares []*CommitShare `json:"shares"`
}

// Reveal is a PVSS reveal.
type Reveal struct {
	Index           int                  `json:"index"`
	DecryptedShares map[int]*PubVerShare `json:"decrypted_shares"`
}

// CommitState is a PVSS commit and the corresponding decrypted share,
// if any.
type CommitState struct {
	Commit         *Commit      `json:"commit"`
	DecryptedShare *PubVerShare `json:"decrypted_share,omitempty"`
}
