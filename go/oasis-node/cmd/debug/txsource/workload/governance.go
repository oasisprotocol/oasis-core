package workload

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"google.golang.org/grpc"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// NameGovernance is the name of the governance workload.
const NameGovernance = "governance"

var (

	// Governance is the governance workload.
	Governance = &governanceWorkload{
		BaseWorkload: NewBaseWorkload(NameGovernance),
	}

	// Timeout after each governance workload iteration.
	iterationTimeout         = 2 * time.Second
	errUnexpectedGovTxResult = fmt.Errorf("unexpected governance tx result")
	numProposerAccounts      = 10
	// How likely voters should vote YES for the proposal made by i'th proposer.
	proposersVoteYesRate = []uint8{
		100,
		99,
		98,
		95,
		92,
		90,
		80,
		70,
		50,
		0,
	}
)

type governanceWorkload struct {
	BaseWorkload

	ctx context.Context
	rng *rand.Rand

	currentEpoch beacon.EpochTime
	parameters   *governance.ConsensusParameters

	consensus  consensus.ClientBackend
	governance governance.Backend

	proposerAccounts []*struct {
		signer  signature.Signer
		address staking.Address
		nonce   uint64
	}
	ensureYesVote map[uint64]bool

	validatorEntities []signature.Signer
}

func (g *governanceWorkload) ensureUpgradeCanceled(upgrade *upgrade.Descriptor) error {
	proposalID, err := g.submitCancelUpgradeProposal(upgrade, false)
	if err != nil {
		return fmt.Errorf("submitting cancel upgrade proposal: %w", err)
	}
	g.ensureYesVote[proposalID] = true
	// Vote for the submitted proposal.
	for _, v := range g.validatorEntities {
		if err := g.submitVote(v, proposalID, governance.VoteYes); err != nil {
			return err
		}
	}
	return nil
}

func (g *governanceWorkload) submitProposalContent(pc *governance.ProposalContent, shouldFail bool) (uint64, error) {
	proposerAcc := g.proposerAccounts[g.rng.Intn(len(g.proposerAccounts))]

	// Submit proposal.
	tx := governance.NewSubmitProposalTx(proposerAcc.nonce, nil, pc)
	proposerAcc.nonce++
	err := g.FundSignAndSubmitTx(g.ctx, proposerAcc.signer, tx)
	switch shouldFail {
	case true:
		if err == nil {
			g.Logger.Error("expected proposal submission to fail",
				"tx", tx,
				"proposal_content", pc,
			)
			return 0, fmt.Errorf("%w: expected proposal submission to fail", errUnexpectedGovTxResult)
		}
		g.Logger.Debug("proposal submission failed (expected)",
			"err", err,
		)
		return 0, nil
	case false:
		if err != nil {
			g.Logger.Error("failed to sign and submit proposal transaction",
				"tx", tx,
				"signer", proposerAcc.signer.Public(),
				"proposal_content", pc,
			)
			return 0, fmt.Errorf("%w: failed to sign and submit tx: %v", errUnexpectedGovTxResult, err)
		}
	}

	g.Logger.Debug("proposal submitted",
		"proposal_content", pc,
	)
	// Find submitted proposal.
	// In case there are multiple proposals with identical content, select the
	// one with higher ID - since that is the more recently submitted proposal.
	aps, err := g.governance.ActiveProposals(g.ctx, consensus.HeightLatest)
	if err != nil {
		return 0, fmt.Errorf("failed to query active proposals: %w", err)
	}
	var proposal *governance.Proposal
	for _, ap := range aps {
		if ap.Content.Equals(pc) {
			if proposal == nil || proposal.ID < ap.ID {
				proposal = ap
			}
		}
	}
	if proposal == nil {
		return 0, fmt.Errorf("submitted proposal not found: %v", pc)
	}

	return proposal.ID, nil
}

func (g *governanceWorkload) doUpgradeProposal() error {
	minUpgradeEpoch := int64(g.currentEpoch + g.parameters.UpgradeMinEpochDiff)
	maxUpgradeEpoch := minUpgradeEpoch + int64(3*g.parameters.UpgradeMinEpochDiff)
	// [minUpgradeEpoch, maxUpgradeEpoch]
	upgradeEpoch := beacon.EpochTime(g.rng.Int63n(maxUpgradeEpoch-minUpgradeEpoch+1) + minUpgradeEpoch)
	nameSuffix := make([]byte, 8)
	if _, err := g.rng.Read(nameSuffix); err != nil {
		return err
	}
	proposalContent := &governance.ProposalContent{
		Upgrade: &governance.UpgradeProposal{
			Descriptor: upgrade.Descriptor{
				Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
				Handler:   upgrade.HandlerName(fmt.Sprintf("test-upgrade_%s", hex.EncodeToString(nameSuffix))),
				Target:    version.Versions,
				Epoch:     upgradeEpoch,
			},
		},
	}

	// Check if upgrade submission is expected to succeed. It should fail in case
	// there is a pending upgrade already scheduled minUpgradeEpoch before/after the
	// proposed upgrade epoch.
	var shouldFail bool
	pendingUpgrades, err := g.governance.PendingUpgrades(g.ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("governance.PendingUpgrades: %w", err)
	}
	for _, pu := range pendingUpgrades {
		if pu.Epoch.AbsDiff(proposalContent.Upgrade.Epoch) < g.parameters.UpgradeMinEpochDiff {
			shouldFail = true
			break
		}
	}

	_, err = g.submitProposalContent(proposalContent, shouldFail)
	switch {
	case errors.Is(err, errUnexpectedGovTxResult):
		// Unexpected gov tx results can happen on epoch transitions:
		// - pending upgrade just being canceled by a different proposal
		// - new pending upgrade could have just been accepted
		if b, _ := g.checkEpochTransition(); b {
			// The error is probably be related to the epoch transition:
			g.Logger.Error("cancel upgrade proposal error on epoch transition", "err", err)
			return nil
		}
		return err
	default:
		return err
	}
}

func (g *governanceWorkload) submitCancelUpgradeProposal(descriptor *upgrade.Descriptor, shouldFail bool) (uint64, error) {
	// Find proposal matching the pending upgrade.
	ps, err := g.governance.Proposals(g.ctx, consensus.HeightLatest)
	if err != nil {
		return 0, fmt.Errorf("querying proposals: %w", err)
	}
	var proposal *governance.Proposal
	for _, p := range ps {
		if p.Content.Upgrade != nil && p.Content.Upgrade.Descriptor.Equals(descriptor) {
			proposal = p
			break
		}
	}
	if proposal == nil {
		g.Logger.Error("proposal for descriptor not found",
			"proposals", ps,
			"descriptor", descriptor,
		)
		return 0, fmt.Errorf("proposal for pending upgrade not found")
	}

	return g.submitProposalContent(
		&governance.ProposalContent{
			CancelUpgrade: &governance.CancelUpgradeProposal{
				ProposalID: proposal.ID,
			},
		}, shouldFail)
}

func (g *governanceWorkload) doCancelUpgradeProposal() error {
	pendingUpgrades, err := g.governance.PendingUpgrades(g.ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("governance.PendingUpgrades: %w", err)
	}

	// Pick a random eligible pending upgrade.
	var pendingUpgrade *upgrade.Descriptor
	var shouldFail bool
OUTER:
	for _, i := range rand.Perm(len(pendingUpgrades)) {
		pu := pendingUpgrades[i]

		d := pu.Epoch.AbsDiff(g.currentEpoch)
		switch {
		case d < g.parameters.UpgradeCancelMinEpochDiff:
			pendingUpgrade = pu
			shouldFail = true
			break OUTER
		case d > g.parameters.UpgradeCancelMinEpochDiff+2:
			pendingUpgrade = pu
			shouldFail = false
			break OUTER
		default:
			// Skip pending upgrades that are about to be closed, as the main
			// workload loop makes sure those will get canceled.
		}
	}
	if pendingUpgrade == nil {
		g.Logger.Debug("no eligible pending upgrade for submitting cancel upgrade proposal, skipping",
			"pending_upgrades", pendingUpgrades,
			"current_epoch", g.currentEpoch,
		)
		return nil
	}

	_, err = g.submitCancelUpgradeProposal(pendingUpgrade, shouldFail)
	switch {
	case errors.Is(err, errUnexpectedGovTxResult):
		// Unexpected gov tx results can happen on epoch transitions:
		// - pending upgrade just being canceled by a different proposal
		if b, _ := g.checkEpochTransition(); b {
			// The error is probably related to the epoch transition:
			g.Logger.Error("cancel upgrade proposal error on epoch transition", "err", err)
			return nil
		}
		return err
	default:
		return err
	}
}

func (g *governanceWorkload) doChangeParametersProposal() error { // nolint: gocyclo
	var (
		shouldFail bool
		module     string
		changes    cbor.RawMessage
	)

	randBool := func() bool {
		return g.rng.Intn(2) == 0
	}

	switch g.rng.Intn(7) {
	case 0:
		params, err := g.consensus.Governance().ConsensusParameters(g.ctx, consensus.HeightLatest)
		if err != nil {
			return err
		}
		var pc governance.ConsensusParameterChanges
		if randBool() {
			pc.StakeThreshold = &params.StakeThreshold
		}
		if randBool() {
			pc.UpgradeCancelMinEpochDiff = &params.UpgradeCancelMinEpochDiff
		}
		if randBool() {
			pc.UpgradeMinEpochDiff = &params.UpgradeMinEpochDiff
		}
		if randBool() {
			pc.VotingPeriod = &params.VotingPeriod
		}
		if randBool() {
			pc.MinProposalDeposit = &params.MinProposalDeposit
		}
		if randBool() {
			pc.EnableChangeParametersProposal = &params.EnableChangeParametersProposal
		}
		if randBool() {
			pc.GasCosts = params.GasCosts
		}
		shouldFail = pc.SanityCheck() != nil
		module = governance.ModuleName
		changes = cbor.Marshal(pc)
	case 1:
		params, err := g.consensus.Staking().ConsensusParameters(g.ctx, consensus.HeightLatest)
		if err != nil {
			return err
		}
		var pc staking.ConsensusParameterChanges
		if randBool() {
			pc.DebondingInterval = &params.DebondingInterval
		}
		if randBool() {
			pc.GasCosts = params.GasCosts
		}
		if randBool() {
			pc.MinDelegationAmount = &params.MinDelegationAmount
		}
		if randBool() {
			pc.MinTransferAmount = &params.MinTransferAmount
		}
		if randBool() {
			pc.MinTransactBalance = &params.MinTransactBalance
		}
		if randBool() {
			pc.DisableTransfers = &params.DisableTransfers
		}
		if randBool() {
			pc.DisableDelegation = &params.DisableDelegation
		}
		if randBool() {
			pc.AllowEscrowMessages = &params.AllowEscrowMessages
		}
		if randBool() {
			pc.MaxAllowances = &params.MaxAllowances
		}
		if randBool() {
			pc.FeeSplitWeightVote = &params.FeeSplitWeightVote
		}
		if randBool() {
			pc.FeeSplitWeightNextPropose = &params.FeeSplitWeightNextPropose
		}
		if randBool() {
			pc.FeeSplitWeightPropose = &params.FeeSplitWeightPropose
		}
		if randBool() {
			pc.RewardFactorEpochSigned = &params.RewardFactorEpochSigned
		}
		if randBool() {
			pc.RewardFactorBlockProposed = &params.RewardFactorBlockProposed
		}
		shouldFail = pc.SanityCheck() != nil
		module = staking.ModuleName
		changes = cbor.Marshal(pc)
	case 2:
		params, err := g.consensus.RootHash().ConsensusParameters(g.ctx, consensus.HeightLatest)
		if err != nil {
			return err
		}
		var pc roothash.ConsensusParameterChanges
		if randBool() {
			pc.GasCosts = params.GasCosts
		}
		if randBool() {
			pc.MaxRuntimeMessages = &params.MaxRuntimeMessages
		}
		if randBool() {
			pc.MaxInRuntimeMessages = &params.MaxInRuntimeMessages
		}
		if randBool() {
			pc.MaxEvidenceAge = &params.MaxEvidenceAge
		}
		shouldFail = pc.SanityCheck() != nil
		module = roothash.ModuleName
		changes = cbor.Marshal(pc)
	case 3:
		params, err := g.consensus.Registry().ConsensusParameters(g.ctx, consensus.HeightLatest)
		if err != nil {
			return err
		}
		var pc registry.ConsensusParameterChanges
		if randBool() {
			pc.DisableRuntimeRegistration = &params.DisableRuntimeRegistration
		}
		if randBool() {
			pc.DisableKeyManagerRuntimeRegistration = &params.DisableKeyManagerRuntimeRegistration
		}
		if randBool() {
			pc.GasCosts = params.GasCosts
		}
		if randBool() {
			pc.MaxNodeExpiration = &params.MaxNodeExpiration
		}
		if randBool() {
			pc.EnableRuntimeGovernanceModels = params.EnableRuntimeGovernanceModels
		}
		if randBool() {
			pc.TEEFeatures = &params.TEEFeatures
		}
		if randBool() {
			pc.MaxRuntimeDeployments = &params.MaxRuntimeDeployments
		}
		shouldFail = pc.SanityCheck() != nil
		module = registry.ModuleName
		changes = cbor.Marshal(pc)
	case 4:
		params, err := g.consensus.Scheduler().ConsensusParameters(g.ctx, consensus.HeightLatest)
		if err != nil {
			return err
		}
		var pc scheduler.ConsensusParameterChanges
		if randBool() {
			pc.MinValidators = &params.MinValidators
		}
		if randBool() {
			pc.MaxValidators = &params.MaxValidators
		}
		shouldFail = pc.SanityCheck() != nil
		module = scheduler.ModuleName
		changes = cbor.Marshal(pc)
	case 5:
		shouldFail = true
		module = governance.ModuleName
		changes = cbor.Marshal(cbor.Marshal(governance.ConsensusParameterChanges{}))
	case 6:
		shouldFail = true
		module = "module"
		changes = cbor.Marshal("changes")
	default:
		return fmt.Errorf("unimplemented")
	}

	proposalContent := &governance.ProposalContent{
		ChangeParameters: &governance.ChangeParametersProposal{
			Module:  module,
			Changes: changes,
		},
	}

	_, err := g.submitProposalContent(proposalContent, shouldFail)
	return err
}

func (g *governanceWorkload) submitVote(voter signature.Signer, proposalID uint64, vote governance.Vote) error {
	tx := governance.NewCastVoteTx(0, nil, &governance.ProposalVote{
		ID:   proposalID,
		Vote: vote,
	})
	err := g.FundSignAndSubmitTx(g.ctx, voter, tx)
	switch {
	case err == nil:
		g.Logger.Debug("proposal vote cast", "vote", vote, "voter", voter.Public(), "proposal_id", proposalID)
		return nil
	case errors.Is(err, registry.ErrNoSuchNode),
		errors.Is(err, governance.ErrNotEligible):
		g.Logger.Error("submitting vote error: voter not a validator, continuing",
			"err", err,
			"voter", voter.Public(),
			"proposal_id", proposalID,
		)
		return nil
	default:
		return fmt.Errorf("failed to sign and submit cast vote transaction: %w", err)
	}
}

func (g *governanceWorkload) doGovernanceVote() error {
	activeProposals, err := g.governance.ActiveProposals(g.ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("governance.ActiveProposals(): %w", err)
	}
	if len(activeProposals) == 0 {
		g.Logger.Debug("no active proposals, skipping submit vote")
		return nil
	}

	var proposal *governance.Proposal
	for _, idx := range rand.Perm(len(activeProposals)) {
		p := activeProposals[idx]
		// Avoid voting for proposals that could close during this iteration.
		if p.ClosesAt <= g.currentEpoch+1 {
			continue
		}
		proposal = p
		break
	}

	// Select vote based on the proposer.
	proposerIdx := -1
	for i, p := range g.proposerAccounts {
		if p.address.Equal(proposal.Submitter) {
			proposerIdx = i
			break
		}
	}
	if proposerIdx == -1 {
		return fmt.Errorf("invalid proposal submitter: %v", proposal.Submitter)
	}
	var vote governance.Vote
	switch {
	case g.ensureYesVote[proposal.ID],
		uint8(g.rng.Intn(100)) < proposersVoteYesRate[proposerIdx]:
		vote = governance.VoteYes
	case g.rng.Intn(100) < 50:
		vote = governance.VoteNo
	default:
		vote = governance.VoteAbstain
	}

	return g.submitVote(g.validatorEntities[g.rng.Intn(len(g.validatorEntities))], proposal.ID, vote)
}

func (g *governanceWorkload) checkEpochTransition() (bool, error) {
	epoch, err := g.Consensus().Beacon().GetEpoch(g.ctx, consensus.HeightLatest)
	if err != nil {
		return false, fmt.Errorf("querying epoch: %w", err)
	}

	return epoch > g.currentEpoch, nil
}

// Implements Workload.
func (g *governanceWorkload) NeedsFunds() bool {
	return true
}

// Implements Workload.
func (g *governanceWorkload) Run(
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	cnsc consensus.ClientBackend,
	sm consensus.SubmissionManager,
	fundingAccount signature.Signer,
	validatorEntities []signature.Signer,
) error {
	var err error

	// Initialize state.
	g.BaseWorkload.Init(cnsc, sm, fundingAccount)
	g.rng = rng
	g.ctx = context.Background()

	g.parameters, err = cnsc.Governance().ConsensusParameters(g.ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("error querying governance consensus parameters: %w", err)
	}

	g.consensus = cnsc
	g.governance = cnsc.Governance()

	g.validatorEntities = validatorEntities
	if len(g.validatorEntities) == 0 {
		return fmt.Errorf("workload requires validator entities")
	}

	g.proposerAccounts = make([]*struct {
		signer  signature.Signer
		address staking.Address
		nonce   uint64
	}, numProposerAccounts)
	fac := memorySigner.NewFactory()
	for i := range g.proposerAccounts {
		var signer signature.Signer
		signer, err = fac.Generate(signature.SignerEntity, rng)
		if err != nil {
			return fmt.Errorf("memory signer factory Generate account %d: %w", i, err)
		}
		g.proposerAccounts[i] = &struct {
			signer  signature.Signer
			address staking.Address
			nonce   uint64
		}{
			signer:  signer,
			address: staking.NewAddress(signer.Public()),
		}
		if err = g.TransferFunds(
			g.ctx,
			fundingAccount,
			g.proposerAccounts[i].address,
			g.parameters.MinProposalDeposit.ToBigInt().Uint64()*1000,
		); err != nil {
			return fmt.Errorf("account funding failure: %w", err)
		}
	}

	g.ensureYesVote = make(map[uint64]bool)

	// Main workload loop.
	for {
		select {
		case <-time.After(iterationTimeout):
		case <-gracefulExit.Done():
			g.Logger.Debug("time's up")
			return nil
		}

		var epoch beacon.EpochTime
		epoch, err = g.Consensus().Beacon().GetEpoch(g.ctx, consensus.HeightLatest)
		if err != nil {
			return fmt.Errorf("querying epoch: %w", err)
		}

		// Epoch transition - update the local state accordingly.
		if epoch > g.currentEpoch {
			g.currentEpoch = epoch

			// Make sure no pending upgrade will go through.
			// XXX: this makes sure that any pending upgrades that are about to be executed are
			// canceled. When txsource suite supports handling upgrades mid-run, remove this part.
			var upgrades []*upgrade.Descriptor
			upgrades, err = g.governance.PendingUpgrades(g.ctx, consensus.HeightLatest)
			if err != nil {
				return fmt.Errorf("querying pending upgrades: %w", err)
			}
			for _, up := range upgrades {
				if up.Epoch.AbsDiff(g.currentEpoch) != g.parameters.UpgradeCancelMinEpochDiff+2 {
					continue
				}
				g.Logger.Debug("ensuring pending upgrade canceled",
					"upgrade", up,
				)
				if err = g.ensureUpgradeCanceled(up); err != nil {
					return fmt.Errorf("ensuring upgrade canceled: %w", err)
				}
			}
		}

		switch rng.Intn(5) {
		case 0:
			if err = g.doUpgradeProposal(); err != nil {
				return fmt.Errorf("submitting governance upgrade proposal: %w", err)
			}
		case 1:
			if err = g.doCancelUpgradeProposal(); err != nil {
				return fmt.Errorf("submitting governance cancel upgrade proposal: %w", err)
			}
		case 2:
			if err = g.doChangeParametersProposal(); err != nil {
				return fmt.Errorf("submitting governance change parameters proposal: %w", err)
			}
		case 3, 4:
			if err = g.doGovernanceVote(); err != nil {
				return fmt.Errorf("submitting governance vote: %w", err)
			}
		default:
			return fmt.Errorf("unimplemented")
		}
	}
}
