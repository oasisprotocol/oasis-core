// Package bootstrap implements the genesis validator/document and
// the testnet (debug) bootstrap service.
package bootstrap

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	golog "log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/internal/crypto"
)

const (
	validatorURIPath = "/bootstrap/v1/validator"
	seedURIPath      = "/bootstap/v1/seeds"
	genesisURIPath   = "/bootstrap/vi/genesis"
)

// GenesisDocument is the ekiden format tendermint GenesisDocument.
type GenesisDocument struct {
	Validators  []*GenesisValidator `codec:"validators"`
	GenesisTime time.Time           `codec:"genesis_time"`
	AppState    string              `codec:"app_state,omit_empty"`
}

// ToTendermint converts the GenesisDocument to tendermint's format.
func (d *GenesisDocument) ToTendermint() (*tmtypes.GenesisDoc, error) {
	doc := tmtypes.GenesisDoc{
		ChainID:         "0xa515",
		GenesisTime:     d.GenesisTime,
		ConsensusParams: tmtypes.DefaultConsensusParams(),
		AppState:        []byte(d.AppState),
	}

	var tmValidators []tmtypes.GenesisValidator
	for _, v := range d.Validators {
		pk := crypto.PublicKeyToTendermint(&v.PubKey)
		validator := tmtypes.GenesisValidator{
			Address: pk.Address(),
			PubKey:  pk,
			Power:   v.Power,
			Name:    v.Name,
		}
		tmValidators = append(tmValidators, validator)
	}

	doc.Validators = tmValidators

	return &doc, nil
}

// GenesisValidator is the ekiden format tendermint GenesisValidator
type GenesisValidator struct {
	PubKey      signature.PublicKey `codec:"pub_key"`
	Name        string              `codec:"name"`
	Power       int64               `codec:"power"`
	CoreAddress string              `codec:"core_address"`
}

// SeedNode is a struct with seed node info
type SeedNode struct {
	PubKey      signature.PublicKey `codec:"pub_key"`
	CoreAddress string              `codec:"core_address"`
}

// ToTendermint converts the SeedNode to tendermint's format.
func (s *SeedNode) ToTendermint() string {
	tmPub := crypto.PublicKeyToTendermint(&s.PubKey)
	seedIDLower := strings.ToLower(tmPub.Address().String())
	return fmt.Sprintf("%s@%s", seedIDLower, s.CoreAddress)
}

type server struct {
	sync.Mutex
	service.BaseBackgroundService

	logger *logging.Logger
	srv    *http.Server

	genesisBootstrapChan chan struct{}
	seedBootstrapChan    chan struct{}

	genesisPath   string
	genesisDoc    []byte
	genesisTime   time.Time
	validators    []*GenesisValidator
	seeds         []*SeedNode
	seedsPath     string
	appState      string
	numValidators int
	numSeeds      int
}

func (s *server) Start() error {
	// Start the server.
	go func() {
		err := s.srv.ListenAndServe()
		if err != http.ErrServerClosed {
			s.logger.Error("error while running server",
				"err", err,
			)
		}
	}()

	// Wait for the quit signal.
	go func() {
		<-s.Quit()
		s.srv.Close()
	}()

	return nil
}

func errMethodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (s *server) handleValidator(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		errMethodNotAllowed(w, http.MethodPost)
		return
	}

	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "failed to read validator", http.StatusInternalServerError)
		return
	}

	var validator GenesisValidator
	if err = json.Unmarshal(b, &validator); err != nil {
		http.Error(w, "malformed validator: "+err.Error(), http.StatusBadRequest)
		return
	}

	// If this was something that should actually be used, sanity checking
	// the validator would be done here.
	validator.Power = 10

	s.Lock()
	defer s.Unlock()

	s.logger.Debug("received validator upload",
		"validator", string(b),
	)

	// Check if validator already exists
	var foundValidator bool
	for _, v := range s.validators {
		if v.PubKey.Equal(validator.PubKey) {
			// Other fields must not change.
			if v.Name != validator.Name || v.Power != validator.Power {
				break
			}

			s.logger.Info("updating validator's core address",
				"validator", validator,
			)

			v.CoreAddress = validator.CoreAddress
			foundValidator = true
			break
		}
	}

	if s.genesisDoc != nil {
		// Already have a genesis document. This means we need to ensure that
		// validators cannot change, only their addresses can. In case a validator
		// re-registers (e.g., due to it being restarted) we shouldn't fail as
		// that would prevent the validator from starting. Instead we just update
		// its CoreAddress and return the updated genesis document.

		if !foundValidator {
			// Updating validators when there is already a genesis document is
			// not allowed.
			s.logger.Error("tried to modify validators after genesis",
				"validator", validator,
			)
			http.Error(w, "already have a genesis doc", http.StatusBadRequest)
			return
		}

		// Update the genesis document. This is done in a separate goroutine and
		// even though the submitting validator may not receive the updated address
		// it doesn't really matter as this is its own address.
		go s.buildGenesis()
		return
	}

	// We don't have a genesisDoc yet, only add validator in case it doesn't yet exist
	if !foundValidator {
		s.validators = append(s.validators, &validator)
		if len(s.validators) == s.numValidators {
			go s.buildGenesis()
		}
	}
	_, _ = io.WriteString(w, "validator upload successful")
}

func (s *server) handleSeedUpload(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		errMethodNotAllowed(w, http.MethodPost)
		return
	}

	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "failed to read seed", http.StatusInternalServerError)
		return
	}

	var seed SeedNode
	if err = json.Unmarshal(b, &seed); err != nil {
		http.Error(w, "malformed seed: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.Lock()
	defer s.Unlock()

	s.logger.Debug("received seed upload",
		"seed", string(b),
	)

	// If seed already exists just update it's address.
	var foundSeed bool
	for _, storedSeed := range s.seeds {
		if storedSeed.PubKey.Equal(seed.PubKey) {
			storedSeed.CoreAddress = seed.CoreAddress
			foundSeed = true
			break
		}
	}
	if !foundSeed {
		s.seeds = append(s.seeds, &seed)
		if len(s.seeds) == s.numSeeds {
			s.logger.Debug("received enough seeds, seed bootstrap finished")
			defer close(s.seedBootstrapChan)
		}
	}
	if s.seedsPath != "" {
		go s.persistSeeds()
	}
	_, _ = io.WriteString(w, "seed upload successful")
}

func (s *server) handleSeedGet(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		errMethodNotAllowed(w, http.MethodGet)
		return
	}

	// Block until server is bootstraping seeds.
	select {
	case <-s.Quit():
		http.Error(w, "server shutting down", http.StatusInternalServerError)
		return
	case <-s.seedBootstrapChan:
	}

	s.Lock()
	defer s.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(json.Marshal(s.seeds))
}

func (s *server) handleSeed(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		s.handleSeedGet(w, req)
	case http.MethodPost:
		s.handleSeedUpload(w, req)
	default:
		errMethodNotAllowed(w, req.Method)
	}
}

func (s *server) handleGenesis(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		errMethodNotAllowed(w, http.MethodGet)
		return
	}

	// Block till a genesis document is available.
	select {
	case <-s.Quit():
		http.Error(w, "server shutting down", http.StatusInternalServerError)
		return
	case <-s.genesisBootstrapChan:
	}

	s.Lock()
	defer s.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.genesisDoc)
}

func (s *server) persistSeeds() {
	s.logger.Debug("persisting seeds")

	s.Lock()
	defer s.Unlock()

	seedsJSON := json.Marshal(s.seeds)
	if s.seedsPath != "" {
		_ = ioutil.WriteFile(s.seedsPath, seedsJSON, 0600)
	}
}

func (s *server) buildGenesis() {
	s.logger.Debug("building genesis document")

	s.Lock()
	defer s.Unlock()

	doc := &GenesisDocument{
		Validators:  s.validators,
		GenesisTime: time.Now(),
		AppState:    s.appState,
	}

	if s.genesisDoc == nil {
		s.genesisTime = doc.GenesisTime
		defer close(s.genesisBootstrapChan)
	} else {
		doc.GenesisTime = s.genesisTime
	}

	s.genesisDoc = json.Marshal(doc)
	if s.genesisPath != "" {
		_ = ioutil.WriteFile(s.genesisPath, s.genesisDoc, 0600)
	}

	s.logger.Info("generated genesis document",
		"genesis_doc", string(s.genesisDoc),
	)
}

// NewServer initializes a new testnet (debug) bootstrap server instance.
func NewServer(addr string, numValidators int, numSeeds int, appState *api.GenesisAppState, dataDir string) (service.BackgroundService, error) {
	baseSvc := *service.NewBaseBackgroundService("tendermint/bootstrap/server")
	s := &server{
		BaseBackgroundService: baseSvc,
		logger:                logging.GetLogger("tendermint/boostrap/server"),
		srv: &http.Server{
			Addr:     addr,
			ErrorLog: golog.New(ioutil.Discard, "tendermint/bootstrap/server/http", 0),
		},
		genesisBootstrapChan: make(chan struct{}),
		seedBootstrapChan:    make(chan struct{}),
		numValidators:        numValidators,
		numSeeds:             numSeeds,
	}
	if appState != nil {
		s.appState = string(json.Marshal(appState))
	}

	// Load the old state iff it exists.
	if dataDir != "" {
		s.genesisPath = filepath.Join(dataDir, "genesis.json")
		s.seedsPath = filepath.Join(dataDir, "seeds.json")

		b, err := ioutil.ReadFile(s.genesisPath)

		if err == nil {
			var doc GenesisDocument
			if err = json.Unmarshal(b, &doc); err != nil {
				s.logger.Error("corrupted genesis document",
					"err", err,
					"genesis_doc", string(b),
				)
			} else {
				s.logger.Info("using existing genesis document",
					"path", s.genesisPath,
					"genesis_doc", string(b),
				)

				if doc.AppState != s.appState {
					s.logger.Warn("appState mismatch, using persisted value",
						"provided", appState,
						"saved", doc.AppState,
					)
				}

				s.genesisDoc = b
				s.genesisTime = doc.GenesisTime
				s.validators = doc.Validators
				s.appState = doc.AppState
				close(s.genesisBootstrapChan)
			}
		}

		// Load saved seed nodes
		seeds, err := ioutil.ReadFile(s.seedsPath)
		if err == nil {
			var seedNodes []*SeedNode
			if err = json.Unmarshal(seeds, &seedNodes); err != nil {
				s.logger.Error("corrupted seed node file",
					"err", err,
					"seeds.json", string(seeds),
				)
			} else {
				s.logger.Info("using existing persisted seed nodes",
					"path", s.seedsPath,
					"seeds.json", string(seeds),
				)

				s.seeds = seedNodes
				if len(s.seeds) >= numSeeds {
					close(s.seedBootstrapChan)
				}
			}
		}
	}

	// Initialize the http mux.
	mux := http.NewServeMux()
	mux.HandleFunc(validatorURIPath, s.handleValidator)
	mux.HandleFunc(seedURIPath, s.handleSeed)
	mux.HandleFunc(genesisURIPath, s.handleGenesis)
	s.srv.Handler = mux

	return s, nil
}

// Client retrives the genesis document from the specified server.
func Client(addr string) (*GenesisDocument, error) {
	resp, err := http.Get("http://" + addr + genesisURIPath)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint/bootstrap: HTTP GET failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrap(statusToError(resp.StatusCode), "tendermint/bootstrap: HTTP GET failed")
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint/bootstrap: failed to read body")
	}

	var doc GenesisDocument
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, errors.Wrap(err, "tendermint/bootstrap: failed to parse genesis document")
	}

	return &doc, nil
}

// GetSeeds retrives the bootstrapped seeds from the specified server.
func GetSeeds(addr string) ([]*SeedNode, error) {
	resp, err := http.Get("http://" + addr + seedURIPath)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint/bootstrap: HTTP GET failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrap(statusToError(resp.StatusCode), "tendermint/bootstrap: HTTP GET failed")
	}

	seeds, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint/bootstrap: failed to read body")
	}

	var seedNodes []*SeedNode
	if err = json.Unmarshal(seeds, &seedNodes); err != nil {
		return nil, errors.Wrap(err, "tendermint/bootstrap: failed to parse seed nodes")
	}

	return seedNodes, nil
}

// Validator posts the node's GenesisValidator to the specified server,
// and retrives the genesis document.
func Validator(addr string, validator *GenesisValidator) (*GenesisDocument, error) {
	b := json.Marshal(validator)
	resp, err := http.Post("http://"+addr+validatorURIPath, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, errors.Wrap(err, "tendermint/bootstrap: HTTP POST failed")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrap(statusToError(resp.StatusCode), "tendermint/bootstrap: HTTP POST failed")
	}

	return Client(addr)
}

// Seed posts the node's data to the specified server announcing
// itself as a seed node.
func Seed(addr string, seed *SeedNode) error {
	b := json.Marshal(seed)
	resp, err := http.Post("http://"+addr+seedURIPath, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return errors.Wrap(err, "tendermint/bootstrap: HTTP POST failed")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.Wrap(statusToError(resp.StatusCode), "tendermint/bootstrap: HTTP POST failed")
	}

	return nil
}

func statusToError(statusCode int) error {
	return fmt.Errorf("%s", http.StatusText(statusCode))
}
