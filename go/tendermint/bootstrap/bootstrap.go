// Package bootstrap implements the genesis validator/document and
// the testnet (debug) bootstrap service.
package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	golog "log"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/tendermint/internal/crypto"
)

const (
	validatorURIPath = "/bootstrap/v1/validator"
	genesisURIPath   = "/bootstrap/vi/genesis"
)

// GenesisDocument is the ekiden format tendermint GenesisDocument.
type GenesisDocument struct {
	Validators  []*GenesisValidator `json:"validators"`
	GenesisTime time.Time           `json:"genesis_time"`
}

// ToTendermint converts the GenesisDocument to tendermint's format.
func (d *GenesisDocument) ToTendermint() (*tmtypes.GenesisDoc, error) {
	doc := tmtypes.GenesisDoc{
		ChainID:         "0xa515",
		GenesisTime:     d.GenesisTime,
		ConsensusParams: tmtypes.DefaultConsensusParams(),
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
	PubKey      signature.PublicKey `json:"pub_key"`
	Name        string              `json:"name"`
	Power       int64               `json:"power"`
	CoreAddress string              `json:"core_address"`
}

type server struct {
	sync.Mutex
	service.BaseBackgroundService

	logger *logging.Logger
	srv    *http.Server

	bootstrappedCh chan struct{}

	genesisPath   string
	genesisDoc    []byte
	validators    []*GenesisValidator
	numValidators int
}

func (s *server) Start() error {
	err := s.srv.ListenAndServe()
	if err == nil {
		go func() {
			<-s.Quit()
			s.srv.Close()
		}()
	}
	return err
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

	if s.genesisDoc != nil {
		http.Error(w, "already have a genesis doc", http.StatusBadRequest)
		return
	}

	s.logger.Debug("received validator upload",
		"validator", string(b),
	)

	s.validators = append(s.validators, &validator)
	if len(s.validators) == s.numValidators {
		go s.buildGenesis()
	}

	_, _ = io.WriteString(w, "validator upload successful")
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
	case <-s.bootstrappedCh:
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.genesisDoc)
}

func (s *server) buildGenesis() {
	s.logger.Debug("building genesis document")

	s.Lock()
	defer s.Unlock()

	doc := &GenesisDocument{
		Validators:  s.validators,
		GenesisTime: time.Now(),
	}

	s.genesisDoc, _ = json.Marshal(doc)
	if s.genesisPath != "" {
		_ = ioutil.WriteFile(s.genesisPath, s.genesisDoc, 0600)
	}

	s.logger.Info("generated genesis document",
		"genesis_doc", string(s.genesisDoc),
	)

	close(s.bootstrappedCh)
}

// NewServer initializes a new testnet (debug) bootstrap server instance.
func NewServer(addr string, numValidators int, dataDir string) (service.BackgroundService, error) {
	baseSvc := *service.NewBaseBackgroundService("tendermint/bootstrap/server")
	s := &server{
		BaseBackgroundService: baseSvc,
		logger:                logging.GetLogger("tendermint/boostrap/server"),
		srv: &http.Server{
			Addr:     addr,
			ErrorLog: golog.New(ioutil.Discard, "tendermint/bootstrap/server/http", 0),
		},
		bootstrappedCh: make(chan struct{}),
		numValidators:  numValidators,
	}

	// Load the old genesis file iff it exists.
	if dataDir != "" {
		s.genesisPath = filepath.Join(dataDir, "genesis.json")

		b, err := ioutil.ReadFile(s.genesisPath)
		if err == nil {
			s.logger.Info("Using existing genesis document",
				"path", s.genesisPath,
				"genesis_doc", string(b),
			)
			s.genesisDoc = b
		}
	}

	// Initialize the http mux.
	mux := http.NewServeMux()
	mux.HandleFunc(validatorURIPath, s.handleValidator)
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

// Validator posts the node's GenesisValidator to the specified server,
// and retrives the genesis document.
func Validator(addr string, validator *GenesisValidator) (*GenesisDocument, error) {
	b, _ := json.Marshal(validator)
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

func statusToError(statusCode int) error {
	return fmt.Errorf("%s", http.StatusText(statusCode))
}
