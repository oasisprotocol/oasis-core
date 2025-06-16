// Package stateless implements a stateless CometBFT consensus node.
package stateless

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

// Service is a stateless CometBFT service.
type Service struct {
	*Services

	ctx    context.Context
	cancel context.CancelFunc
	quitCh chan struct{}

	submitter consensusAPI.SubmissionManager

	logger *logging.Logger
}

// NewService creates a new stateless CometBFT service.
func NewService(services *Services, submitter consensusAPI.SubmissionManager) (*Service, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &Service{
		ctx:       ctx,
		cancel:    cancel,
		quitCh:    make(chan struct{}),
		Services:  services,
		submitter: submitter,
		logger:    logging.GetLogger("cometbft/stateless/service"),
	}, nil
}

// SupportedFeatures implements consensusAPI.Service.
func (s *Service) SupportedFeatures() consensusAPI.FeatureMask {
	return consensusAPI.FeatureServices
}

// Synced implements consensusAPI.Service.
func (s *Service) Synced() <-chan struct{} {
	return s.Services.Synced()
}

// GetAddresses implements consensusAPI.Service.
func (s *Service) GetAddresses() ([]node.ConsensusAddress, error) {
	return nil, nil
}

// Checkpointer implements consensusAPI.Service.
func (s *Service) Checkpointer() checkpoint.Checkpointer {
	return nil
}

// Pruner implements consensusAPI.Service.
func (s *Service) Pruner() consensusAPI.StatePruner {
	return &nonePruner{}
}

// SubmissionManager implements consensusAPI.Service.
func (s *Service) SubmissionManager() consensusAPI.SubmissionManager {
	return s.submitter
}

// Cleanup implements consensusAPI.Service.
func (s *Service) Cleanup() {}

// Name implements consensusAPI.Service.
func (s *Service) Name() string {
	return "cometbft/stateless"
}

// Start implements consensusAPI.Service.
func (s *Service) Start() error {
	go func() {
		defer close(s.quitCh)
		if err := s.Serve(s.ctx); err != nil {
			s.logger.Error("stopped", "err", err)
		}
	}()

	return nil
}

// Stop implements consensusAPI.Service.
func (s *Service) Stop() {
	s.cancel()
	<-s.quitCh
}

// Quit implements consensusAPI.Service.
func (s *Service) Quit() <-chan struct{} {
	return s.quitCh
}

// Serve starts the service.
func (s *Service) Serve(ctx context.Context) error {
	s.logger.Info("started")

	if err := s.serve(ctx); err != nil {
		s.logger.Error("stopped", "err", err)
		return err
	}

	return nil
}

func (s *Service) serve(ctx context.Context) error {
	if err := s.Services.Serve(ctx); err != nil {
		return fmt.Errorf("services stopped: %w", err)
	}
	return nil
}
