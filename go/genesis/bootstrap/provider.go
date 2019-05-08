// Package bootstrap implements the genesis validator/document and
// the testnet (debug) bootstrap service.
package bootstrap

import "github.com/oasislabs/ekiden/go/genesis/api"

// Provider is a genesis document provider that uses the bootstrap server.
type Provider struct {
	address string

	document *api.Document
}

// GetGenesisDocument returns the genesis document.
func (p *Provider) GetGenesisDocument() (*api.Document, error) {
	if p.document != nil {
		return p.document, nil
	}

	doc, err := getGenesis(p.address)
	if err != nil {
		p.document = doc
	}

	return doc, err
}

func (p *Provider) RegisterValidator(validator *api.Validator) error {
	return registerValidator(p.address, validator)
}

func (p *Provider) RegisterSeed(seed *SeedNode) error {
	return registerSeed(p.address, seed)
}

func (p *Provider) GetSeeds() ([]*SeedNode, error) {
	return getSeeds(p.address)
}

func NewProvider(address string) (api.Provider, error) {
	return &Provider{
		address: address,
	}, nil
}
