package fixtures

import (
	"context"
	"fmt"
	"sync"

	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

var (
	registeredFixtures sync.Map

	// ErrMissingFixture is the error returned when getting a nonexisting fixture.
	ErrMissingFixture = fmt.Errorf("fixture does not exist")
)

// Fixture is a protocol server fixture.
type Fixture interface {
	// Name is the name of the fixture.
	Name() string

	// Populate populates the db with the fixture.
	Populate(context.Context, db.NodeDB) (*node.Root, error)
}

// Register registers a new fixture.
func Register(fixture Fixture) {
	name := fixture.Name()
	if _, isRegistered := registeredFixtures.Load(name); isRegistered {
		panic(fmt.Errorf("fixture already registered: %s", name))
	}
	registeredFixtures.Store(name, fixture)
}

// GetFixture returns a registered fixture by name.
func GetFixture(name string) (Fixture, error) {
	h, exists := registeredFixtures.Load(name)
	if !exists {
		return nil, ErrMissingFixture
	}

	return h.(Fixture), nil
}
