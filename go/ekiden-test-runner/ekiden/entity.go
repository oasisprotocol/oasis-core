package ekiden

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
)

var entityArgsDebugTest = []string{
	"--" + flags.CfgDebugTestEntity,
	"--" + common.CfgDebugAllowTestKeys,
}

// Entity is an ekiden entity.
type Entity struct {
	dir *env.Dir

	entity       *entity.Entity
	entitySigner signature.Signer

	isDebugTestEntity bool
}

// EntityCfg is the ekiden entity provisioning configuration.
type EntityCfg struct {
	IsDebugTestEntity      bool
	AllowEntitySignedNodes bool
	Restore                bool
}

// Inner returns the actual ekiden entity and it's signer.
func (ent *Entity) Inner() (*entity.Entity, signature.Signer) {
	return ent.entity, ent.entitySigner
}

// EntityKeyPath returns the path to the entity private key.
func (ent *Entity) EntityKeyPath() string {
	if ent.isDebugTestEntity {
		return ""
	}
	return filepath.Join(ent.dir.String(), fileSigner.FileEntityKey)
}

// DescriptorPath returns the path to the entity descriptor.
func (ent *Entity) DescriptorPath() string {
	if ent.isDebugTestEntity {
		return ""
	}
	return filepath.Join(ent.dir.String(), "entity.json")
}

func (ent *Entity) toGenesisArgs() []string {
	if ent.dir != nil {
		return []string{"--entity", ent.dir.String()}
	} else if ent.isDebugTestEntity {
		return entityArgsDebugTest
	}

	return nil
}

func (ent *Entity) toGenesisDescriptorArgs() []string {
	if ent.dir != nil {
		return []string{"--entity", filepath.Join(ent.dir.String(), "entity_genesis.json")}
	} else if ent.isDebugTestEntity {
		return entityArgsDebugTest
	}

	return nil
}

// NewEntity provisions a new entity and adds it to the network.
func (net *Network) NewEntity(cfg *EntityCfg) (*Entity, error) {
	var ent *Entity
	if cfg.IsDebugTestEntity {
		ent = &Entity{
			isDebugTestEntity: true,
		}
		ent.entity, ent.entitySigner, _ = entity.TestEntity()
	} else {
		entName := fmt.Sprintf("entity-%d", len(net.entities))
		entityDir, err := net.baseDir.NewSubDir(entName)
		if err != nil {
			net.logger.Error("failed to create entity subdir",
				"err", err,
				"entity_name", entName,
			)
			return nil, errors.Wrap(err, "ekiden/entity: failed to create entity subdir")
		}

		if !cfg.Restore {
			args := []string{
				"registry", "entity", "init",
				"--datadir", entityDir.String(),
			}
			if cfg.AllowEntitySignedNodes {
				args = append(args, "--entity.debug.allow_entity_signed_nodes")
			}

			var w io.WriteCloser
			w, err = entityDir.NewLogWriter("provision.log")
			if err != nil {
				return nil, err
			}
			defer w.Close()

			if err = net.runEkidenBinary(w, args...); err != nil {
				net.logger.Error("failed to provision entity",
					"err", err,
					"entity_name", entName,
				)
				return nil, errors.Wrap(err, "ekiden/entity: failed to provision entity")
			}
		}

		ent = &Entity{
			dir: entityDir,
		}
		signerFactory := fileSigner.NewFactory(entityDir.String(), signature.SignerEntity)
		ent.entity, ent.entitySigner, err = entity.Load(entityDir.String(), signerFactory)
		if err != nil {
			net.logger.Error("failed to load newly provisoned entity",
				"err", err,
				"entity_name", entName,
			)
			return nil, errors.Wrap(err, "ekiden/entity: failed to load newly provisioned entity")
		}
	}

	net.entities = append(net.entities, ent)

	return ent, nil
}
