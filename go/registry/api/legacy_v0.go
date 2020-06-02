package api

// TODO: Remove this when dropping support for node descriptor version 0 (oasis-core#2918).

import (
	goEd25519 "crypto/ed25519"
	"crypto/x509"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

func nodeV0parseTLSPubKey(logger *logging.Logger, sigNode *node.MultiSignedNode) (signature.PublicKey, error) {
	var (
		cert    *x509.Certificate
		certPub signature.PublicKey
		err     error
	)
	type v0Node struct {
		// We are only interested in the old "committee certificate" field.
		Committee struct {
			Certificate []byte `json:"certificate"`
		} `json:"committee"`
	}
	var node v0Node
	if err = cbor.Unmarshal(sigNode.Blob, &node); err != nil {
		logger.Error("RegisterNode: invalid v0 node descriptor",
			"node", node,
			"err", err,
		)
		return certPub, ErrInvalidArgument
	}

	cert, err = x509.ParseCertificate(node.Committee.Certificate)
	if err != nil {
		logger.Error("RegisterNode: failed to parse v0 committee certificate",
			"err", err,
			"node", node,
		)
		return certPub, fmt.Errorf("%w: failed to parse v0 committee certificate", ErrInvalidArgument)
	}

	edPub, ok := cert.PublicKey.(goEd25519.PublicKey)
	if !ok {
		logger.Error("RegisterNode: incorrect v0 committee certifiate signing algorithm",
			"node", node,
		)
		return certPub, fmt.Errorf("%w: incorrect v0 committee certificate signing algorithm", ErrInvalidArgument)
	}

	if err = certPub.UnmarshalBinary(edPub); err != nil {
		// This should NEVER happen.
		logger.Error("RegisterNode: malformed v0 committee certificate signing key",
			"err", err,
			"node", node,
		)
		return certPub, fmt.Errorf("%w: malformed v0 committee certificate signing key", ErrInvalidArgument)
	}

	return certPub, nil
}
