// SPDX-License-Identifier: MPL-2.0

// Package secp256k1signer implements a minimal OpenBao secrets engine that
// holds non-exportable secp256k1 keys and produces EVM-verifiable
// (ecrecover-compatible) ECDSA signatures over caller-supplied 32-byte
// digests. It exists because stock OpenBao transit offers no secp256k1 key
// type (openbao/openbao#2618, wontfix).
package secp256k1signer

import (
	"context"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pluginVersion is injected at build time via
// -ldflags "-X github.com/IndependentImpact/openbao-plugin-secp256k1.pluginVersion=vX.Y.Z"
var pluginVersion = "v0.0.0-dev"

type backend struct {
	*framework.Backend

	// keyLock serializes writes to key entries. Reads of immutable key
	// material (signing) do not take it.
	keyLock sync.Mutex
}

// Factory returns the configured backend for plugin serving.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() *backend {
	b := &backend{}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// Private key material gets an extra layer of encryption under a
			// capable seal.
			SealWrapStorage: []string{"keys/"},
		},
		Paths: []*framework.Path{
			b.pathKeysList(),
			b.pathKeys(),
			b.pathKeysConfig(),
			b.pathKeysRotate(),
			b.pathSign(),
		},
		RunningVersion: pluginVersion,
	}
	return b
}

const backendHelp = `
The secp256k1 secrets engine holds non-exportable secp256k1 private keys and
signs caller-supplied 32-byte digests, returning 65-byte r||s||v signatures
verifiable by the EVM ecrecover precompile. Key material can never be read,
exported, or backed up through any endpoint.
`
