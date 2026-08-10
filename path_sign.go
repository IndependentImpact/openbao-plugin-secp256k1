// SPDX-License-Identifier: MPL-2.0

package secp256k1signer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) pathSign() *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + keyNamePattern + "$",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString, Description: "Name of the key to sign with."},
			"input": {
				Type:        framework.TypeString,
				Description: "Base64-encoded 32-byte digest to sign (e.g. the Keccak-256 EIP-712 digest).",
				Required:    true,
			},
			"prehashed": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Must be true. This engine signs digests only; it never hashes for the caller.",
			},
			"key_version": {
				Type:        framework.TypeInt,
				Default:     0,
				Description: "Key version to sign with. 0 (default) means the latest version.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleSign},
		},
		HelpSynopsis: "Sign a 32-byte digest, returning a 65-byte r||s||v signature verifiable by the EVM ecrecover precompile.",
	}
}

func (b *backend) handleSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	if !d.Get("prehashed").(bool) {
		return logical.ErrorResponse("prehashed must be true: this engine signs caller-supplied digests only"), nil
	}

	inputB64 := d.Get("input").(string)
	if inputB64 == "" {
		return logical.ErrorResponse("input is required"), nil
	}
	digest, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse("input is not valid base64: %s", err), nil
	}
	// The underlying library silently truncates longer inputs and zero-pads
	// shorter ones, which would sign the wrong value without any error.
	if len(digest) != 32 {
		return logical.ErrorResponse("input must decode to exactly 32 bytes, got %d", len(digest)), nil
	}

	entry, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("key %q not found", name), nil
	}

	version := d.Get("key_version").(int)
	if version == 0 {
		version = entry.LatestVersion
	}
	kv, ok := entry.Versions[version]
	if !ok {
		return logical.ErrorResponse("key %q has no version %d", name, version), nil
	}
	if len(kv.PrivateKey) != 32 {
		return nil, fmt.Errorf("stored private key has invalid length %d", len(kv.PrivateKey))
	}

	priv := secp256k1.PrivKeyFromBytes(kv.PrivateKey)
	defer priv.Zero()

	sig, err := evmSign(priv, digest)
	if err != nil {
		return nil, err
	}

	pub := priv.PubKey()
	return &logical.Response{
		Data: map[string]any{
			"signature":               "0x" + hex.EncodeToString(sig),
			"key_version":             version,
			"public_key_compressed":   "0x" + hex.EncodeToString(pub.SerializeCompressed()),
			"public_key_uncompressed": "0x" + hex.EncodeToString(pub.SerializeUncompressed()),
			"evm_address":             evmAddress(pub),
		},
	}, nil
}

// evmSign produces a 65-byte r||s||v signature over a 32-byte digest, with
// v in {27, 28}, as expected by the EVM ecrecover precompile. The signature
// is RFC6979-deterministic and low-S (EIP-2).
func evmSign(priv *secp256k1.PrivateKey, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	// isCompressedKey must be false: true would add 4 to the recovery code,
	// putting v in 31..34, which ecrecover rejects.
	compact := secpecdsa.SignCompact(priv, digest, false)
	v := compact[0]
	// 29/30 encode an ephemeral X >= N overflow (~2^-128); the EVM has no
	// encoding for them.
	if v != 27 && v != 28 {
		return nil, fmt.Errorf("signature has recovery code %d, unrepresentable in EVM ecrecover", v)
	}
	sig := make([]byte, 65)
	copy(sig[:64], compact[1:])
	sig[64] = v
	return sig, nil
}
