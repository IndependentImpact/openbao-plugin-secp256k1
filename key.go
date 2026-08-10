// SPDX-License-Identifier: MPL-2.0

package secp256k1signer

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/crypto/sha3"
)

const keyStoragePrefix = "keys/"

type keyVersion struct {
	// PrivateKey is the 32-byte big-endian scalar. It never leaves storage
	// through any API response.
	PrivateKey  []byte    `json:"private_key"`
	CreatedTime time.Time `json:"created_time"`
}

type keyEntry struct {
	Versions        map[int]*keyVersion `json:"versions"`
	LatestVersion   int                 `json:"latest_version"`
	DeletionAllowed bool                `json:"deletion_allowed"`
}

func (b *backend) getKey(ctx context.Context, s logical.Storage, name string) (*keyEntry, error) {
	raw, err := s.Get(ctx, keyStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	entry := new(keyEntry)
	if err := raw.DecodeJSON(entry); err != nil {
		return nil, err
	}
	return entry, nil
}

func (b *backend) putKey(ctx context.Context, s logical.Storage, name string, entry *keyEntry) error {
	raw, err := logical.StorageEntryJSON(keyStoragePrefix+name, entry)
	if err != nil {
		return err
	}
	return s.Put(ctx, raw)
}

func newKeyVersion() (*keyVersion, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	defer priv.Zero()
	return &keyVersion{
		PrivateKey:  priv.Serialize(),
		CreatedTime: time.Now().UTC(),
	}, nil
}

// publicData returns the exposable material for one key version. Private key
// bytes are never included.
func (kv *keyVersion) publicData() (map[string]any, error) {
	if len(kv.PrivateKey) != 32 {
		return nil, fmt.Errorf("stored private key has invalid length %d", len(kv.PrivateKey))
	}
	priv := secp256k1.PrivKeyFromBytes(kv.PrivateKey)
	defer priv.Zero()
	pub := priv.PubKey()
	return map[string]any{
		"public_key_compressed":   "0x" + hex.EncodeToString(pub.SerializeCompressed()),
		"public_key_uncompressed": "0x" + hex.EncodeToString(pub.SerializeUncompressed()),
		"evm_address":             evmAddress(pub),
		"created_time":            kv.CreatedTime.Format(time.RFC3339),
	}, nil
}

// evmAddress derives the Ethereum-style address: the last 20 bytes of
// Keccak-256 over the 64-byte X||Y public key (the uncompressed SEC1 encoding
// with its 0x04 prefix dropped). Lowercase hex, no EIP-55 checksum.
func evmAddress(pub *secp256k1.PublicKey) string {
	h := sha3.NewLegacyKeccak256()
	h.Write(pub.SerializeUncompressed()[1:])
	return "0x" + hex.EncodeToString(h.Sum(nil)[12:])
}
