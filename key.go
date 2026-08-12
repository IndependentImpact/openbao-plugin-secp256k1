// SPDX-License-Identifier: MPL-2.0

package secp256k1signer

import (
	"context"
	"encoding/hex"
	"errors"
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

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (kv *keyVersion) wipe() {
	if kv != nil {
		wipeBytes(kv.PrivateKey)
	}
}

// wipe overwrites every decoded private scalar in the entry. Handlers that
// load or create an entry must arrange for this to run on all return paths
// (SEC-002); Go's GC gives no erasure guarantee for copies it has already
// moved, so deployments must additionally forbid core dumps and swap.
func (e *keyEntry) wipe() {
	if e == nil {
		return
	}
	for _, kv := range e.Versions {
		kv.wipe()
	}
}

func (b *backend) getKey(ctx context.Context, s logical.Storage, name string) (*keyEntry, error) {
	raw, err := s.Get(ctx, keyStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	// The round-trip buffer holds the serialized scalars. The plugin owns it
	// after Get — the gRPC storage client decodes each reply into a fresh
	// slice — so overwrite it once decoded. (The inmem test storage aliases
	// its buffers instead; tests wrap it in a copying layer that mirrors the
	// gRPC ownership semantics.)
	defer wipeBytes(raw.Value)
	entry := new(keyEntry)
	if err := raw.DecodeJSON(entry); err != nil {
		entry.wipe()
		return nil, err
	}
	return entry, nil
}

func (b *backend) putKey(ctx context.Context, s logical.Storage, name string, entry *keyEntry) error {
	raw, err := logical.StorageEntryJSON(keyStoragePrefix+name, entry)
	if err != nil {
		return err
	}
	// Same ownership argument as getKey: the gRPC storage client copies the
	// entry into the request message and does not retain this buffer.
	defer wipeBytes(raw.Value)
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

// privKeyFromStored converts a stored scalar into a private key, failing
// closed on corrupt values (SEC-003): dcrd's PrivKeyFromBytes silently
// reduces out-of-range scalars, so zero and >= N values are rejected here
// instead of being accepted as a different key.
func privKeyFromStored(stored []byte) (*secp256k1.PrivateKey, error) {
	if len(stored) != 32 {
		return nil, fmt.Errorf("stored private key has invalid length %d", len(stored))
	}
	var s secp256k1.ModNScalar
	overflow := s.SetByteSlice(stored)
	if overflow || s.IsZero() {
		s.Zero()
		return nil, errors.New("stored private key scalar is out of range")
	}
	priv := secp256k1.NewPrivateKey(&s)
	s.Zero()
	return priv, nil
}

// publicData returns the exposable material for one key version. Private key
// bytes are never included.
func (kv *keyVersion) publicData() (map[string]any, error) {
	priv, err := privKeyFromStored(kv.PrivateKey)
	if err != nil {
		return nil, err
	}
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
