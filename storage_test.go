// SPDX-License-Identifier: MPL-2.0

package secp256k1signer

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// copyingStorage wraps a logical.Storage and deep-copies entry values on Get
// and Put. InmemStorage aliases its buffers, but the production gRPC storage
// client decodes each Get reply into a fresh slice and serializes Put entries
// into the request message — the plugin owns both buffers and wipes them
// (SEC-002). This wrapper gives tests the same ownership semantics so those
// wipes don't corrupt the test store.
type copyingStorage struct {
	under logical.Storage
}

func cloneEntry(e *logical.StorageEntry) *logical.StorageEntry {
	return &logical.StorageEntry{
		Key:      e.Key,
		Value:    append([]byte(nil), e.Value...),
		SealWrap: e.SealWrap,
	}
}

func (c copyingStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	e, err := c.under.Get(ctx, key)
	if err != nil || e == nil {
		return e, err
	}
	return cloneEntry(e), nil
}

func (c copyingStorage) Put(ctx context.Context, e *logical.StorageEntry) error {
	return c.under.Put(ctx, cloneEntry(e))
}

func (c copyingStorage) Delete(ctx context.Context, key string) error {
	return c.under.Delete(ctx, key)
}

func (c copyingStorage) List(ctx context.Context, prefix string) ([]string, error) {
	return c.under.List(ctx, prefix)
}

func (c copyingStorage) ListPage(ctx context.Context, prefix, after string, limit int) ([]string, error) {
	return c.under.ListPage(ctx, prefix, after, limit)
}

// putCorruptKey stores a key entry whose private scalar is attacker-or-corruption
// shaped rather than a valid scalar in [1, N-1].
func putCorruptKey(t *testing.T, s logical.Storage, name string, scalar []byte) {
	t.Helper()
	entry := &keyEntry{
		Versions:      map[int]*keyVersion{1: {PrivateKey: scalar}},
		LatestVersion: 1,
	}
	raw, err := logical.StorageEntryJSON(keyStoragePrefix+name, entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
}

// TestCorruptScalarFailsClosed covers SEC-003: dcrd's PrivKeyFromBytes
// silently reduces out-of-range scalars, so a corrupted zero or >= N value
// must be rejected by the plugin instead of being accepted as a different key.
func TestCorruptScalarFailsClosed(t *testing.T) {
	overflow := make([]byte, 32)
	for i := range overflow {
		overflow[i] = 0xFF
	}
	cases := []struct {
		name   string
		scalar []byte
	}{
		{"zero scalar", make([]byte, 32)},
		{"overflow scalar", overflow},
		{"truncated scalar", make([]byte, 16)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, s := getTestBackend(t)
			putCorruptKey(t, s, "corrupt", tc.scalar)

			for _, req := range []*logical.Request{
				{Operation: logical.ReadOperation, Path: "keys/corrupt", Storage: s},
				{Operation: logical.UpdateOperation, Path: "sign/corrupt", Storage: s, Data: map[string]any{
					"input":     "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=",
					"prehashed": true,
				}},
			} {
				resp, err := b.HandleRequest(context.Background(), req)
				if err == nil && (resp == nil || !resp.IsError()) {
					t.Errorf("%s %s accepted a corrupt stored scalar", req.Operation, req.Path)
				}
				if err != nil && strings.Contains(err.Error(), "reduce") {
					t.Errorf("error suggests silent reduction: %v", err)
				}
			}
		})
	}
}
