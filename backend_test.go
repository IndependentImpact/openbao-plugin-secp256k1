// SPDX-License-Identifier: MPL-2.0

package secp256k1signer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = copyingStorage{under: &logical.InmemStorage{}}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return b, config.StorageView
}

func doRequest(t *testing.T, b logical.Backend, s logical.Storage, op logical.Operation, path string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Data:      data,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("%s %s: %v", op, path, err)
	}
	return resp
}

func mustCreateKey(t *testing.T, b logical.Backend, s logical.Storage, name string) *logical.Response {
	t.Helper()
	resp := doRequest(t, b, s, logical.CreateOperation, "keys/"+name, nil)
	if resp.IsError() {
		t.Fatalf("create key: %v", resp.Error())
	}
	return resp
}

func signDigest(t *testing.T, b logical.Backend, s logical.Storage, name string, digest []byte, extra map[string]any) *logical.Response {
	t.Helper()
	data := map[string]any{
		"input":     base64.StdEncoding.EncodeToString(digest),
		"prehashed": true,
	}
	for k, v := range extra {
		data[k] = v
	}
	return doRequest(t, b, s, logical.UpdateOperation, "sign/"+name, data)
}

func decodeSig(t *testing.T, resp *logical.Response) []byte {
	t.Helper()
	if resp.IsError() {
		t.Fatalf("sign: %v", resp.Error())
	}
	sigHex := resp.Data["signature"].(string)
	if !strings.HasPrefix(sigHex, "0x") {
		t.Fatalf("signature not 0x-prefixed: %s", sigHex)
	}
	sig, err := hex.DecodeString(sigHex[2:])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length %d, want 65", len(sig))
	}
	return sig
}

func testDigest(seed byte) []byte {
	d := make([]byte, 32)
	for i := range d {
		d[i] = seed
	}
	return d
}

func TestSignRoundTrip(t *testing.T) {
	b, s := getTestBackend(t)
	mustCreateKey(t, b, s, "test-key")

	digest := testDigest(0xAB)
	resp := signDigest(t, b, s, "test-key", digest, nil)
	sig := decodeSig(t, resp)

	v := sig[64]
	if v != 27 && v != 28 {
		t.Fatalf("v = %d, want 27 or 28", v)
	}

	// Rebuild dcrd's compact layout [v||r||s] and recover.
	compact := append([]byte{v}, sig[:64]...)
	pub, wasCompressed, err := secpecdsa.RecoverCompact(compact, digest)
	if err != nil {
		t.Fatal(err)
	}
	if wasCompressed {
		t.Fatal("recovery reports compressed key; v must stay in 27/28")
	}
	wantPub := resp.Data["public_key_uncompressed"].(string)
	gotPub := "0x" + hex.EncodeToString(pub.SerializeUncompressed())
	if gotPub != wantPub {
		t.Fatalf("recovered pubkey %s != response pubkey %s", gotPub, wantPub)
	}
}

func TestSignDeterministicAndLowS(t *testing.T) {
	b, s := getTestBackend(t)
	mustCreateKey(t, b, s, "k")

	digest := testDigest(0x01)
	sig1 := decodeSig(t, signDigest(t, b, s, "k", digest, nil))
	sig2 := decodeSig(t, signDigest(t, b, s, "k", digest, nil))
	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Fatal("RFC6979 signatures over the same digest differ")
	}

	var sScalar secp256k1.ModNScalar
	if overflow := sScalar.SetByteSlice(sig1[32:64]); overflow {
		t.Fatal("s overflows group order")
	}
	if sScalar.IsOverHalfOrder() {
		t.Fatal("signature is not low-S")
	}
}

func TestSignInputValidation(t *testing.T) {
	b, s := getTestBackend(t)
	mustCreateKey(t, b, s, "k")

	cases := []struct {
		name string
		data map[string]any
	}{
		{"prehashed false", map[string]any{"input": base64.StdEncoding.EncodeToString(testDigest(1)), "prehashed": false}},
		{"prehashed missing", map[string]any{"input": base64.StdEncoding.EncodeToString(testDigest(1))}},
		{"missing input", map[string]any{"prehashed": true}},
		{"bad base64", map[string]any{"input": "not-base64!!!", "prehashed": true}},
		{"digest 31 bytes", map[string]any{"input": base64.StdEncoding.EncodeToString(make([]byte, 31)), "prehashed": true}},
		{"digest 33 bytes", map[string]any{"input": base64.StdEncoding.EncodeToString(make([]byte, 33)), "prehashed": true}},
		{"digest 64 bytes", map[string]any{"input": base64.StdEncoding.EncodeToString(make([]byte, 64)), "prehashed": true}},
	}
	for _, tc := range cases {
		resp := doRequest(t, b, s, logical.UpdateOperation, "sign/k", tc.data)
		if !resp.IsError() {
			t.Errorf("%s: expected error response, got %v", tc.name, resp.Data)
		}
	}

	if resp := signDigest(t, b, s, "nosuchkey", testDigest(2), nil); !resp.IsError() {
		t.Error("signing with unknown key should fail")
	}
}

func TestRotationAndVersions(t *testing.T) {
	b, s := getTestBackend(t)
	created := mustCreateKey(t, b, s, "k")
	addrV1 := created.Data["versions"].(map[string]any)["1"].(map[string]any)["evm_address"].(string)

	rotated := doRequest(t, b, s, logical.UpdateOperation, "keys/k/rotate", nil)
	if rotated.IsError() {
		t.Fatalf("rotate: %v", rotated.Error())
	}
	if lv := rotated.Data["latest_version"].(int); lv != 2 {
		t.Fatalf("latest_version = %d, want 2", lv)
	}

	digest := testDigest(0x33)
	respLatest := signDigest(t, b, s, "k", digest, nil)
	if respLatest.Data["key_version"].(int) != 2 {
		t.Fatal("default signing did not use latest version")
	}
	if respLatest.Data["evm_address"].(string) == addrV1 {
		t.Fatal("rotated key has same address as version 1")
	}

	respV1 := signDigest(t, b, s, "k", digest, map[string]any{"key_version": 1})
	if respV1.Data["evm_address"].(string) != addrV1 {
		t.Fatal("explicit version 1 signing did not use version 1 key")
	}

	if resp := signDigest(t, b, s, "k", digest, map[string]any{"key_version": 5}); !resp.IsError() {
		t.Error("signing with nonexistent version should fail")
	}
}

func TestCreateDeleteSemantics(t *testing.T) {
	b, s := getTestBackend(t)
	mustCreateKey(t, b, s, "k")

	// Re-creating must fail (existence check routes to update handler).
	if resp := doRequest(t, b, s, logical.UpdateOperation, "keys/k", nil); !resp.IsError() {
		t.Fatal("re-creating an existing key should fail")
	}

	// Delete is gated.
	if resp := doRequest(t, b, s, logical.DeleteOperation, "keys/k", nil); !resp.IsError() {
		t.Fatal("delete without deletion_allowed should fail")
	}
	doRequest(t, b, s, logical.UpdateOperation, "keys/k/config", map[string]any{"deletion_allowed": true})
	if resp := doRequest(t, b, s, logical.DeleteOperation, "keys/k", nil); resp.IsError() {
		t.Fatalf("delete after enabling deletion_allowed failed: %v", resp.Error())
	}
	if resp := doRequest(t, b, s, logical.ReadOperation, "keys/k", nil); resp != nil {
		t.Fatal("key still readable after delete")
	}
}

// TestNoPrivateMaterialExposed asserts the structural non-exportability the
// specs rely on: no export/backup-like path exists, and no response leaks
// private key bytes. Per SEC-005, whole responses are serialized and scanned
// — nested maps included — for the scalar in hex and base64 form, across
// create, read, rotate, config, sign, and error responses.
func TestNoPrivateMaterialExposed(t *testing.T) {
	b, s := getTestBackend(t)
	forbidden := regexp.MustCompile(`export|backup|restore|private`)
	for _, p := range b.(*backend).Paths {
		if forbidden.MatchString(p.Pattern) {
			t.Errorf("forbidden path pattern present: %s", p.Pattern)
		}
	}

	created := mustCreateKey(t, b, s, "k")

	scalars := func() [][]byte {
		raw, err := s.Get(context.Background(), "keys/k")
		if err != nil {
			t.Fatal(err)
		}
		var entry keyEntry
		if err := raw.DecodeJSON(&entry); err != nil {
			t.Fatal(err)
		}
		out := make([][]byte, 0, len(entry.Versions))
		for _, kv := range entry.Versions {
			out = append(out, kv.PrivateKey)
		}
		return out
	}

	assertClean := func(label string, resp *logical.Response) {
		t.Helper()
		if resp == nil {
			return
		}
		serialized, err := json.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		haystack := strings.ToLower(string(serialized))
		for _, scalar := range scalars() {
			for form, needle := range map[string]string{
				"hex":    hex.EncodeToString(scalar),
				"base64": base64.StdEncoding.EncodeToString(scalar),
			} {
				if strings.Contains(haystack, strings.ToLower(needle)) {
					t.Errorf("%s response contains private scalar (%s form)", label, form)
				}
			}
		}
	}

	assertClean("create", created)
	assertClean("read", doRequest(t, b, s, logical.ReadOperation, "keys/k", nil))
	assertClean("rotate", doRequest(t, b, s, logical.UpdateOperation, "keys/k/rotate", nil))
	assertClean("config", doRequest(t, b, s, logical.UpdateOperation, "keys/k/config", map[string]any{"deletion_allowed": false}))
	assertClean("sign", signDigest(t, b, s, "k", testDigest(9), nil))
	assertClean("error", signDigest(t, b, s, "k", testDigest(9), map[string]any{"key_version": 99}))
}
