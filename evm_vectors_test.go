// SPDX-License-Identifier: MPL-2.0

package secp256k1signer

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Known-answer vectors from go-ethereum's crypto test suite
// (crypto/signature_test.go and crypto/crypto_test.go). go-ethereum encodes
// the recovery id as 0/1 at the end; the EVM ecrecover domain is 27/28.
const (
	gethMsg    = "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008"
	gethSig    = "90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301"
	gethPubkey = "04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652"

	gethPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"
	gethAddrHex = "0x970e8128ab834e8eac17ab8e3812f010678cf791"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRecoveryByteConventionAgainstGeth proves our r||s||v layout matches
// Ethereum's: geth's v(0/1)+27 as a leading byte must recover geth's pubkey
// through dcrd's RecoverCompact.
func TestRecoveryByteConventionAgainstGeth(t *testing.T) {
	digest := mustHex(t, gethMsg)
	ethSig := mustHex(t, gethSig)

	compact := make([]byte, 65)
	compact[0] = ethSig[64] + 27
	copy(compact[1:], ethSig[:64])

	pub, _, err := secpecdsa.RecoverCompact(compact, digest)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pub.SerializeUncompressed()); got != gethPubkey {
		t.Fatalf("recovered pubkey %s, want %s", got, gethPubkey)
	}
}

// TestEvmAddressAgainstGeth proves address derivation (Keccak-256 over X||Y,
// last 20 bytes) against go-ethereum's known key/address pair.
func TestEvmAddressAgainstGeth(t *testing.T) {
	priv := secp256k1.PrivKeyFromBytes(mustHex(t, gethPrivHex))
	defer priv.Zero()
	if got := evmAddress(priv.PubKey()); got != gethAddrHex {
		t.Fatalf("evmAddress = %s, want %s", got, gethAddrHex)
	}
}

// TestEvmSignKnownAnswer pins the full signing output for a fixed key and
// digest. RFC6979 makes this byte-exact and permanent; any change to the
// byte layout or the underlying library's nonce derivation will surface here.
func TestEvmSignKnownAnswer(t *testing.T) {
	priv := secp256k1.PrivKeyFromBytes(mustHex(t, gethPrivHex))
	defer priv.Zero()
	digest := mustHex(t, gethMsg)

	sig, err := evmSign(priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(sig)

	// Cross-check internally before pinning: recover must yield the key's
	// own public key.
	compact := append([]byte{sig[64]}, sig[:64]...)
	pub, _, err := secpecdsa.RecoverCompact(compact, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.IsEqual(priv.PubKey()) {
		t.Fatal("recovered pubkey does not match signing key")
	}

	const pinned = "9defa1c2b4651bb84078f886927d9437601f2fa7cab434321fee78463415b22501edb8bedea423ceefab7537ca516f25e9a1f24e34adc42ee9377a5d78e853461b"
	if got != pinned {
		t.Fatalf("signature = %s, want pinned %s", got, pinned)
	}
}
