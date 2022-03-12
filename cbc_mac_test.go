package insecurecrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCbcMac(t *testing.T) {
	// Test from FIPS 113 (https://doi.org/10.6028/NBS.FIPS.113)
	key, err := hex.DecodeString("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("7654321 Now is the time for ")
	expected, err := hex.DecodeString("f1d30f68")
	if err != nil {
		t.Fatal(err)
	}

	got, err := cbcMacHashWithDesForTesting(key, message)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got[:4], expected) {
		t.Fatalf("cbcmac is wrong\nexpected:\t%x\ngot:\t\t%x", expected, got)
	}
}
