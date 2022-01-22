package insecurecrypto

import (
	"bytes"
	"testing"
)

func isPaddingConsistent(in []byte, t *testing.T) {
	padThenUnpad, err := removePadding(padToMultipleOfBlockSize(in, 16))
	if err != nil {
		t.Errorf("Got unexpected error: %s", err)
	}
	if !bytes.Equal(padThenUnpad, in) {
		t.Errorf("Failed to unpad!\nexpected:\n%q\ngot:\n%q", in, padThenUnpad)
	}
}

func TestPadding(t *testing.T) {

	t.Run(
		"padding is correct",
		func(t *testing.T) {
			testString := []byte("I LIKE TO PAD MY MESSAGES")
			got := pkcs7Padding(testString, 30)

			expectString := []byte("I LIKE TO PAD MY MESSAGES\x05\x05\x05\x05\x05")
			if !bytes.Equal(got, expectString) {
				t.Errorf("Failed to pad!\nexpected:\n%q\ngot:\n%q", expectString, got)
			}
		},
	)

	t.Run(
		"padding is consistent",
		func(t *testing.T) {
			isPaddingConsistent([]byte("I LIKE TO PAD MY MESSAGES"), t)
			isPaddingConsistent([]byte("a"), t)
			isPaddingConsistent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), t)
			isPaddingConsistent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), t)
		},
	)

}
