package insecurecrypto

import (
	"bytes"
	"testing"
)

func isECBConsistent(pt, key []byte, t *testing.T) {
	enc, err := Aes128ECBEncrypt(pt, key)
	if err != nil {
		t.Errorf("ecb encryption failed: %s", err)
	}
	dec, err := Aes128ECBDecrypt(enc, key)
	if err != nil {
		t.Errorf("ecb decryption failed: %s", err)
	}

	if !bytes.Equal(dec, pt) {
		t.Errorf("ecb mode is inconsistent!\nexpected:\n%x\ngot:\n%x",
			pt,
			dec)
	}
}

func TestEcbMode(t *testing.T) {
	key := []byte("AAAAAAAAAAAAAAAA")

	isECBConsistent([]byte("a"), key, t)
	isECBConsistent([]byte("aaaaaaaa"), key, t)
	isECBConsistent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), key, t)
	isECBConsistent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), key, t)
}
