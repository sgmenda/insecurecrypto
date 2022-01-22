package insecurecrypto

import (
	"bytes"
	"testing"
)

func isCBCConsistent(pt, key, iv []byte, t *testing.T) {
	enc, err := Aes128CBCEncrypt(pt, key, iv)
	if err != nil {
		t.Errorf("cbc encryption failed: %s", err)
	}
	dec, err := Aes128CBCDecrypt(enc, key)
	if err != nil {
		t.Errorf("cbc decryption failed: %s", err)
	}

	if !bytes.Equal(dec, pt) {
		t.Errorf("cbc mode is inconsistent!\nexpected:\n%x\ngot:\n%x",
			pt,
			dec)
	}
}

func TestCbcMode(t *testing.T) {
	key := []byte("AAAAAAAAAAAAAAAA")
	iv := []byte("AAAAAAAAAAAAAAAA")

	isCBCConsistent([]byte("a"), key, iv, t)
	isCBCConsistent([]byte("aaaaaaaa"), key, iv, t)
	isCBCConsistent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), key, iv, t)
	isCBCConsistent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), key, iv, t)
}
