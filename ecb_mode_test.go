package insecurecrypto

import (
	"bytes"
	"testing"
)

func isECBConsistent(pt, key []byte, t *testing.T) {
	encDec := aes128ECBDecrypt(aes128ECBEncrypt(pt, key), key)
	if !bytes.Equal(encDec, pt) {
		t.Errorf("ECB mode is inconsistent!\nexpected:\n%x\ngot:\n%x",
			pt,
			encDec)
	}
}

func TestEcbMode(t *testing.T) {
	key := []byte("AAAAAAAAAAAAAAAA")

	isECBConsistent([]byte("a"), key, t)
	isECBConsistent([]byte("aaaaaaaa"), key, t)
	isECBConsistent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), key, t)
	isECBConsistent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), key, t)
}
