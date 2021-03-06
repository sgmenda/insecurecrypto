package insecurecrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func Aes128CBCEncrypt(pt, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}

	// Pad input to a multiple of block size
	paddedPt, err := AddPadding(pt, byte(blockSize))
	if err != nil {
		return nil, fmt.Errorf("failed to add padding: %s", err)
	}

	ct := make([]byte, len(paddedPt)+blockSize) // +blockSize to include iv in ct
	copy(ct[:blockSize], iv)

	cbcmode := cipher.NewCBCEncrypter(block, iv)
	cbcmode.CryptBlocks(ct[blockSize:], paddedPt)

	return ct, nil
}

func Aes128CBCDecrypt(ct, key []byte) ([]byte, error) {

	if (len(ct) < 2*blockSize) || (len(ct)%blockSize != 0) {
		return nil, errors.New("invalid ciphertext length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}

	iv := ct[:blockSize]
	pt := make([]byte, len(ct)-blockSize)

	cbcmode := cipher.NewCBCDecrypter(block, iv)
	cbcmode.CryptBlocks(pt, ct[blockSize:])

	// Remove padding and return result if succeeded
	d, err := RemovePadding(pt)
	if err != nil {
		return nil, fmt.Errorf("failed to remove padding with error: %s", err)
	}
	return d, nil
}

func Aes128CBCPaddingOracle(ct, key []byte) (bool, error) {

	if (len(ct) < 2*blockSize) || (len(ct)%blockSize != 0) {
		return false, errors.New("invalid ciphertext length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return false, errors.New("failed to initialize cipher")
	}

	iv := ct[:blockSize]
	pt := make([]byte, len(ct)-blockSize)

	cbcmode := cipher.NewCBCDecrypter(block, iv)
	cbcmode.CryptBlocks(pt, ct[blockSize:])

	// Return true if padded correctly and false if padded incorrectly
	_, err = RemovePadding(pt)
	if err == nil {
		return true, nil
	}
	return false, nil
}
