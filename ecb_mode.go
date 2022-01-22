package insecurecrypto

import (
	"crypto/aes"
	"errors"
	"fmt"
)

const blockSize = 16

func Aes128ECBEncrypt(pt, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}

	// Pad input to a multiple of block size
	paddedPt := padToMultipleOfBlockSize(pt, byte(blockSize))

	ct := make([]byte, len(paddedPt))

	// Enumerate the blocks, decrypting and adding to pt
	for blockBegin, blockEnd := 0, blockSize; blockEnd <= len(paddedPt); blockBegin, blockEnd = blockEnd, blockEnd+blockSize {
		block.Encrypt(ct[blockBegin:blockEnd], paddedPt[blockBegin:blockEnd])
	}
	return ct, nil
}

func Aes128ECBDecrypt(ct, key []byte) ([]byte, error) {
	if (len(ct) < blockSize) || (len(ct)%blockSize != 0) {
		panic("invalid ecb ciphertext length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}

	pt := make([]byte, len(ct))

	// Enumerate the blocks, decrypting and adding to pt
	for blockBegin, blockEnd := 0, blockSize; blockEnd <= len(ct); blockBegin, blockEnd = blockEnd, blockEnd+blockSize {
		block.Decrypt(pt[blockBegin:blockEnd], ct[blockBegin:blockEnd])
	}

	// Remove padding and return result if succeeded
	d, err := removePadding(pt)
	if err != nil {
		return nil, fmt.Errorf("failed to remove padding with error: %s", err)
	}
	return d, nil
}
