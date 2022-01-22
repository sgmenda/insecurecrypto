package insecurecrypto

import (
	"crypto/aes"
	"log"
)

func Aes128ECBEncrypt(pt, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	blockSize := 16

	// Pad input to a multiple of block size
	paddedTargetBytes := padToMultipleOfBlockSize(pt, byte(blockSize))

	ct := make([]byte, len(paddedTargetBytes))

	// Enumerate the blocks, decrypting and adding to pt
	for blockBegin, blockEnd := 0, blockSize; blockEnd <= len(paddedTargetBytes); blockBegin, blockEnd = blockEnd, blockEnd+blockSize {
		cipher.Encrypt(ct[blockBegin:blockEnd], paddedTargetBytes[blockBegin:blockEnd])
	}
	return ct
}

func Aes128ECBDecrypt(ct, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	pt := make([]byte, len(ct))
	blockSize := 16

	// Enumerate the blocks, decrypting and adding to pt
	for blockBegin, blockEnd := 0, blockSize; blockEnd <= len(ct); blockBegin, blockEnd = blockEnd, blockEnd+blockSize {
		cipher.Decrypt(pt[blockBegin:blockEnd], ct[blockBegin:blockEnd])
	}

	// Remove padding and return result if succeeded
	d, e := removePadding(pt)
	if e != nil {
		log.Println("Failed to remove padding with error ", e)
		return nil
	}
	return d
}
