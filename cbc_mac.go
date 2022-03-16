package insecurecrypto

import (
	"crypto/aes"
	"crypto/des"
	"errors"
	"fmt"
)

func Aes128CbcMacHash(key, message []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}

	// Pad input to a multiple of block size
	paddedMessage, err := AddPadding(message, byte(block.BlockSize()))
	if err != nil {
		return nil, fmt.Errorf("failed to add padding: %s", err)
	}

	// init previous block to 0..0
	prevBlock := make([]byte, block.BlockSize())

	for i := 0; i < len(paddedMessage); i += block.BlockSize() {
		currentBlock := paddedMessage[i : i+block.BlockSize()]
		for j := range prevBlock {
			prevBlock[j] ^= currentBlock[j]
		}
		block.Encrypt(prevBlock, prevBlock)
	}
	return prevBlock, nil
}

func desCbcMacHashForTesting(key, message []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}

	// Pad input to a multiple of block size WITH ZEROES
	paddedMessage := make([]byte, len(message)+(int(blockSize)-len(message)%int(blockSize)))
	copy(paddedMessage, message)

	// init previous block to 0..0
	prevBlock := make([]byte, block.BlockSize())

	for i := 0; i < len(paddedMessage); i += block.BlockSize() {
		currentBlock := paddedMessage[i : i+block.BlockSize()]
		for j := range prevBlock {
			prevBlock[j] ^= currentBlock[j]
		}
		block.Encrypt(prevBlock, prevBlock)
	}
	return prevBlock, nil
}
