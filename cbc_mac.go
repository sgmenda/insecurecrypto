package insecurecrypto

import (
	"crypto/aes"
	"crypto/des"
	"errors"
)

func CbcMacHash(key, message []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}

	// Pad input to a multiple of block size
	paddedMessage := padToMultipleOfBlockSize(message, byte(block.BlockSize()))
	if len(key) == 8 {
		paddedMessage = message
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

func cbcMacHashWithDesForTesting(key, message []byte) ([]byte, error) {
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
