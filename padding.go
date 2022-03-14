package insecurecrypto

import (
	"errors"
	"fmt"
)

func pkcs7Padding(input []byte, targetLength byte) ([]byte, error) {
	if int(targetLength) < len(input) {
		panic("padding target length less than input length!")
	}
	paddingLength := targetLength - byte(len(input))
	for i := byte(0); i < paddingLength; i++ {
		input = append(input, byte(paddingLength))
	}
	return input, nil
}

// Adds PKCS7 padding.
func AddPadding(input []byte, blockSize byte) ([]byte, error) {
	// We only need to pad the last block.
	lastBlockLength := byte(len(input) % int(blockSize))
	lastBlock := input[len(input)-int(lastBlockLength):]
	paddedLastBlock, err := pkcs7Padding(lastBlock, blockSize)
	if err != nil {
		return nil, err
	}

	// The output is first N-1 blocks and the padded last block
	paddedInput := append(input[0:len(input)-int(lastBlockLength)], paddedLastBlock...)

	// Basic Checks
	if (len(paddedInput) % int(blockSize)) != 0 {
		panic("Length of padded input is not a multiple of block size.")
	}
	if len(paddedInput) == len(input) {
		panic("Length of padded input is same as length of input.")
	}
	return paddedInput, nil
}

// Removes PKCS7 padding.
func RemovePadding(input []byte) ([]byte, error) {
	amountOfPadding := input[len(input)-1]
	if (int(amountOfPadding) > len(input)) || (int(amountOfPadding) == 0) {
		return nil, errors.New("invalid padding")
	}
	for i := byte(1); i <= amountOfPadding; i++ {
		if input[len(input)-int(i)] != amountOfPadding {
			return nil, fmt.Errorf("invalid padding at byte %d. Expected %x, Got %x", len(input)-1, amountOfPadding, input[len(input)-int(i)])
		}
	}
	return input[:len(input)-int(amountOfPadding)], nil
}
