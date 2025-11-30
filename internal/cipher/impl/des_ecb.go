package cipher

import (
	"bytes"
	"crypto/des"
	"encoding/hex"
	"strings"
)

// DESedeECB implements Triple DES ECB mode
type DESedeECB struct {
	key1 []byte
	key2 []byte
}

// NewDESedeECB creates a new DESedeECB cipher
func NewDESedeECB(key1, key2 []byte) *DESedeECB {
	return &DESedeECB{
		key1: key1,
		key2: key2,
	}
}

func (d *DESedeECB) desEncryptECB(data, key []byte) []byte {
	// Pad data to block size
	paddedData := data
	blockSize := des.BlockSize
	if len(data)%blockSize != 0 {
		paddedData = make([]byte, (len(data)/blockSize+1)*blockSize)
		copy(paddedData, data)
	}

	block, _ := des.NewTripleDESCipher(key)
	ciphertext := make([]byte, len(paddedData))

	// ECB mode - encrypt each block independently
	for i := 0; i < len(paddedData); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], paddedData[i:i+blockSize])
	}

	return ciphertext
}

func (d *DESedeECB) desDecryptECB(data, key []byte) []byte {
	blockSize := des.BlockSize
	block, _ := des.NewTripleDESCipher(key)
	plaintext := make([]byte, len(data))

	// ECB mode - decrypt each block independently
	for i := 0; i < len(data); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], data[i:i+blockSize])
	}

	return plaintext
}

func (d *DESedeECB) Encrypt(text string) string {
	r1 := d.desEncryptECB([]byte(text), d.key1)
	r2 := d.desEncryptECB(r1, d.key2)
	return strings.ToUpper(hex.EncodeToString(r2))
}

func (d *DESedeECB) Decrypt(hexStr string) string {
	data, _ := hex.DecodeString(hexStr)
	r1 := d.desDecryptECB(data, d.key2)
	r2 := d.desDecryptECB(r1, d.key1)
	// Remove trailing zeros
	r2 = bytes.TrimRight(r2, "\x00")
	return string(r2)
}
