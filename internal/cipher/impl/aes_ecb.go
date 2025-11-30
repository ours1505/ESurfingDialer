package cipher

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"strings"
)

// AESECB implements AES ECB mode encryption/decryption
type AESECB struct {
	key1 []byte
	key2 []byte
}

// NewAESECB creates a new AESECB cipher
func NewAESECB(key1, key2 []byte) *AESECB {
	return &AESECB{
		key1: key1,
		key2: key2,
	}
}

func (a *AESECB) aesEncryptECB(data, key []byte) []byte {
	// Pad data to block size
	paddedData := data
	if len(data)%aes.BlockSize != 0 {
		paddedData = make([]byte, (len(data)/aes.BlockSize+1)*aes.BlockSize)
		copy(paddedData, data)
	}

	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(paddedData))

	// ECB mode - encrypt each block independently
	for i := 0; i < len(paddedData); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], paddedData[i:i+aes.BlockSize])
	}

	return ciphertext
}

func (a *AESECB) aesDecryptECB(data, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	plaintext := make([]byte, len(data))

	// ECB mode - decrypt each block independently
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}

	return plaintext
}

func (a *AESECB) Encrypt(text string) string {
	r1 := a.aesEncryptECB([]byte(text), a.key1)
	r2 := a.aesEncryptECB(r1, a.key2)
	return strings.ToUpper(hex.EncodeToString(r2))
}

func (a *AESECB) Decrypt(hexStr string) string {
	data, _ := hex.DecodeString(hexStr)
	r1 := a.aesDecryptECB(data, a.key2)
	r2 := a.aesDecryptECB(r1, a.key1)
	// Remove trailing zeros
	r2 = bytes.TrimRight(r2, "\x00")
	return string(r2)
}
