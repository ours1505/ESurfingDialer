package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
)

// AESCBC implements AES CBC mode encryption/decryption
type AESCBC struct {
	key1 []byte
	key2 []byte
	iv   []byte
}

// NewAESCBC creates a new AESCBC cipher
func NewAESCBC(key1, key2, iv []byte) *AESCBC {
	return &AESCBC{
		key1: key1,
		key2: key2,
		iv:   iv,
	}
}

func (a *AESCBC) aesEncrypt(data, key []byte) []byte {
	// Pad data to block size
	paddedData := data
	if len(data)%aes.BlockSize != 0 {
		paddedData = make([]byte, (len(data)/aes.BlockSize+1)*aes.BlockSize)
		copy(paddedData, data)
	}

	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, a.iv)
	mode.CryptBlocks(ciphertext, paddedData)

	// Prepend IV
	result := make([]byte, len(a.iv)+len(ciphertext))
	copy(result, a.iv)
	copy(result[len(a.iv):], ciphertext)
	return result
}

func (a *AESCBC) aesDecrypt(data, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, a.iv)
	mode.CryptBlocks(plaintext, data)
	return plaintext
}

func (a *AESCBC) Encrypt(text string) string {
	r1 := a.aesEncrypt([]byte(text), a.key1)
	r2 := a.aesEncrypt(r1, a.key2)
	return strings.ToUpper(hex.EncodeToString(r2))
}

func (a *AESCBC) Decrypt(hexStr string) string {
	data, _ := hex.DecodeString(hexStr)
	r1 := a.aesDecrypt(data[16:], a.key2)
	r2 := a.aesDecrypt(r1[16:], a.key1)
	// Remove trailing zeros
	r2 = bytes.TrimRight(r2, "\x00")
	return string(r2)
}
