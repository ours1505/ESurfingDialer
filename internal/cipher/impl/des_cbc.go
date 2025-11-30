package cipher

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"strings"
)

// DESedeCBC implements Triple DES CBC mode
type DESedeCBC struct {
	key1 []byte
	key2 []byte
	iv   []byte
}

// NewDESedeCBC creates a new DESedeCBC cipher
func NewDESedeCBC(key1, key2, iv []byte) *DESedeCBC {
	return &DESedeCBC{
		key1: key1,
		key2: key2,
		iv:   iv,
	}
}

func (d *DESedeCBC) desEncrypt(data, key []byte) []byte {
	// Pad data to block size
	paddedData := data
	blockSize := des.BlockSize
	if len(data)%blockSize != 0 {
		paddedData = make([]byte, (len(data)/blockSize+1)*blockSize)
		copy(paddedData, data)
	}

	block, _ := des.NewTripleDESCipher(key)
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, d.iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext
}

func (d *DESedeCBC) desDecrypt(data, key []byte) []byte {
	block, _ := des.NewTripleDESCipher(key)
	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, d.iv)
	mode.CryptBlocks(plaintext, data)
	return plaintext
}

func (d *DESedeCBC) Encrypt(text string) string {
	r1 := d.desEncrypt([]byte(text), d.key1)
	r2 := d.desEncrypt(r1, d.key2)
	return strings.ToUpper(hex.EncodeToString(r2))
}

func (d *DESedeCBC) Decrypt(hexStr string) string {
	data, _ := hex.DecodeString(hexStr)
	r1 := d.desDecrypt(data, d.key2)
	r2 := d.desDecrypt(r1, d.key1)
	// Remove trailing zeros
	r2 = bytes.TrimRight(r2, "\x00")
	return string(r2)
}
