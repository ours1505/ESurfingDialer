package cipher

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// ModXTEA implements a modified XTEA algorithm
type ModXTEA struct {
	key1 []uint32
	key2 []uint32
	key3 []uint32
}

// NewModXTEA creates a new ModXTEA cipher
func NewModXTEA(key1, key2, key3 []uint32) *ModXTEA {
	return &ModXTEA{key1: key1, key2: key2, key3: key3}
}

func (m *ModXTEA) encryptBlock(v0, v1 uint32, key []uint32) (uint32, uint32) {
	sum := uint32(0)
	delta := uint32(0x9E3779B9)
	
	for i := 0; i < 32; i++ {
		v0 += ((v1<<4 ^ v1>>5) + v1) ^ (sum + key[sum&3])
		sum += delta
		v1 += ((v0<<4 ^ v0>>5) + v0) ^ (sum + key[(sum>>11)&3])
	}
	
	return v0, v1
}

func (m *ModXTEA) decryptBlock(v0, v1 uint32, key []uint32) (uint32, uint32) {
	delta := uint32(0x9E3779B9)
	sum := delta * 32
	
	for i := 0; i < 32; i++ {
		v1 -= ((v0<<4 ^ v0>>5) + v0) ^ (sum + key[(sum>>11)&3])
		sum -= delta
		v0 -= ((v1<<4 ^ v1>>5) + v1) ^ (sum + key[sum&3])
	}
	
	return v0, v1
}

func (m *ModXTEA) Encrypt(text string) string {
	data := []byte(text)
	// Pad to 8-byte boundary
	if len(data)%8 != 0 {
		padded := make([]byte, (len(data)/8+1)*8)
		copy(padded, data)
		data = padded
	}
	
	result := make([]byte, len(data))
	
	for i := 0; i < len(data); i += 8 {
		v0 := binary.BigEndian.Uint32(data[i : i+4])
		v1 := binary.BigEndian.Uint32(data[i+4 : i+8])
		
		// Triple encryption
		v0, v1 = m.encryptBlock(v0, v1, m.key1)
		v0, v1 = m.encryptBlock(v0, v1, m.key2)
		v0, v1 = m.encryptBlock(v0, v1, m.key3)
		
		binary.BigEndian.PutUint32(result[i:i+4], v0)
		binary.BigEndian.PutUint32(result[i+4:i+8], v1)
	}
	
	return strings.ToUpper(hex.EncodeToString(result))
}

func (m *ModXTEA) Decrypt(hexStr string) string {
	data, _ := hex.DecodeString(hexStr)
	result := make([]byte, len(data))
	
	for i := 0; i < len(data); i += 8 {
		v0 := binary.BigEndian.Uint32(data[i : i+4])
		v1 := binary.BigEndian.Uint32(data[i+4 : i+8])
		
		// Triple decryption (reverse order)
		v0, v1 = m.decryptBlock(v0, v1, m.key3)
		v0, v1 = m.decryptBlock(v0, v1, m.key2)
		v0, v1 = m.decryptBlock(v0, v1, m.key1)
		
		binary.BigEndian.PutUint32(result[i:i+4], v0)
		binary.BigEndian.PutUint32(result[i+4:i+8], v1)
	}
	
	// Remove trailing zeros
	for len(result) > 0 && result[len(result)-1] == 0 {
		result = result[:len(result)-1]
	}
	
	return string(result)
}
