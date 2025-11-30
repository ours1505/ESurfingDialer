package cipher

// CipherInterface defines the interface for encryption/decryption
type CipherInterface interface {
	Encrypt(text string) string
	Decrypt(hex string) string
}
