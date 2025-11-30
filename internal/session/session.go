package session

import (
	"fmt"
	"os"
	"time"

	"github.com/Rsplwe/ESurfingDialer/internal/cipher"
	"github.com/Rsplwe/ESurfingDialer/internal/states"
)

var (
	initialized bool
	cipherImpl  cipher.CipherInterface
)

// Initialize initializes the session with ZSM data
func Initialize(zsm []byte) error {
	fmt.Println("Initializing Session...")
	var err error
	initialized, err = load(zsm)
	return err
}

// IsInitialized returns whether the session is initialized
func IsInitialized() bool {
	return initialized
}

func load(zsm []byte) (bool, error) {
	if len(zsm) < 4 {
		return false, fmt.Errorf("invalid zsm header")
	}

	header := string(zsm[0:3])
	keyLen := int(zsm[3])
	pos := 4

	if pos+keyLen > len(zsm) {
		return false, fmt.Errorf("invalid key length")
	}

	key := string(zsm[pos : pos+keyLen])
	pos += keyLen

	if pos >= len(zsm) {
		return false, fmt.Errorf("invalid algo id length")
	}

	algoIdLen := int(zsm[pos])
	pos++

	if pos+algoIdLen > len(zsm) {
		return false, fmt.Errorf("invalid algo id")
	}

	algoId := string(zsm[pos : pos+algoIdLen])

	var err error
	cipherImpl, err = cipher.GetInstance(algoId)
	if err != nil {
		saveBytesToFile(fmt.Sprintf("algo_dump_%d.bin", currentTimeMillis()), zsm)
		return false, err
	}

	states.AlgoID = algoId
	fmt.Printf("Type: %s\n", header)
	fmt.Printf("Algo Id: %s\n", algoId)
	fmt.Printf("Key: %s\n", key)

	return true, nil
}

// Decrypt decrypts hex string
func Decrypt(hex string) string {
	return cipherImpl.Decrypt(hex)
}

// Encrypt encrypts text
func Encrypt(text string) string {
	return cipherImpl.Encrypt(text)
}

// Free frees the session
func Free() {
	initialized = false
}

func saveBytesToFile(fileName string, data []byte) {
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	absPath, _ := os.Getwd()
	fmt.Printf("Please submit issue to https://github.com/Rsplwe/ESurfingDialer/issues and attach the file %s/%s\n", absPath, fileName)
}

func currentTimeMillis() int64 {
	return timeNow().UnixNano() / 1e6
}

// For testing purposes
var timeNow = func() interface{ UnixNano() int64 } {
	return timeProvider{}
}

type timeProvider struct{}

func (timeProvider) UnixNano() int64 {
	return time.Now().UnixNano()
}
