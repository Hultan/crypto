package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

const keyPath = "/home/per/.softteam_key"

func getKey() ([]byte, error) {
	// Open file
	file, err := os.Open(keyPath)
	if err != nil {
		return nil, err
	}

	// Read file
	b, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Close file
	if err = file.Close(); err != nil {
		return nil, err
	}

	return b[:len(b)-1], nil
}

// https://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64

// Encrypt : Encrypts a string
func Encrypt(plainText string) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", err
	}

	text := []byte(plainText)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return fmt.Sprintf("%x", ciphertext), nil
}

// Decrypt : Decrypts an encrypted string
func Decrypt(encryptedString string) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", err
	}

	text, _ := hex.DecodeString(encryptedString)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(text) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
