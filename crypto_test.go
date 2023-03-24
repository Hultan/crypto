package crypto

import (
	"testing"
)

// Can't test encrypt, iv is different each run, so encrypted value is different each time
// func TestCrypto_Encrypt(t *testing.T) {
// 	fw := NewFramework()
//
// 	encrypted, err := fw.Crypto.Encrypt("Per Hultqvist")
// 	assert.Nil(t, err)<
// 	assert.Equal(t, "17efd7c819007d79c9a1c287163b77ea2549a7255dc913b93c3d3a9e4ca975b7c35829ef", encrypted)
// }

const encryptedString = "17efd7c819007d79c9a1c287163b77ea2549a7255dc913b93c3d3a9e4ca975b7c35829ef"
const decryptedString = "Per Hultqvist"

func TestCrypto_Decrypt(t *testing.T) {

	c := &Crypto{}
	decrypted, err := c.Decrypt(encryptedString)
	if err != nil {
		t.Error("decryption failed : ", err)
		return
	}
	if decrypted != decryptedString {
		t.Errorf("decryption failed : Expected '%s', got '%s'", decryptedString, decrypted)
		return
	}
}
