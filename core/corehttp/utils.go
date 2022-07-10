package corehttp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

func reversal(a []byte) []byte {
	n := len(a) - 1
	if n < 2 {
		return a
	}
	m := 0
	for m < n {
		a[m], a[n] = a[n], a[m]
		m++
		n--
	}
	return a
}

func encodee(key string, msg string) ([]byte, error) {
	return nil, nil
}

func decodee(privatekey string, ciphermsg string) ([]byte, error) {
	pkey, _ := hex.DecodeString(privatekey)
	ciphertext, _ := hex.DecodeString(ciphermsg)

	block, err := aes.NewCipher(pkey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic("open: " + err.Error())
	}
	return plaintext, nil
}
