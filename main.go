package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Performs ECDH key exchange and returns the shared secret key
func ECDHKeyExchange(pubKey, privKey []byte) ([]byte, error) {
	// Decode the public key
	ecCurve := elliptic.P256() // you can change the elliptic curve as needed
	ecPubKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	pub := ecPubKey.(*ecdsa.PublicKey)

	// Compute the X-coordinate of the shared secret point
	x, _ := ecCurve.ScalarMult(pub.X, pub.Y, privKey)

	// Return the X-coordinate as the shared secret key
	return x.Bytes(), nil
}

// Encrypts plaintext using the shared secret key and returns the ciphertext
func EncryptWithXChaCha20Poly1305(plaintext, sharedSecret []byte) ([]byte, error) {
	// Generate a random 24-byte nonce
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Generate a XChaCha20-Poly1305 cipher using the shared secret and nonce
	cipher, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, err
	}

	// Encrypt the plaintext using the cipher
	ciphertext := cipher.Seal(nil, nonce, plaintext, nil)

	// Append the nonce to the ciphertext
	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil
}

func main() {
	// Generate a key pair for ECDH key exchange
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Generate a random 32-byte secret key for XChaCha20-Poly1305 encryption
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		panic(err)
	}

	// Generate a recipient key pair for ECDH key exchange
	// We will not have it in real life, but only the public key
	recipientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Encode the recipient public key for ECDH key exchange
	recipientPubKey, err := x509.MarshalPKIXPublicKey(&recipientPrivKey.PublicKey)
	if err != nil {
		panic(err)
	}

	// Perform ECDH key exchange with the recipient's public key
	// In this example, we assume that the recipient's public key is already known
	// and is stored in recipientPubKey
	sharedSecret, err = ECDHKeyExchange(recipientPubKey, privKey.D.Bytes())
	if err != nil {
		panic(err)
	}

	// Encrypt the plaintext using XChaCha20-Poly1305
	plaintext := []byte("Hello, world!")
	ciphertext, err := EncryptWithXChaCha20Poly1305(plaintext, sharedSecret)
	if err != nil {
		panic(err)
	}

	// Print the encrypted ciphertext
	fmt.Println("Encrypted ciphertext: ", ciphertext)
}
