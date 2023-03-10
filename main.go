package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
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

// Decrypts ciphertext using the shared secret key and returns the plaintext
func DecryptWithXChaCha20Poly1305(ciphertext, sharedSecret []byte) ([]byte, error) {
	// Extract the nonce from the ciphertext
	nonce := ciphertext[:24]

	// Generate a XChaCha20-Poly1305 cipher using the shared secret and nonce
	cipher, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, err
	}

	// Decrypt the ciphertext using the cipher
	plaintext, err := cipher.Open(nil, nonce, ciphertext[24:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func curve25519Example() {
	//TODO: Remove depricated functions form here

	// Generate sender's private and public keys
	var senderPrivateKey [32]byte
	if _, err := rand.Read(senderPrivateKey[:]); err != nil {
		panic(err)
	}

	var senderPublicKey [32]byte
	curve25519.ScalarBaseMult(&senderPublicKey, &senderPrivateKey)

	// Generate recipient's private and public keys
	var recipientPrivateKey [32]byte
	if _, err := rand.Read(recipientPrivateKey[:]); err != nil {
		panic(err)
	}

	var recipientPublicKey [32]byte
	curve25519.ScalarBaseMult(&recipientPublicKey, &recipientPrivateKey)

	// Perform key exchange
	var sharedKeySender [32]byte
	curve25519.ScalarMult(&sharedKeySender, &senderPrivateKey, &recipientPublicKey)

	var sharedKeyRecipient [32]byte
	curve25519.ScalarMult(&sharedKeyRecipient, &recipientPrivateKey, &senderPublicKey)

	// Verify that the shared keys match
	if sharedKeySender != sharedKeyRecipient {
		panic("Shared keys do not match")
	}

	fmt.Println("Shared key:", sharedKeySender)
}

func main() {
	// Generate a key pair for ECDH key exchange
	senderPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
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
	sharedSecret, err := ECDHKeyExchange(recipientPubKey, senderPrivKey.D.Bytes())
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

	////////////// RECIPIENT SIDE

	// Imitate getting of bytes of the sender public key
	publicKeyOfSender, err := x509.MarshalPKIXPublicKey(&senderPrivKey.PublicKey)
	if err != nil {
		panic(err)
	}

	// Perform ECDH key exchange with the sender public key
	// Basically, we imitate that do not have access to the shared key
	sharedKeyRecipientSecret, err := ECDHKeyExchange(publicKeyOfSender, recipientPrivKey.D.Bytes())
	if err != nil {
		panic(err)
	}

	decryptedText, err := DecryptWithXChaCha20Poly1305(ciphertext, sharedKeyRecipientSecret)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted text:", string(decryptedText))

	curve25519Example()
}
