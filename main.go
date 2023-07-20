package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	privateKeyFile := "private.pem"
	publicKeyFile := "public.pem"
	keySize := 2048

	err := GenerateRSAKeyPair(privateKeyFile, publicKeyFile, keySize)
	if err != nil {
		fmt.Println("Error generating RSA key pair:", err)
		return
	}

	fmt.Println("RSA key pair generated successfully.")
}

// GenerateRSAKeyPair generates a new RSA key pair and saves the private and public keys to the specified files.
func GenerateRSAKeyPair(privateKeyFileName, publicKeyFileName string, keySize int) error {
	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return err
	}

	// Save private key to file
	privateKeyFile, err := os.Create(privateKeyFileName)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	err = pem.Encode(privateKeyFile, privateKeyPEM)
	if err != nil {
		return err
	}

	// Save public key to file
	publicKeyFile, err := os.Create(publicKeyFileName)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}

	err = pem.Encode(publicKeyFile, publicKeyPEM)
	if err != nil {
		return err
	}

	return nil
}

// EncryptWithRSA encrypts the data using the given public key.
func EncryptWithRSA(publicKeyFile string, data []byte) ([]byte, error) {
	// Load public key from file
	publicKeyPEM, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse DER encoded public key")
	}

	// Encrypt the data using the public key
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// SignWithRSA signs the data using the given private key.
func SignWithRSA(privateKeyFile string, data []byte) ([]byte, error) {
	// Load private key from file
	privateKeyPEM, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Calculate the hash of the data
	hashed := sha256.Sum256(data)

	// Sign the hashed data using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// DecryptWithRSA decrypts the data using the given private key.
func DecryptWithRSA(privateKeyFile string, encryptedData []byte) ([]byte, error) {
	// Load private key from file
	privateKeyPEM, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Decrypt the data using the private key
	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedData)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// VerifySignatureWithRSA verifies the signature of the data using the given public key.
func VerifySignatureWithRSA(publicKeyFile string, data, signature []byte) error {
	// Load public key from file
	publicKeyPEM, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to parse DER encoded public key")
	}

	// Calculate the hash of the data
	hashed := sha256.Sum256(data)

	// Verify the signature using the public key
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}