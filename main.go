package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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