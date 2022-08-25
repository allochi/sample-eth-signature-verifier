package main

import (
	"bytes"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type Request struct {
	Data           []byte
	PublicKeyECDSA *ecdsa.PublicKey
	PublicKeyBytes []byte
	Address        string
	Signature      []byte
}

func main() {
	var msg string
	var key string

	flag.StringVar(&msg, "msg", "", "message to encrypt and verify")
	flag.StringVar(&key, "key", "", "private key")
	flag.Parse()

	request := NewRequest(key, msg)
	response := VerifyMessage(request)
	fmt.Println(response)
}

func VerifyMessage(r Request) bool {
	// crypto.HexToECDSA()
	publicKeyBytes := crypto.FromECDSAPub(r.PublicKeyECDSA)
	hash := crypto.Keccak256Hash(r.Data)
	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), r.Signature)
	if err != nil {
		log.Println(err)
	}
	return bytes.Equal(sigPublicKey, publicKeyBytes)
}

func NewRequest(key, msg string) Request {
	privateKey, err := crypto.HexToECDSA(key)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Printf("publicKey: %s\n", address)
	// pp.Println(privateKey)

	data := []byte(msg)
	hash := crypto.Keccak256Hash(data)
	fmt.Printf("hash: %s\n", hash.Hex())

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("signature: %s\n", hexutil.Encode(signature))

	return Request{
		data,
		publicKeyECDSA,
		publicKeyBytes,
		address,
		signature,
	}
}
