package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/sync/semaphore"
	"strings"
)

var oldAlgo = errors.New("Password was hased with an algorithm that has now been replaced.")

var hashSemaphore *semaphore.Weighted

func init() {
	hashSemaphore = semaphore.NewWeighted(15)
}

type HashPair struct {
	HashAlgo int32
	PassHash string
}

type algoEntry struct {
	hash    func(pass string, arg uint) string
	compare func(pass, hash string, arg uint) bool
	arg     uint
}

var passAlgos []algoEntry = []algoEntry{
	{hash: argon2Hash, compare: argon2Compare, arg: 0},
}

// Used for timing obfuscation
var fakePassHash []userEntry
var fakePassEntropy []byte = make([]byte, 128)

func init() {
	fakePassHash = make([]userEntry, 0, len(passAlgos))
	for algo, entry := range passAlgos {
		hash := entry.hash("hunter2D#EXdx4&%$JmP68", entry.arg) // maybe change to randomly generated.
		fakePassHash = append(fakePassHash, userEntry{Hash: HashPair{int32(algo), hash}})
	}

	n, err := rand.Read(fakePassEntropy)
	if err != nil {
		panic(err)
	}
	if n != 128 {
		panic("bad entropy")
	}
}

func argon2Core(pass string, salt []byte, arg uint) string {
	var time, memory, keyLen uint32
	var threads uint8
	switch arg {
	case 0:
		// low memory reccomendation from OWASP+key length recommended from the Argon2 spec
		memory, time, threads, keyLen = 15*1024, 2, 1, 16
	default:
		panic("invalid argument number")
	}
	hash := argon2.IDKey([]byte(pass), salt, time, memory, threads, keyLen)
	return fmt.Sprintf("%s$%s",
		base64.URLEncoding.EncodeToString(salt),
		base64.URLEncoding.EncodeToString(hash))
}

func argon2Hash(pass string, arg uint) string {
	var salt []byte
	switch arg {
	case 0:
		// low memory reccomendation from OWASP+key length recommended from the Argon2 spec
		salt = make([]byte, 16)
		_, err := rand.Read(salt)
		if err != nil {
			panic(err)
		}
	default:
		panic("invalid argument number")
	}
	return argon2Core(pass, salt, arg)
}

func argon2Compare(pass, hash1 string, arg uint) bool {
	// Parse errors can only be the result of programmer error, so we panic.
	var parseErr error = errors.New("Fatal error, unparsable password hash")

	sh := strings.Split(hash1, "$")
	if len(sh) != 2 {
		panic(parseErr)
	}
	salt, err := base64.URLEncoding.DecodeString(sh[0])
	if err != nil {
		panic(parseErr)
	}

	hash2 := argon2Core(pass, salt, arg)
	return subtle.ConstantTimeCompare([]byte(hash1), []byte(hash2)) == 1 // allocation :/
}

func passHash(pass string) HashPair {
	hashAlgo := int32(len(passAlgos) - 1)
	entry := passAlgos[hashAlgo]
	passHash := entry.hash(pass, entry.arg)
	return HashPair{hashAlgo, passHash}
}

func passCompare(pass string, hash HashPair) (bool, error) {
	if hash.HashAlgo < 0 || int(hash.HashAlgo) >= len(passAlgos) {
		panic("Fatal error, incorrect algo number")
	}
	entry := passAlgos[hash.HashAlgo]

	var err error
	if int(hash.HashAlgo) < len(passAlgos)-1 {
		err = oldAlgo
	}

	return entry.compare(pass, hash.PassHash, entry.arg), err
}
