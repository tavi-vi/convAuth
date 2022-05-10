package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha512"
)

const tokenDuration = time.Hour * 24 * 30

var HMACKey []byte = make([]byte, 128)

func init() {
	n, err := rand.Read(HMACKey)
	if err != nil {
		panic(err)
	}
	if n != 128 {
		panic("bad entropy")
	}
}

type authToken struct {
	Issued   time.Time
	Expires  time.Time
	Username string
}

func checkHMACSHA512(tokData, hmacResult1 []byte) bool {
	hmacResult2 := hmacSHA512(tokData)
	return subtle.ConstantTimeCompare(hmacResult1, hmacResult2) == 1
}

func hmacSHA512(tokData []byte) []byte {
	hmacResult := hmac.New(sha512.New, HMACKey)
	_, err := hmacResult.Write(tokData)
	if err != nil {
		panic(err)
	}
	return hmacResult.Sum(nil)
}

func issueToken(username string) (string, time.Time) {
	now := time.Now()
	expires := now.Add(tokenDuration)
	tokData, err := json.Marshal(authToken{
		Issued:   now,
		Expires:  expires,
		Username: username,
	})
	if err != nil {
		panic(err)
	}
	hmacResult := hmacSHA512(tokData)
	cookieValue := fmt.Sprintf("%s.%s",
		base64.StdEncoding.EncodeToString(tokData),
		base64.StdEncoding.EncodeToString(hmacResult),
	)
	return cookieValue, expires
}

var expiredToken error = errors.New("Token expired")

func authz(cookie, hostname string, u *url.URL) error {
	failedAuth := errors.New("Failed to authorize")
	sc := strings.Split(cookie, ".")
	if len(sc) != 2 {
		return failedAuth
	}
	tokData, err := base64.StdEncoding.DecodeString(sc[0])
	if err != nil {
		return failedAuth
	}
	hmacResult, err := base64.StdEncoding.DecodeString(sc[1])
	if err != nil {
		return failedAuth
	}
	if !checkHMACSHA512(tokData, hmacResult) {
		return failedAuth
	}
	var tok authToken
	err = json.Unmarshal(tokData, &tok)
	if err != nil {
		panic(err)
	}
	if tok.Expires.Before(time.Now()) {
		return expiredToken
	}
	return nil
}
