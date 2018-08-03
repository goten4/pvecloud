package auth

import (
	"fmt"
	"time"
	"crypto/sha1"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto"
	"encoding/base64"
)

const (
	authPrivateKey = "/etc/pve/priv/authkey.key"
	pveKey = "/etc/pve/pve-www.key"
)

var (
	Cookie = ""
	CsrfToken = ""
)

func init() {
	now := time.Now().Unix()
	Cookie, _ = generateCookie(now, authPrivateKey)
	CsrfToken, _ = generateCsrfToken(now, pveKey)
}

func generateCookie(now int64, keyfile string) (string, error) {

	timestamp := fmt.Sprintf("%08X", now)
	message := fmt.Sprintf("PVE:root@pam:%s", timestamp)
	signature, err := signMessageWithKey(message, keyfile)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("PVEAuthCookie=%s::%s", message, signature), nil
}

func signMessageWithKey(message string, keyfile string) (string, error) {

	keyContent, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return "", fmt.Errorf("Could not read private key : %v", err)
	}

	block, _ := pem.Decode(keyContent)
	if block == nil {
		return "", fmt.Errorf("Could not decode private key : %v", err)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("Could not parse private key : %v", err)
	}

	hashedMessage := sha1.Sum([]byte(message))
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA1, hashedMessage[:])
	if err != nil {
		return "", fmt.Errorf("Could not sign with auth private key : %v", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func generateCsrfToken(now int64, keyfile string) (string, error) {

	timestamp := fmt.Sprintf("%08X", now)
	pveKeyContent, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return "", fmt.Errorf("Could not read pve www key : %v", err)
	}

	secret := sha1Base64(pveKeyContent)
	csrfToken := sha1Base64([]byte(fmt.Sprintf("%s:root@pam%s", timestamp, secret)))
	return fmt.Sprintf("CSRFPreventionToken:%s:%s", timestamp, csrfToken), nil
}

func sha1Base64(data []byte) string {
	hashedData := sha1.Sum(data)
	return base64.RawStdEncoding.EncodeToString(hashedData[:])
}