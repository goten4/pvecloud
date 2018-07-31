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
	Cookie, _ = generateCookie()
	CsrfToken, _ = generateCsrfToken()
}

func generateCookie() (string, error) {

	timestamp := fmt.Sprintf("%08X", time.Now().Unix())
	message := fmt.Sprintf("PVE:root@pam:%s", timestamp)
	hashed := sha1.Sum([]byte(message))

	authKeyContent, err := ioutil.ReadFile(authPrivateKey)
	if err != nil {
		return "", fmt.Errorf("Could not read auth private key")
	}
	block, _ := pem.Decode(authKeyContent)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("Could not parse auth private key")
	}

	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA1, hashed[:])
	if err != nil {
		return "", fmt.Errorf("Could not sign with auth private key")
	}

	return fmt.Sprintf("PVEAuthCookie=%s::%s", message, base64.StdEncoding.EncodeToString(signature)), nil
}

func generateCsrfToken() (string, error) {

	timestamp := fmt.Sprintf("%08X", time.Now().Unix())
	pveKeyContent, err := ioutil.ReadFile(pveKey)
	if err != nil {
		return "", fmt.Errorf("Could not read pve www key")
	}
	hashed := sha1.Sum(pveKeyContent)
	secret := base64.RawStdEncoding.EncodeToString(hashed[:])
	hashed = sha1.Sum([]byte(fmt.Sprintf("%s:root@pam%s", timestamp, secret)))
	csrfToken := base64.RawStdEncoding.EncodeToString(hashed[:])
	return fmt.Sprintf("CSRFPreventionToken:%s:%s", timestamp, csrfToken), nil
}