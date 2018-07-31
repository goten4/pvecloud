package main
import (
	"flag"
	"fmt"
	"os"
	"github.com/goten4/pvecloud/global"
	"io/ioutil"
						"crypto/sha1"
	"time"
			"encoding/base64"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto"
)

func main() {

	help := flag.Bool("h", false, "show this help")
	version := flag.Bool("v", false, "show version")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [COMMAND] [HOSTNAME]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "COMMANDS\n")
		fmt.Fprintf(os.Stderr, "  create\n")
		fmt.Fprintf(os.Stderr, "  start\n")
		fmt.Fprintf(os.Stderr, "  stop\n")
		fmt.Fprintf(os.Stderr, "  delete\n")
		fmt.Fprintf(os.Stderr, "  status\n")
		fmt.Fprintf(os.Stderr, "OPTIONS\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	if *version {
		fmt.Printf("PVECloud, version %s\n", global.Version)
		return
	}

	timestamp := fmt.Sprintf("%08X", time.Now().Unix())
	message := fmt.Sprintf("PVE:root@pam:%s", timestamp)
	hashed := sha1.Sum([]byte(message))

	authKeyContent, err := ioutil.ReadFile("/etc/pve/priv/authkey.key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read private key authkey.key !\n")
		return
	}
	block, _ := pem.Decode(authKeyContent)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not parse private key authkey.key !\n")
		return
	}

	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA1, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not sign with private key authkey.key !\n")
		return
	}

	fmt.Printf("PVEAuthCookie=%s::%s\n", message, base64.StdEncoding.EncodeToString(signature))


	wwwKeyContent, err := ioutil.ReadFile("/etc/pve/pve-www.key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read private key pve-www.key !\n")
		return
	}
	hashed = sha1.Sum(wwwKeyContent)
	secret := base64.RawStdEncoding.EncodeToString(hashed[:])
	hashed = sha1.Sum([]byte(fmt.Sprintf("%s:root@pam%s", timestamp, secret)))
	csrfToken := base64.RawStdEncoding.EncodeToString(hashed[:])
	fmt.Printf("CSRFPreventionToken:%s:%s\n", timestamp, csrfToken)
}
