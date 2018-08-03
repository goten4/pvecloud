package auth

import (
	"testing"
	"fmt"
)
const expectedSignature = "tDkxU1iRr4aYEesL5/powuBblXEfrqB+HcJYei5g+ng0yKJOc3NRSQCZg8zDjS/CCqDhFjx9hunW7448TQrMLqQ/Ym2gKmwbP1VWBCKz58TAHVGkuSxZnSJ262mMtDnE4yIc0douHq2nrS9+zlpQvCjCOTxhviYgt+AqXY923vDpzWbyCHfmozb1+U85CjKYr/v8AKX6+A0dRhCTkRzLnrO/VcD06vL8+sn/+VVBjVHsHWQm6mHYN0zautw1mW0xw8HWMzY5dXjjtCKjnAS0ttr0xkLQG7/GZxwonovosCGfYMpzbWYL9uQsvvINnlLKLeUdkZr5u5Ev8+aQNwy6dg=="
const expectedToken = "CSRFPreventionToken:5B6487B8:dI86OKNzX3BRFlY2TrvJGiU+rkg"
const expectedCookie = "PVEAuthCookie=PVE:root@pam:5B6487B8::KemlFnoAGIap51XQ3NPSvzmrRaEI8a45tjo6VjfLRp/8YwSTT5a9FCXshuFVQmzBOkv+gLtiwtqTdPD/r/y9DvfWFFFUfntfQoIgwn0rFwg3EoTi6VebEvCeXtMLNt/od3V+gWl17FzfsoQg2iRh+TZ8NhqhCm2F/mx0aNSqMaO+ANTErVmifckdLw54NZXumw6SiEwRjZwARXQ0hwlcocnOQll0vkQpxbBRqOkBmypC0ckHNKP4sBw0DE11CYLC7JWM+NtXyWzMR7bT0lpud7KkyvDUwwjltYTpm3Mw8s3QCs6xB9YRZtNYzoHrORsFlQDAoq9aC9UVmjnEmI6D3A=="
const now = 1533315000

func TestSignMessageWithKeyReadingError(t *testing.T) {
	_, err := signMessageWithKey("test", "unknown_key")
	if err == nil {
		t.Fatal("Expected error while reading unknown key")
	}
}

func TestSignMessageWithKeyDecodingError(t *testing.T) {
	_, err := signMessageWithKey("test", "invalid_key")
	if err == nil {
		t.Fatal("Expected error while decoding invalid key")
	}
}

func TestSignMessageWithKeyParsingError(t *testing.T) {
	_, err := signMessageWithKey("test", "dsa_key")
	if err == nil {
		t.Fatal("Expected error while parsing dsa key")
	}
}

func TestSignMessageWithKeySuccess(t *testing.T) {
	signature, err := signMessageWithKey("test", "rsa_key")
	if err != nil {
		t.Fatal(err)
	}
	if signature != expectedSignature {
		t.Fatal(fmt.Sprintf("Expected signature : tDkxU1iRr4aYEesL5... got : %s", signature))
	}
}

func TestSha1Base64(t *testing.T) {
	result := sha1Base64([]byte("test"))
	if result != "qUqP5cyxm6YcTAhz05Hph5gvu9M" {
		t.Fatal(fmt.Sprintf("Expected qUqP5cyxm6YcTAhz05Hph5gvu9M got : %s", result))
	}
}

func TestGenerateCookieWithUnknownKey(t *testing.T) {
	_, err := generateCookie(now, "unknown_key")
	if err == nil {
		t.Fatal("Expected error while reading unknown key")
	}
}

func TestGenerateCookieSuccess(t *testing.T) {
	cookie, err := generateCookie(now, "rsa_key")
	if err != nil {
		t.Fatal(err)
	}
	if cookie != expectedCookie {
		t.Fatal(fmt.Sprintf("Expected cookie : PVEAuthCookie=PVE:root@pam:5B6487B8::KemlFnoAGIap51... got : %s", cookie))
	}
}

func TestGenerateCsrfTokenWithUnknownKey(t *testing.T) {
	_, err := generateCsrfToken(now, "unknown_key")
	if err == nil {
		t.Fatal("Expected error while reading unknown key")
	}
}

func TestGenerateCsrfTokenSuccess(t *testing.T) {
	token, err := generateCsrfToken(now, "rsa_key")
	if err != nil {
		t.Fatal(err)
	}
	if token != expectedToken {
		t.Fatal(fmt.Sprintf("Expected token : CSRFPreventionToken:5B6487B8:dI86OKNzX3BRFl... got : %s", token))
	}
}