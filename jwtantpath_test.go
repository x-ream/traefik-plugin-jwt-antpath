// Package jwtantpath a plugin to verify jwt exclude configured paths.
package traefik_plugin_jwt_antpath

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		desc   string
		paths  []string
		expErr bool
	}{
		{
			desc:   "should return no error",
			paths:  []string{`/foo/**`},
			expErr: false,
		},
		{
			desc:   "should return no error",
			paths:  []string{"/foo/*"},
			expErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			cfg := &Config{
				Paths: test.paths,
			}

			if _, err := New(context.Background(), nil, cfg, "name"); test.expErr && err == nil {
				t.Errorf("expected error on bad regexp format")
			}
		})
	}
}

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		desc      string
		paths     []string
		reqPath   string
		hasHeader bool
		userId    int64
	}{
		{
			desc:      "should no header",
			paths:     []string{"/test"},
			reqPath:   "/test",
			hasHeader: false,
			userId:    1,
		},
		{
			desc:      "should no header",
			paths:     []string{"/test", "/toto"},
			reqPath:   "/toto",
			hasHeader: false,
			userId:    2,
		},
		{
			desc:      "should has header",
			paths:     []string{"/test", "/toto"},
			reqPath:   "/plop",
			hasHeader: true,
			userId:    3,
		},
		{
			desc:      "should has header",
			reqPath:   "/test",
			hasHeader: true,
			userId:    4,
		},
		{
			desc:      "should no header",
			paths:     []string{`/foo/**`},
			reqPath:   "/foo/bar/zzz",
			hasHeader: false,
			userId:    5,
		},
		{
			desc:      "should no header",
			paths:     []string{`/foo/**`},
			reqPath:   "/foo/bar",
			hasHeader: false,
			userId:    6,
		},
		{
			desc:      "should no header",
			paths:     []string{`/foo/**`},
			reqPath:   "/foo",
			hasHeader: false,
			userId:    7,
		},
		{
			desc:      "should no header",
			paths:     []string{`/*/foo/**`},
			reqPath:   "/xxx/foo",
			hasHeader: false,
			userId:    8,
		},
		{
			desc:      "should has header",
			paths:     []string{`/*/foo/**`},
			reqPath:   "/xxx/zzz/foo",
			hasHeader: true,
			userId:    9,
		},
		{
			desc:      "should no header",
			paths:     []string{`/*/foo/**`},
			reqPath:   "/xxx/foo/mmm/nnn",
			hasHeader: false,
			userId:    10,
		},
		{
			desc:      "should has header",
			paths:     []string{`/*/foo/**`},
			reqPath:   "/xxx/888/foo/mmm/nnn",
			hasHeader: true,
			userId:    11,
		},
		{
			desc:      "should no header",
			paths:     []string{`/zzz/zzz/*/foo/**`},
			reqPath:   "/zzz/zzz/xxx/foo/mmm/nnn",
			hasHeader: false,
			userId:    12,
		},
		{
			desc:      "should has header",
			paths:     []string{`/zzz/zxz/*/foo/**`},
			reqPath:   "/zzz/zzz/xxx/foo/mmm/nnn",
			hasHeader: true,
			userId:    13,
		},
		{
			desc:      "should no header",
			paths:     []string{`/zzz/zzz/*/foo/**`},
			reqPath:   "/zzz/zzz/xxx/foo",
			hasHeader: false,
			userId:    14,
		},
		{
			desc:      "should no header",
			paths:     []string{`/zzz/zzz/*/foo/**`},
			reqPath:   "/zzz/zzz/xxx/foo/{345}",
			hasHeader: false,
			userId:    15,
		},
		// endWithOneStar below....
		{
			desc:      "should no header",
			paths:     []string{`/zzz/*`},
			reqPath:   "/zzz/xxx",
			hasHeader: false,
			userId:    16,
		},
		{
			desc:      "should has header",
			paths:     []string{`/zzz/*`},
			reqPath:   "/zzz/xxx/xxxx",
			hasHeader: true,
			userId:    17,
		},
		//  endWithOneStar 1star: 1+ below....
		{
			desc:      "should has header",
			paths:     []string{`/*/zzz/*`},
			reqPath:   "/zzz/xxx/xxxx",
			hasHeader: true,
			userId:    18,
		},
		{
			desc:      "should has header",
			paths:     []string{`/*/zzz/*`},
			reqPath:   "/zzz/xxx/xxxx/zzz",
			hasHeader: true,
			userId:    19,
		},
		{
			desc:      "should no header",
			paths:     []string{`/*/zzz/*`},
			reqPath:   "/zzz/zzz/xxxx",
			hasHeader: false,
			userId:    20,
		},
		{
			desc:      "should has header",
			paths:     []string{`/*/zzz/*`},
			reqPath:   "/zzz/zzz/xxxx/ooo",
			hasHeader: true,
			userId:    21,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			cfg := &Config{
				Paths: test.paths,
			}

			userId := 0
			hasHeader := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				v := req.Header.Get("userId")
				if v != "" {
					hasHeader = true
					id, err := strconv.Atoi(v)
					if err != nil {
						fmt.Println(err.Error())
					} else {
						userId = id
					}
				}
			})

			SECRET := "abcZSEDDXA+++XDANNHDKEK234223OOPPP133...9US++"
			cfg.SecureKey = SECRET
			cfg.HeaderKey = "Authorization"

			user := map[string]interface{}{
				"UserId":   test.userId,
				"NickName": "ooooHig",
			}
			fmt.Println(time.Now().Unix() + 30*24*60*60)
			token, _ := CreateToken([]byte(SECRET), user, int(time.Now().Unix())+30*24*60*60)

			handler, err := New(context.Background(), next, cfg, "jwt verification")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			url := fmt.Sprintf("http://localhost%s", test.reqPath)
			req := httptest.NewRequest(http.MethodGet, url, nil)

			req.Header.Add("Authorization", "Bearer "+token)
			handler.ServeHTTP(recorder, req)

			if hasHeader != test.hasHeader {
				t.Errorf("handle failed")
			}

			if hasHeader {
				fmt.Println(test.userId)
				fmt.Println(userId)
				if int64(userId) != test.userId {
					t.Errorf("handle failed")
				}
			}

		})
	}

}

func CreateToken(key []byte, m map[string]interface{}, expMinute int) (string, error) {
	header := `{"alg":"HS256","typ":"JWT"}`

	m["exp"] = expMinute
	m["iat"] = time.Now().Unix()
	payload, jsonErr := json.Marshal(m)
	if jsonErr != nil {
		return "", jsonErr
	}

	encodedHeader := encodeBase64(header)
	encodedPayload := encodeBase64(string(payload))
	HeaderAndPayload := encodedHeader + "." + encodedPayload

	signature, err := sign(key, []byte(HeaderAndPayload))
	if err != nil {
		return "", err
	}

	return HeaderAndPayload + "." + signature, nil
}

func TestPrivateKeyEncrypt(t *testing.T) {
	var privateKeyStr = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvSicp1V0YNiNQzSvMmQTYw07ACHaZaoWfIxHkDNu1TzmBI2h
PO2MAwVoUjOAFgat0G4fzgU3h44QljGHVCRWbS2VX6iRizg6bMeutAU7EIuuqa06
dJo99ByDPUnkXPngutUfYS9ZIEC6RPODg9zG0OyEHL4YhkPpit0BOWSBRw1yqrj+
KSya9SUdr7Pr2qBZLa+JgjOYS/JvEs1d5p+dVugGo9XU5AEN6sUQxWr0miYmYd/k
C7k7kD+LMBlwLD6ttzKrGN7A8rBm1Xf5FUziwGv+LIarktc05Hj2P6qDBbaKnhw1
PEvfgswpWUFzIl8K86TfdsGgPhBX1HzR7xRLRQIDAQABAoIBAQCT/dQiLv9wTbyn
me6AFD/+vPkuL045QAt7whyzOyo5dv3XDh/aFVf3fSGTPmu1z9/pNF95xicdzQ45
E+L2978OiB1XzACi1YkQVmHewkDlvwMWCUu0soBKHoynRMp/25fxVJDKbkriqwGQ
tJxubCq4hnMOMcPqN/PeCu7MQk/Kj+fwlSnzXUXtsBsZvj0eDgaYp7rbMJCv4dVJ
4v3QsLWfAAw3Da6x9hxP7fMmigFdyln3K9+KYwpfG1o5C8Ndb49gs2ooyRdWk8Kq
wyH+UXfmvMbDAyzgYTMK7WfDipiU2vS5hQZZtGbbdLXLUfIQlcPuWEqx5MYsR6ME
i1L00XoBAoGBAM8YikhpInalwzn9nyhftqYTu8MSq+al4AOkkYVuSmvTYpzCZJ68
ehLG3otUMcIPz798sPyWKcytpfqH4XyqEhYC6lJfVPNJ5GEjgGnKI1VvjScDuTGi
tBbOtLndo9nA6BgAehKqERMdujbk+CUM5UPwGi4AA1+3bTionK/EUwQFAoGBAOnT
uOM4x2v7UE+XJ0CoYacqTAevz173Sr4NdlUhp8rfoTKGbyz9S1X6jxUNYcd8cvEg
ulvo3Fkix0rWBb3hSDf2F/E2nwrDQNPDxbVAYW4etacKPLTD5paAFzPXLMaHe31e
KpQX7sP3uvThbg4S4Vro1tkTXpR6tJR9rPMvKA5BAoGAYx6EuOmQ9CacTPolngZJ
fi19tX0PR4JmuHegqrNB7V+sGAk2bX8aEjiatSbj9dTpguXkM9CPSwZlpYY5lxgz
NdPJYQl9uD/Kje+W+4si5DZS4bR3g9kyxqPCfh8l2AfrTemUg7BgIb0drj5iwiDs
7lpRvWiGNN6u6OpSrBGUBh0CgYEA2TCqCZTR14EGJgeWlD5TBn0JRhKNof49VK8Y
fRbXzl9OUaoBVl6oPWKQyNM3QZ5c/ZCSyZBQLBNb3i1SA/9fn2tc7db4f3zBmHG+
EQ+N8EViIZgmrxlP8/dileqGUpnBoL94+ToJs8lFxPQnz7bF0DV6awPM1EnttgfO
P8xLfoECgYAJqgkPQLuimH498j5KCbQt0FtTJhdQ5OSdAiswg8ko8P7eBYBcLp5V
O2tXR405Q2UGfreGyMhHS5ok4fBwrBYRKdMHGyFgCOuj/GhrbnZJrfMErGLX0SF+
yc6T+XzAjVROOkQVwVgTm9p1oaNLI0RHOboJBM4UVfLkOwZu4TUxng==
-----END RSA PRIVATE KEY-----
`

	var certStr = `
-----BEGIN CERTIFICATE-----
MIIC7jCCAdagAwIBAgIUPcK7l6xgzjZ3fFkJ/SXyrd84qFYwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAxMEdGVzdDAeFw0yNDAxMzAwNjU4MDBaFw0yOTAxMjgwNjU4
MDBaMA8xDTALBgNVBAMTBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC9KJynVXRg2I1DNK8yZBNjDTsAIdplqhZ8jEeQM27VPOYEjaE87YwDBWhS
M4AWBq3Qbh/OBTeHjhCWMYdUJFZtLZVfqJGLODpsx660BTsQi66prTp0mj30HIM9
SeRc+eC61R9hL1kgQLpE84OD3MbQ7IQcvhiGQ+mK3QE5ZIFHDXKquP4pLJr1JR2v
s+vaoFktr4mCM5hL8m8SzV3mn51W6Aaj1dTkAQ3qxRDFavSaJiZh3+QLuTuQP4sw
GXAsPq23MqsY3sDysGbVd/kVTOLAa/4shquS1zTkePY/qoMFtoqeHDU8S9+CzClZ
QXMiXwrzpN92waA+EFfUfNHvFEtFAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTAUDVpCxpFJE5FaHvBwaAuO7MdtzAN
BgkqhkiG9w0BAQsFAAOCAQEAsO+mJNG8bFxxKV2S6WU9/ZYPGS7sDYnLBbOxVvH8
+G6gZH+6rnBu5qLBT1i3OB7I4NsR/zh8jeIM2ZMKpKBG7owk1zfqhjy8ms/5UMJR
LaELjpm/VqWyaDSHjWH2/uq4MUiheye4moBw3omJUMoyvcFSPIVB4+d2pAYtDDQJ
Ofi21MzZ1kMa4ZL0VkNEjEQGsNFkgiXxlDeFrXzYs+kNm6GCrH/zgntZiP10WPyJ
GBRqR6REaJM86xb+swZZSGFVlNKLaAh3cBFyNnXrM7ywVVLsv+y7AAsyOisIa5eT
W44Q5FwGTMk+6YohCFP7ZWaLVnI+3zHzLddF2M1+PnUcAQ==
-----END CERTIFICATE-----
`
	fmt.Println(privateKeyStr)
	fmt.Println(certStr)

	privateKey, err := getPriKey([]byte(privateKeyStr))

	if err != nil {
		fmt.Println(err)
		return
	}

	testStr := "hello world, start test encrypt and decrypt"
	startTime := time.Now().UnixMicro()
	buf, err := encryptByPrivateKey([]byte(testStr), privateKey)
	endTime := time.Now().UnixMicro()
	fmt.Println("encrypt time:", endTime-startTime)

	if err != nil {
		fmt.Println(err)
		return
	}

	startTime = time.Now().UnixMicro()

	block, _ := pem.Decode([]byte(certStr))
	if block == nil {
		log.Fatal("Failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("parse cert failed: " + err.Error())
	}

	// get RSA PublicKey
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Errorf("test failed")
		return
	}

	buf, err = decryptByPublicKey(buf, publicKey)
	endTime = time.Now().UnixMicro()
	fmt.Println("decrypt time:", endTime-startTime)

	if err != nil {
		fmt.Println(err)
		return
	}

	if testStr != string(buf) {
		t.Errorf("test failed")
	}
}

func decryptByPublicKey(input []byte, publicKey *rsa.PublicKey) ([]byte, error) {

	output := bytes.NewBuffer(nil)
	err := pubKeyIO(publicKey, bytes.NewReader(input), output, false)
	if err != nil {
		return []byte(""), err
	}
	return io.ReadAll(output)
}

// copy from https://github.com/farmerx/gorsa
func pubKeyIO(pub *rsa.PublicKey, in io.Reader, out io.Writer, isEncrytp bool) (err error) {
	k := (pub.N.BitLen() + 7) / 8
	if isEncrytp {
		k = k - 11
	}
	buf := make([]byte, k)
	var b []byte
	size := 0
	for {
		size, err = in.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}
		if isEncrytp {
			b, err = rsa.EncryptPKCS1v15(rand.Reader, pub, b)
		} else {
			b, err = pubKeyDecrypt(pub, b)
		}
		if err != nil {
			return err
		}
		if _, err = out.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// copy from https://github.com/farmerx/gorsa
func pubKeyDecrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if k != len(data) {
		return nil, errors.New("data length error")
	}
	m := new(big.Int).SetBytes(data)
	if m.Cmp(pub.N) > 0 {
		return nil, errors.New("message too long for RSA public key size")
	}
	m.Exp(m, big.NewInt(int64(pub.E)), pub.N)
	d := leftPad(m.Bytes(), k)
	if d[0] != 0 {
		return nil, errors.New("data broken, first byte is not zero")
	}
	if d[1] != 0 && d[1] != 1 {
		return nil, errors.New("data is not encrypted by the private key")
	}
	var i = 2
	for ; i < len(d); i++ {
		if d[i] == 0 {
			break
		}
	}
	i++
	if i == len(d) {
		return nil, nil
	}
	return d[i:], nil
}

// copy from https://github.com/farmerx/gorsa
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}
