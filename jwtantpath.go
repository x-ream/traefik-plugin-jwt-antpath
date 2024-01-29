// Package jwtantpath a plugin to verify jwt exclude configured paths.
package traefik_plugin_jwt_antpath

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type OneStar struct {
	has1Star bool
	idx      int
	arr      []string
}

type TwoStarSuffix struct {
	endWith2Star  bool
	pathTrim2Star string
}

type PathParse struct {
	path    string
	prefix2 string
	OneStar
	TwoStarSuffix
}

type KeyHS256 struct {
	kty string //oct
	kid string
	k   string
	alg string //HS256
}

type JWT struct {
	header    string
	Payload   map[string]interface{}
	signature string
}

type JwksConfig struct {
	Enabled   bool   `json:"enabled,omitempty" toml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Interval  string `json:"interval,omitempty" toml:"interval,omitempty" yaml:"interval,omitempty"`
	Uri       string `json:"uri,omitempty" toml:"uri,omitempty" yaml:"uri,omitempty"`
	ClientId  string `json:"clientId,omitempty" toml:"clientId,omitempty" yaml:"clientId,omitempty"`
	ClientKey string `json:"clientKey,omitempty" toml:"clientKey,omitempty" yaml:"clientKey,omitempty"`
}

// Config holds the plugin configuration.
type Config struct {
	Paths     []string   `json:"paths,omitempty" toml:"paths,omitempty" yaml:"paths,omitempty"`
	HeaderKey string     `json:"headerKey,omitempty" toml:"headerKey,omitempty" yaml:"headerKey,omitempty"`
	SecureKey string     `json:"secureKey,omitempty" toml:"secureKey,omitempty" yaml:"secureKey,omitempty"`
	Jwks      JwksConfig `json:"jwks,omitempty" toml:"jwks,omitempty" yaml:"jwks,omitempty"`
	key       *KeyHS256
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type JwtAntPath struct {
	name       string
	next       http.Handler
	pathParses []PathParse
	headerKey  string
	key        *KeyHS256
}

// New creates and returns a plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	var pathParses = make([]PathParse, len(config.Paths))

	for i, path := range config.Paths {

		pathParses[i] = PathParse{
			path:    path,
			prefix2: string(path[:2]),
		}

		var endWith2Star = strings.HasSuffix(path, "/**")

		if endWith2Star {
			pathParses[i].TwoStarSuffix = TwoStarSuffix{
				pathTrim2Star: strings.TrimSuffix(path, "/**"),
				endWith2Star:  endWith2Star,
			}
		}

		p := path
		if endWith2Star {
			p = pathParses[i].TwoStarSuffix.pathTrim2Star
		}

		if strings.Contains(p, "*") {
			pathParses[i].OneStar = OneStar{
				has1Star: true,
				idx:      strings.Index(p, "*"),
				arr:      strings.Split(p, "*"),
			}
		}

	}

	var key = KeyHS256{
		k: config.SecureKey,
	}
	config.key = &key

	schedule(config)

	return &JwtAntPath{
		name:       name,
		next:       next,
		pathParses: pathParses,
		headerKey:  config.HeaderKey,
		key:        &key,
	}, nil
}

func (ja *JwtAntPath) filter1Star(currentPath string, parse PathParse) bool {

	if parse.OneStar.has1Star {

		if parse.TwoStarSuffix.endWith2Star { //no match **, return true
			if !strings.Contains(currentPath, parse.OneStar.arr[len(parse.OneStar.arr)-1]) {
				return true
			}
		}

		for _, v := range parse.OneStar.arr { // replace re
			currentPath = strings.Replace(currentPath, v, " ", 1)
		}

		cpArr := strings.Split(strings.TrimSpace(currentPath), " ")
		l := len(cpArr)
		offset := 0
		if l > 1 && parse.TwoStarSuffix.endWith2Star {
			offset = 1
		}

		var skip = true
		for i, cp := range cpArr {
			if i < l-offset && strings.Contains(cp, "/") {
				skip = false
				break
			}
		}
		if skip {
			return true
		}

	}
	return false
}

func (ja *JwtAntPath) filter2StarSuffix(currentPath string, parse PathParse) bool {
	if parse.TwoStarSuffix.endWith2Star {

		if ja.filter1Star(currentPath, parse) {
			return true
		}

		if strings.HasPrefix(currentPath, parse.TwoStarSuffix.pathTrim2Star) {
			return true
		}
	}

	return false
}

func (ja *JwtAntPath) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	currentPath := req.URL.EscapedPath()

	if currentPath == "/" {
		ja.next.ServeHTTP(rw, req)
		return
	}

	for _, parse := range ja.pathParses {

		if parse.prefix2 != "/*" && !strings.HasPrefix(currentPath, parse.prefix2) {
			continue
		}

		if currentPath == parse.path {
			ja.next.ServeHTTP(rw, req)
			return
		}

		if ja.filter2StarSuffix(currentPath, parse) {
			ja.next.ServeHTTP(rw, req)
			return
		}

		if ja.filter1Star(currentPath, parse) {
			ja.next.ServeHTTP(rw, req)
			return
		}

	}

	if ja.verifyJwt(rw, req) {
		ja.next.ServeHTTP(rw, req)
	}
}

func (ja *JwtAntPath) verifyJwt(rw http.ResponseWriter, req *http.Request) bool {

	token := req.Header.Get(ja.headerKey)
	if token == "" {
		http.Error(rw, "No "+ja.headerKey, http.StatusUnauthorized)
		return false
	}

	token = strings.TrimPrefix(token, "Bearer ")

	jwt, err, code := ParseJwt(token, []byte(ja.key.k))

	if err != nil {
		http.Error(rw, err.Error(), code)
		return false
	}

	delete(jwt.Payload, "exp")
	delete(jwt.Payload, "iat")

	for k, v := range jwt.Payload {
		req.Header.Add(k, fmt.Sprintf("%v", v))
	}

	return true
}

func schedule(config *Config) {
	if config.Jwks.Enabled && config.Jwks.ClientKey != "" && config.Jwks.Uri != "" {
		go func() {
			clientPrivateKey, err := getPriKey([]byte(config.Jwks.ClientKey))
			if err != nil {
				return
			}
			var httpClient = &http.Client{Timeout: 30 * time.Second}
			for {
				refreshJwks(httpClient, config, clientPrivateKey)
				d, err := time.ParseDuration(config.Jwks.Interval)
				if err == nil {
					time.Sleep(d)
				} else {
					time.Sleep(11 * time.Minute)
				}
			}
		}()
	}
}

func refreshJwks(httpClient *http.Client, config *Config, clientPrivateKey *rsa.PrivateKey) {

	req, err := http.NewRequest("GET", config.Jwks.Uri, nil)
	if err != nil {
		return
	}

	validTime := time.Now().Unix() + 60*1000
	var signStr = config.Jwks.ClientId + ":" + strconv.FormatInt(validTime, 13)
	signBytes, err := encryptByPrivateKey([]byte(signStr), clientPrivateKey)
	if err != nil {
		return
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Client-Id", config.Jwks.ClientId)
	req.Header.Add("Sign", base64.StdEncoding.EncodeToString(signBytes))

	rep, err := httpClient.Do(req)
	if err != nil {
		return
	}
	defer rep.Body.Close()
	body, err := io.ReadAll(rep.Body)
	if err != nil {
		return
	}

	var key = KeyHS256{}
	err = json.Unmarshal(body, &key)
	if err != nil {
		return
	}

	if key.kid == "oct" && key.alg == "HS256" {
		config.key.k = key.k
	}

}

func ParseJwt(token string, key []byte) (*JWT, error, int) {
	jwtParts := strings.Split(token, ".")
	if len(jwtParts) != 3 {
		return nil, fmt.Errorf("illegal token"),
			http.StatusUnauthorized
	}

	encodedHeader := jwtParts[0]
	encodedPayload := jwtParts[1]
	signature := jwtParts[2]

	testSignature, err := sign(key, []byte(encodedHeader+"."+encodedPayload))
	if err != nil {
		return nil, fmt.Errorf(err.Error()), http.StatusUnauthorized
	}

	if signature != testSignature {
		return nil, fmt.Errorf("signature wrong"), http.StatusUnauthorized
	}

	dstPayload, _ := base64.RawURLEncoding.DecodeString(encodedPayload)

	payload := make(map[string]interface{})
	err = json.Unmarshal(dstPayload, &payload)

	if err != nil {
		return nil, fmt.Errorf(err.Error()), http.StatusUnauthorized
	}

	if time.Now().Unix() > int64(payload["exp"].(float64)) {
		return nil, fmt.Errorf("token has expired"), http.StatusUnauthorized
	}

	return &JWT{encodedHeader, payload, signature}, nil, http.StatusOK
}

func sign(key []byte, data []byte) (string, error) {
	hash := hmac.New(sha256.New, key)
	_, err := hash.Write(data)
	if err != nil {
		return "", err
	}
	return encodeBase64(string(hash.Sum(nil))), nil
}

func encodeBase64(data string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(data))
}

// copy from https://github.com/farmerx/gorsa
func encryptByPrivateKey(input []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return []byte(""), errors.New(`Please set the private key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(privateKey, bytes.NewReader(input), output, true)
	if err != nil {
		return []byte(""), err
	}
	return output.AvailableBuffer(), nil
	//return ioutil.ReadAll(output)
}

// copy from https://github.com/farmerx/gorsa
func getPriKey(privateKeyBuffer []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyBuffer)
	if block == nil {
		return nil, errors.New("get private key error")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return pri, nil
	}
	pri2, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pri2.(*rsa.PrivateKey), nil
}

// copy from https://github.com/farmerx/gorsa
func priKeyIO(pri *rsa.PrivateKey, r io.Reader, w io.Writer, isEncrytp bool) (err error) {
	k := (pri.N.BitLen() + 7) / 8
	if isEncrytp {
		k = k - 11
	}
	buf := make([]byte, k)
	var b []byte
	size := 0
	for {
		size, err = r.Read(buf)
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
			b, err = priKeyEncrypt(rand.Reader, pri, b)
		} else {
			b, err = rsa.DecryptPKCS1v15(rand.Reader, pri, b)
		}
		if err != nil {
			return err
		}
		if _, err = w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// copy from https://github.com/farmerx/gorsa
func priKeyEncrypt(rand io.Reader, priv *rsa.PrivateKey, hashed []byte) ([]byte, error) {
	tLen := len(hashed)
	k := (priv.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, errors.New("data length error")
	}
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k], hashed)
	m := new(big.Int).SetBytes(em)
	c, err := decrypt(rand, priv, m)
	if err != nil {
		return nil, err
	}
	copyWithLeftPad(em, c.Bytes())
	return em, nil
}

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// copy from https://github.com/farmerx/gorsa
func decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.N) > 0 {
		err = errors.New("decryption error")
		return
	}
	var ir *big.Int
	if random != nil {
		var r *big.Int

		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			var ok bool
			ir, ok = modInverse(r, priv.N)
			if ok {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N)
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}
	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}
	if ir != nil {
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

// copy from https://github.com/farmerx/gorsa
func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}

// copy from https://github.com/farmerx/gorsa
func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		return
	}
	if x.Cmp(bigOne) < 0 {
		x.Add(x, n)
	}
	return x, true
}
