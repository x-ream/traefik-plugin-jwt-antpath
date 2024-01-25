// Package jwtantpath a plugin to verify jwt exclude configured paths.
package traefik_plugin_jwt_antpath

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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

type JWT struct {
	header    string
	Payload   map[string]interface{}
	signature string
}

// Config holds the plugin configuration.
type Config struct {
	Paths     []string `json:"paths,omitempty" toml:"paths,omitempty" yaml:"paths,omitempty"`
	SecureKey string   `json:"secureKey,omitempty" toml:"secureKey,omitempty" yaml:"secureKey,omitempty"`
	HeaderKey string   `json:"headerKey,omitempty" toml:"headerKey,omitempty" yaml:"headerKey,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type JwtAntPath struct {
	name       string
	next       http.Handler
	pathParses []PathParse
	secureKey  []byte
	headerKey  string
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

	return &JwtAntPath{
		name:       name,
		next:       next,
		pathParses: pathParses,
		secureKey:  []byte(config.SecureKey),
		headerKey:  config.HeaderKey,
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

	jwt, err, code := ParseJwt(token, ja.secureKey)

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
