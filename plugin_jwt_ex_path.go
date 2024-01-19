// Package plugin_jwt_ex_path a plugin to verify jwt exclude configured paths.
package plugin_jwt_ex_path

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
	Payload   string
	signature string
}

// Config holds the plugin configuration.
type Config struct {
	Paths     []string `json:"paths,omitempty"`
	SecureKey string   `json:"secureKey,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type JwtExPath struct {
	name       string
	next       http.Handler
	paths      *[]string
	pathParses []PathParse
	key        []byte
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

	return &JwtExPath{
		name:       name,
		next:       next,
		paths:      &config.Paths,
		pathParses: pathParses,
		key:        []byte(config.SecureKey),
	}, nil
}

func (jxp *JwtExPath) filter1Star(currentPath string, parse PathParse) bool {

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

func (jxp *JwtExPath) filter2StarSuffix(currentPath string, parse PathParse) bool {
	if parse.TwoStarSuffix.endWith2Star {

		fmt.Println("parse.TwoStarSuffix.endWith2Star:", parse.TwoStarSuffix.pathTrim2Star)

		if jxp.filter1Star(currentPath, parse) {
			return true
		}

		if strings.HasPrefix(currentPath, parse.TwoStarSuffix.pathTrim2Star) {
			return true
		}
	}

	return false
}

func (jxp *JwtExPath) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	currentPath := req.URL.EscapedPath()

	if currentPath == "/" {
		jxp.next.ServeHTTP(rw, req)
		return
	}

	for _, parse := range jxp.pathParses {

		if parse.prefix2 != "/*" && !strings.HasPrefix(currentPath, parse.prefix2) {
			continue
		}

		if currentPath == parse.path {
			jxp.next.ServeHTTP(rw, req)
			return
		}

		if jxp.filter2StarSuffix(currentPath, parse) {
			jxp.next.ServeHTTP(rw, req)
			return
		}

		if jxp.filter1Star(currentPath, parse) {
			jxp.next.ServeHTTP(rw, req)
			return
		}

	}

	jxp.verifyJwt(rw, req)

	jxp.next.ServeHTTP(rw, req)
}

func (jxp *JwtExPath) verifyJwt(rw http.ResponseWriter, req *http.Request) {

	token := req.Header.Get("Authorization")
	if token == "" {
		http.Error(rw, "No Authorization", http.StatusUnauthorized)
		return
	}

	token = strings.TrimPrefix(token, "Bearer ")

	jwt, err, code := ParseJwt(token, jxp.key)

	if err != nil {
		http.Error(rw, err.Error(), code)
		return
	}

	jsonMap := make(map[string]interface{})
	err = json.Unmarshal([]byte(jwt.Payload), &jsonMap)

	for k, v := range jsonMap {
		req.Header.Add(k, fmt.Sprintf("%v", v))
	}
}

func ParseJwt(token string, key []byte) (*JWT, error, int) {
	jwtParts := strings.Split(token, ".")
	if len(jwtParts) != 3 {
		return nil, fmt.Errorf("非法token"),
			http.StatusUnauthorized
	}

	encodedHeader := jwtParts[0]
	encodedPayload := jwtParts[1]
	signature := jwtParts[2]

	confirmSignature, err := generateSignature(key, []byte(encodedHeader+"."+encodedPayload))
	if err != nil {
		return nil, fmt.Errorf(err.Error()), http.StatusUnauthorized
	}

	if signature != confirmSignature {
		return nil, fmt.Errorf("signature wrong"), http.StatusUnauthorized
	}

	dstPayload, _ := base64.RawURLEncoding.DecodeString(encodedPayload)

	return &JWT{encodedHeader, string(dstPayload), signature}, nil, http.StatusOK
}

func generateSignature(key []byte, data []byte) (string, error) {
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
