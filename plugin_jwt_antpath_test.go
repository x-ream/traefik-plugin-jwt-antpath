// Package traefik_plugin_jwt_antpath a plugin to verify jwt exclude configured paths.
package traefik_plugin_jwt_antpath

import (
	"context"
	"encoding/json"
	"fmt"
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
