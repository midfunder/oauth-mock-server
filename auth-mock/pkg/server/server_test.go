package server

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"crypto/rand"
	"crypto/rsa"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestJWKSEncoding(t *testing.T) {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, 256*8)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "http://example.com/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	serveJWKS(w, req, key)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAccessToken(t *testing.T) {
	srv := NewAuthServer(&AuthServerOptions{"/var/tmp"}).(*authServer)

	req := httptest.NewRequest("GET", "http://example.com/oauth/token", nil)
	sub := "user@example.com"
	session := &sessionState{
		aud:      "api.example.com",
		clientID: "webapp.example.com",
	}

	token, err := srv.getAccessToken(req, sub, session)
	require.NoError(t, err)

	tok, err := jose.ParseSigned(token)
	require.NoError(t, err)

	payload, err := tok.Verify(&srv.key.PublicKey)
	assert.NoError(t, err)

	var jspayload map[string]json.RawMessage
	err = json.Unmarshal(payload, &jspayload)
	assert.NoError(t, err)
	var decodedID string
	err = json.Unmarshal(jspayload["sub"], &decodedID)
	assert.NoError(t, err)
	assert.Equal(t, sub, decodedID)
}

func TestUserinfoUnknownID(t *testing.T) {
	srv := NewAuthServer(&AuthServerOptions{"/var/tmp"}).(*authServer)

	req := httptest.NewRequest("GET", "http://example.com/oauth/token", nil)
	session := &sessionState{
		email:    "user@example.com",
		name:     "John Doe",
		aud:      "api.example.com",
		clientID: "webapp.example.com",
	}
	id := makeSubject(session.email)

	token, err := srv.getAccessToken(req, id, session)
	require.NoError(t, err)

	req = httptest.NewRequest("GET", "http://example.com/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	srv.userinfo(w, req)
	assert.Equal(t, http.StatusExpectationFailed, w.Code)
}

func TestUserinfoOK(t *testing.T) {
	srv := NewAuthServer(&AuthServerOptions{"/var/tmp"}).(*authServer)

	req := httptest.NewRequest("GET", "http://example.com/oauth/token", nil)
	session := &sessionState{
		email:    "user@example.com",
		name:     "John Doe",
		aud:      "api.example.com",
		clientID: "webapp.example.com",
	}

	id := makeSubject(session.email)
	srv.setSessionState(id, session)
	token, err := srv.getAccessToken(req, id, session)
	require.NoError(t, err)

	req = httptest.NewRequest("GET", "http://example.com/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	srv.userinfo(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWebMessage(t *testing.T) {
	srv := NewAuthServer(&AuthServerOptions{"../../static"}).(*authServer)
	session := &sessionState{
		email:    "user@example.com",
		name:     "John Doe",
		aud:      "api.example.com",
		clientID: "webapp.example.com",
	}

	sub := makeSubject(session.email)

	params := url.Values{
		"response_mode": []string{"web_message"},
		"redirect_uri":  []string{"http://client.example.com"},
		"state":         []string{"1234"},
	}
	req := httptest.NewRequest("GET", "http://example.com/authorize?"+params.Encode(), nil)
	req.AddCookie(&http.Cookie{
		Name:  cookieName,
		Value: sub,
	})

	srv.setSessionState(sub, session)

	w := httptest.NewRecorder()
	srv.authorize(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body, err := ioutil.ReadAll(w.Result().Body)
	assert.NoError(t, err)

	doc := string(body)
	re := regexp.MustCompile(`var redirectURI = \"(.*)\"`)
	m := re.FindStringSubmatch(doc)
	require.Len(t, m, 2)
	assert.Equal(t, params.Get("redirect_uri"), m[1])
}
