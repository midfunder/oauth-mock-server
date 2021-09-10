package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type AuthServerOptions struct {
	StaticDir string
}

type AuthServer interface {
	ServeHTTP(w http.ResponseWriter, req *http.Request)
}

const cookieName = "authMock"

type sessionState struct {
	email       string
	name        string
	isValidated bool
	clientID    string
	aud         string
	redirectUri string
	nonce       string
}

type authServer struct {
	opts     *AuthServerOptions
	key      *rsa.PrivateKey
	signer   jose.Signer
	sessions map[string]*sessionState
	mutex    sync.Mutex
}

func NewAuthServer(opts *AuthServerOptions) AuthServer {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, 256*8)
	if err != nil {
		log.Fatal().Err(err).Msg("RSA GenerateKey")
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("new RSA Signer")
	}
	return &authServer{
		opts:     opts,
		key:      key,
		signer:   signer,
		sessions: make(map[string]*sessionState),
	}
}

func (srv *authServer) getSessionState(subject string) (*sessionState, bool) {
	srv.mutex.Lock()
	defer srv.mutex.Unlock()
	s, ok := srv.sessions[subject]
	return s, ok
}

func (srv *authServer) setSessionState(subject string, session *sessionState) {
	srv.mutex.Lock()
	defer srv.mutex.Unlock()
	srv.sessions[subject] = session
}

func (srv *authServer) clearSessionState(subject string) {
	srv.mutex.Lock()
	defer srv.mutex.Unlock()
	delete(srv.sessions, subject)
}

func makeSubject(email string) string {
	return "oauth|" + base64.StdEncoding.EncodeToString([]byte(email))
}

type authTokenResponse struct {
	IdToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (srv *authServer) getIDToken(req *http.Request, subject string, session *sessionState) (string, error) {
	claims := jwt.Claims{
		Issuer:  "https://" + req.Host + "/",
		Subject: subject,
		Audience: jwt.Audience{
			session.clientID,
		},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}
	extClaims := struct {
		Nonce         string `json:"nonce"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified bool   `json:"email_verified"`
	}{
		Email:         session.email,
		Name:          session.name,
		Nonce:         session.nonce,
		EmailVerified: session.isValidated,
	}
	return jwt.Signed(srv.signer).Claims(claims).Claims(extClaims).CompactSerialize()
}

func (srv *authServer) getAccessToken(req *http.Request, subject string, session *sessionState) (string, error) {
	claims := jwt.Claims{
		Issuer:  "https://" + req.Host + "/",
		Subject: subject,
		Audience: jwt.Audience{
			session.aud,
			"https://" + req.Host + "/userinfo",
		},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}
	extClaims := struct {
		AuthorizedParty string `json:"azp"`
		Scope           string `json:"scope"`
	}{
		AuthorizedParty: session.clientID,
		Scope:           "openid profile email",
	}
	return jwt.Signed(srv.signer).Claims(claims).Claims(extClaims).CompactSerialize()
}

func (srv *authServer) generateToken(w http.ResponseWriter, req *http.Request, subject string, session *sessionState) {
	// grant_type: "authorization_code"
	idToken, err := srv.getIDToken(req, subject, session)
	if err != nil {
		log.Error().Err(err).Msg("id_token generation")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accessToken, err := srv.getAccessToken(req, subject, session)
	if err != nil {
		log.Error().Err(err).Msg("access_token generation")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response := authTokenResponse{
		TokenType:   "Bearer",
		IdToken:     idToken,
		AccessToken: accessToken,
		ExpiresIn:   60 * 60,
		Scope:       "openid profile email",
	}

	data, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("pragma", "no-cache")
	w.Write(data)
}

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

func (srv *authServer) authToken(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", req.Header.Get("Origin"))

	if req.Method == http.MethodOptions {
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", req.Header.Get("access-control-request-headers"))
		w.Header().Add("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
	}

	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	dec := json.NewDecoder(req.Body)
	var request tokenRequest
	if err := dec.Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	state, ok := srv.getSessionState(request.Code)
	if !ok {
		http.Error(w, "Invalid token request code", http.StatusBadRequest)
		return
	}

	srv.generateToken(w, req, request.Code, state)
}

func getCookieValue(req *http.Request) (string, bool) {
	cookie, err := req.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	return cookie.Value, true
}

func makeRedirectURI(subject string, values url.Values) url.URL {
	query := url.Values{}
	query.Add("state", values.Get("state"))
	query.Add("code", subject)
	return url.URL{
		Path:     values.Get("redirect_uri"),
		RawQuery: query.Encode(),
	}
}

func (srv *authServer) updateSession(session *sessionState, values url.Values) {
	session.nonce = values.Get("nonce")
	session.clientID = values.Get("client_id")
	session.aud = values.Get("audience")
	session.redirectUri = values.Get("redirect_uri")
}

func (srv *authServer) authWebMessage(w http.ResponseWriter, subject string, query url.Values) {
	tmpl, err := template.ParseFiles(path.Join(srv.opts.StaticDir, "authorize.tmpl.html"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		RedirectURI string
		Code        string
		State       string
	}{
		RedirectURI: query.Get("redirect_uri"),
		Code:        subject,
		State:       query.Get("state"),
	}
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (srv *authServer) authorize(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if zerolog.GlobalLevel() == zerolog.DebugLevel {
		m := log.Debug()
		for k, v := range req.URL.Query() {
			m = m.Str(k, strings.Join(v, ","))
		}
		m.Msg("authorize")
	}

	// Redirect back to client if we already have login information.
	if subject, ok := getCookieValue(req); ok {
		log.Debug().Str("sub", subject).Msg("recv cookie")
		if session, exists := srv.getSessionState(subject); exists {
			srv.updateSession(session, req.URL.Query())

			if req.URL.Query().Get("response_mode") == "web_message" {
				srv.authWebMessage(w, subject, req.URL.Query())
				return
			}
			redirectURI := makeRedirectURI(subject, req.URL.Query())
			http.Redirect(w, req, redirectURI.RequestURI(), http.StatusFound)
			return
		}
	}

	http.Redirect(w, req, "login?"+req.URL.RawQuery, http.StatusFound)
}

// POST request with form data
func (srv *authServer) loginHandler(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	email := req.FormValue("email")
	if email == "" {
		http.Error(w, "email must be specified", http.StatusBadRequest)
		return
	}

	var isValidated bool
	if v, err := strconv.ParseBool(req.FormValue("validated")); err == nil {
		isValidated = v
	}

	values := req.URL.Query()

	subject := makeSubject(email)
	session := &sessionState{
		email:       email,
		name:        req.FormValue("name"),
		isValidated: isValidated,
		nonce:       values.Get("nonce"),
		clientID:    values.Get("client_id"),
		aud:         values.Get("audience"),
		redirectUri: values.Get("redirect_uri"),
	}
	srv.setSessionState(subject, session)
	cookie := &http.Cookie{
		Name:   cookieName,
		Value:  subject,
		MaxAge: 60 * 60,
	}
	http.SetCookie(w, cookie)

	// build redirect_uri
	redirectURI := makeRedirectURI(subject, values)
	http.Redirect(w, req, redirectURI.RequestURI(), http.StatusFound)
}

func (srv *authServer) login(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		http.ServeFile(w, req, path.Join(srv.opts.StaticDir, "login.html"))
	case http.MethodPost:
		srv.loginHandler(w, req)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (srv *authServer) logout(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if subject, ok := getCookieValue(req); ok {
		srv.clearSessionState(subject)
		http.SetCookie(w, &http.Cookie{Name: cookieName, MaxAge: -1})
	}
	redirectURI := req.URL.Query().Get("returnTo")
	http.Redirect(w, req, redirectURI, http.StatusFound)
}

func (srv *authServer) userinfo(w http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer") {
		http.Error(w, "Missing authentication header", http.StatusBadRequest)
		return
	}

	token, err := jwt.ParseSigned(authHeader[len("Bearer")+1:])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var claims jwt.Claims
	if err := token.Claims(&srv.key.PublicKey, &claims); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	session, ok := srv.getSessionState(claims.Subject)
	if !ok {
		http.Error(w, "Unknown subject", http.StatusExpectationFailed)
		return
	}

	userinfo := struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified bool   `json:"email_verified"`
	}{
		Subject:       claims.Subject,
		Email:         session.email,
		Name:          session.name,
		EmailVerified: session.isValidated,
	}

	response, err := json.Marshal(userinfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.Write(response)
}

func (srv *authServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Info().
		Str("method", req.Method).
		Str("path", req.URL.Path).
		Msg("HTTP request")

	switch req.URL.Path {
	case "/authorize":
		srv.authorize(w, req)
	case "/login":
		srv.login(w, req)
	case "/v2/logout":
		srv.logout(w, req)
	case "/oauth/token":
		srv.authToken(w, req)
	case "/userinfo":
		srv.userinfo(w, req)
	case "/.well-known/jwks.json":
		serveJWKS(w, req, srv.key)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
