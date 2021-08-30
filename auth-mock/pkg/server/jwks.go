package server

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

func serveJWKS(w http.ResponseWriter, req *http.Request, key *rsa.PrivateKey) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	pub := &key.PublicKey
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub, KeyID: "authKey", Algorithm: "RS256", Use: "sig"}},
	}
	encoded, err := json.Marshal(jwks)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-type", "application/json")
	w.Write(encoded)
}
