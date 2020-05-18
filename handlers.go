package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"

	kiteconnect "github.com/zerodhatech/gokiteconnect"
)

const (
	ssoRedirectURI = "/session/sso_login"
)

// handleAuthInit initializes a Kite Connect login.
func handleAuthInit(w http.ResponseWriter, r *http.Request) {
	var (
		app = r.Context().Value("app").(*App)
		kc  = kiteconnect.New(app.APIKey)

		payload = r.URL.Query().Get("sso")
		hexSig  = r.URL.Query().Get("sig")
	)

	// Missing Discourse params.
	if payload == "" || hexSig == "" {
		sendResp("Invalid params.", http.StatusBadRequest, w)
		return
	}

	// Validate the HMAC.
	if !validateHMAC([]byte(payload), app.SSOSecret, hexSig) {
		sendResp(fmt.Sprintf("Invalid or expired request."),
			http.StatusForbidden, w)
		return
	}

	// Base64 decode the payload query params.
	params, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		sendResp(fmt.Sprintf("Error decoding payload: %v", err),
			http.StatusBadRequest, w)
		return
	}

	// Parse the params and get the nonce out.
	qParams, err := url.ParseQuery(string(params))
	if err != nil {
		sendResp(fmt.Sprintf("Error parsing payload query params: %v", err),
			http.StatusBadRequest, w)
		return
	}
	nonce := qParams.Get("nonce")

	// Construct redirect_params for Kite Connect.
	redirParams := url.Values{}
	redirParams.Set("nonce", nonce)

	// Add redirect_params to the Kite Connect login URL.
	u, _ := url.Parse(kc.GetLoginURL())
	outQp := u.Query()
	outQp.Set("redirect_params", redirParams.Encode())
	u.RawQuery = outQp.Encode()

	// Redirect to the Kite Connect login page.
	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

// handleAuthFinish takes the request_token from the Kite Connect redirect,
// validates it, and hands over the session to Discourse.
func handleAuthFinish(w http.ResponseWriter, r *http.Request) {
	var (
		app = r.Context().Value("app").(*App)
		kc  = kiteconnect.New(app.APIKey)

		status   = r.URL.Query().Get("status")
		reqToken = r.URL.Query().Get("request_token")
		nonce    = r.URL.Query().Get("nonce")
	)

	// Auth didn't happen. Redirect back.
	if status != "success" {
		sendResp("Auth failed or was cancelled.", http.StatusBadRequest, w)
		return
	}
	if len(reqToken) == 0 || len(nonce) == 0 {
		sendResp("Invalid auth params.", http.StatusBadRequest, w)
		return
	}

	// Create Kite session.
	user, err := kc.GenerateSession(reqToken, app.APISecret)
	if err != nil {
		sendResp(fmt.Sprintf("Error getting Kite session: %v. Retry.", err), http.StatusBadRequest, w)
		return
	}

	// Prepare the values to send to Discourse.
	out := url.Values{}
	out.Set("nonce", nonce)
	out.Set("email", user.Email)
	out.Set("external_id", user.UserID)
	out.Set("name", user.UserShortName)
	out.Set("avatar_url", user.AvatarURL)

	// Encode the outgoing payload and compute it's HMAC.
	outB := base64.StdEncoding.EncodeToString([]byte(out.Encode()))
	outHMAC := computeHMAC([]byte(outB), app.SSOSecret)

	// Redirect back to Discourse.
	u, _ := url.Parse(app.SSORootURL + ssoRedirectURI)
	q := u.Query()
	q.Add("sso", string(outB))
	q.Add("sig", string(outHMAC))
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

func wrap(next http.HandlerFunc, app *App) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), interface{}("app"), app)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateHMAC validates a messageagainst a hex encoded HMAC-256.
func validateHMAC(raw []byte, key []byte, hexSig string) bool {
	// Decode the hex encoded HMAC.
	sig, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(sig, expectedMAC)
}

// computeHMAC computes the and returns the hex encoded HMAC-SHA256 of a string.
func computeHMAC(msg, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return hex.EncodeToString(h.Sum(nil))
}

// sendResp sends a JSON error envelope to the HTTP response.
func sendResp(message string, status int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(message))
}
