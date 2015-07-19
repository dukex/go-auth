package auth

import (
	"encoding/json"
	"net/http"
)

type emailPasswordParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// HTTP server

// Authorize is a middleware to authorize user in a defined provider.
// Send provider name as params and the return is a http handle
//
//
//	GET   /auth/google     auth.Authorize("google")
//	GET   /auth/facebook   auth.Authorize("facebook")
//	POST  /sign_in         auth.Authorize("email")
//
func (a *Auth) Authorize(providerName string) http.HandlerFunc {
	provider := a.Providers[providerName]
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case provider == nil:
			w.WriteHeader(404)
			w.Write([]byte("Provider '" + providerName + "' not found"))
			return
		case providerName == EmailPasswordProvider.Name:
			if r.Method == "GET" {
				w.WriteHeader(404)
			} else {
				a.SignIn(w, r)
			}
			return
		}
		a.oauthAuthorize(provider, w, r)
	}
}

func (a *Auth) oauthAuthorize(provider *builderConfig, w http.ResponseWriter, r *http.Request) {
	url := provider.Auth.AuthCodeURL("")
	http.Redirect(w, r, url, http.StatusFound)
}

// HTTP Handler to sign in users is expected email and password in request body as JSON
//
//	{"email": "myemail@domain.com", "password": "abc123"}
func (a *Auth) SignIn(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var params emailPasswordParams
	decoder.Decode(&params) // TODO: test error here

	foundPassword, wasFound := a.Helper.PasswordByEmail(params.Email)
	if !wasFound {
		w.WriteHeader(http.StatusForbidden)
	}

	err := checkHash(foundPassword, params.Password)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
	} else {
		user, _ := a.Helper.FindUserDataByEmail(params.Email)
		w.Write([]byte(user))
	}
}
