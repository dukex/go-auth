package auth

import (
	"encoding/json"
	"net/http"

	oauth "golang.org/x/oauth2"
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

	if params.Email == "" || params.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	foundPassword, wasFound := a.Helper.PasswordByEmail(params.Email)
	if !wasFound {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := checkHash(foundPassword, params.Password)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	user, ok := a.Helper.FindUserDataByEmail(params.Email)

	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(user))
}

// The oauth endpoint callback, configured on provider, Send provider name as params
// OAuthCallback will receive code params from provider and get user information
//
//	```
//	GET   /auth/google/callback     http.HandlerFunc -> auth.OAuthCallback("google", w, r)

//	GET   /auth/facebook/callback   http.HandlerFunc -> auth.OAuthCallback("facebook", w, r)
//	```
func (a *Auth) OAuthCallback(providerName string, w http.ResponseWriter, r *http.Request) (string, error) {
	return a.oAuthUser(providerName, w, r)
}

func (a *Auth) oAuthUser(providerName string, w http.ResponseWriter, r *http.Request) (userID string, err error) {
	code := r.FormValue("code")
	provider := a.Providers[providerName]
	token, err := provider.Auth.Exchange(oauth.NoContext, code)
	if err != nil {
		return
	}
	client := provider.Auth.Client(oauth.NoContext, token)
	response, err := client.Get(provider.UserInfoURL)
	if err != nil {
		return
	}
	defer response.Body.Close()

	var user User
	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&user)
	// user.Token = NewUserToken()
	if err != nil {
		return
	}
	return a.Helper.FindUserFromOAuth(providerName, &user, response)
}
