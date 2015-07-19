package auth

import (
	"encoding/json"
	"log"
	"net/http"

	"code.google.com/p/goauth2/oauth"
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

// The oauth endpoint callback, configured on provider, Send provider name as params and method will return http handle
//
//	```
//	GET   /auth/callback/google     auth.OAuthCallback("google")
//	GET   /auth/callback/facebook   auth.OAuthCallback("facebook")
//	```
func (a *Auth) OAuthCallback(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// userId, err := a.oAuthUser(providerName, request)
		a.oAuthUser(providerName, w, r)
		//if err != nil {
		//http.Redirect(w, request, b.URLS.SignIn, http.StatusTemporaryRedirect)
		//} else {
		//b.login(request, w, strconv.FormatInt(userId, 10))
		//}
	}
}

// OAuthCallback receive code params from provider and get user information
func (a *Auth) oAuthUser(providerName string, w http.ResponseWriter, r *http.Request) {
	provider := a.Providers[providerName]
	code := r.FormValue("code")
	t := &oauth.Transport{Config: provider.Auth}

	token, errx := t.Exchange(code)
	log.Println(t.Token)
	log.Println(t.TokenCache)
	log.Println("TOKEN", code, token, errx)

	// response, err := t.Client().Get(provider.UserInfoURL)
	//if err != nil {
	//	log.Println(err)

	//	w.WriteHeader(http.StatusBadRequest)
	//	return
	//}
	//defer response.Body.Close()

	//log.Println(ioutil.ReadAll(response.Body))
	//
	// 	var user User
	// 	decoder := json.NewDecoder(responseAuth.Body)
	// 	user.Token = NewUserToken()
	// 	err := decoder.Decode(&user)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	//
	// 	return b.UserSetupFn(provider, &user, responseAuth)
}
