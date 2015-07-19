// This auth provides sign in and sign up by oauth2 and email/password.
// Inspired in omniauth and devise gem
package auth

import (
	"os"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

// Auth is the Authentication config, this store providers and UserHelper interface
type Auth struct {
	Providers map[string]*builderConfig
	Helper    UserHelper
}

func NewAuth() *Auth {
	auth := new(Auth)
	auth.Providers = make(map[string]*builderConfig, 0)
	return auth
}

//
// // SignUp Hanlder to sign up user, send a http POST with email and password params on body
// //
// //	```
// //	POST   /users/sign_up   SignUp
// //	```
// func (b *Builder) SignUp() func(http.ResponseWriter, *http.Request) {
// 	return func(w http.ResponseWriter, request *http.Request) {
// 		email := request.FormValue("email")
// 		password := request.FormValue("password")
// 		hpassword, err := generateHash(password)
// 		if err != nil {
// 			http.Redirect(w, request, b.URLS.SignUp+"?password=error", http.StatusTemporaryRedirect)
// 			return
// 		}
//
// 		userID, err := b.UserCreateFn(email, hpassword, NewUserToken(), request)
// 		if err != nil {
// 			http.Redirect(w, request, b.URLS.SignIn+"?user=exists", http.StatusTemporaryRedirect)
// 		} else {
// 			b.login(request, w, strconv.FormatInt(userID, 10))
// 		}
// 	}
// }
//
// // SignIn Handler to sign in user, send a http POST with email and password params on body
// //
// //	```
// //	POST   /users/sign_in   SignIn
// //	```
// func (b *Builder) SignIn() func(http.ResponseWriter, *http.Request) {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		email := r.FormValue("email")
// 		password := r.FormValue("password")
// 		userPassword, ok := b.UserPasswordByEmail(email)
//
// 		if !ok {
// 			http.Redirect(w, r, b.URLS.SignIn+"?user=not_found", http.StatusTemporaryRedirect)
// 		}
//
// 		err := checkHash(userPassword, password)
// 		if err != nil {
// 			http.Redirect(w, r, b.URLS.SignIn+"?user=no_match", http.StatusTemporaryRedirect)
// 		} else {
// 			userId, _ := b.UserIdByEmail(email)
// 			b.login(r, w, strconv.FormatInt(userId, 10))
// 		}
// 	}
// }
//
// // SignOut Handler Method to sign out user, send a http GET
// //
// //	```
// //	GET   /users/sign_out   SignOut
// //	```
// func (b *Builder) SignOut() func(http.ResponseWriter, *http.Request) {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		session := b.Logout(r)
// 		session.Save(r, w)
//
// 		http.Redirect(w, r, b.URLS.SignIn, http.StatusTemporaryRedirect)
// 	}
// }
//
// // Protected to be used on protected path, send the original http handle as params and if user is logged Protected will pass user to original handler else Protected will save URL and send user to Sign In. Protected send as first params the user id.
// //
// //	```
// //	GET   /dashboard   Protected(DashboardHandle)
// //	```
// func (b *Builder) Protected(fn func(string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		userID, ok := b.CurrentUser(r)
// 		if ok {
// 			fn(userID, w, r)
// 		} else {
// 			b.SetReturnTo(w, r, r.URL.String())
// 			http.Redirect(w, r, b.URLS.SignIn, http.StatusTemporaryRedirect)
// 		}
// 	}
// }
//
// func (b *Builder) SetReturnTo(w http.ResponseWriter, r *http.Request, url string) {
// 	session, _ := store.Get(r, "_session")
// 	session.Values["return_to"] = url
// 	session.Save(r, w)
// }
//
// func (b *Builder) ResetPassword() func(http.ResponseWriter, *http.Request) {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		email := r.FormValue("email")
// 		token := NewUserToken()
// 		go b.UserResetPasswordFn(token, email)
// 		http.Redirect(w, r, b.URLS.ResetPasswordSuccess, http.StatusTemporaryRedirect)
// 	}
// }
//
// func (b *Builder) Login(r *http.Request, userId string) *sessions.Session {
// 	session, _ := store.Get(r, "_session")
// 	session.Values["user_id"] = userId
// 	return session
// }
//
// func (b *Builder) Logout(r *http.Request) *sessions.Session {
// 	session, _ := store.Get(r, "_session")
// 	session.Values["user_id"] = nil
// 	return session
// }
//
// // helper
//
// func (b *Builder) login(r *http.Request, w http.ResponseWriter, userId string) {
// 	session := b.Login(r, userId)
//
// 	var returnTo string
// 	returnToSession := session.Values["return_to"]
// 	returnTo, ok := returnToSession.(string)
// 	if !ok {
// 		returnTo = b.URLS.Redirect
// 	}
//
// 	go b.LoginFn(userId)
//
// 	session.Values["return_to"] = nil
// 	session.Save(r, w)
// 	http.Redirect(w, r, returnTo, 302)
// }
//
// // CurrentUser func expect you send the request(```http.Request```) and return the user id as string and bool true if is OK
// func (b *Builder) CurrentUser(r *http.Request) (id string, ok bool) {
// 	session, _ := store.Get(r, "_session")
// 	userId := session.Values["user_id"]
// 	id, ok = userId.(string)
// 	if !ok {
// 		id, ok = b.getUserIdByAuthorizationToken(r)
// 	}
// 	return
// }
//
// func (b *Builder) getUserIdByAuthorizationToken(r *http.Request) (id string, ok bool) {
// 	tokenAuthorization := strings.Split(r.Header.Get("Authorization"), " ")
// 	if len(tokenAuthorization) == 2 {
// 		var _id int64
// 		_id, ok = b.UserIdByToken(tokenAuthorization[1])
// 		id = strconv.Itoa(int(_id))
// 		return
// 	}// 	return
// }
//

//
// func generateRandomToken() int64 {
// 	rand.Seed(time.Now().Unix())
// 	return rand.Int63()
// }
//
// func NewUserToken() string {
// 	hash, _ := generateHash(strconv.Itoa(int(generateRandomToken())))
// 	return base64.URLEncoding.EncodeToString([]byte(hash))
// }

// // URLS
//
// type URLS struct {
// 	Redirect             string
// 	SignIn               string
// 	SignUp               string
// 	ResetPasswordSuccess string
// }

//
//type User struct {
// 	Id      string
// 	Email   string
// 	Link    string
// 	Name    string
// 	Gender  string
// 	Locale  string
// 	Picture string
// 	Token   string
//}
