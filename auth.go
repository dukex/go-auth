// This auth provides sign in and sign up by oauth2 and email/password.
// Inspired in omniauth and devise gem
package auth

// var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

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

// // Protected to be used on protected path, send the original http handle as params and if user is logged Protected will pass user to original handler else Protected will save URL and send user to Sign In. Protected send as first params the user id.
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
