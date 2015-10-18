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
