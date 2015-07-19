package authenticator

import "code.google.com/p/goauth2/oauth"

// Provider is a oauth2 provider, like facebook or google
// Name is the provider name, the package use it as a index.
// Key is the oauth2 key, normally called ACCESS_KEY
// Secret is the oauth2 secret key, normally called ACCESS_SECRET
// RedirectURL is a URL configured in provider
// TokenURL is a URL to get the token on provider
// AuthURL is a URL to auth user on provider
// UserInfoURL is a URL to get User Information on provider
// Scope is whats the scope your app wants
type Provider struct {
	Name        string
	Key         string
	Secret      string
	RedirectURL string
	TokenURL    string
	AuthURL     string
	UserInfoURL string
	Scope       string
}

// Default Provider to works with email/password sing in
var EmailPasswordProvider = Provider{
	Name: "emailpassword",
}

// Internal auth config builder
type builderConfig struct {
	Auth        *oauth.Config
	UserInfoURL string
}

// Add many Providers to auth
func (b *Auth) NewProviders(providers []Provider) {
	for _, p := range providers {
		b.NewProvider(p)
	}
}

// Add a Providers to auth
func (a *Auth) NewProvider(p Provider) {
	config := &oauth.Config{
		ClientId:     p.Key,
		ClientSecret: p.Secret,
		RedirectURL:  p.RedirectURL,
		Scope:        p.Scope,
		AuthURL:      p.AuthURL,
		TokenURL:     p.TokenURL,
	}

	provider := new(builderConfig)
	provider.Auth = config
	provider.UserInfoURL = p.UserInfoURL

	a.Providers[p.Name] = provider
}
