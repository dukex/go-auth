package auth

import oauth "golang.org/x/oauth2"

// Provider is a oauth2 provider, like facebook or google
// 	Name is the provider name, the package use it as a index.
// 	Key is the oauth2 key, normally called ACCESS_KEY
// 	Secret is the oauth2 secret key, normally called ACCESS_SECRET
// 	RedirectURL is a URL configured in provider
// 	TokenURL is a URL to get the token on provider
// 	AuthURL is a URL to auth user on provider
// 	UserInfoURL is a URL to get User Information on provider
// 	Scope is whats the scope your app wants
type Provider struct {
	Name        string
	Key         string
	Secret      string
	RedirectURL string
	TokenURL    string
	AuthURL     string
	UserInfoURL string
	Scopes      []string
}

// Email/Password default provider
var EmailPasswordProvider = Provider{
	Name: "emailpassword",
}

// Internal auth config builder
type builderConfig struct {
	Auth        *oauth.Config
	UserInfoURL string
}

func (b *Auth) NewProviders(providers []Provider) {
	for _, p := range providers {
		b.NewProvider(p)
	}
}

func (a *Auth) NewProvider(p Provider) {
	config := &oauth.Config{
		ClientID:     p.Key,
		ClientSecret: p.Secret,
		RedirectURL:  p.RedirectURL,
		Scopes:       p.Scopes,
		Endpoint: oauth.Endpoint{
			AuthURL:  p.AuthURL,
			TokenURL: p.TokenURL,
		},
	}

	provider := new(builderConfig)
	provider.Auth = config
	provider.UserInfoURL = p.UserInfoURL

	a.Providers[p.Name] = provider
}
