package login2

import (
	"encoding/json"
	"fmt"
	"net/http"

	"code.google.com/p/goauth2/oauth"
	"github.com/gorilla/mux"
)

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

type BuilderConfig struct {
	Auth        *oauth.Config
	UserInfoURL string
}

type Builder struct {
	Providers map[string]*BuilderConfig
}

type User struct {
	Email string
}

func NewBuilder(userProviders []*Provider) *Builder {
	builder := new(Builder)
	builder.Providers = make(map[string]*BuilderConfig, 0)

	for _, p := range userProviders {
		config := &oauth.Config{
			ClientId:     p.Key,
			ClientSecret: p.Secret,
			RedirectURL:  p.RedirectURL,
			Scope:        p.Scope,
			AuthURL:      p.AuthURL,
			TokenURL:     p.TokenURL,
			TokenCache:   oauth.CacheFile("cache-" + p.Name + ".json"),
		}

		provider := new(BuilderConfig)
		provider.Auth = config
		provider.UserInfoURL = p.UserInfoURL

		builder.Providers[p.Name] = provider
	}

	return builder
}

func (b *Builder) Router(r *mux.Router) {
	for provider, _ := range b.Providers {
		r.HandleFunc("/auth/"+provider, b.Authorize(provider))

		r.HandleFunc("/auth/callback/{provider}", func(w http.ResponseWriter, request *http.Request) {
			vars := mux.Vars(request)
			provider := vars["provider"]

			user := b.Callback(provider, request)
			fmt.Println(provider, user)
		})
	}

}
func (b *Builder) Authorize(provider string) func(w http.ResponseWriter, r *http.Request) {
	config := b.Providers[provider]

	return func(w http.ResponseWriter, r *http.Request) {
		url := config.Auth.AuthCodeURL("")
		http.Redirect(w, r, url, http.StatusFound)
	}
}

func (b *Builder) Callback(provider string, r *http.Request) User {
	config := b.Providers[provider]
	code := r.FormValue("code")
	t := &oauth.Transport{Config: config.Auth}
	t.Exchange(code)
	responseAuth, _ := t.Client().Get(config.UserInfoURL)
	defer responseAuth.Body.Close()

	var user User
	decoder := json.NewDecoder(responseAuth.Body)
	err := decoder.Decode(&user)
	if err != nil {
		panic(err)
	}
	return user
}
