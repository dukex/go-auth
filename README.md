# Go Auth

Easy way to sign in and sign up users using oauth and email/password

See [Doc](http://godoc.org/github.com/dukex/go-auth)

The master version is a Work in Progress, use v1 instead
``` sh
$ go get gopkg.in/dukex/go-auth.v1
```

``` go
import authenticator "gopkg.in/dukex/go-auth.v1"
```

``` go
loginBuilder := authenticator.NewBuilder()
```

## Config

To config your oauth provider use ```NewProvider``` func

``` go
provider := &authenticator.Provider{
  RedirectURL: os.Getenv("GOOGLE_CALLBACK_URL"),
  AuthURL:     "https://accounts.google.com/o/oauth2/auth",
  TokenURL:    "https://accounts.google.com/o/oauth2/token",
  Name:        "google",
  Key:         os.Getenv("GOOGLE_CLIENT_ID"),
  Secret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
  Scope:       "https://www.googleapis.com/auth/userinfo.email",
  UserInfoURL: "https://www.googleapis.com/oauth2/v1/userinfo?alt=json",
}

loginBuilder.NewProvider(provider)
```

The func ```NewProviders``` accept a ```Provider``` array


``` go
providers := make([]*authenticator.Provider, 0)

providers = append(providers, &authenticator.Provider{
  RedirectURL: os.Getenv("GOOGLE_CALLBACK_URL"),
  AuthURL:     "https://accounts.google.com/o/oauth2/auth",
  TokenURL:    "https://accounts.google.com/o/oauth2/token",
  Name:        "google",
  Key:         os.Getenv("GOOGLE_CLIENT_ID"),
  Secret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
  Scope:       "https://www.googleapis.com/auth/userinfo.email",
  UserInfoURL: "https://www.googleapis.com/oauth2/v1/userinfo?alt=json",
})

loginBuilder.NewProviders(providers)

```

Login2 works with callback to be a agnostic way to sign in and sign up users, ```login2.Builder``` accept 4 callbacks

```  go
loginBuilder.UserSetupFn = func(provider string, user *auth.User, rawResponde *http.Response) (int64, error)  {
}

loginBuilder.UserCreateFn = func(email string, password string, request *http.Request) (int64, error) {
}

loginBuilder.UserIdByEmail = func(email string) (int64, error) {
}

loginBuilder.UserPasswordByEmail = func(email string) (string, error) {
}

loginBuilder.UserResetPasswordFn = func(token string, email string) {
}
```


To http handlers works you need config your URLs, login2 has URL type:

``` go
type URLS struct {
  Redirect                string
  SignIn                  string
  SignUp                  string
  ResetPasswordSuccess    string
}
```

And ```Builder``` has URLS field

``` go
loginBuilder.URLS = authenticator.URLS{
  Redirect: "/dashbaord",
  SignIn:    "/login",
  SignUp:  "/register",
  ResetPasswordSuccess: "/reset_password_success"
}
```
After your sign or sign up login2 will send user to ```Redirect``` url.

When login2 need sign in user, e.g User trying access protected path, login2 will send user to ```SignIn``` url.

When login2 need send up user, login2 will send user to ```SignUp``` url.

TODO: ResetPasswordSuccess
