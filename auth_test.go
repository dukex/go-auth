package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type AuthSuite struct{}

var _ = Suite(&AuthSuite{})

func (s *AuthSuite) TestNewAuth(c *C) {
	providers := []Provider{Provider{Name: "Duke", Key: "CsE34", Secret: "Aeee", Scopes: []string{"email"}, RedirectURL: "/d"}}

	auth := NewAuth()
	auth.NewProviders(providers)

	client := *auth.Providers["Duke"]

	c.Assert(client.Auth.ClientID, Equals, providers[0].Key)
}

func (s *AuthSuite) TestAuthorizerOAuthRedirect(c *C) {
	provider := Provider{Name: "facebook", Key: "CsE34", Secret: "Aeee", Scopes: []string{"email"}, RedirectURL: "/d"}
	providerRedirectTo := "/?client_id=CsE34&redirect_uri=%2Fd&response_type=code&scope=email"

	auth := NewAuth()
	auth.NewProvider(provider)

	r := httpTest(auth.Authorize("facebook"), "GET", nil, "")
	c.Assert(r.Header().Get("Location"), Equals, providerRedirectTo)
}

func (s *AuthSuite) TestNotFoundAuthorizerConfigured(c *C) {
	auth := NewAuth()

	r := httpTest(auth.Authorize("facebook"), "GET", nil, "")

	c.Assert(r.Code, Equals, http.StatusNotFound)
	c.Assert(r.Body.String(), Equals, "Provider 'facebook' not found")
}

func (s *AuthSuite) TestAuthorizerEmailPasswordProvider(c *C) {
	auth := NewAuth()
	auth.NewProvider(EmailPasswordProvider)
	r := httpTest(auth.Authorize(EmailPasswordProvider.Name), "GET", nil, "")
	c.Assert(r.Code, Equals, http.StatusNotFound)
}

func (s *AuthSuite) TestAuthorizerEmailPasswordProviderNotFoundUser(c *C) {
	h := mockUserHelper()
	auth := NewAuth()
	auth.NewProvider(EmailPasswordProvider)
	auth.Helper = h
	h.On("PasswordByEmail", "duke@br.com").Return("", false)
	var authData = []byte(`{"email":"duke@br.com", "password":"abc123"}`)
	r := httpTest(auth.Authorize(EmailPasswordProvider.Name), "POST", bytes.NewBuffer(authData), "")
	c.Assert(r.Code, Equals, http.StatusForbidden)
	h.AssertExpectations(c)
}

func (s *AuthSuite) TestAuthorizerEmailPasswordProviderPasswordDontMatch(c *C) {
	h := mockUserHelper()
	auth := NewAuth()
	auth.NewProvider(EmailPasswordProvider)
	auth.Helper = h
	h.On("PasswordByEmail", "duke@br.com").Return("x", true)
	var authData = []byte(`{"email":"duke@br.com", "password":"abc123"}`)
	r := httpTest(auth.Authorize(EmailPasswordProvider.Name), "POST", bytes.NewBuffer(authData), "")
	c.Assert(r.Code, Equals, http.StatusForbidden)
	h.AssertExpectations(c)
}

func (s *AuthSuite) TestAuthorizerEmailPasswordProviderSignInAndReturnsUser(c *C) {
	h := mockUserHelper()
	auth := NewAuth()
	auth.NewProvider(EmailPasswordProvider)
	auth.Helper = h

	password := "abc123"
	hashed, _ := GenerateHash(password)
	h.On("PasswordByEmail", "duke@br.com").Return(hashed, true)
	h.On("FindUserDataByEmail", "duke@br.com").Return("{user}", true)
	var authData = []byte("{\"email\":\"duke@br.com\", \"password\":\"" + password + "\"}")
	r := httpTest(auth.Authorize(EmailPasswordProvider.Name), "POST", bytes.NewBuffer(authData), "")
	c.Assert(r.Code, Equals, http.StatusOK)
	c.Assert(r.Body.String(), Equals, "{user}")
	h.AssertExpectations(c)
}

func (s *AuthSuite) TestOAuthCallbackWithoutCode(c *C) {
	// provider := Provider{Name: "facebook", Key: "CsE34", Secret: "Aeee", Scope: "email"}

	// auth := NewAuth()
	// auth.NewProvider(provider)

	// r := httpTest(auth.OAuthCallback("facebook"), "POST", nil, "application/x-www-form-urlencoded")
	// c.Assert(r.Code, Equals, http.StatusBadRequest)
}

func (s *AuthSuite) TestOAuthCallback(c *C) {
	oauthServer := mockHTTP(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if r.URL.String() == "/token" {
			w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
		} else {
			w.Write([]byte(`{"name": "Test"}`))
		}
	})

	h := mockUserHelper()

	provider := Provider{Name: "facebook", UserInfoURL: oauthServer.URL, TokenURL: oauthServer.URL + "/token"}
	auth := NewAuth()
	auth.NewProvider(provider)
	auth.Helper = h

	data := url.Values{}
	data.Set("code", "123")

	h.On("FindUserFromOAuth", "facebook", mock.AnythingOfType("*auth.User"), mock.AnythingOfType("*http.Response")).Return("e3123", nil)
	handle := func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.OAuthCallback("facebook", w, r)
		c.Assert(id, Equals, "e3123")
		c.Assert(err, Not(NotNil))
	}

	r := httpTest(handle, "POST", strings.NewReader(data.Encode()), "application/x-www-form-urlencoded")
	c.Assert(r.Code, Equals, http.StatusOK)
}

func (s *AuthSuite) TestCurrentUserHTTPToken(c *C) {
	h := mockUserHelper()
	auth := NewAuth()
	auth.Helper = h

	token := "Th3us3rTok3n"

	h.On("FindUserByToken", token).Return("id1234", true)

	handle := func() http.HandlerFunc { return func(w http.ResponseWriter, r *http.Request) {} }()
	r, _ := http.NewRequest("GET", "", nil)
	r.Header.Add("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handle.ServeHTTP(w, r)

	user, ok := auth.CurrentUser(r)
	c.Assert(ok, Equals, true)
	c.Assert(user, Equals, "id1234")
}

func (s *AuthSuite) TestCurrentUserHTTPNotToken(c *C) {
	h := mockUserHelper()
	auth := NewAuth()
	auth.Helper = h

	handle := func() http.HandlerFunc { return func(w http.ResponseWriter, r *http.Request) {} }()
	r, _ := http.NewRequest("GET", "", nil)
	w := httptest.NewRecorder()
	handle.ServeHTTP(w, r)

	user, ok := auth.CurrentUser(r)
	c.Assert(ok, Equals, false)
	c.Assert(user, Equals, "")
}

//
// func TestGetUserIdByAuthorizationToken(t *testing.T) {
// 	r := new(http.Request)
// 	r.Header = make(http.Header, 0)
//
// 	builder := NewAuth()
// 	builder.UserIdByToken = func(token string) (int64, bool) {
// 		if token == "x" {
// 			return 5, true
// 		}
// 		return 0, false
// 	}
//
// 	_, ok := builder.getUserIdByAuthorizationToken(r)
// 	if ok {
// 		t.Errorf("Expected ok is false when no have header")
// 	}
//
// 	r.Header.Add("Authorization", "Token z")
// 	_, ok = builder.getUserIdByAuthorizationToken(r)
// 	if ok {
// 		t.Errorf("Expected ok is false when UserIdByToken returns false")
// 	}
//
// 	r.Header.Del("Authorization")
// 	r.Header.Add("Authorization", "Token x")
// 	id, ok := builder.getUserIdByAuthorizationToken(r)
// 	if !ok || id != "5" {
// 		t.Errorf("Expected ok is true and id is 5 but returns %s and %s", ok, id)
// 	}
//
// }
