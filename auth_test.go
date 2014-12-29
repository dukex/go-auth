package login2

import (
	"testing"

	"net/http"
)

func TestNewBuilder(t *testing.T) {
	providers := []*Provider{&Provider{Name: "Duke", Key: "CsE34", Secret: "Aeee", Scope: "email", RedirectURL: "/d"}}
	builder := NewBuilder()
	builder.NewProviders(providers)

	expected := "CsE34"

	client := *builder.Providers["Duke"]
	current := client.Auth.ClientId

	if current != expected {
		t.Errorf("Expected [%s] but [%s]", expected, current)
	}
}

func TestGetUserIdByAuthorizationToken(t *testing.T) {
	r := new(http.Request)
	r.Header = make(http.Header, 0)

	builder := NewBuilder()
	builder.UserIdByToken = func(token string) (int64, bool) {
		if token == "x" {
			return 5, true
		}
		return 0, false
	}

	_, ok := builder.getUserIdByAuthorizationToken(r)
	if ok {
		t.Errorf("Expected ok is false when no have header")
	}

	r.Header.Add("Authorization", "Token z")
	_, ok = builder.getUserIdByAuthorizationToken(r)
	if ok {
		t.Errorf("Expected ok is false when UserIdByToken returns false")
	}

	r.Header.Del("Authorization")
	r.Header.Add("Authorization", "Token x")
	id, ok := builder.getUserIdByAuthorizationToken(r)
	if !ok || id != "5" {
		t.Errorf("Expected ok is true and id is 5 but returns %s and %s", ok, id)
	}

}
