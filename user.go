package auth

import (
	"encoding/base64"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

// UserHelper interface has some important method to auth works
//
// PasswordByEmail func(email string) (string, bool)
//
// Called when user sign in by email/password to get user password and check with inputed password, the method will send user email as string and expect the user password as string
//
//
// FindUserDataByEmail func(email string) (string, bool)
//
// Should returns a user data in string format(json/xml)
// Will be use to SignIn handler after user SignIn
type UserHelper interface {
	PasswordByEmail(email string) (string, bool)
	FindUserDataByEmail(email string) (string, bool)
	FindUserByToken(token string) (string, bool)
	FindUserFromOAuth(provider string, user *User, rawResponse *http.Response) (string, error)
}

// CurrentUser func expect you send the request(```http.Request```) and return the user id as string and bool true if is OK
func (a *Auth) CurrentUser(r *http.Request) (id string, ok bool) {
	tokenAuthorization := strings.Split(r.Header.Get("Authorization"), " ")
	if len(tokenAuthorization) == 2 {
		id, ok = a.Helper.FindUserByToken(tokenAuthorization[1])
	} else {
		session, _ := store.Get(r, "_session")
		id, ok = session.Values["user_id"].(string)
	}
	return
}

func generateRandomToken() int64 {
	rand.Seed(time.Now().Unix())
	return rand.Int63()
}

func NewUserToken() string {
	hash, _ := GenerateHash(strconv.Itoa(int(generateRandomToken())))
	return base64.URLEncoding.EncodeToString([]byte(hash))
}

func (a *Auth) Login(r *http.Request, userId string) *sessions.Session {
	session, _ := store.Get(r, "_session")
	session.Values["user_id"] = userId
	return session
}

func (a *Auth) Logout(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "_session")
	session.Values["user_id"] = ""
	return session
}

type User struct {
	Id      string
	Email   string
	Link    string
	Name    string
	Gender  string
	Locale  string
	Picture string
	Token   string
}
