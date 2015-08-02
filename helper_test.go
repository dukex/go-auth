package auth

import (
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/stretchr/testify/mock"
)

func httpTest(handle http.HandlerFunc, method string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	r, _ := http.NewRequest(method, "", body)
	r.Header.Add("Content-Type", contentType)
	w := httptest.NewRecorder()
	handle.ServeHTTP(w, r)
	return w
}

type userHelper struct {
	mock.Mock
}

func (h *userHelper) PasswordByEmail(email string) (string, bool) {
	args := h.Called(email)
	return args.String(0), args.Bool(1)
}

func (h *userHelper) FindUserDataByEmail(email string) (string, bool) {
	args := h.Called(email)
	return args.String(0), args.Bool(1)
}

func (h *userHelper) FindUserByToken(token string) (string, bool) {
	args := h.Called(token)
	return args.String(0), args.Bool(1)
}

func (h *userHelper) FindUserFromOAuth(provider string, user *User, r *http.Response) (string, error) {
	args := h.Called(provider, user, r)
	return args.String(0), args.Error(1)
}

func mockUserHelper() *userHelper {
	return new(userHelper)
}

func mockHTTP(handler http.HandlerFunc) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(handler))
	return server
}
