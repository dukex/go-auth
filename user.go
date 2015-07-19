package auth

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
	//Setup(provider string, user *User, rawResponde *http.Response) (int64, error)
	//Create(email string, password string, token string, request *http.Request) (int64, error)
	//ResetPassword(token string, email string)
	//FindByEmail(email string) (int64, bool)
	//FindByToken(token string) (int64, bool)
	//Login(userId int64)
}
