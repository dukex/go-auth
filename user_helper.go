package authenticator

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

// Follow the iser helper documentation:
//
//	UserSetupFn         func(provider string, user *login2.User, rawResponse *http.Response) (int64, error)
//
// Called when user return from oauth provider, this method will send a provider
// origin as string, some user information as ```login2.User``` and the raw
// response from origin(login2 will make a request to ``` UserInfoURL```
// configured on provider config). To sign in user the method expect the user
// id as int64
//
//
//	UserCreateFn        func(email string, password string, token string, request *http.Request) (int64, error)
//
// Called when user sign up by email/password, the method will send email and password as string, password // is encrypted hash, and expect the user id as int64
//
//	UserIdByEmail       func(email string) (int64, error)
//
// Called when user sign in by email/password to get the user id by email after check the password with ```UserPasswordByEmail```, the method will send the user email as string and expect the user id as int64
//
