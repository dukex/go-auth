package auth

import . "gopkg.in/check.v1"

type UserSuite struct{}

var _ = Suite(&UserSuite{})

func (s *UserSuite) TestNewUserToken(c *C) {
	token := NewUserToken()
	c.Assert(token, NotNil)
	c.Assert(NewUserToken(), Not(Equals), token)
}
