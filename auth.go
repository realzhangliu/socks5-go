package socks5

type Socks5Auth interface {
	Authenticate(...interface{}) bool
}

type defAuth struct {
	userInfo map[string]string
}

func (s *defAuth) Authenticate(b ...interface{}) bool {
	if s.userInfo == nil {
		return true
	}
	if len(b) != 2 {
		return false
	}
	user, ok := b[0].(string)
	if !ok {
		return false
	}
	pwd, ok := b[1].(string)
	if !ok {
		return false
	}
	if s.userInfo[user] == pwd {
		return true
	}
	return false
}
func (s *defAuth) LoadUserInfo(fn func() map[string]string) {
	s.userInfo = fn()
}

type VerifyUser func(username, passwd string) bool

//DEFAULT method 2
func (s *VerifyUser) Authenticate(username, passwd string) bool {
	return true
}
