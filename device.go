package oauthdevice

import "time"

type ODProvider interface {
	RequestCode([]string) (ODProviderCode, error)
	RequestAuthToken(code ODProviderCode) (ODProviderToken, error)
}

type ODProviderToken interface {
	Token() string
	TokenType() string
	Scopes() []string
	AuthorizationHeader() string
}

type ODProviderCode interface {
	UserCode() string
	DeviceCode() string
	VerificationURL() string
	ExpiresIn() time.Duration
	Interval() time.Duration
}

type Authenticator struct {
	p ODProvider
}

func New(provider ODProvider) *Authenticator {
	return &Authenticator{p: provider}
}

func (a *Authenticator) RequestCode(scopes []string) (ODProviderCode, error) {
	return a.p.RequestCode(scopes)
}

func (a *Authenticator) RequestAuthToken(c ODProviderCode) (ODProviderToken, error) {
	return a.p.RequestAuthToken(c)
}
