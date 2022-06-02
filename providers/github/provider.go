package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	oauthd "github.com/vatsimnerd/oauth-device"
)

type Provider struct {
	clientID   string
	httpClient *http.Client
}

type CodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type Code struct {
	cr *CodeResponse
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type Token struct {
	tr *TokenResponse
}

type ErrorResponse struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
	Interval         int    `json:"interval"`
}

const (
	codeRequestURL  = "https://github.com/login/device/code"
	tokenRequestURL = "https://github.com/login/oauth/access_token"
	grantType       = "urn:ietf:params:oauth:grant-type:device_code"
)

var (
	log = logrus.WithField("module", "provider.github")
)

func New(clientID string, httpClient *http.Client) *Provider {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Provider{clientID, httpClient}
}

func (e ErrorResponse) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
}

func (p *Provider) RequestCode(scopes []string) (oauthd.ODProviderCode, error) {
	form := url.Values{}
	form.Add("client_id", p.clientID)
	form.Add("scope", strings.Join(scopes, ","))
	req, err := http.NewRequest("POST", codeRequestURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.WithError(err).Debug("error creating request")
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		log.WithError(err).Debug("error sending request")
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Debug("error reading response body")
		return nil, err
	}

	err = extractError(data)
	if err != nil {
		log.WithError(err).Debug("error response from oauth server")
		return nil, err
	}

	var cr CodeResponse
	err = json.Unmarshal(data, &cr)
	if err != nil {
		log.WithError(err).Debug("error unmarshaling oauth code response")
		return nil, err
	}

	return &Code{cr: &cr}, nil
}

func (p *Provider) requestAuthTokenOnce(deviceCode string) (*Token, error) {
	form := url.Values{}
	form.Add("client_id", p.clientID)
	form.Add("device_code", deviceCode)
	form.Add("grant_type", grantType)
	req, err := http.NewRequest("POST", tokenRequestURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.WithError(err).Debug("error creating request")
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		log.WithError(err).Debug("error sending request")
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Debug("error reading response body")
		return nil, err
	}

	err = extractError(data)
	if err != nil {
		log.WithError(err).Debug("error response from oauth server")
		return nil, err
	}

	var tr TokenResponse
	err = json.Unmarshal(data, &tr)
	if err != nil {
		log.WithError(err).Debug("error unmarshaling oauth token response")
		return nil, err
	}
	return &Token{tr: &tr}, nil
}

func (p *Provider) RequestAuthToken(code oauthd.ODProviderCode) (oauthd.ODProviderToken, error) {
	interval := code.Interval()

	token, err := p.requestAuthTokenOnce(code.DeviceCode())
	if err == nil {
		return token, nil
	}

	nextTick := time.After(interval)
	expire := time.After(code.ExpiresIn())
	for {
		select {
		case <-nextTick:
			token, err := p.requestAuthTokenOnce(code.DeviceCode())
			if err == nil {
				return token, nil
			}
			if eresp, ok := err.(ErrorResponse); ok && eresp.Interval > 0 {
				log.Printf("new interval: %d\n", eresp.Interval)
				interval = time.Second * time.Duration(eresp.Interval)
			}
			nextTick = time.After(interval)
		case <-expire:
			log.Debug("authorization session expired")
			return nil, errors.New("expired")
		}
	}
}

func (c *Code) UserCode() string {
	return c.cr.UserCode
}

func (c *Code) DeviceCode() string {
	return c.cr.DeviceCode
}

func (c *Code) VerificationURL() string {
	return c.cr.VerificationURI
}

func (c *Code) ExpiresIn() time.Duration {
	return time.Second * time.Duration(c.cr.ExpiresIn)
}

func (c *Code) Interval() time.Duration {
	return time.Second * time.Duration(c.cr.Interval)
}

func (t *Token) Token() string {
	return t.tr.AccessToken
}

func (t *Token) TokenType() string {
	return t.tr.TokenType
}

func (t *Token) Scopes() []string {
	return strings.Split(t.tr.Scope, ",")
}

func (t *Token) AuthorizationHeader() string {
	return "Token " + t.Token()
}

func extractError(data []byte) error {
	var e ErrorResponse
	err := json.Unmarshal(data, &e)
	if err != nil {
		return err
	}

	if e.ErrorCode != "" {
		return e
	}
	return nil
}
