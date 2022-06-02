package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	oauthd "github.com/vatsimnerd/oauth-device"
	"github.com/vatsimnerd/oauth-device/providers/github"
	"github.com/vatsimnerd/oauth-device/providers/yandex"
)

func main() {
	var debug bool
	var deviceID string
	var auth *oauthd.Authenticator

	flag.BoolVar(&debug, "d", false, "debug mode")
	flag.StringVar(&deviceID, "device", "", "optional device id for some providers")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: oauth-device [-d] [-device=xxx] <provider> <client-id> [<client-secret>]")
	}

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	switch strings.ToLower(args[0]) {
	case "github":
		auth = oauthd.New(github.New(flag.Arg(1), http.DefaultClient))
	case "yandex":
		auth = oauthd.New(yandex.New(flag.Arg(1), flag.Arg(2), deviceID, http.DefaultClient))
	}
	code, err := auth.RequestCode(nil)
	if err != nil {
		logrus.WithError(err).Fatal("error requesting code")
	}

	fmt.Printf("Follow the link %s and enter your user code: %s\n", code.VerificationURL(), code.UserCode())

	t, err := auth.RequestAuthToken(code)
	if err != nil {
		logrus.WithError(err).Fatal("error requesting token")
	}

	fmt.Println("Token acquired successfully.")
	fmt.Printf("Use the following header to authenticate:\n  Authorization: %s\n", t.AuthorizationHeader())
}
