// Package github provides you access to Github's OAuth2
// infrastructure.
package github

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	oauth2gh "golang.org/x/oauth2/github"
)

// Credentials stores google client-ids.
type Credentials struct {
	ClientID     string `json:"clientid"`
	ClientSecret string `json:"secret"`
}

var (
	conf                      *oauth2.Config
	cred                      Credentials
	state                     string
	store                     sessions.CookieStore
	authenticationRedirectURL string
)

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func Setup(redirectURL, credFile string, scopes []string, secret []byte, authenticationRedirectURL string) {
	store = sessions.NewCookieStore(secret)
	var c Credentials
	file, err := ioutil.ReadFile(credFile)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] File error: %v\n", err)
	}
	json.Unmarshal(file, &c)
	conf = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     oauth2gh.Endpoint,
	}
	authenticationRedirectURL = authenticationRedirectURL
}

func Session(name string) gin.HandlerFunc {
	return sessions.Sessions(name, store)
}

func LoginHandler(ctx *gin.Context) {
	state = randToken()
	session := sessions.Default(ctx)
	session.Set("state", state)
	session.Save()

	response := struct {
		GithubURI string `json:"github_uri"`
	}{GetLoginURL(state)}

	strURL, err := json.Marshal(response)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Error :%v", err))
		return
	}
	ctx.Writer.Write(strURL)
}

func GetLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func ExchangeToken(ctx *gin.Context) *oauth2.Token {
	tok, err := conf.Exchange(oauth2.NoContext, ctx.Query("code"))
	if err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err)
	}
	return tok
}

func Auth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Handle the exchange code to initiate a transport.
		session := sessions.Default(ctx)
		retrievedState := session.Get("state")
		if retrievedState != ctx.Query("state") {
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
			return
		}

		tok, err := conf.Exchange(oauth2.NoContext, ctx.Query("code"))
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}
		session.Set("access_token", tok)
		session.Save()
		ctx.Redirect(http.StatusMovedPermanently, authenticationRedirectURL)
	}
}

func CheckAuthenticatedUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		accessToken, ok := session.Get("access_token").(*oauth2.Token)
		if !ok {
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("missing accessToken"))
		}
		client := github.NewClient(conf.Client(oauth2.NoContext, accessToken))
		user, _, err := client.Users.Get(oauth2.NoContext, "")
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}
		ctx.Set("user", user)
	}
}
