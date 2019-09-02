package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/gin-gonic/gin"
	"github.com/lzecca78/gin-oauth2/github"
)

var redirectURL, credFile, authenticationRedirectURL string

func init() {
	bin := path.Base(os.Args[0])
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
Usage of %s
================
`, bin)
		flag.PrintDefaults()
	}
	flag.StringVar(&redirectURL, "redirect", "http://127.0.0.1:8081/auth/", "URL to be redirected to after the first authentication.")
	flag.StringVar(&credFile, "cred-file", "./example/github/test-clientid.github.json", "Credential JSON file")
	flag.StringVar(&authenticationRedirectURL, "authentication-redirect", "http://127.0.0.1:8081/", "URL to be redirect after checking the user is correctly authorized")
}

func main() {
	flag.Parse()

	scopes := []string{
		"repo",
		// You have to select your own scope from here -> https://developer.github.com/v3/oauth/#scopes
	}
	secret := []byte("secret")
	sessionName := "goquestsession"
	router := gin.Default()
	// init settings for github auth
	github.Setup(redirectURL, credFile, scopes, secret, authenticationRedirectURL)
	router.Use(github.Session(sessionName))

	router.GET("/login", github.LoginHandler)
	router.GET("/auth", github.Auth())

	// protected url group
	private := router.Group("/")
	private.Use(github.CheckAuthenticatedUser())
	private.GET("/info", UserInfoHandler)
	private.GET("/", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"message": "Hello from private for groups"})
	})

	router.Run("127.0.0.1:8081")
}

func UserInfoHandler(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"Hello": "from private", "user": ctx.MustGet("user")})
}
