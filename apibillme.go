package apibillme

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/apibillme/auth0"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/tidwall/gjson"

	"github.com/tidwall/buntdb"

	"github.com/apibillme/restly"

	"github.com/spf13/cast"
	"github.com/spf13/viper"

	"github.com/gin-gonic/gin"
)

// for stubbing
var restlyPostJSON = restly.PostJSON
var auth0ValidateNet = auth0.ValidateNet
var auth0GetEmail = auth0.GetEmail
var auth0GetURLScopes = auth0.GetURLScopes

func getBaseURLPath(URL string) string {
	// only get the base url component of the URL (e.g. /[users]/12 to users)
	URL = strings.Trim(URL, "/")
	urlPieces := strings.Split(URL, "/")
	return urlPieces[0]
}

func validateRBAC(serverMethod string, serverBaseURL string, token *jwt.Token) error {
	// extract scopes from access_token
	scopes, err := auth0GetURLScopes(token)
	if err != nil {
		return err
	}
	// set RBAC to fail as default
	RBACMatch := false
	// loop through each scope
	for _, scope := range scopes {
		// match scope method and url to requested method and url
		if serverMethod == scope.Method && serverBaseURL == scope.URL {
			RBACMatch = true
		}
	}
	// raise error if RBAC fails
	if !RBACMatch {
		return errors.New("RBAC validation failed")
	}
	return nil
}

func searchStripeJSON(path string, serverMethod string, serverBaseURL string) (bool, error) {
	// open stripe.json
	jsonBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return false, err
	}

	// check if any of the baseURL(s) match with the method called
	matched := false
	result := gjson.ParseBytes(jsonBytes)
	baseURLs := result.Get(`scopes.#[method=="` + serverMethod + `"]#.baseURL`)

	for _, baseURL := range baseURLs.Array() {
		if baseURL.String() == serverBaseURL {
			matched = true
		}
	}
	return matched, nil
}

func processRequest(db *buntdb.DB, req *http.Request) error {
	// viper auto config
	viper.AutomaticEnv()
	auth0JWK := cast.ToString(viper.Get("auth0_jwk"))
	auth0Audience := cast.ToString(viper.Get("auth0_audience"))
	auth0Issuer := cast.ToString(viper.Get("auth0_issuer"))

	// validate JWT on Auth0 and return token
	token, err := auth0ValidateNet(db, auth0JWK, auth0Audience, auth0Issuer, req)

	if err != nil {
		return errors.New("Unauthorized - Invalid Token")
	}

	// get server URL & Method
	serverURL := strings.ToLower(req.URL.String())
	serverBaseURL := getBaseURLPath(serverURL)
	serverMethod := strings.ToLower(req.Method)

	// validate RBAC if required by ENV VARS
	useRBAC := cast.ToBool(viper.Get("rbac_validate"))
	if useRBAC {
		err := validateRBAC(serverMethod, serverBaseURL, token)
		if err != nil {
			return errors.New("Unauthorized - Invalid Scope Permissions")
		}
	}

	// validate Stripe if required by ENV VARS
	useStripe := cast.ToBool(viper.Get("stripe_validate"))
	if useStripe {
		stripeKey := cast.ToString(viper.Get("stripe_key"))
		stripeJSONPath := cast.ToString(viper.Get("stripe_json_path"))
		runStripe, err := searchStripeJSON(stripeJSONPath, serverMethod, serverBaseURL)
		if err != nil {
			return errors.New("Unauthorized - cannot find stripe.json on server - contact your admin")
		}
		if runStripe {
			userEmail, err := auth0GetEmail(token, auth0Audience)
			if err != nil {
				return errors.New("Unauthorized - cannot get email address from token")
			}
			body := `{"serverMethod":"` + serverMethod + `", "serverBaseURL":"` + serverBaseURL + `", "userEmail":"` + userEmail + `"}`
			req := restly.New()
			req.Header.Add("x-stripe-key", stripeKey)
			_, err = restlyPostJSON(req, "https://api.apibill.me/charge", body)
			if err != nil {
				return errors.New("Unauthorized - No Active Subscription to this URL")
			}
		}
	}
	return nil
}

// Run - process apibill.me request (Auth0 and Stripe)
func Run(db *buntdb.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := processRequest(db, c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return // have to return to stop middleware
		}
		c.Next()
	}
}
