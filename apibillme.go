package apibillme

import (
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tidwall/gjson"

	"github.com/auth0-community/go-auth0"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	stripe "github.com/stripe/stripe-go"
	sc "github.com/stripe/stripe-go/client"
	"github.com/stripe/stripe-go/customer"
	"github.com/stripe/stripe-go/sub"

	"github.com/gin-gonic/gin"
	jose "gopkg.in/square/go-jose.v2"
)

type claims map[string]interface{}

func validateJWT(request *http.Request, auth0Audience string, auth0JWK string, auth0Issuer string) (claims, error) {
	// Auth0 JWK client application authentication with claims
	client := auth0.NewJWKClient(auth0.JWKClientOptions{URI: auth0JWK}, nil)
	configuration := auth0.NewConfiguration(client, []string{auth0Audience}, auth0Issuer, jose.RS256)
	validator := auth0.NewValidator(configuration, nil)

	// validate JWT & Claims
	tok, tokErr := validator.ValidateRequest(request)
	claims := map[string]interface{}{}
	claimsErr := validator.Claims(request, tok, &claims)
	if tokErr != nil || claimsErr != nil {
		return nil, errors.New("")
	}
	return claims, nil
}

// capture each scope (e.g. get:users)
func captureAllScopes(scopeClaim string) []string {
	r := regexp.MustCompile(`(?m)([a-z]+:[a-z]+)`)
	return r.FindAllString(scopeClaim, -1)
}

// only get the base url component of the URL (e.g. /[users]/12 to users)
func getBaseURLPath(URL string) string {
	URL = strings.Trim(URL, "/")
	urlPieces := strings.Split(URL, "/")
	return urlPieces[0]
}

func validateRBAC(serverMethod string, serverBaseURL string, claims claims) error {
	// extract scopes from access_token
	scopeClaim := cast.ToString(claims["scope"])
	scopeMatches := captureAllScopes(scopeClaim)
	// set RBAC to fail as default
	RBACMatch := false
	// loop through each scope
	for _, scope := range scopeMatches {
		// split scope by method:URL
		scopePieces := strings.Split(scope, ":")
		// match scope method and url to requested method and url
		if serverMethod == scopePieces[0] && serverBaseURL == scopePieces[1] {
			RBACMatch = true
		}
	}
	// raise error if RBAC fails
	if !RBACMatch {
		return errors.New("")
	}
	return nil
}

func extractUserEmailFromClaims(claims claims, auth0Audience string) string {
	key := auth0Audience + "email"
	return cast.ToString(claims[key])
}

// extract API calls
func getCustomerAccounts(sx *sc.API, claims claims, auth0Audience string) *customer.Iter {
	userEmail := extractUserEmailFromClaims(claims, auth0Audience)
	customerListParams := &stripe.CustomerListParams{}
	customerListParams.Filters.AddFilter("email", "", userEmail)
	return sx.Customers.List(customerListParams)
}

// extract API calls
func getSubscriptions(sx *sc.API, customerID string) *sub.Iter {
	subscriptionParams := &stripe.SubscriptionListParams{}
	subscriptionParams.Filters.AddFilter("customer", "", customerID)
	return sx.Subscriptions.List(subscriptionParams)
}

// extract API calls
func writeUsageRecord(sx *sc.API, subscriptionItemID string, timestamp int64) {
	// override for testing as VCR changes value on every run
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}
	usageParams := &stripe.UsageRecordParams{
		Quantity:         stripe.Int64(1),
		Timestamp:        stripe.Int64(timestamp),
		SubscriptionItem: stripe.String(subscriptionItemID),
	}
	sx.UsageRecords.New(usageParams)
}

// extract API calls
func getStripeProductName(sx *sc.API, productID string) string {
	prod, _ := sx.Products.Get(productID, nil)
	return prod.Name
}

func validateStripeSubscription(subscriptionStatus stripe.SubscriptionStatus) bool {
	if subscriptionStatus == "active" || subscriptionStatus == "trialing" {
		return true
	}
	return false
}

func validateStripeScope(productName string, serverMethod string, serverBaseURL string) bool {
	productScopePieces := strings.Split(productName, ":")
	if serverMethod == productScopePieces[0] && serverBaseURL == productScopePieces[1] {
		return true
	}
	return false
}

func getExecutablePath() string {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return filepath.Dir(ex)
}

func searchStripeJSON(path string, serverMethod string, serverBaseURL string) bool {
	// open stripe.json
	JSONBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panic(err)
	}

	// check if any of the baseURL(s) match with the method called
	matched := false
	JSON := gjson.ParseBytes(JSONBytes)
	baseURLs := JSON.Get(`scopes.#[method=="` + serverMethod + `"]#.baseURL`)

	for _, baseURL := range baseURLs.Array() {
		if baseURL.String() == serverBaseURL {
			matched = true
		}
	}
	return matched
}

func validateStripe(serverMethod string, serverBaseURL string, claims claims, auth0Audience string, stripeKey string, timestamp int64) error {

	// Stripe API connection
	sx := sc.New(stripeKey, nil)

	// in case we want to reject any routes that are not stripe subscribed then track it for rejection
	validated := false

	// each email can have multiple customer accounts
	customerAccounts := getCustomerAccounts(sx, claims, auth0Audience)

	for customerAccounts.Next() {
		customerID := customerAccounts.Customer().ID
		subscriptions := getSubscriptions(sx, customerID)

		// a customer can have multiple subscriptions
		for subscriptions.Next() {
			subscription := subscriptions.Subscription()
			subscriptionActive := validateStripeSubscription(subscription.Status)

			// a subscription can have multiple subscription items
			for _, subItem := range subscription.Items.Data {

				subscriptionItemID := subItem.ID
				productID := subItem.Plan.Product
				productName := getStripeProductName(sx, productID)

				scopeValidated := validateStripeScope(productName, serverMethod, serverBaseURL)
				usageType := subItem.Plan.UsageType

				switch {
				case subscriptionActive && scopeValidated && usageType == "metered":
					writeUsageRecord(sx, subscriptionItemID, timestamp)
					validated = true
				case subscriptionActive && scopeValidated && usageType == "licensed":
					validated = true
				}
			}
		}
	}
	if !validated {
		return errors.New("")
	}
	return nil
}

// Run - Stripe & Auth0 integration for API URL billing Gin Middlware for KrakenD
func Run() gin.HandlerFunc {
	return func(c *gin.Context) {
		// viper auto config
		viper.AutomaticEnv()
		auth0JWK := cast.ToString(viper.Get("auth0_jwk"))
		auth0Audience := cast.ToString(viper.Get("auth0_audience"))
		auth0Issuer := cast.ToString(viper.Get("auth0_issuer"))

		// validate JWT on Auth0 and return claims
		claims, err := validateJWT(c.Request, auth0Audience, auth0JWK, auth0Issuer)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Message": "Unauthorized - Invalid Token or Invalid Claims"})
			return
		}

		// get server URL & Method
		serverURL := strings.ToLower(c.Request.URL.String())
		serverBaseURL := getBaseURLPath(serverURL)
		serverMethod := strings.ToLower(c.Request.Method)

		// validate RBAC if required by ENV VARS
		useRBAC := cast.ToBool(viper.Get("rbac_validate"))
		if useRBAC {
			err := validateRBAC(serverMethod, serverBaseURL, claims)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Message": "Unauthorized - Invalid Scope Permissions"})
				return
			}
		}

		// validate Stripe if required by ENV VARS
		useStripe := cast.ToBool(viper.Get("stripe_validate"))
		if useStripe {
			stripeKey := cast.ToString(viper.Get("stripe_key"))
			stripeJSONPath := getExecutablePath() + cast.ToString(viper.Get("stripe_json_path"))
			runStripe := searchStripeJSON(stripeJSONPath, serverMethod, serverBaseURL)
			if runStripe {
				err := validateStripe(serverMethod, serverBaseURL, claims, auth0Audience, stripeKey, 0)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Message": "Unauthorized - No Active Subscription to this URL"})
					return
				}
			}
		}

		// goto next middleware
		c.Next()
	}
}
