package auth0

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/jws"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/spf13/cast"
	"github.com/valyala/fasthttp"

	"github.com/lestrrat-go/jwx/jwt"

	"github.com/tidwall/buntdb"
	"github.com/tidwall/gjson"
)

// reference vars here for stubbing
var jwkFetch = jwk.Fetch
var jwsVerifyWithJWK = jws.VerifyWithJWK
var jwtParseString = jwt.ParseString

func validateToken(jwkURL string, jwtToken string) (*jwt.Token, error) {
	// get JWKs and validate them against JWT token
	set, err := jwkFetch(jwkURL)
	if err != nil {
		return nil, err
	}

	var errstrings []string

	matches := 0
	for _, key := range set.Keys {
		_, err = jwsVerifyWithJWK([]byte(jwtToken), key)
		if err == nil {
			matches++
		} else {
			errstrings = append(errstrings, err.Error())
		}
	}

	// if JWT validated then verify token
	if matches > 0 {
		return verifyToken(jwtToken)
	}

	// token is invalid
	return nil, errors.New(strings.Join(errstrings, "\n"))
}

func verifyToken(jwtToken string) (*jwt.Token, error) {
	// parse & verify claims of JWT token
	token, err := jwtParseString(jwtToken)
	if err != nil {
		return nil, err
	}
	err = token.Verify()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func extractBearerTokenNet(req *http.Request) []string {
	bearerToken := req.Header.Get("Authorization")
	return strings.Split(bearerToken, " ")
}

func extractBearerToken(req *fasthttp.RequestCtx) []string {
	bearerTokenBytes := req.Request.Header.Peek("Authorization")
	bearerToken := cast.ToString(bearerTokenBytes)
	return strings.Split(bearerToken, " ")
}

func verifyBearerToken(tokenParts []string) (string, error) {
	if len(tokenParts) < 2 {
		return "", errors.New("Authorization header must have a Bearer token")
	}
	if tokenParts[0] != "Bearer" {
		return "", errors.New("Authorization header must have a Bearer token")
	}
	return tokenParts[1], nil
}

func getJwtToken(req *fasthttp.RequestCtx) (string, error) {
	tokenParts := extractBearerToken(req)
	return verifyBearerToken(tokenParts)
}

func getJwtTokenNet(req *http.Request) (string, error) {
	tokenParts := extractBearerTokenNet(req)
	return verifyBearerToken(tokenParts)
}

func processToken(db *buntdb.DB, jwtToken string, jwkURL string, audience string, issuer string) (*jwt.Token, error) {
	// check if token is in db
	err := db.View(func(tx *buntdb.Tx) error {
		_, err := tx.Get(jwtToken)
		if err != nil {
			return err
		}
		return nil
	})

	// if not then validate & verify token and save in db
	if err != nil {
		token, err := validateToken(jwkURL, jwtToken)
		if err != nil {
			return nil, err
		}
		// validate audience
		if token.Audience() != audience {
			return nil, errors.New("audience is not valid")
		}
		// validate issuer
		if token.Issuer() != issuer {
			return nil, errors.New("issuer is not valid")
		}

		err = db.Update(func(tx *buntdb.Tx) error {
			_, _, err := tx.Set(jwtToken, jwtToken, nil)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// if so then only verify token
	token, err := verifyToken(jwtToken)

	// if everything is good return token
	return token, nil
}

// GetEmail - get email as a custom claim from the access_token
func GetEmail(token *jwt.Token, audience string) (string, error) {
	// have to escape the periods in the URL (gjson specific)
	field := audience + "email"
	field = strings.Replace(field, ".", `\.`, -1)
	return tokenParser(token, field)
}

// URLScope - url scope type
type URLScope struct {
	Method string
	URL    string
}

// GetURLScopes - get the URL scopes from the scopes from the token
func GetURLScopes(token *jwt.Token) ([]URLScope, error) {
	var urlScopes []URLScope
	scopes, err := tokenParser(token, "scope")
	if err != nil {
		return nil, err
	}
	r := regexp.MustCompile(`(?m)([a-z]+:[a-z]+)`)
	urlScopesArray := r.FindAllString(scopes, -1)
	for _, urlScope := range urlScopesArray {
		urlParts := strings.Split(urlScope, ":")
		urlScopeObj := URLScope{
			Method: urlParts[0],
			URL:    urlParts[1],
		}
		urlScopes = append(urlScopes, urlScopeObj)
	}
	return urlScopes, nil
}

func tokenParser(token *jwt.Token, field string) (string, error) {
	jsonBytes, err := token.MarshalJSON()
	if err != nil {
		return "", err
	}
	result := gjson.ParseBytes(jsonBytes)
	scopes := result.Get(field).String()
	if scopes == "" {
		return "", errors.New("there are no " + field)
	}
	return scopes, nil
}

// GetScopes - get the scopes of the token
func GetScopes(token *jwt.Token) ([]string, error) {
	scopesStr, err := tokenParser(token, "scope")
	if err != nil {
		return nil, err
	}
	scopes := strings.Split(scopesStr, " ")
	return scopes, nil
}

// Validate - validate with JWK & JWT Auth0 & audience for fasthttp
func Validate(db *buntdb.DB, jwkURL string, audience string, issuer string, req *fasthttp.RequestCtx) (*jwt.Token, error) {
	// extract token from header
	jwtToken, err := getJwtToken(req)
	if err != nil {
		return nil, err
	}
	// process token
	return processToken(db, jwtToken, jwkURL, audience, issuer)
}

// ValidateNet - validate with JWK & JWT Auth0 & audience for net/http
func ValidateNet(db *buntdb.DB, jwkURL string, audience string, issuer string, req *http.Request) (*jwt.Token, error) {
	// extract token from header
	jwtToken, err := getJwtTokenNet(req)
	if err != nil {
		return nil, err
	}
	// process token
	return processToken(db, jwtToken, jwkURL, audience, issuer)
}
