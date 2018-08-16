package apibillme

import (
	json "encoding/json"
	"net/http"
	"net/url"
	"testing"

	vcr "github.com/ad2games/vcr-go"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSpec(t *testing.T) {

	jsonRaw := []byte(`{"aud":["https://httpbin.org/","https://example.auth0.com/userinfo"],"azp":"XVAI8Kui89nJ4MrRpS8LbfbnzxgOIKR4","exp":1534315474,"https://httpbin.org/email":"example@test.com","iat":1534308274,"iss":"https://example.auth0.com/","scope":"openid profile email get:get","sub":"github|892404"}`)

	Convey("captureAllScopes should capture scopes", t, func() {
		expectedScopes := []string{"get:get", "post:post"}
		testScopes := "openid profile email get:get post:post"
		So(captureAllScopes(testScopes), ShouldResemble, expectedScopes)
	})

	Convey("getBaseURLPath", t, func() {
		Convey("should get base URL for one path", func() {
			So(getBaseURLPath("/users"), ShouldEqual, "users")
		})

		Convey("should get base URL for multiple paths", func() {
			So(getBaseURLPath("/users/12/13/14"), ShouldEqual, "users")
		})
	})

	Convey("validateRBAC", t, func() {
		serverBaseURL := "users"
		serverMethod := "get"

		Convey("should validate with scope defined", func() {
			jsonRaw := []byte(`{"scope": "openid profile email get:users"}`)
			claims := claims{}
			json.Unmarshal(jsonRaw, &claims)
			So(validateRBAC(serverMethod, serverBaseURL, claims), ShouldBeNil)
		})

		Convey("should error with undefined url and defined method", func() {
			jsonRaw := []byte(`{"scope": "openid profile email get:get"}`)
			claims := claims{}
			json.Unmarshal(jsonRaw, &claims)
			So(validateRBAC(serverMethod, serverBaseURL, claims), ShouldBeError)
		})

		Convey("should error with scope fully undefined", func() {
			jsonRaw := []byte(`{"scope": "openid profile email post:users"}`)
			claims := claims{}
			json.Unmarshal(jsonRaw, &claims)
			So(validateRBAC(serverMethod, serverBaseURL, claims), ShouldBeError)
		})
	})

	Convey("validateStripeSubscription", t, func() {
		Convey("should work with active", func() {
			So(validateStripeSubscription("active"), ShouldBeTrue)
		})
		Convey("should work with trialing", func() {
			So(validateStripeSubscription("trialing"), ShouldBeTrue)
		})
		Convey("should not work with anything else", func() {
			So(validateStripeSubscription("foobar"), ShouldBeFalse)
		})
	})

	Convey("validateStripeScope", t, func() {
		Convey("should match when valid", func() {
			So(validateStripeScope("get:users", "get", "users"), ShouldBeTrue)
		})
		Convey("should not match when invalid", func() {
			So(validateStripeScope("get:get", "get", "users"), ShouldBeFalse)
		})
	})

	Convey("extractUserEmailFromClaims", t, func() {
		claims := claims{}
		json.Unmarshal(jsonRaw, &claims)

		Convey("should get the correct email if valid claim", func() {
			email := extractUserEmailFromClaims(claims, "https://httpbin.org/")
			So(email, ShouldEqual, "example@test.com")
			// So(err, ShouldBeNil)
		})
		Convey("should get error if cannot get email from claim", func() {
			email := extractUserEmailFromClaims(claims, "foobar")
			So(email, ShouldBeEmpty)
			// So(err, ShouldBeError)
		})
	})

	Convey("validateJWT", t, func() {
		Convey("should error when invalid token", func() {
			// use VCR
			vcr.Start("auth0_failure", nil)
			defer vcr.Stop()

			// create fake http request
			header := http.Header{}
			http.Header.Add(header, "Authorization", "Bearer blah")
			url := &url.URL{
				Path: "/get",
			}
			request := http.Request{
				Method: "get",
				Header: header,
				URL:    url,
			}
			// Set temp OS ENV VARS
			auth0JWK := "https://example.auth0.com/.well-known/jwks.json"
			auth0Audience := "https://httpbin.org/"
			auth0Issuer := "https://example.auth0.com/"
			// call the method
			claims, err := validateJWT(&request, auth0Audience, auth0JWK, auth0Issuer)
			So(err, ShouldBeError)
			So(claims, ShouldHaveSameTypeAs, claims)
		})
		// TODO: get around expiry of valid tokens for the happy path test
	})

	// Stripe Integration Tests with VCR
	Convey("validateStripe", t, func() {
		Convey("should work with stripe_reject set", func() {
			// use VCR
			vcr.Start("stripe_success", nil)
			defer vcr.Stop()

			claims := claims{}
			json.Unmarshal(jsonRaw, &claims)
			err := validateStripe("get", "get", claims, "https://httpbin.org/", true, "", 1534319043)
			So(err, ShouldBeNil) // should not have an error
		})
		Convey("should error with stripe_reject set", func() {
			// use VCR
			vcr.Start("stripe_failure", nil)
			defer vcr.Stop()

			claims := claims{}
			json.Unmarshal(jsonRaw, &claims)
			err := validateStripe("get", "users", claims, "https://httpbin.org/", true, "", 0)
			So(err, ShouldBeError) // should be an error
		})
	})
}
