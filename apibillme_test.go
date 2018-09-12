package apibillme

import (
	"errors"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/apibillme/stubby"
	"github.com/lestrrat-go/jwx/jwt"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/tidwall/buntdb"
)

func TestSpec(t *testing.T) {

	Convey("processRequest", t, func() {

		db, err := buntdb.Open(":memory:")
		if err != nil {
			log.Panic(err)
		}
		defer db.Close()

		jwtTokenFull := `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1FTTNNRFEzTkRBME56RkJRME13TkVJNVFVSTVPVVkyTWpNNFJEWTRSamRDUXpKR1JrTTFOQSJ9.eyJodHRwczovL2h0dHBiaW4ub3JnL2VtYWlsIjoiYmV2YW5AYmV2YW5odW50LmNvbSIsImlzcyI6Imh0dHBzOi8vYmV2YW5odW50LmF1dGgwLmNvbS8iLCJzdWIiOiJnaXRodWJ8ODkyNDA0IiwiYXVkIjpbImh0dHBzOi8vaHR0cGJpbi5vcmcvIiwiaHR0cHM6Ly9iZXZhbmh1bnQuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTUzNjY5NjQ3MCwiZXhwIjoxNTM2NzAzNjcwLCJhenAiOiJYVkFJOEt1aTg5bko0TXJScFM4TGJmYm56eGdPSUtSNCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwgZ2V0OmdldCBnZXQ6dXNlcnMifQ.LLqJwOf5dzKyotzyZAkhXwRe_WAAg2D8mqAoRjRXKaJm1AcBgInyN-8zqVAULGXw5qJ2XvqF4VUaBFzdoo3rxobjp_XbsFwa7o3cSvup-RKmbNr7bsCCtgHUILzYenugNHrszgvUNyrDtDZjtwINhLTVrnK6R1CXWKzWB3E0uH2W7Lwcl0G2nFYltYZU8BHJFje0a_x3mn2CIgcqIhjgKdP4KZZZhuu2SrIzqATHkt9SksQu8t4uIKtFzT-fl5gHHBRNwN-p0xotpHO-4Zqt901U6DNF-XmGXbprXWeiBt9PydC7XQ36txy9poLlrFdGkBMh_Cm6LQplK7WxFCLDMg`

		Convey("Success", func() {
			ctx, err := http.NewRequest("GET", "/users/12", nil)
			So(err, ShouldBeNil)
			token, err := jwt.ParseString(jwtTokenFull)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&auth0ValidateNet, token, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&restlyPostJSON, nil, nil)
			defer stub2.Reset()
			stub3 := stubby.StubFunc(&auth0GetEmail, "test@example.com", nil)
			defer stub3.Reset()
			os.Setenv("RBAC_VALIDATE", "true")
			os.Setenv("STRIPE_VALIDATE", "true")
			os.Setenv("STRIPE_JSON_PATH", "testdata/stripe.json")

			err = processRequest(db, ctx)
			So(err, ShouldBeNil)
		})

		Convey("Failure - cannot validate token", func() {
			ctx, err := http.NewRequest("GET", "/users/12", nil)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&auth0ValidateNet, nil, errors.New("foobar"))
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&restlyPostJSON, nil, nil)
			defer stub2.Reset()
			stub3 := stubby.StubFunc(&auth0GetEmail, "test@example.com", nil)
			defer stub3.Reset()
			os.Setenv("RBAC_VALIDATE", "true")
			os.Setenv("STRIPE_VALIDATE", "true")
			os.Setenv("STRIPE_JSON_PATH", "testdata/stripe.json")

			err = processRequest(db, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - cannot get email from token", func() {
			ctx, err := http.NewRequest("GET", "/users/12", nil)
			So(err, ShouldBeNil)
			token, err := jwt.ParseString(jwtTokenFull)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&auth0ValidateNet, token, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&restlyPostJSON, nil, nil)
			defer stub2.Reset()
			stub3 := stubby.StubFunc(&auth0GetEmail, nil, errors.New("email parsing failed"))
			defer stub3.Reset()
			os.Setenv("RBAC_VALIDATE", "true")
			os.Setenv("STRIPE_VALIDATE", "true")
			os.Setenv("STRIPE_JSON_PATH", "testdata/stripe.json")

			err = processRequest(db, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - stripe fails to find product", func() {
			ctx, err := http.NewRequest("GET", "/users/12", nil)
			So(err, ShouldBeNil)
			token, err := jwt.ParseString(jwtTokenFull)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&auth0ValidateNet, token, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&restlyPostJSON, nil, errors.New("random error"))
			defer stub2.Reset()
			stub3 := stubby.StubFunc(&auth0GetEmail, "test@example.com", nil)
			defer stub3.Reset()
			os.Setenv("RBAC_VALIDATE", "true")
			os.Setenv("STRIPE_VALIDATE", "true")
			os.Setenv("STRIPE_JSON_PATH", "testdata/stripe.json")

			err = processRequest(db, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - RBAC failed due to invalid path", func() {
			ctx, err := http.NewRequest("GET", "/foobar/12", nil)
			So(err, ShouldBeNil)
			token, err := jwt.ParseString(jwtTokenFull)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&auth0ValidateNet, token, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&restlyPostJSON, nil, nil)
			defer stub2.Reset()
			stub3 := stubby.StubFunc(&auth0GetEmail, "test@example.com", nil)
			defer stub3.Reset()
			os.Setenv("RBAC_VALIDATE", "true")

			err = processRequest(db, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - RBAC failed due to GetURLScopes failure", func() {
			ctx, err := http.NewRequest("GET", "/foobar/12", nil)
			So(err, ShouldBeNil)
			token, err := jwt.ParseString(jwtTokenFull)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&auth0ValidateNet, token, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&restlyPostJSON, nil, nil)
			defer stub2.Reset()
			stub3 := stubby.StubFunc(&auth0GetEmail, "test@example.com", nil)
			defer stub3.Reset()
			stub4 := stubby.StubFunc(&auth0GetURLScopes, nil, errors.New("foobar"))
			defer stub4.Reset()

			os.Setenv("RBAC_VALIDATE", "true")

			err = processRequest(db, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - cannot find stripe.json", func() {
			ctx, err := http.NewRequest("GET", "/users/12", nil)
			So(err, ShouldBeNil)
			token, err := jwt.ParseString(jwtTokenFull)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&auth0ValidateNet, token, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&restlyPostJSON, nil, nil)
			defer stub2.Reset()
			stub3 := stubby.StubFunc(&auth0GetEmail, "test@example.com", nil)
			defer stub3.Reset()
			os.Setenv("RBAC_VALIDATE", "true")
			os.Setenv("STRIPE_VALIDATE", "true")
			os.Setenv("STRIPE_JSON_PATH", "testdata/foobar.json")

			err = processRequest(db, ctx)
			So(err, ShouldBeError)
		})
	})
}
