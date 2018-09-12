# Auth0 authentication for net/http and fasthttp

[![Go Report](https://goreportcard.com/badge/github.com/apibillme/auth0)](https://goreportcard.com/report/github.com/apibillme/auth0) [![GolangCI](https://golangci.com/badges/github.com/apibillme/auth0.svg)](https://golangci.com/r/github.com/apibillme/auth0) [![Travis](https://travis-ci.org/apibillme/auth0.svg?branch=master)](https://travis-ci.org/apibillme/auth0#) [![codecov](https://codecov.io/gh/apibillme/auth0/branch/master/graph/badge.svg)](https://codecov.io/gh/apibillme/auth0) ![License](https://img.shields.io/github/license/mashape/apistatus.svg) ![Maintenance](https://img.shields.io/maintenance/yes/2018.svg) [![GoDoc](https://godoc.org/github.com/apibillme/auth0?status.svg)](https://godoc.org/github.com/apibillme/auth0)


## Features:
* Full authentication for Auth0 - or with any JWKs endpoint
* Works with [net/http](https://golang.org/pkg/net/http/) and [fasthttp](https://github.com/valyala/fasthttp)
* About 200 LOC
* In-memory key (token) caching with [BuntDB](https://github.com/tidwall/buntdb) - note: no key eviction due to the possibility of expired keys hammering your server

```bash
go get github.com/apibillme/auth0-middleware
```

## Example

```go
func main() {
    db, err := buntdb.Open(":memory:")
    if err != nil {
        log.Panic(err)
    }
    defer db.Close()

    app := restserve.New()

    app.Use("/", func(ctx *fasthttp.RequestCtx, next func(error)) {
        jwkEndpoint := "https://example.auth0.com/.well-known/jwks.json"
        audience := "https://httpbin.org/"
        issuer := "https://example.auth0.com/"
        _, err := auth0.Validate(db, jwkEndpoint, audience, issuer, ctx)
        if err != nil {
            ctx.SetStatusCode(401)
            ctx.SetBodyString(`{"error":"` + cast.ToString(err) + `"}`)
        } else {
            next(nil)
        }
    })

    app.Use("/hello", func(ctx *fasthttp.RequestCtx, next func(error)) {
        ctx.SetStatusCode(200)
        ctx.SetBodyString(`{"hello": "foobar"}`)
    })
}
```
Check out [restserve](https://github.com/apibillme/restserve)
