# apibillme

[![Go Report](https://goreportcard.com/badge/github.com/apibillme/apibillme)](https://goreportcard.com/report/github.com/apibillme/apibillme) [![GolangCI](https://golangci.com/badges/github.com/apibillme/apibillme.svg)](https://golangci.com/r/github.com/apibillme/apibillme) [![Travis](https://travis-ci.org/apibillme/apibillme.svg?branch=master)](https://travis-ci.org/apibillme/apibillme#) [![codecov](https://codecov.io/gh/apibillme/apibillme/branch/master/graph/badge.svg)](https://codecov.io/gh/apibillme/apibillme) ![License](https://img.shields.io/github/license/mashape/apistatus.svg) ![Maintenance](https://img.shields.io/maintenance/yes/2018.svg) [![GoDoc](https://godoc.org/github.com/apibillme/apibillme?status.svg)](https://godoc.org/github.com/apibillme/apibillme)

## Auth0 Integration
- sign up for free account
- create API with a friendly name, audience (very important: use trailing slash - e.g. `https://httpbin.org/`), and choose `RS256`
    - assign API scopes based on http verbs and KrakenD endpoints - e.g. `get:users`
- create a SPA application - turn on any iDP you want
- install the Auth0 Authorization extension
- Auth0 Rules:
    - ensure that the `auth0-authorization-extension` rule exists and is turned on
    - add `RBAC` rule and turn it on - this will only allow users to access their assigned scopes and will assign them to the access_token when requested:
    ```javascript
    function (user, context, callback) {
        var permissions = user.permissions || [];
        var requestedScopes = context.request.body.scope || context.request.query.scope;
        var filteredScopes = requestedScopes.split(' ').filter( function(x) {
            return x.indexOf(':') < 0;
        });
        Array.prototype.push.apply(filteredScopes, permissions);
        context.accessToken.scope = filteredScopes.join(' ');

        callback(null, user, context);
    }
    ```
    - add `Add User Email to Access Token` rule and turn it on - this will assign the user email to the access_token which is necessary to link Auth0 and Stripe:
    ```javascript
    function (user, context, callback) {
        const namespace = context.request.query.audience;
        context.accessToken[namespace + 'email'] = user.email;
        callback(null, user, context);
    }
    ```
- Use the Authorization Extension - add RBAC permissions that match your API scopes (e.g. `get:users`)
- Create a user with a valid email address
- Setup a SPA with Auth0 login
    - use this example [here](https://github.com/auth0-samples/auth0-react-samples/tree/master/01-Login)
        - edit Auth.js with your SPA application client ID, the audience of your API (e.g. `https://httpbin.org/`), responseType of `token id_token`, and scope to include your RBAC'ed API scopes (e.g. `openid profile email get:users`)
            - you will want to use the access_token as `Authorization: Bearer access_token` for your API requests to your API gateway
- Set your ENV VARS:
    - `auth0_jwk`, `auth0_audience`, `auth0_issuer`, `rbac_validate` (RBAC is optional)

## Stripe Integration
- sign up for a pay as go account
- create a restricted Stripe API Key with the following permissions - `Customers: Read only, Products and SKUs: Read only, Plans: Read only, Subscriptions: Read only, Usage Records: Read and Write`
- create a customer with the same valid email address you did for Auth0 - note: Stripe allows duplicate accounts for each email address - be careful
- create a product that has the product name of your required scope (e.g. `get:users`) and assign a pricing plan (both metered and recurring are supported)
- create a subscription for that customer for that product with pricing plan
- Set your ENV VARS:
    - `stripe_key`, `stripe_validate` (Stripe is optional), `stripe_json_path` (the path to the stripe.json - e.g. `/conf/stripe.json`)
- create the scopes that you want on Stripe in `/conf/stripe.json` - this is to only call the Stripe APIs for those scopes (keeps the non-Stripe calls fast)
