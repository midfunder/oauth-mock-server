# oauth-mock-server

The auth-mock directory contains a OAuth authentication server that
allows the user to select its identity parameters without suplying
any credentials. It is designed as a mock server for integration test.

The _app-client_ directory contains a react app which uses the  [auth0/auth0-react](https://www.npmjs.com/package/@auth0/auth0-react) npm
package to authenticate with an OAuth server.

The _app-server_ directory contains a node / nest.js API server that uses
_@nestjs/{passport,jwt}_ to verify JWT tokens and retrieve information about
the user.

The web client / api server combo was manually tested against an auth0 API.
The _integration_ directory contains an end2end integration test which
performs a login operation against the mock oauth server and which is being
run by github actions.

The app-client / app-server where configured by using 2 distinct applications
under the same domain.

The react app-client requires the following environment variables when building:

```sh
REACT_APP_AUTH_DOMAIN=
REACT_APP_AUTH_CLIENT_ID=
REACT_APP_AUTH_AUDIENCE=
```

Where _DOMAIN_ is the auth0 domain which identifies the oauth server,
_CLIENT_ID_ is the identifier of the oauth application and _AUDIENCE_
identifies the _app-server_ application.

The application server is configured with:
```sh
AUTH_JWKS_URL=https://<domain>/.well-known/jwks.json
```

which is the location of the JWKS json file that contains the public RS256 key
used to verify the signed JWTs.

The mock server attempts to follow the oauth authorization process defined in [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749); however it has only
been tested against the auth0-specific client APIs.
