# Discourse SSO in Go
[Discourse SSO](https://meta.discourse.org/t/official-single-sign-on-for-discourse-sso/13045) in Go for [Kite Connect](https://kite.trade).Serves as a template for implementing other Discourse integrations.

# Usage
Compile the app with `go build` and host it at a public endpoint (eg: `http://sso.site.com`). 

Add the auth endpoint `http://sso.site.com/kite/auth` as the `sso_url` in Discourse settings).

Execute the program with the config vars:
```
SSO_ROOT_URL=https://discuss.zerodha.com \
SSO_SECRET=discourse_sso_secret \
KITE_KEY=kite_api_key \
KITE_SECRET=kite_api_secret \
./kite-discourse-sso
```

Licensed under the MIT License.
