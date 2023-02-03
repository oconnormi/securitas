# Securitas

Small net/http middleware for requiring token based authn and supporting claims based authz via a groups claim.

## RequireToken usage

the `RequireToken` middleware can enforce that a token is present on a request. By default some simple validation is performed using JWK as well checking for expiry. Additional validations can be configured as desired.

### net/http

```go
func HomeHandler(w http.ResponseWriter, r *http.Request) {
    token := r.Context().Value("Token").(jwt.Token)
    name, ok := token.Get("name")
    if !ok {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(fmt.Sprintf("Welcome Home %s", name))
}

func main() {
    requireToken = securitas.NewRequireToken(
        "https://myidp/realm/certs",
        jwt.WithIssuer("https://myidp/realm"),
        jwt.WithAudience("https://myapp.example.com")
    )
    http.Handle("/", requireToken.Validate(HomeHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Chi

```go
package main

func HomeHandler(w http.ResponseWriter, r *http.Request) {
    token := r.Context().Value("Token").(jwt.Token)
    name, ok := token.Get("name")
    if !ok {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(fmt.Sprintf("Welcome Home %s", name))
}

func main() {
    r := chi.NewRouter()
    requireToken = securitas.NewRequireToken(
        "https://myidp/realm/certs",
        jwt.WithIssuer("https://myidp/realm"),
        jwt.WithAudience("https://myapp.example.com")
    )
    r.Use(requireToken.Validate)
    r.Get("/", HomeHandler)
}
```