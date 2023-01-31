package securitas

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	TOKEN_CTX_KEY  TokenContextKey  = "Token"
	GROUPS_CTX_KEY GroupsContextKey = "Groups"
)

type TokenContextKey string
type GroupsContextKey string

type Validator interface {
	Validate(next http.Handler) http.Handler
}

type RequireToken struct {
	c                 *jwk.Cache
	jwks              jwk.Set
	ValidationOptions *[]jwt.ValidateOption
}

func NewRequireToken(jwksUrl string, options ...jwt.ValidateOption) (RequireToken, error) {
	ctx := context.Background()
	c := jwk.NewCache(ctx)
	err := c.Register(jwksUrl, jwk.WithMinRefreshInterval(15*time.Minute))
	if err != nil {
		log.Default().Fatalf("Unable to register JWKS URL %s", jwksUrl)
		return RequireToken{}, nil
	}
	_, err = c.Refresh(ctx, jwksUrl)
	if err != nil {
		log.Default().Fatalf("Unable to retrieve JWKS from %s", jwksUrl)
		return RequireToken{}, nil
	}
	cached := jwk.NewCachedSet(c, jwksUrl)
	jwt.RegisterCustomField("groups", []string{})
	return RequireToken{
		c:                 c,
		ValidationOptions: &options,
		jwks:              cached,
	}, nil
}

func (v RequireToken) Validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token, err := jwt.ParseRequest(r, jwt.WithKeySet(v.jwks))
		if err != nil {
			log.Default().Printf("Unable to locate token %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx = context.WithValue(ctx, TOKEN_CTX_KEY, token)
		err = jwt.Validate(token, *v.ValidationOptions...)
		if err != nil {
			log.Default().Printf("Token was invalid %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type RequireGroups struct {
	Required []string
}

type hashedGroupsClaim map[string]bool

func newHashedGroupsClaim(claim []string) hashedGroupsClaim {
	hashed := make(hashedGroupsClaim)
	for _, v := range claim {
		hashed[v] = true
	}
	return hashed
}

func (h hashedGroupsClaim) containsGroups(groups []string) bool {
	for _, v := range groups {
		if !h[v] {
			return false
		}
	}
	return true
}

func (v RequireGroups) Validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token := ctx.Value(TOKEN_CTX_KEY).(jwt.Token)
		groupsClaim, ok := token.Get("groups")
		if !ok {
			log.Default().Println("No groups claim found")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		groups := groupsClaim.([]string)
		hashed := newHashedGroupsClaim(v.Required)
		if !hashed.containsGroups(groups) {
			log.Default().Printf("Missing required groups. has: %v, needs: %v", groups, v.Required)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx = context.WithValue(ctx, GROUPS_CTX_KEY, groups)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
