package securitas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestNewHashedGroupsClaim(t *testing.T) {
	claim := []string{"foo", "bar"}

	h := newHashedGroupsClaim(claim)

	if !h["foo"] {
		t.Fatalf("Want foo=true, got foo=%v", !h["foo"])
	}

	if !h["bar"] {
		t.Fatalf("Want bar=true, got bar=%v", !h["bar"])
	}
}

func TestContainsGroup(t *testing.T) {
	claim := []string{"foo", "bar"}

	h := newHashedGroupsClaim(claim)

	ok := h.containsGroups([]string{"foo"})
	if !ok {
		t.Fatalf("Want true, got %v", ok)
	}
}

func TestContainsGroups(t *testing.T) {
	claim := []string{"foo", "bar"}

	h := newHashedGroupsClaim(claim)

	ok := h.containsGroups([]string{"foo", "bar"})
	if !ok {
		t.Fatalf("Want true, got %v", ok)
	}
}

func TestMissingGroup(t *testing.T) {
	claim := []string{"foo"}

	h := newHashedGroupsClaim(claim)

	ok := h.containsGroups([]string{"bar"})
	if ok {
		t.Fatalf("Want false, got %v", ok)
	}
}

func TestRequiredGroups(t *testing.T) {
	token, err := jwt.NewBuilder().Claim("groups", []string{"foo", "bar"}).Build()
	if err != nil {
		t.Fatalf("Unable to construct token")
	}
	ctx := context.WithValue(context.Background(), TOKEN_CTX_KEY, token)

	requiredGroups := RequireGroups{Required: []string{"foo", "bar"}}

	r, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080/foo", nil)
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
	requiredGroups.Validate(nextHandler).ServeHTTP(httptest.NewRecorder(), r)
}

func TestRequireGroupsInvalidTokenType(t *testing.T) {
	ctx := context.WithValue(context.Background(), TOKEN_CTX_KEY, "foo")
	requiredGroups := RequireGroups{Required: []string{"foo", "bar"}}

	r, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080/foo", nil)
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	})
	recorder := httptest.NewRecorder()
	requiredGroups.Validate(nextHandler).ServeHTTP(recorder, r)
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 StatusCode, got %v", recorder.Result().StatusCode)
	}
}

func TestRequireGroupsMissingClaim(t *testing.T) {
	token, err := jwt.NewBuilder().Build()
	if err != nil {
		t.Fatalf("Unable to construct token")
	}
	ctx := context.WithValue(context.Background(), TOKEN_CTX_KEY, token)
	requiredGroups := RequireGroups{Required: []string{"foo", "bar"}}

	r, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080/foo", nil)
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	})
	recorder := httptest.NewRecorder()
	requiredGroups.Validate(nextHandler).ServeHTTP(recorder, r)
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 StatusCode, got %v", recorder.Result().StatusCode)
	}
}

func TestRequireGroupsMissingGroup(t *testing.T) {
	token, err := jwt.NewBuilder().Claim("groups", []string{"foo"}).Build()
	if err != nil {
		t.Fatalf("Unable to construct token")
	}
	ctx := context.WithValue(context.Background(), TOKEN_CTX_KEY, token)
	requiredGroups := RequireGroups{Required: []string{"foo", "bar"}}

	r, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080/foo", nil)
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	})
	recorder := httptest.NewRecorder()
	requiredGroups.Validate(nextHandler).ServeHTTP(recorder, r)
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 StatusCode, got %v", recorder.Result().StatusCode)
	}
}
