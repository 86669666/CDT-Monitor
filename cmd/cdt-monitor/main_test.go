package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeListen(t *testing.T) {
	if got := normalizeListen(":8080"); got != ":8080" {
		t.Fatalf("port-only = %q", got)
	}
	if got := normalizeListen("127.0.0.1:9090"); got != ":9090" {
		t.Fatalf("host-port = %q", got)
	}
	if got := normalizeListen("bad"); got != ":8080" {
		t.Fatalf("invalid = %q", got)
	}
}

func TestHealthcheckClientDoesNotFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	_, err := healthcheckClient().Get(source.URL + "/healthz")
	if !errors.Is(err, errHealthcheckRedirect) {
		t.Fatalf("err=%v", err)
	}
	if hit {
		t.Fatal("healthcheck followed a redirect")
	}
}
