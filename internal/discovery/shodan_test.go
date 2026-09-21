package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestShodanDiscoverer_SinglePage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("key"); got != "test-key" {
			t.Errorf("expected key=test-key, got %q", got)
		}
		if got := r.URL.Query().Get("query"); got != `ssl.jarm:"deadbeef"` {
			t.Errorf("unexpected query param: %q", got)
		}

		json.NewEncoder(w).Encode(shodanResponse{
			Total: 2,
			Matches: []shodanMatch{
				{IPStr: "203.0.113.10", Port: 443, Org: "Example Hosting", ASN: "AS64500"},
				{IPStr: "203.0.113.11", Port: 8443, Org: "Example Hosting", ASN: "AS64500"},
			},
		})
	}))
	defer srv.Close()

	d := NewShodanDiscoverer("test-key")
	d.Client = srv.Client()
	// Point the discoverer at the test server instead of the real API.
	origURL := shodanSearchURL
	shodanSearchURL = srv.URL
	defer func() { shodanSearchURL = origURL }()

	candidates, err := d.Discover(context.Background(), `ssl.jarm:"deadbeef"`, 100)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
	if candidates[0].IP != "203.0.113.10" || candidates[0].Port != 443 {
		t.Errorf("unexpected first candidate: %+v", candidates[0])
	}
	if candidates[0].Source != "shodan" {
		t.Errorf("expected source=shodan, got %q", candidates[0].Source)
	}
}

func TestShodanDiscoverer_NoAPIKey(t *testing.T) {
	d := NewShodanDiscoverer("")
	if _, err := d.Discover(context.Background(), "ssl.jarm:x", 10); err == nil {
		t.Fatal("expected error when no API key is configured, got nil")
	}
}

func TestShodanDiscoverer_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(shodanResponse{Error: "Invalid API key"})
	}))
	defer srv.Close()

	d := NewShodanDiscoverer("bad-key")
	d.Client = srv.Client()
	origURL := shodanSearchURL
	shodanSearchURL = srv.URL
	defer func() { shodanSearchURL = origURL }()

	_, err := d.Discover(context.Background(), "ssl.jarm:x", 10)
	if err == nil {
		t.Fatal("expected error on 401 response, got nil")
	}
}
