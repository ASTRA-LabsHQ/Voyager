package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// shodanSearchURL is a var (not const) so tests can point Discover() at a
// local httptest server instead of the real Shodan API.
var shodanSearchURL = "https://api.shodan.io/shodan/host/search"

// shodanPageSize is fixed by the Shodan API itself: it always returns up to
// 100 matches per page, regardless of what's requested.
const shodanPageSize = 100

// ShodanDiscoverer finds candidates via the Shodan host search API
// (https://developer.shodan.io/api). This is a plain clearnet HTTP client —
// enrichment/discovery calls to third-party APIs go over clearnet, not Tor,
// since Voyager is authenticating with an API key and most providers
// rate-limit or block Tor exit traffic anyway.
type ShodanDiscoverer struct {
	APIKey string
	Client *http.Client
}

func NewShodanDiscoverer(apiKey string) *ShodanDiscoverer {
	return &ShodanDiscoverer{
		APIKey: apiKey,
		Client: &http.Client{Timeout: 20 * time.Second},
	}
}

func (s *ShodanDiscoverer) Name() string { return "shodan" }

type shodanMatch struct {
	IPStr string `json:"ip_str"`
	Port  int    `json:"port"`
	Org   string `json:"org"`
	ASN   string `json:"asn"`
}

type shodanResponse struct {
	Matches []shodanMatch `json:"matches"`
	Total   int           `json:"total"`
	Error   string        `json:"error"`
}

// Discover pages through Shodan's search results for query until it has
// limit candidates or runs out of results. Each page past the first that
// includes filters costs a Shodan query credit — callers should keep limit
// reasonable on free-tier keys.
func (s *ShodanDiscoverer) Discover(ctx context.Context, query string, limit int) ([]Candidate, error) {
	if s.APIKey == "" {
		return nil, fmt.Errorf("shodan: no API key configured (set SHODAN_API_KEY)")
	}
	if limit <= 0 {
		limit = shodanPageSize
	}

	var candidates []Candidate
	for page := 1; len(candidates) < limit; page++ {
		matches, err := s.fetchPage(ctx, query, page)
		if err != nil {
			return candidates, err
		}
		if len(matches) == 0 {
			break
		}

		for _, m := range matches {
			candidates = append(candidates, Candidate{
				IP:     m.IPStr,
				Port:   m.Port,
				Source: "shodan",
				Query:  query,
				Org:    m.Org,
				ASN:    m.ASN,
			})
			if len(candidates) >= limit {
				break
			}
		}

		if len(matches) < shodanPageSize {
			break // last page
		}
	}

	return candidates, nil
}

func (s *ShodanDiscoverer) fetchPage(ctx context.Context, query string, page int) ([]shodanMatch, error) {
	u := shodanSearchURL + "?" + url.Values{
		"key":   {s.APIKey},
		"query": {query},
		"page":  {strconv.Itoa(page)},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("shodan: build request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan: request failed: %w", err)
	}
	defer resp.Body.Close()

	var parsed shodanResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("shodan: decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := parsed.Error
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("shodan: %s", msg)
	}

	return parsed.Matches, nil
}
