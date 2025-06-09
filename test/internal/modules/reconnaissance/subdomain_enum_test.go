// test/internal/modules/reconnaissance/subdomain_enum_test.go
package reconnaissance_test

import (
	"apexPenetrateGo/internal/modules/reconnaissance"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Mock HTTP server to control responses during tests
func setupMockServer(status int) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		// For HEAD requests, body is typically empty, but ensure it's closed if present.
		io.Copy(io.Discard, r.Body)
	})
	return httptest.NewServer(handler)
}

func TestSubdomainEnumerator_EnumerateSubdomains_Default(t *testing.T) {
	// Mock server that returns 200 for any request (not used in new logic, but kept for future HTTP-based validation)
	mockServer := setupMockServer(http.StatusOK)
	defer mockServer.Close()

	oldClient := reconnaissance.DefaultHTTPClient
	reconnaissance.DefaultHTTPClient = mockServer.Client()
	defer func() { reconnaissance.DefaultHTTPClient = oldClient }()

	enumerator := reconnaissance.NewSubdomainEnumerator("example.com")
	subdomains, err := enumerator.EnumerateSubdomains()
	if err != nil {
		t.Fatalf("EnumerateSubdomains returned an error: %v", err)
	}

	// We can't predict the exact count, but should get at least some subdomains from crt.sh or DNS if available
	if len(subdomains) == 0 {
		t.Errorf("Expected at least one subdomain, got 0")
	}

	// Check that all returned subdomains are for the correct domain
	for _, sub := range subdomains {
		if !strings.HasSuffix(sub, ".example.com") {
			t.Errorf("Subdomain %s does not match target domain", sub)
		}
	}
}

func TestSubdomainEnumerator_TargetCleaning(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://www.target.com/path", "www.target.com"},
		{"https://another.net", "another.net"},
		{"sub.domain.org", "sub.domain.org"},
		{"http://example.com", "example.com"},
	}

	for _, tt := range tests {
		enumerator := reconnaissance.NewSubdomainEnumerator(tt.input)
		if enumerator.target != tt.expected {
			t.Errorf("For input %q, expected target %q, got %q", tt.input, tt.expected, enumerator.target)
		}
	}
}

// Helper to assert if a slice contains a string
func assertContains(t *testing.T, slice []string, item string) {
	t.Helper()
	found := false
	for _, s := range slice {
		if s == item {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected slice to contain %q, but it didn't. Contents: %v", item, slice)
	}
}
