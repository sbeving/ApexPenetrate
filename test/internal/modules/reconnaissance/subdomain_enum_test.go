// test/internal/modules/reconnaissance/subdomain_enum_test.go
package reconnaissance_test

import (
	"apexPenetrateGo/internal/modules/reconnaissance"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestSubdomainEnumerator_EnumerateSubdomains_DefaultWordlist(t *testing.T) {
	// Mock server that returns 200 for any request
	mockServer := setupMockServer(http.StatusOK)
	defer mockServer.Close()

	// Redirect HTTP client to our mock server for all requests
	oldClient := reconnaissance.DefaultHTTPClient
	reconnaissance.DefaultHTTPClient = mockServer.Client()
	defer func() { reconnaissance.DefaultHTTPClient = oldClient }()

	enumerator := reconnaissance.NewSubdomainEnumerator("example.com", "") // Use default wordlist

	subdomains, err := enumerator.EnumerateSubdomains()
	if err != nil {
		t.Fatalf("EnumerateSubdomains returned an error: %v", err)
	}

	// Based on the mock server, all default wordlist entries should resolve.
	// Plus the passive placeholders for "example.com"
	expectedCount := len(reconnaissance.GetDefaultWordlist()) + 2 // +2 for passive placeholders
	if len(subdomains) != expectedCount {
		t.Errorf("Expected %d subdomains, got %d", expectedCount, len(subdomains))
	}

	// Check if some expected subdomains are present
	assertContains(t, subdomains, "www.example.com")
	assertContains(t, subdomains, "api.example.com")
	assertContains(t, subdomains, "test.example.com")    // From passive placeholder
	assertContains(t, subdomains, "another.example.com") // From passive placeholder
}

func TestSubdomainEnumerator_EnumerateSubdomains_CustomWordlist(t *testing.T) {
	mockServer := setupMockServer(http.StatusOK)
	defer mockServer.Close()

	oldClient := reconnaissance.DefaultHTTPClient
	reconnaissance.DefaultHTTPClient = mockServer.Client()
	defer func() { reconnaissance.DefaultHTTPClient = oldClient }()

	// Create a temporary wordlist file
	tempFile, err := os.CreateTemp("", "wordlist_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name()) // Clean up the file

	content := "customsub1
customsub2
"
	_, err = tempFile.WriteString(content)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close() // Close the file before reading

	enumerator := reconnaissance.NewSubdomainEnumerator("testdomain.com", tempFile.Name())

	subdomains, err := enumerator.EnumerateSubdomains()
	if err != nil {
		t.Fatalf("EnumerateSubdomains returned an error: %v", err)
	}

	// Based on the mock server, all custom wordlist entries should resolve.
	// Passive enumeration for "testdomain.com" will not add anything by default.
	if len(subdomains) != 2 {
		t.Errorf("Expected 2 subdomains, got %d", len(subdomains))
	}

	assertContains(t, subdomains, "customsub1.testdomain.com")
	assertContains(t, subdomains, "customsub2.testdomain.com")
}

func TestSubdomainEnumerator_EnumerateSubdomains_NoResolution(t *testing.T) {
	// Mock server that returns 404 for all requests (no resolution)
	mockServer := setupMockServer(http.StatusNotFound)
	defer mockServer.Close()

	oldClient := reconnaissance.DefaultHTTPClient
	reconnaissance.DefaultHTTPClient = mockServer.Client()
	defer func() { reconnaissance.DefaultHTTPClient = oldClient }()

	enumerator := reconnaissance.NewSubdomainEnumerator("noexist.com", "")

	subdomains, err := enumerator.EnumerateSubdomains()
	if err != nil {
		t.Fatalf("EnumerateSubdomains returned an error: %v", err)
	}

	// No subdomains should be found from brute-force or passive if target is not "example.com"
	if len(subdomains) != 0 {
		t.Errorf("Expected 0 subdomains, got %d", len(subdomains))
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
		enumerator := reconnaissance.NewSubdomainEnumerator(tt.input, "")
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
