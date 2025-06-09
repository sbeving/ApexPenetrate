package reconnaissance

import (
	"testing"
	"time"
)

func TestPortScanner_ScanPorts(t *testing.T) {
	scanner := NewPortScanner("127.0.0.1", []int{22, 80, 443, 9999}, 200*time.Millisecond)
	results := scanner.ScanPorts()
	if len(results) != 4 {
		t.Errorf("Expected 4 results, got %d", len(results))
	}
	for port, state := range results {
		t.Logf("Port %d: %s", port, state)
	}
}
