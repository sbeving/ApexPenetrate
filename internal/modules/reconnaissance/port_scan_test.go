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
	validStates := map[string]bool{"open": true, "closed": true, "filtered": true}
	for port, state := range results {
		t.Logf("Port %d: %s", port, state)
		if !validStates[state] {
			t.Errorf("Invalid state for port %d: %s", port, state)
		}
	}
	open, closed, filtered := 0, 0, 0
	for _, state := range results {
		switch state {
		case "open":
			open++
		case "closed":
			closed++
		case "filtered":
			filtered++
		}
	}
	t.Logf("Summary: %d open, %d closed, %d filtered", open, closed, filtered)
}

func TestPortScanner_EmptyPorts(t *testing.T) {
	scanner := NewPortScanner("127.0.0.1", []int{}, 200*time.Millisecond)
	results := scanner.ScanPorts()
	if len(results) == 0 {
		t.Log("No ports provided, result is empty as expected.")
	} else {
		t.Errorf("Expected empty result for no ports, got %d", len(results))
	}
}

func TestPortScanner_InvalidIP(t *testing.T) {
	scanner := NewPortScanner("256.256.256.256", []int{80}, 200*time.Millisecond)
	results := scanner.ScanPorts()
	if state, ok := results[80]; ok {
		t.Logf("Port 80 on invalid IP: %s", state)
		if state != "closed" && state != "filtered" {
			t.Errorf("Expected closed or filtered for invalid IP, got %s", state)
		}
	} else {
		t.Errorf("Expected result for port 80, got none")
	}
}
