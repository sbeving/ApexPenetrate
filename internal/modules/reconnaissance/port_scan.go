// internal/modules/reconnaissance/port_scan.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core/logger"
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

// PortScanner holds the state for port scanning
// PortScanner scans TCP ports on a target IP address.
type PortScanner struct {
	TargetIP string
	Ports    []int
	Timeout  time.Duration
	Log      *logrus.Logger
}

// NewPortScanner creates a new instance of PortScanner
func NewPortScanner(targetIP string, ports []int, timeout time.Duration) *PortScanner {
	if len(ports) == 0 {
		ports = []int{21, 22, 80, 443, 8080} // Common ports
	}
	if timeout == 0 {
		timeout = 1 * time.Second
	}
	return &PortScanner{
		TargetIP: targetIP,
		Ports:    ports,
		Timeout:  timeout,
		Log:      logger.GetLogger(),
	}
}

// ScanPorts concurrently scans the specified ports and returns their status.
func (s *PortScanner) ScanPorts() map[int]string {
	s.Log.Infof("Starting port scan for %s on ports %v...", s.TargetIP, s.Ports)
	results := make(map[int]string)
	resultsCh := make(chan struct {
		port  int
		state string
	}, len(s.Ports))

	for _, port := range s.Ports {
		go func(port int) {
			address := net.JoinHostPort(s.TargetIP, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", address, s.Timeout)
			if err != nil {
				resultsCh <- struct {
					port  int
					state string
				}{port, "CLOSED"}
				return
			}
			conn.Close()
			resultsCh <- struct {
				port  int
				state string
			}{port, "OPEN"}
		}(port)
	}

	for i := 0; i < len(s.Ports); i++ {
		res := <-resultsCh
		results[res.port] = res.state
	}

	s.Log.Info("Port scan complete.")
	return results
}

// ScanPortRange scans a range of ports (inclusive) and returns their status.
func (s *PortScanner) ScanPortRange(ctx context.Context, start, end int) map[int]string {
	if start < 1 || end > 65535 || start > end {
		s.Log.Errorf("Invalid port range: %d-%d", start, end)
		return nil
	}
	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	// Temporarily override Ports for this scan
	origPorts := s.Ports
	s.Ports = ports
	results := s.ScanPortsCtx(ctx)
	s.Ports = origPorts
	return results
}

// ScanPortsCtx is like ScanPorts but supports context cancellation.
func (s *PortScanner) ScanPortsCtx(ctx context.Context) map[int]string {
	s.Log.Infof("Starting port scan for %s on ports %v...", s.TargetIP, s.Ports)
	results := make(map[int]string)
	resultsCh := make(chan struct {
		port  int
		state string
	}, len(s.Ports))

	for _, port := range s.Ports {
		go func(port int) {
			select {
			case <-ctx.Done():
				resultsCh <- struct {
					port  int
					state string
				}{port, "CANCELLED"}
				return
			default:
				address := net.JoinHostPort(s.TargetIP, fmt.Sprintf("%d", port))
				conn, err := net.DialTimeout("tcp", address, s.Timeout)
				if err != nil {
					resultsCh <- struct {
						port  int
						state string
					}{port, "CLOSED"}
					return
				}
				conn.Close()
				resultsCh <- struct {
					port  int
					state string
				}{port, "OPEN"}
			}
		}(port)
	}

	for i := 0; i < len(s.Ports); i++ {
		res := <-resultsCh
		results[res.port] = res.state
	}

	s.Log.Info("Port scan complete.")
	return results
}

// ScanPortsWithBanners scans ports and grabs banners for open ports.
func (s *PortScanner) ScanPortsWithBanners() map[int]map[string]string {
	s.Log.Infof("Starting port scan with banner grabbing for %s on ports %v...", s.TargetIP, s.Ports)
	results := make(map[int]map[string]string)
	resultsCh := make(chan struct {
		port   int
		state  string
		banner string
	}, len(s.Ports))

	for _, port := range s.Ports {
		go func(port int) {
			address := net.JoinHostPort(s.TargetIP, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", address, s.Timeout)
			if err != nil {
				resultsCh <- struct {
					port          int
					state, banner string
				}{port, "CLOSED", ""}
				return
			}
			defer conn.Close()
			// Try to grab a banner (read a line or up to 128 bytes)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			reader := bufio.NewReader(conn)
			banner, _ := reader.ReadString('\n')
			if len(banner) == 0 {
				buf := make([]byte, 128)
				n, _ := reader.Read(buf)
				banner = string(buf[:n])
			}
			resultsCh <- struct {
				port          int
				state, banner string
			}{port, "OPEN", banner}
		}(port)
	}

	for i := 0; i < len(s.Ports); i++ {
		res := <-resultsCh
		results[res.port] = map[string]string{"state": res.state, "banner": res.banner}
	}

	s.Log.Info("Port scan with banner grabbing complete.")
	return results
}
