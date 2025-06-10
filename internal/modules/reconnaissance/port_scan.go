// internal/modules/reconnaissance/port_scan.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"apexPenetrateGo/internal/core/logger"
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
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

// Port Scanner Plugin Implementation
type portScanPlugin struct{}

func (p *portScanPlugin) Name() string {
	return "PortScan"
}

func (p *portScanPlugin) Description() string {
	return "TCP port scanner with banner grabbing capabilities"
}

func (p *portScanPlugin) Category() string {
	return "reconnaissance"
}

func (p *portScanPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "ports", Type: "string", Default: "22,80,443,8080,3389", Description: "Comma-separated ports or ranges (e.g., 1-1000,8080)", Required: false},
		{Name: "timeout", Type: "string", Default: "3s", Description: "Connection timeout per port", Required: false},
		{Name: "threads", Type: "int", Default: 100, Description: "Number of concurrent threads", Required: false},
		{Name: "banner", Type: "bool", Default: true, Description: "Enable banner grabbing", Required: false},
	}
}

func (p *portScanPlugin) Help() string {
	return `
🔍 PortScan Module - TCP Port Scanner with Banner Grabbing

📋 DESCRIPTION:
   Advanced TCP port scanner that detects open ports and grabs service banners.
   Supports concurrent scanning with customizable timeout and thread count.

🎯 USAGE EXAMPLES:
   • Basic scan on common ports:
     apex> use PortScan
     apex(PortScan)> set ports 22,80,443,8080
     apex(PortScan)> run

   • Scan port range with custom timeout:
     apex(PortScan)> set ports 1-1000
     apex(PortScan)> set timeout 5s
     apex(PortScan)> set threads 50
     apex(PortScan)> run

   • Quick scan without banner grabbing:
     apex(PortScan)> set banner false
     apex(PortScan)> set ports 1-65535
     apex(PortScan)> run

⚙️  OPTIONS:
   ports    - Target ports (comma-separated or ranges)
   timeout  - Connection timeout (e.g., 3s, 500ms)
   threads  - Concurrent connections (1-1000)
   banner   - Enable/disable banner grabbing

🛡️  DETECTION EVASION:
   • Use longer timeouts to avoid triggering IDS
   • Reduce thread count for stealthier scanning
   • Consider using UDP scan for additional coverage

💡 PRO TIPS:
   • Combine with ServiceVersionDetect for detailed enumeration
   • Use CVEScanner after finding open services
   • Save results for later analysis and reporting
`
}

func (p *portScanPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	// Parse options
	portsStr := "22,80,443,8080,3389"
	if val, ok := options["ports"]; ok && val != nil {
		portsStr = val.(string)
	}

	timeoutStr := "3s"
	if val, ok := options["timeout"]; ok && val != nil {
		timeoutStr = val.(string)
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout format: %v", err)
	}

	// Parse ports
	ports := []int{}
	portParts := strings.Split(portsStr, ",")
	for _, part := range portParts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// Range format (e.g., "1-1000")
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start > end {
				continue
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			// Single port
			port, err := strconv.Atoi(part)
			if err == nil && port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports specified")
	}
	// Create scanner and run
	scanner := NewPortScanner(target, ports, timeout)
	results := scanner.ScanPorts()
	// Extract open ports for response
	openPorts := []int{}
	portDetails := make(map[string]interface{})

	for port, state := range results {
		if state == "OPEN" {
			openPorts = append(openPorts, port)
			portDetails[fmt.Sprintf("%d", port)] = map[string]string{"state": state}
		}
	}

	return map[string]interface{}{
		"open_ports":    openPorts,
		"port_details":  portDetails,
		"total_scanned": len(ports),
		"target":        target,
	}, nil
}

func init() {
	core.RegisterPlugin(&portScanPlugin{})
}
