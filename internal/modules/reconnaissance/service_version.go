// internal/modules/reconnaissance/service_version.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type ServiceVersionResult struct {
	Target string
	Port   int
	Banner string
	Info   string
	Error  string
}

type ServiceVersionScanner struct {
	Target  string
	Ports   []int
	Timeout time.Duration
}

func NewServiceVersionScanner(target string, ports []int, timeout time.Duration) *ServiceVersionScanner {
	if len(ports) == 0 {
		ports = []int{21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5900, 8080}
	}
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &ServiceVersionScanner{Target: target, Ports: ports, Timeout: timeout}
}

// Scan grabs banners from open ports and tries to parse version info
func (s *ServiceVersionScanner) Scan() []ServiceVersionResult {
	results := []ServiceVersionResult{}
	for _, port := range s.Ports {
		addr := fmt.Sprintf("%s:%d", s.Target, port)
		conn, err := net.DialTimeout("tcp", addr, s.Timeout)
		if err != nil {
			results = append(results, ServiceVersionResult{Target: s.Target, Port: port, Error: err.Error()})
			continue
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		banner := ""
		scan := bufio.NewScanner(conn)
		if scan.Scan() {
			banner = scan.Text()
		}
		if banner == "" {
			// Try reading raw bytes
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			banner = string(buf[:n])
		}
		conn.Close()
		info := parseBanner(banner)
		results = append(results, ServiceVersionResult{Target: s.Target, Port: port, Banner: banner, Info: info})
	}
	return results
}

func parseBanner(banner string) string {
	banner = strings.ToLower(banner)
	sigs := map[string]string{
		"ssh":   "SSH",
		"ftp":   "FTP",
		"smtp":  "SMTP",
		"http":  "HTTP",
		"mysql": "MySQL",
		"rdp":   "RDP",
		"vnc":   "VNC",
		"pop3":  "POP3",
		"imap":  "IMAP",
	}
	for sig, name := range sigs {
		if strings.Contains(banner, sig) {
			return name + " detected"
		}
	}
	if len(banner) > 0 {
		return "Unknown service"
	}
	return "No banner"
}

func (r ServiceVersionResult) String() string {
	if r.Error != "" {
		return fmt.Sprintf("❌ %s:%d - %s", r.Target, r.Port, r.Error)
	}
	return fmt.Sprintf("🔎 %s:%d - %s\n  Banner: %s", r.Target, r.Port, r.Info, r.Banner)
}

type serviceVersionPlugin struct{}

func (p *serviceVersionPlugin) Name() string { return "ServiceVersionDetect" }
func (p *serviceVersionPlugin) Description() string {
	return "Detects service versions via banner grabbing (nmap-like)"
}
func (p *serviceVersionPlugin) Category() string { return "scan" }
func (p *serviceVersionPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	ports := []int{}
	if val, ok := options["ports"]; ok {
		switch v := val.(type) {
		case string:
			for _, pstr := range strings.Split(v, ",") {
				pstr = strings.TrimSpace(pstr)
				if pstr == "" {
					continue
				}
				if n, err := strconv.Atoi(pstr); err == nil {
					ports = append(ports, n)
				}
			}
		case []int:
			ports = v
		}
	}
	timeout := 2 * time.Second
	if val, ok := options["timeout"]; ok {
		if t, ok := val.(string); ok {
			if d, err := time.ParseDuration(t); err == nil {
				timeout = d
			}
		}
	}
	scanner := NewServiceVersionScanner(target, ports, timeout)
	return scanner.Scan(), nil
}
func (p *serviceVersionPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "ports", Type: "string", Default: "21,22,23,25,53,80,110,143,443,3306,3389", Description: "Comma-separated TCP ports to scan for service version", Required: false},
		{Name: "timeout", Type: "string", Default: "2s", Description: "Timeout per port (e.g. 1s, 500ms)", Required: false},
	}
}

func init() {
	core.RegisterPlugin(&serviceVersionPlugin{})
}
