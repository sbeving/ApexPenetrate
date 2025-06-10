// internal/modules/reconnaissance/udp_port_scan.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type UDPPortScanResult struct {
	Target string
	Ports  []int
	Status map[int]string // port -> open/closed/filtered
}

func UDPPortScan(target string, ports []int, timeout time.Duration) *UDPPortScanResult {
	if len(ports) == 0 {
		ports = []int{53, 67, 68, 69, 123, 161, 500, 514, 520, 33434} // common UDP ports
	}
	status := make(map[int]string)
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("udp", addr, timeout)
		if err != nil {
			status[port] = "filtered"
			continue
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))
		_, err = conn.Write([]byte("\x00"))
		if err != nil {
			status[port] = "filtered"
			continue
		}
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		if err != nil {
			// No response: could be open or filtered (UDP is stateless)
			status[port] = "open|filtered"
		} else {
			status[port] = "open"
		}
	}
	return &UDPPortScanResult{Target: target, Ports: ports, Status: status}
}

func (r *UDPPortScanResult) String() string {
	msg := fmt.Sprintf("\n📡 UDP Port Scan for %s:\n", r.Target)
	for _, port := range r.Ports {
		msg += fmt.Sprintf("  %d/udp: %s\n", port, r.Status[port])
	}
	return msg
}

type udpPortScannerPlugin struct{}

func (p *udpPortScannerPlugin) Name() string { return "UDPPortScan" }
func (p *udpPortScannerPlugin) Description() string {
	return "Scans UDP ports for open/filtered status"
}
func (p *udpPortScannerPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	ports := []int{}
	if val, ok := options["ports"]; ok {
		switch v := val.(type) {
		case string:
			// parse comma-separated string
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
	return UDPPortScan(target, ports, timeout), nil
}
func (p *udpPortScannerPlugin) Category() string { return "scan" }
func (p *udpPortScannerPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "ports", Type: "string", Default: "53,67,68,69,123,161,500,514,520,33434", Description: "Comma-separated UDP ports to scan", Required: false},
		{Name: "timeout", Type: "string", Default: "2s", Description: "Timeout per port (e.g. 1s, 500ms)", Required: false},
	}
}
func (p *udpPortScannerPlugin) Help() string {
	return `
📡 UDP Port Scanner - UDP Service Discovery

DESCRIPTION:
  Scans UDP ports to discover services that don't respond to TCP connections.
  Essential for finding DNS, SNMP, DHCP and other UDP-based services.

USAGE:
  udpportscan <target_ip> [options]

OPTIONS:
  ports   - Comma-separated UDP port list (default: common UDP ports)
  timeout - Response timeout per port (default: 2s)

EXAMPLES:
  udpportscan 192.168.1.1
  udpportscan dns.server.com --ports 53,853
  udpportscan 10.0.0.1 --timeout 5s

COMMON UDP SERVICES:
  • DNS (53): Domain name resolution
  • DHCP (67,68): Dynamic host configuration
  • TFTP (69): Trivial file transfer
  • NTP (123): Network time protocol
  • SNMP (161): Simple network management

PRO TIPS:
  💡 UDP scanning is slower and less reliable than TCP
  💡 Look for SNMP (161) for network device management
  💡 Check for NTP (123) for time-based attacks
  💡 DNS (53) can reveal internal network information

RISK LEVEL: Low to Medium (service discovery for targeted attacks)
`
}

func init() {
	core.RegisterPlugin(&udpPortScannerPlugin{})
}
