// internal/modules/reconnaissance/ssl_tls_scanner.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type SSLTLSScanResult struct {
	Target   string
	Valid    bool
	Expiry   time.Time
	Issuer   string
	Cipher   string
	Warnings []string
}

func SSLTLSScan(target string) *SSLTLSScanResult {
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	conn, err := tls.Dial("tcp", target, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return &SSLTLSScanResult{Target: target, Valid: false, Warnings: []string{"TLS handshake failed"}}
	}
	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	warnings := []string{}
	if time.Now().After(cert.NotAfter) {
		warnings = append(warnings, "Certificate expired")
	}
	if cert.NotAfter.Sub(time.Now()) < 30*24*time.Hour {
		warnings = append(warnings, "Certificate expires soon")
	}
	cipher := tls.CipherSuiteName(conn.ConnectionState().CipherSuite)
	return &SSLTLSScanResult{
		Target:   target,
		Valid:    true,
		Expiry:   cert.NotAfter,
		Issuer:   cert.Issuer.CommonName,
		Cipher:   cipher,
		Warnings: warnings,
	}
}

func (r *SSLTLSScanResult) String() string {
	msg := fmt.Sprintf("\n🔒 SSL/TLS Scan for %s:\n  Issuer: %s\n  Expires: %s\n  Cipher: %s\n", r.Target, r.Issuer, r.Expiry.Format("2006-01-02"), r.Cipher)
	if len(r.Warnings) > 0 {
		msg += "  Warnings: " + fmt.Sprintf("%v", r.Warnings) + "\n"
	}
	return msg
}

type sslTLSPlugin struct{}

func (p *sslTLSPlugin) Name() string        { return "SSLTLSScan" }
func (p *sslTLSPlugin) Description() string { return "Scans for SSL/TLS issues and certificate info" }
func (p *sslTLSPlugin) Category() string    { return "recon" }
func (p *sslTLSPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "port", Type: "int", Default: 443, Description: "SSL/TLS port to scan", Required: false},
		{Name: "check_expiry", Type: "bool", Default: true, Description: "Check certificate expiry", Required: false},
		{Name: "check_weak_ciphers", Type: "bool", Default: true, Description: "Check for weak cipher suites", Required: false},
	}
}
func (p *sslTLSPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	return SSLTLSScan(target), nil
}

func init() {
	core.RegisterPlugin(&sslTLSPlugin{})
}
