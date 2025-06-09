# ApexPenetrateGo

![ApexPenetrate Logo Placeholder](https://via.placeholder.com/150x50?text=ApexPenetrate-Go)

ApexPenetrateGo is an automated penetration testing tool written in Go. It streamlines various stages of security assessments, from reconnaissance to vulnerability scanning and reporting.

## Features (Initial)

* **Reconnaissance:**
    * Subdomain Enumeration (Concurrent Brute-force with HTTP HEAD requests)
    * (Placeholder for Passive methods)
* **Modular Architecture:** Designed for easy extension with new testing modules.
* **Flexible Output:** Save results in JSON, TXT, CSV, or display directly to console.
* **Robust Logging:** Detailed logging for debugging and audit trails using logrus.
* **Single Binary:** Compile into a single executable for easy deployment.
* **Fast, concurrent TCP port scanning**
* **Shodan & Censys API Integration:** Enriches recon with internet-wide data (use --shodan, --censys-id, --censys-secret flags)
* **Web Vulnerability Scanning:** Automated XSS detection (with more to come)
* **Modular CLI:** Select modules to run with --modules (e.g. recon,ports,shodan,xss,smb)
* **Config File Support:** Store API keys, module toggles, and constants in apexpenetrate.yaml or .json
* **DNS Recon:** Automated DNS record enumeration
* **HTTP Recon:** HTTP header and status code analysis
* **SQLi Scanner:** Automated SQL injection detection

## Installation

Go 1.22 or newer is required.

1.  **Clone the repository:**
    `ash
    git clone [https://github.com/YourUsername/apexPenetrateGo.git](https://github.com/YourUsername/apexPenetrateGo.git)
    cd apexPenetrateGo
    `

2.  **Download dependencies and build the executable:**
    `ash
    go mod tidy
    go build -o apexpenetrate .
    `
    This will create an executable named pexpenetrate (or pexpenetrate.exe on Windows) in the current directory.

3.  **(Optional) Add to your PATH:**
    For easier access, move the pexpenetrate executable to a directory in your system's PATH (e.g., /usr/local/bin/ on Linux/macOS, or a directory added to PATH on Windows).

## Usage

### Basic Reconnaissance

To perform subdomain enumeration on a target:

`ash
./apexpenetrate recon example.com
`
(On Windows, use .\apexpenetrate.exe recon example.com)

### Using a Custom Wordlist

`ash
./apexpenetrate recon example.com --wordlist path/to/your/wordlist.txt
`

### Saving Results to a File

Save results in JSON format:

`ash
./apexpenetrate recon example.com --output results.json --format json
`

Save results in plain text:

`ash
./apexpenetrate recon example.com --output subdomains.txt --format txt
`

### Verbose Output for Debugging

`ash
./apexpenetrate -v recon example.com
`

### Running the CLI

To run the CLI directly:

`ash
go run main.go
`

### TCP Port Scanning

Scan a range of ports on a target:

```sh
./apexpenetrate scan --target 127.0.0.1 --ports 1-1024
```

Scan specific ports:

```sh
./apexpenetrate scan --target 127.0.0.1 --ports 22,80,443
```

Set a custom timeout per port:

```sh
./apexpenetrate scan --target 127.0.0.1 --ports 80 --timeout 500ms
```

### Full Automated Workflow

Run all recon modules in sequence (subdomain enum, port scan, banner grab, SMB enum):

```sh
./apexpenetrate full-auto --target example.com
```

## Running Tests

Navigate to the root of the pexPenetrateGo project and run:

`ash
go test ./...
`

## Example: Port Scanning

To scan specific ports on a target IP:

```go
scanner := reconnaissance.NewPortScanner("127.0.0.1", []int{22, 80, 443}, time.Second)
results := scanner.ScanPorts()
for port, state := range results {
    fmt.Printf("Port %d: %s\n", port, state)
}
```

## Project Structure

`
apexPenetrateGo/
├── main.go
├── go.mod
├── go.sum
├── cmd/
│   ├── root.go
│   ├── recon.go
│   └── scan.go
├── internal/
│   ├── core/
│   │   ├── errors.go
│   │   └── logger/
│   │       └── logger.go
│   ├── modules/
│   │   ├── reconnaissance/
│   │   │   ├── subdomain_enum.go
│   │   │   └── port_scan.go
│   │   ├── network_vulnerabilities/
│   │   │   └── smb_enum.go
│   │   └── web_vulnerabilities/
│   │       └── xss_scanner.go
│   ├── output/
│   │   └── formatter.go
│   └── reporting/
│       └── report_gen.go
└── test/
    └── internal/
        └── modules/
            └── reconnaissance/
                └── subdomain_enum_test.go
`

## Contributing

We welcome contributions! Please see our CONTRIBUTING.md (to be created) for details on how to contribute.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
