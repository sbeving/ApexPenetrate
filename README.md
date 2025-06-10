# ApexPenetrateGo

<p align="center">
  <img src="assets/logo.png" width="320" alt="ApexPenetrateGo Logo"/>
</p>

<p align="center">
  <a href="https://github.com/yourusername/apexpenetratego/stargazers"><img src="https://img.shields.io/github/stars/yourusername/apexpenetratego?style=social"/></a>
  <img src="https://img.shields.io/github/license/yourusername/apexpenetratego"/>
</p>

---

> **ApexPenetrateGo** is a modern, modular, and visually stunning automated penetration testing tool for professionals. Fast, extensible, and beautiful.

---

## 🚀 Demo

![ApexPenetrateGo CLI Demo](assets/demo.gif)

> **Place your logo as `assets/logo.png` and a CLI demo as `assets/demo.gif` for best results!**

---

## Why ApexPenetrateGo?
- **All-in-one**: Recon, OSINT, port scan, web vulns, reporting, and more.
- **Beautiful CLI**: Colorful, emoji-rich, and ASCII art banners.
- **Modular**: Add your own plugins and modules easily.
- **Fast & Concurrent**: Built with Go for speed and reliability.
- **API Integrations**: Shodan, Censys, crt.sh, and more.
- **Pro Reporting**: HTML, JSON, TXT, CSV outputs.
- **Open Source & Community-Driven**

---

## Features

* **Reconnaissance:**
    * Subdomain Enumeration (DNS + OSINT, no wordlists needed)
    * DNS Recon, HTTP Recon
* **Port Scanning:** Fast, concurrent TCP scan with banner grabbing
* **Web Vulnerability Scanning:** XSS, SQLi modules
* **API Integrations:** Shodan, Censys, crt.sh
* **Modular CLI:** Run only what you want with `--modules`
* **Config File Support:** YAML/JSON for API keys and settings
* **Beautiful Output:** Console, JSON, TXT, CSV, HTML report
* **Extensible:** Easy to add new modules/plugins

---

## Installation

**Go 1.22+ required.**

```sh
# Clone the repository
git clone https://github.com/yourusername/apexpenetratego.git
cd apexpenetratego

# Build the executable
go build -o apexpenetrate

# (Optional) Install globally
# On Linux/macOS:
sudo mv apexpenetrate /usr/local/bin/
# On Windows, add the folder to your PATH
```

---

## Usage

### Basic Reconnaissance

```sh
apexpenetrate recon example.com
```

### Save Results as JSON

```sh
apexpenetrate recon example.com -o results.json -f json
```

### Full Automated Workflow

```sh
apexpenetrate full-auto --target example.com
```

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

- Open issues for bugs/feature requests
- Submit pull requests for improvements
- Add your module/plugin to the registry!

---

## License

[MIT](LICENSE)

---

## ⭐️ Star This Project!
If you like ApexPenetrateGo, please give us a star on GitHub and share it with your friends and colleagues!

<p align="center">
  <a href="https://github.com/yourusername/apexpenetratego/stargazers">
    <img src="https://img.shields.io/github/stars/yourusername/apexpenetratego?style=social"/>
  </a>
</p>

---

## Acknowledgements
- Inspired by tools like Amass, Subfinder, Nmap, and ProjectDiscovery.
- Thanks to the Go community and all contributors!
