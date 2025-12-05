# TryHarder Security Suite

```
  _____          _  _               _
 |_   _| __ _  _| || |__ _ _ _ __| |___ _ _
   | || '__| || | __ / _` | '_/ _` / -_) '_|
   |_||_|   \_, |_||_\__,_|_| \__,_\___|_|
            |__/   Security Suite v1.0.0
```

**15-in-1 Browser Security Testing Toolkit**

A powerful browser extension for security researchers, penetration testers, and CTF players. All tools work directly in your browser - no external dependencies required.

## Author

**a0x194** - [GitHub](https://github.com/a0x194)

Part of the [TryHarder](https://www.tryharder.space) CTF Platform

## Features

### Tier 1 - Core Reconnaissance
| Tool | Description |
|------|-------------|
| **SubRecon** | Subdomain enumeration via certificate transparency logs and wordlists |
| **ParamFuzz** | Parameter discovery with multiple wordlist presets |
| **JSHunter** | Extract endpoints, secrets, domains, emails, and IPs from JavaScript files |
| **SQLiDetect** | SQL injection vulnerability detection (error, time, boolean, union-based) |
| **AuthBypass** | IDOR testing, method override, header bypass, and path traversal |

### Tier 2 - Information Gathering
| Tool | Description |
|------|-------------|
| **WaybackMiner** | Mine historical data from Wayback Machine |
| **HeaderAudit** | Security headers analysis and recommendations |
| **APIRecon** | API endpoint discovery (Swagger, GraphQL, common paths) |
| **PortRush** | Fast async port scanning with preset configurations |
| **GitLeaks** | Detect exposed .git folders and sensitive files |

### Tier 3 - Advanced Analysis
| Tool | Description |
|------|-------------|
| **ProtoDetect** | Protocol detection on non-standard ports |
| **CertWatch** | SSL/TLS certificate analysis and subdomain discovery |
| **DNSTracer** | DNS record enumeration and security analysis |
| **WebTechFP** | Website technology fingerprinting |
| **CachePoison** | Web cache poisoning detection |

## Installation

### Chrome / Edge (Chromium-based browsers)

1. Download or clone this repository
2. Open `chrome://extensions/` (or `edge://extensions/`)
3. Enable "Developer mode" (toggle in top-right)
4. Click "Load unpacked"
5. Select the `tryharder-extension` folder

### Firefox

1. Download or clone this repository
2. Open `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on"
4. Select the `manifest.json` file in the `tryharder-extension` folder

> **Note:** For permanent Firefox installation, the extension needs to be signed by Mozilla or installed in Developer Edition with `xpinstall.signatures.required` set to `false`.

## Usage

1. Click the TryHarder icon in your browser toolbar
2. Select a tool from the sidebar (organized by tier)
3. Enter target information and configure options
4. Click "Run" to start the scan
5. View results and export in multiple formats (JSON, CSV, Markdown, HTML)

## Keyboard Shortcuts

- `Ctrl+Shift+T` - Open extension popup
- `Escape` - Close popup

## Export Formats

All results can be exported in:
- **JSON** - Full structured data
- **CSV** - Spreadsheet-compatible format
- **Markdown** - Documentation-ready format
- **HTML** - Styled report for sharing

## Disclaimer

This tool is intended for **authorized security testing only**. Always ensure you have proper authorization before testing any target. Unauthorized access to computer systems is illegal.

The authors are not responsible for any misuse of this tool.

## Tech Stack

- Manifest V3 (Chrome/Edge/Firefox compatible)
- Pure JavaScript (ES6 Modules)
- No external dependencies
- Custom TryHarder theme (black/green cyber aesthetic)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Links

- **Platform**: [https://www.tryharder.space](https://www.tryharder.space)
- **GitHub**: [https://github.com/a0x194](https://github.com/a0x194)
- **Issues**: [Report a bug](https://github.com/a0x194/tryharder-extension/issues)

---

```
>_TH  Built with passion by the TryHarder team
```
