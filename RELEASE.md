# TryHarder Security Suite v1.0.0 - Release Notes

## Download

**All browsers use the same file:** `tryharder-security-suite-v1.0.0.zip`

This extension is built with Manifest V3 and is compatible with:
- Google Chrome (v88+)
- Microsoft Edge (v88+)
- Mozilla Firefox (v109+)
- Brave Browser
- Opera
- Any Chromium-based browser

---

## Installation Guide

### Chrome / Edge / Brave / Opera (Chromium-based)

1. Download `tryharder-security-suite-v1.0.0.zip`
2. Extract the ZIP file to a folder
3. Open your browser and go to:
   - **Chrome**: `chrome://extensions/`
   - **Edge**: `edge://extensions/`
   - **Brave**: `brave://extensions/`
   - **Opera**: `opera://extensions/`
4. Enable **"Developer mode"** (toggle in top-right corner)
5. Click **"Load unpacked"**
6. Select the extracted folder (the one containing `manifest.json`)
7. Done! Click the TryHarder icon in your toolbar

### Firefox

**Option 1: Temporary Installation (for testing)**
1. Download `tryharder-security-suite-v1.0.0.zip`
2. Extract the ZIP file
3. Go to `about:debugging#/runtime/this-firefox`
4. Click **"Load Temporary Add-on"**
5. Select the `manifest.json` file inside the extracted folder
6. Done! Note: Extension will be removed when Firefox closes

**Option 2: Permanent Installation (Developer Edition)**
1. Download Firefox Developer Edition
2. Go to `about:config`
3. Set `xpinstall.signatures.required` to `false`
4. Install the extension normally

**Option 3: Submit to Mozilla Add-ons (for public distribution)**
- Submit the ZIP to https://addons.mozilla.org for signing

---

## What's Included

### 15 Security Tools:

| Tier | Tool | Description |
|------|------|-------------|
| 1 | SubRecon | Subdomain enumeration via CT logs |
| 1 | ParamFuzz | Parameter discovery |
| 1 | JSHunter | JavaScript secrets extraction |
| 1 | SQLiDetect | SQL injection detection |
| 1 | AuthBypass | IDOR & auth bypass testing |
| 2 | WaybackMiner | Wayback Machine mining |
| 2 | HeaderAudit | Security headers analysis |
| 2 | APIRecon | API endpoint discovery |
| 2 | PortRush | Port scanning |
| 2 | GitLeaks | Exposed .git detection |
| 3 | ProtoDetect | Protocol detection |
| 3 | CertWatch | Certificate analysis |
| 3 | DNSTracer | DNS enumeration |
| 3 | WebTechFP | Technology fingerprinting |
| 3 | CachePoison | Cache poisoning detection |

---

## File Structure

```
tryharder-security-suite-v1.0.0/
├── manifest.json          # Extension manifest (MV3)
├── popup.html             # Main UI
├── css/
│   └── popup.css          # TryHarder theme styling
├── js/
│   ├── background.js      # Service worker
│   ├── content.js         # Content script
│   ├── popup.js           # Main controller
│   ├── modules/           # 15 tool modules
│   │   ├── jshunter.js
│   │   ├── paramfuzz.js
│   │   ├── subrecon.js
│   │   ├── sqlidetect.js
│   │   ├── authbypass.js
│   │   ├── wayback.js
│   │   ├── headeraudit.js
│   │   ├── apirecon.js
│   │   ├── portrush.js
│   │   ├── gitleaks.js
│   │   ├── certwatch.js
│   │   ├── dnstracer.js
│   │   ├── webtechfp.js
│   │   ├── cachepoison.js
│   │   └── protodetect.js
│   └── utils/             # Utility modules
│       ├── ui.js
│       ├── storage.js
│       └── export.js
├── icons/                 # Extension icons
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
├── README.md
└── LICENSE
```

---

## Changelog

### v1.0.0 (2024-12-03)
- Initial release
- 15 security tools integrated
- Cross-browser support (Chrome, Edge, Firefox)
- TryHarder black/green cyber theme
- Export to JSON, CSV, Markdown, HTML
- Context menu integration
- Auto-fill current URL

---

## Author

**a0x194** - https://github.com/a0x194

## Platform

**TryHarder CTF** - https://www.tryharder.space

---

## Legal

For authorized security testing only. Always ensure you have permission before testing any target.

MIT License - see LICENSE file for details.
