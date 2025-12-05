/**
 * TryHarder Security Suite - PortRush Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Fast async port scanning (browser-limited)
 */

import { UI } from '../utils/ui.js';

export class PortRush {
  constructor(app) {
    this.app = app;
    this.results = [];
    this.isRunning = false;

    // Port presets
    this.portPresets = {
      common: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 8080],
      web: [80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 9443, 3000, 5000],
      top100: [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
        1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
        5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
        8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154
      ]
    };

    // Service signatures
    this.serviceSignatures = {
      21: 'FTP',
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      53: 'DNS',
      80: 'HTTP',
      110: 'POP3',
      111: 'RPC',
      135: 'MSRPC',
      139: 'NetBIOS',
      143: 'IMAP',
      443: 'HTTPS',
      445: 'SMB',
      993: 'IMAPS',
      995: 'POP3S',
      1433: 'MSSQL',
      1521: 'Oracle',
      3306: 'MySQL',
      3389: 'RDP',
      5432: 'PostgreSQL',
      5900: 'VNC',
      6379: 'Redis',
      8080: 'HTTP-Proxy',
      8443: 'HTTPS-Alt',
      27017: 'MongoDB'
    };
  }

  async run(options) {
    console.log('[PortRush] Starting scan with options:', options);

    if (!options.host) {
      UI.showToast('Please enter a target host');
      return;
    }

    this.results = [];
    this.isRunning = true;

    try {
      const host = this.normalizeHost(options.host);
      let ports = [];

      // Get port list based on preset
      switch (options.preset) {
        case 'common':
          ports = this.portPresets.common;
          break;
        case 'web':
          ports = this.portPresets.web;
          break;
        case 'top100':
          ports = this.portPresets.top100;
          break;
        case 'custom':
          ports = this.parseCustomPorts(options.customPorts);
          break;
        default:
          ports = this.portPresets.common;
      }

      if (ports.length === 0) {
        UI.showToast('No ports to scan');
        return;
      }

      const total = ports.length;
      let scanned = 0;
      let open = 0;

      // Scan ports in batches
      const batchSize = 10;
      for (let i = 0; i < ports.length; i += batchSize) {
        if (!this.isRunning) break;

        const batch = ports.slice(i, i + batchSize);
        const results = await Promise.all(
          batch.map(port => this.checkPort(host, port))
        );

        results.forEach(result => {
          scanned++;
          if (result.open) {
            open++;
            this.results.push({
              type: 'port',
              title: `Port ${result.port} - ${result.service}`,
              value: `${host}:${result.port}`,
              subtitle: result.protocol,
              severity: this.getPortSeverity(result.port),
              details: result
            });
          }
        });

        const progress = Math.round((scanned / total) * 100);
        UI.updateProgress('portProgress', progress, `Scanned ${scanned}/${total} ports`);
      }

      UI.hideProgress('portProgress');
      this.renderResults();
      UI.showToast(`PortRush found ${open} open ports`);

    } catch (error) {
      console.error('[PortRush] Error:', error);
      UI.hideProgress('portProgress');
      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  normalizeHost(host) {
    host = host.replace(/^https?:\/\//, '');
    host = host.split('/')[0];
    host = host.split(':')[0];
    return host;
  }

  parseCustomPorts(portString) {
    if (!portString) return [];

    const ports = new Set();
    const parts = portString.split(',');

    for (const part of parts) {
      const trimmed = part.trim();
      if (trimmed.includes('-')) {
        // Range: 80-100
        const [start, end] = trimmed.split('-').map(Number);
        for (let p = start; p <= end && p <= 65535; p++) {
          ports.add(p);
        }
      } else {
        const port = parseInt(trimmed);
        if (port > 0 && port <= 65535) {
          ports.add(port);
        }
      }
    }

    return Array.from(ports).slice(0, 1000); // Limit to 1000 ports
  }

  async checkPort(host, port) {
    const result = {
      port,
      open: false,
      service: this.serviceSignatures[port] || 'Unknown',
      protocol: 'TCP'
    };

    // Browser limitation: We can only check HTTP/HTTPS ports effectively
    // For other ports, we use timing-based inference
    try {
      const protocols = port === 443 || port === 8443 ? ['https'] : ['http', 'https'];

      for (const protocol of protocols) {
        const url = `${protocol}://${host}:${port}/`;
        const startTime = Date.now();

        try {
          const response = await chrome.runtime.sendMessage({
            action: 'proxyFetch',
            url,
            options: { timeout: 2000 }
          });

          const elapsed = Date.now() - startTime;

          // If we got any response (even error), port might be open
          if (response.success || elapsed < 1500) {
            result.open = true;
            result.protocol = protocol.toUpperCase();

            // Check if it's actually HTTP
            if (response.status) {
              result.service = `HTTP (${response.status})`;
            }
            break;
          }
        } catch (e) {
          // Connection refused is usually fast, timeout is slow
          const elapsed = Date.now() - startTime;
          if (elapsed < 500 && e.message?.includes('refused')) {
            // Port is closed
            break;
          }
        }
      }
    } catch (e) {
      // Port check failed
    }

    return result;
  }

  getPortSeverity(port) {
    // High-risk ports
    if ([21, 22, 23, 3389, 5900, 6379, 27017].includes(port)) {
      return 'high';
    }
    // Database ports
    if ([1433, 1521, 3306, 5432].includes(port)) {
      return 'medium';
    }
    // Web ports
    if ([80, 443, 8080, 8443].includes(port)) {
      return 'info';
    }
    return 'low';
  }

  renderResults() {
    // Sort by port number
    this.results.sort((a, b) => (a.details?.port || 0) - (b.details?.port || 0));

    UI.renderResults('portResults', this.results);
    this.app.results.portrush = this.results;
    this.app.updateStats();
  }

  stop() {
    this.isRunning = false;
  }
}
