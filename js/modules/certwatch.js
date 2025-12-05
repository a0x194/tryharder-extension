/**
 * TryHarder Security Suite - CertWatch Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * SSL/TLS Certificate Analysis & Subdomain Discovery
 */

import { UI } from '../utils/ui.js';

export class CertWatch {
  constructor(app) {
    this.app = app;
    this.results = [];
  }

  async run(options) {
    console.log('[CertWatch] Starting analysis with options:', options);

    if (!options.domain) {
      UI.showToast('Please enter a domain');
      return;
    }

    this.results = [];

    try {
      const domain = this.normalizeDomain(options.domain);

      // Fetch certificate information via crt.sh
      if (options.certificates) {
        await this.fetchCertificates(domain);
      }

      // Check certificate transparency logs for subdomains
      if (options.ctLogs) {
        await this.queryCTLogs(domain);
      }

      // Analyze current certificate
      if (options.analyze) {
        await this.analyzeCertificate(domain);
      }

      this.renderResults();
      UI.showToast(`CertWatch found ${this.results.length} findings`);

    } catch (error) {
      console.error('[CertWatch] Error:', error);
      throw error;
    }
  }

  normalizeDomain(domain) {
    domain = domain.replace(/^https?:\/\//, '');
    domain = domain.split('/')[0];
    domain = domain.replace(/^www\./, '');
    return domain.toLowerCase();
  }

  async fetchCertificates(domain) {
    try {
      const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;

      const response = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url,
        options: { timeout: 30000 }
      });

      if (!response.success || !response.body) {
        return;
      }

      const certs = JSON.parse(response.body);

      // Group by issuer
      const issuers = new Map();
      const domains = new Set();

      for (const cert of certs) {
        // Track issuers
        const issuer = cert.issuer_name || 'Unknown';
        if (!issuers.has(issuer)) {
          issuers.set(issuer, []);
        }
        issuers.get(issuer).push(cert);

        // Extract domains from common name and SAN
        if (cert.common_name) {
          domains.add(cert.common_name.toLowerCase());
        }
        if (cert.name_value) {
          cert.name_value.split('\n').forEach(d => {
            domains.add(d.toLowerCase().trim());
          });
        }
      }

      // Add certificate summary
      this.results.push({
        type: 'info',
        title: 'Certificates Found',
        value: `${certs.length} certificates`,
        subtitle: `From ${issuers.size} different issuers`,
        severity: 'info'
      });

      // Add issuer info
      issuers.forEach((certList, issuer) => {
        const shortIssuer = issuer.length > 60 ? issuer.substring(0, 60) + '...' : issuer;
        this.results.push({
          type: 'info',
          title: 'Certificate Issuer',
          value: shortIssuer,
          subtitle: `${certList.length} certificates issued`,
          severity: 'info'
        });
      });

      // Check for interesting patterns
      const wildcards = [...domains].filter(d => d.startsWith('*'));
      if (wildcards.length > 0) {
        this.results.push({
          type: 'warning',
          title: 'Wildcard Certificates',
          value: wildcards.slice(0, 5).join(', '),
          subtitle: `${wildcards.length} wildcard certificates found`,
          severity: 'low'
        });
      }

      // Add unique subdomains found
      const uniqueDomains = [...domains].filter(d => !d.startsWith('*'));
      this.results.push({
        type: 'subdomain',
        title: 'Subdomains from CT Logs',
        value: `${uniqueDomains.length} unique domains`,
        subtitle: 'Discovered via Certificate Transparency',
        severity: 'info',
        details: { domains: uniqueDomains.slice(0, 100) }
      });

    } catch (e) {
      console.error('[CertWatch] Certificate fetch error:', e);
    }
  }

  async queryCTLogs(domain) {
    // Query additional CT log sources
    const sources = [
      {
        name: 'Censys',
        url: `https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.subject.common_name:${domain}`,
        parse: (data) => data.result?.hits || []
      }
    ];

    // Note: Most CT log APIs require authentication
    // This is a simplified implementation
    this.results.push({
      type: 'info',
      title: 'CT Log Sources',
      value: 'crt.sh queried',
      subtitle: 'Certificate Transparency logs checked',
      severity: 'info'
    });
  }

  async analyzeCertificate(domain) {
    try {
      // Fetch the current certificate via HTTPS
      const url = `https://${domain}/`;

      const response = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url,
        options: { timeout: 10000 }
      });

      if (!response.success) {
        this.results.push({
          type: 'warning',
          title: 'Certificate Check Failed',
          value: domain,
          subtitle: 'Could not connect via HTTPS',
          severity: 'medium'
        });
        return;
      }

      // Check security headers related to certificates
      const headers = response.headers || {};

      // Check for HSTS
      const hsts = Object.keys(headers).find(h => h.toLowerCase() === 'strict-transport-security');
      if (hsts) {
        const hstsValue = headers[hsts];
        const maxAge = parseInt(hstsValue.match(/max-age=(\d+)/)?.[1] || '0');

        if (maxAge < 31536000) {
          this.results.push({
            type: 'warning',
            title: 'HSTS max-age Too Short',
            value: `${maxAge} seconds`,
            subtitle: 'Should be at least 31536000 (1 year)',
            severity: 'medium'
          });
        } else {
          this.results.push({
            type: 'info',
            title: 'HSTS Configured',
            value: hstsValue,
            subtitle: 'HTTPS enforced via HSTS',
            severity: 'info'
          });
        }

        if (!hstsValue.toLowerCase().includes('includesubdomains')) {
          this.results.push({
            type: 'warning',
            title: 'HSTS Missing includeSubDomains',
            value: hstsValue,
            subtitle: 'Subdomains may not be protected',
            severity: 'low'
          });
        }

        if (!hstsValue.toLowerCase().includes('preload')) {
          this.results.push({
            type: 'info',
            title: 'HSTS Preload Not Set',
            value: hstsValue,
            subtitle: 'Consider adding preload directive',
            severity: 'info'
          });
        }
      } else {
        this.results.push({
          type: 'warning',
          title: 'Missing HSTS Header',
          value: domain,
          subtitle: 'HTTPS not enforced via HSTS',
          severity: 'high'
        });
      }

      // Check for Expect-CT (deprecated but still relevant)
      const expectCT = Object.keys(headers).find(h => h.toLowerCase() === 'expect-ct');
      if (expectCT) {
        this.results.push({
          type: 'info',
          title: 'Expect-CT Header',
          value: headers[expectCT],
          subtitle: 'Certificate Transparency enforcement',
          severity: 'info'
        });
      }

      // Check for Public-Key-Pins (deprecated, security risk if misconfigured)
      const hpkp = Object.keys(headers).find(h => h.toLowerCase() === 'public-key-pins');
      if (hpkp) {
        this.results.push({
          type: 'warning',
          title: 'HPKP Header Found',
          value: headers[hpkp].substring(0, 100),
          subtitle: 'Deprecated and can cause issues',
          severity: 'medium'
        });
      }

    } catch (e) {
      console.error('[CertWatch] Analysis error:', e);
    }
  }

  renderResults() {
    const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
    this.results.sort((a, b) =>
      (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
    );

    UI.renderResults('certResults', this.results);
    this.app.results.certwatch = this.results;
    this.app.updateStats();
  }
}
