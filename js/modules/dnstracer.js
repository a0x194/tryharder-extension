/**
 * TryHarder Security Suite - DNSTracer Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * DNS Record Enumeration & Analysis
 */

import { UI } from '../utils/ui.js';

export class DNSTracer {
  constructor(app) {
    this.app = app;
    this.results = [];

    // DNS record types to query
    this.recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA'];
  }

  async run(options) {
    console.log('[DNSTracer] Starting enumeration with options:', options);

    if (!options.domain) {
      UI.showToast('Please enter a domain');
      return;
    }

    this.results = [];

    try {
      const domain = this.normalizeDomain(options.domain);

      // Query DNS records using public DNS-over-HTTPS
      if (options.records) {
        await this.queryDNSRecords(domain, options.recordTypes || this.recordTypes);
      }

      // Check for zone transfer vulnerability
      if (options.zoneTransfer) {
        await this.checkZoneTransfer(domain);
      }

      // Analyze DNS security
      if (options.security) {
        await this.analyzeDNSSecurity(domain);
      }

      // Check common subdomains via DNS
      if (options.subdomains) {
        await this.bruteforceSubdomains(domain);
      }

      this.renderResults();
      UI.showToast(`DNSTracer found ${this.results.length} records`);

    } catch (error) {
      console.error('[DNSTracer] Error:', error);
      throw error;
    }
  }

  normalizeDomain(domain) {
    domain = domain.replace(/^https?:\/\//, '');
    domain = domain.split('/')[0];
    domain = domain.replace(/^www\./, '');
    return domain.toLowerCase();
  }

  async queryDNSRecords(domain, types) {
    for (const type of types) {
      try {
        // Use Google's DNS-over-HTTPS
        const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;

        const response = await chrome.runtime.sendMessage({
          action: 'proxyFetch',
          url,
          options: { timeout: 10000 }
        });

        if (!response.success || !response.body) continue;

        const data = JSON.parse(response.body);

        if (data.Answer && data.Answer.length > 0) {
          for (const record of data.Answer) {
            const finding = this.analyzeRecord(type, record);
            this.results.push(finding);
          }
        }
      } catch (e) {
        // Skip failed queries
      }

      await this.sleep(100);
    }
  }

  analyzeRecord(type, record) {
    const result = {
      type: 'dns',
      title: `${type} Record`,
      value: record.data || record.value || '',
      subtitle: `TTL: ${record.TTL || 'N/A'}`,
      severity: 'info'
    };

    switch (type) {
      case 'A':
      case 'AAAA':
        result.subtitle = `IP Address (TTL: ${record.TTL}s)`;
        break;

      case 'MX':
        result.title = 'Mail Server (MX)';
        result.subtitle = `Priority: ${record.data?.split(' ')[0] || 'N/A'}`;
        result.value = record.data?.split(' ').slice(1).join(' ') || record.data;
        break;

      case 'TXT':
        result.title = 'TXT Record';
        // Check for interesting TXT records
        const txt = record.data?.toLowerCase() || '';
        if (txt.includes('v=spf')) {
          result.title = 'SPF Record';
          result.severity = 'info';
          // Check for weak SPF
          if (txt.includes('+all')) {
            result.severity = 'high';
            result.subtitle = 'Weak SPF: +all allows any sender!';
          } else if (txt.includes('~all')) {
            result.severity = 'medium';
            result.subtitle = 'Soft fail SPF (~all)';
          }
        } else if (txt.includes('v=dmarc')) {
          result.title = 'DMARC Record';
          if (txt.includes('p=none')) {
            result.severity = 'medium';
            result.subtitle = 'DMARC policy set to none';
          }
        } else if (txt.includes('v=dkim')) {
          result.title = 'DKIM Record';
        } else if (txt.includes('google-site-verification') ||
                   txt.includes('facebook-domain-verification') ||
                   txt.includes('ms=')) {
          result.title = 'Domain Verification';
          result.subtitle = 'Third-party service verification';
        }
        break;

      case 'NS':
        result.title = 'Name Server (NS)';
        result.subtitle = 'Authoritative DNS server';
        break;

      case 'SOA':
        result.title = 'SOA Record';
        result.subtitle = 'Start of Authority';
        break;

      case 'CNAME':
        result.title = 'CNAME Record';
        result.subtitle = 'Alias for another domain';
        // Check for potential subdomain takeover
        const cname = record.data?.toLowerCase() || '';
        if (this.isTakeoverCandidate(cname)) {
          result.severity = 'high';
          result.subtitle = 'Potential subdomain takeover!';
          result.type = 'vuln';
        }
        break;

      case 'CAA':
        result.title = 'CAA Record';
        result.subtitle = 'Certificate Authority Authorization';
        break;

      case 'SRV':
        result.title = 'SRV Record';
        result.subtitle = 'Service location record';
        break;
    }

    return result;
  }

  isTakeoverCandidate(cname) {
    const takeoverPatterns = [
      'amazonaws.com', 's3.amazonaws.com', 's3-website',
      'cloudfront.net', 'azurewebsites.net', 'blob.core.windows.net',
      'cloudapp.net', 'azureedge.net', 'trafficmanager.net',
      'herokuapp.com', 'herokudns.com',
      'wordpress.com', 'pantheonsite.io',
      'domains.tumblr.com', 'ghost.io',
      'myshopify.com', 'shopify.com',
      'surge.sh', 'bitbucket.io',
      'ghost.org', 'helpjuice.com',
      'helpscoutdocs.com', 'feedpress.me',
      'freshdesk.com', 'readme.io',
      'statuspage.io', 'uservoice.com',
      'desk.com', 'teamwork.com',
      'unbounce.com', 'tictail.com',
      'bigcartel.com', 'cargo.site'
    ];

    return takeoverPatterns.some(pattern => cname.includes(pattern));
  }

  async checkZoneTransfer(domain) {
    // Note: Zone transfer check requires TCP connection
    // This is a limited check via DNS query
    this.results.push({
      type: 'info',
      title: 'Zone Transfer Check',
      value: 'Limited check (browser)',
      subtitle: 'Full AXFR check requires specialized tools',
      severity: 'info'
    });
  }

  async analyzeDNSSecurity(domain) {
    // Check DNSSEC
    try {
      const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DNSKEY`;

      const response = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url,
        options: { timeout: 10000 }
      });

      if (response.success && response.body) {
        const data = JSON.parse(response.body);

        if (data.AD) {
          this.results.push({
            type: 'info',
            title: 'DNSSEC Enabled',
            value: 'Authenticated Data',
            subtitle: 'Domain has DNSSEC validation',
            severity: 'info'
          });
        } else if (data.Answer) {
          this.results.push({
            type: 'info',
            title: 'DNSSEC Keys Found',
            value: `${data.Answer.length} DNSKEY records`,
            subtitle: 'DNSSEC is configured',
            severity: 'info'
          });
        } else {
          this.results.push({
            type: 'warning',
            title: 'DNSSEC Not Enabled',
            value: domain,
            subtitle: 'Domain lacks DNSSEC protection',
            severity: 'low'
          });
        }
      }
    } catch (e) {
      // Skip
    }

    // Check for email security records
    await this.checkEmailSecurity(domain);
  }

  async checkEmailSecurity(domain) {
    // Check DMARC
    try {
      const dmarcUrl = `https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`;

      const response = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url: dmarcUrl,
        options: { timeout: 10000 }
      });

      if (response.success && response.body) {
        const data = JSON.parse(response.body);

        if (!data.Answer || data.Answer.length === 0) {
          this.results.push({
            type: 'warning',
            title: 'Missing DMARC',
            value: domain,
            subtitle: 'No DMARC record found - email spoofing possible',
            severity: 'medium'
          });
        }
      }
    } catch (e) {
      // Skip
    }
  }

  async bruteforceSubdomains(domain) {
    const commonSubdomains = [
      'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
      'app', 'blog', 'shop', 'store', 'secure', 'vpn', 'remote',
      'portal', 'cdn', 'static', 'assets', 'img', 'images', 'media',
      'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap', 'webmail'
    ];

    const found = [];

    for (const sub of commonSubdomains) {
      try {
        const subdomain = `${sub}.${domain}`;
        const url = `https://dns.google/resolve?name=${encodeURIComponent(subdomain)}&type=A`;

        const response = await chrome.runtime.sendMessage({
          action: 'proxyFetch',
          url,
          options: { timeout: 5000 }
        });

        if (response.success && response.body) {
          const data = JSON.parse(response.body);
          if (data.Answer && data.Answer.length > 0) {
            found.push({
              subdomain,
              ip: data.Answer[0].data
            });
          }
        }
      } catch (e) {
        // Skip
      }

      await this.sleep(50);
    }

    if (found.length > 0) {
      this.results.push({
        type: 'subdomain',
        title: 'Subdomains Found (DNS)',
        value: `${found.length} subdomains resolved`,
        subtitle: found.slice(0, 5).map(f => f.subdomain).join(', '),
        severity: 'info',
        details: { subdomains: found }
      });
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  renderResults() {
    const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
    this.results.sort((a, b) =>
      (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
    );

    UI.renderResults('dnsResults', this.results);
    this.app.results.dnstracer = this.results;
    this.app.updateStats();
  }
}
