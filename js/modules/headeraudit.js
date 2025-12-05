/**
 * TryHarder Security Suite - HeaderAudit Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Security headers analysis and recommendations
 */

import { UI } from '../utils/ui.js';

export class HeaderAudit {
  constructor(app) {
    this.app = app;
    this.results = [];

    // Security headers to check
    this.securityHeaders = {
      'strict-transport-security': {
        name: 'Strict-Transport-Security (HSTS)',
        description: 'Enforces HTTPS connections',
        severity: 'high',
        recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
      },
      'content-security-policy': {
        name: 'Content-Security-Policy (CSP)',
        description: 'Prevents XSS and data injection attacks',
        severity: 'high',
        recommendation: 'Add a strict CSP header to control resource loading'
      },
      'x-content-type-options': {
        name: 'X-Content-Type-Options',
        description: 'Prevents MIME type sniffing',
        severity: 'medium',
        recommendation: 'Add: X-Content-Type-Options: nosniff'
      },
      'x-frame-options': {
        name: 'X-Frame-Options',
        description: 'Prevents clickjacking attacks',
        severity: 'medium',
        recommendation: 'Add: X-Frame-Options: DENY or SAMEORIGIN'
      },
      'x-xss-protection': {
        name: 'X-XSS-Protection',
        description: 'Legacy XSS filter (use CSP instead)',
        severity: 'low',
        recommendation: 'Add: X-XSS-Protection: 1; mode=block (or rely on CSP)'
      },
      'referrer-policy': {
        name: 'Referrer-Policy',
        description: 'Controls referrer information leakage',
        severity: 'low',
        recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin'
      },
      'permissions-policy': {
        name: 'Permissions-Policy',
        description: 'Controls browser features and APIs',
        severity: 'low',
        recommendation: 'Add: Permissions-Policy: geolocation=(), camera=(), microphone=()'
      },
      'cache-control': {
        name: 'Cache-Control',
        description: 'Controls caching of sensitive data',
        severity: 'low',
        recommendation: 'For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate'
      }
    };

    // Headers that reveal information
    this.infoLeakHeaders = [
      'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
      'x-generator', 'x-drupal-cache', 'x-varnish', 'via'
    ];
  }

  async run(options) {
    console.log('[HeaderAudit] Starting audit with options:', options);

    if (!options.url) {
      UI.showToast('Please enter a URL');
      return;
    }

    this.results = [];

    try {
      const response = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url: options.url,
        options: { timeout: 10000 }
      });

      if (!response.success) {
        UI.showToast('Failed to reach target');
        return;
      }

      const headers = response.headers || {};
      const headerKeys = Object.keys(headers).map(h => h.toLowerCase());

      // Check for missing security headers
      for (const [headerKey, config] of Object.entries(this.securityHeaders)) {
        if (!headerKeys.includes(headerKey)) {
          this.results.push({
            type: 'warning',
            title: `Missing: ${config.name}`,
            value: config.recommendation,
            subtitle: config.description,
            severity: config.severity
          });
        } else {
          // Check header value
          const value = headers[Object.keys(headers).find(h => h.toLowerCase() === headerKey)];
          const issues = this.analyzeHeaderValue(headerKey, value);

          if (issues.length > 0) {
            this.results.push({
              type: 'warning',
              title: `Weak: ${config.name}`,
              value: value,
              subtitle: issues.join('; '),
              severity: 'medium'
            });
          } else {
            this.results.push({
              type: 'info',
              title: `Present: ${config.name}`,
              value: value,
              subtitle: 'Header is configured',
              severity: 'info'
            });
          }
        }
      }

      // Check for information disclosure headers
      for (const headerKey of this.infoLeakHeaders) {
        const foundHeader = Object.keys(headers).find(h => h.toLowerCase() === headerKey);
        if (foundHeader) {
          this.results.push({
            type: 'warning',
            title: `Info Leak: ${foundHeader}`,
            value: headers[foundHeader],
            subtitle: 'This header reveals server information',
            severity: 'low'
          });
        }
      }

      // Check for interesting headers
      this.checkInterestingHeaders(headers);

      this.renderResults();
      UI.showToast(`HeaderAudit found ${this.results.length} findings`);

    } catch (error) {
      console.error('[HeaderAudit] Error:', error);
      throw error;
    }
  }

  analyzeHeaderValue(headerKey, value) {
    const issues = [];
    const lowerValue = value.toLowerCase();

    switch (headerKey) {
      case 'strict-transport-security':
        if (!lowerValue.includes('max-age')) {
          issues.push('Missing max-age directive');
        } else {
          const maxAge = parseInt(lowerValue.match(/max-age=(\d+)/)?.[1] || '0');
          if (maxAge < 31536000) {
            issues.push('max-age should be at least 1 year (31536000)');
          }
        }
        if (!lowerValue.includes('includesubdomains')) {
          issues.push('Consider adding includeSubDomains');
        }
        break;

      case 'content-security-policy':
        if (lowerValue.includes("'unsafe-inline'")) {
          issues.push("Contains 'unsafe-inline' which weakens XSS protection");
        }
        if (lowerValue.includes("'unsafe-eval'")) {
          issues.push("Contains 'unsafe-eval' which allows code execution");
        }
        if (lowerValue.includes('*')) {
          issues.push('Contains wildcard (*) which is too permissive');
        }
        break;

      case 'x-frame-options':
        if (!['deny', 'sameorigin'].includes(lowerValue)) {
          issues.push('Should be DENY or SAMEORIGIN');
        }
        break;

      case 'x-content-type-options':
        if (lowerValue !== 'nosniff') {
          issues.push('Value should be "nosniff"');
        }
        break;
    }

    return issues;
  }

  checkInterestingHeaders(headers) {
    const interestingPatterns = {
      'set-cookie': {
        check: (v) => !v.toLowerCase().includes('httponly') || !v.toLowerCase().includes('secure'),
        title: 'Cookie Security Issue',
        subtitle: 'Cookie missing HttpOnly or Secure flag'
      },
      'access-control-allow-origin': {
        check: (v) => v === '*',
        title: 'CORS Wildcard',
        subtitle: 'Access-Control-Allow-Origin allows any origin'
      },
      'access-control-allow-credentials': {
        check: (v) => v.toLowerCase() === 'true',
        title: 'CORS Credentials',
        subtitle: 'Credentials allowed with CORS'
      }
    };

    for (const [headerKey, config] of Object.entries(interestingPatterns)) {
      const foundHeader = Object.keys(headers).find(h => h.toLowerCase() === headerKey);
      if (foundHeader && config.check(headers[foundHeader])) {
        this.results.push({
          type: 'warning',
          title: config.title,
          value: headers[foundHeader],
          subtitle: config.subtitle,
          severity: 'medium'
        });
      }
    }
  }

  renderResults() {
    // Sort by severity
    const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
    this.results.sort((a, b) =>
      (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
    );

    UI.renderResults('headerResults', this.results);
    this.app.results.headeraudit = this.results;
    this.app.updateStats();
  }
}
