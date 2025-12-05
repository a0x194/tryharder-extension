/**
 * TryHarder Security Suite - AuthBypass Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * IDOR, privilege escalation & auth bypass testing
 */

import { UI } from '../utils/ui.js';

export class AuthBypass {
  constructor(app) {
    this.app = app;
    this.results = [];

    // Headers to try for bypass
    this.bypassHeaders = [
      { 'X-Original-URL': '/' },
      { 'X-Rewrite-URL': '/' },
      { 'X-Custom-IP-Authorization': '127.0.0.1' },
      { 'X-Forwarded-For': '127.0.0.1' },
      { 'X-Forwarded-Host': 'localhost' },
      { 'X-Host': 'localhost' },
      { 'X-Remote-IP': '127.0.0.1' },
      { 'X-Remote-Addr': '127.0.0.1' },
      { 'X-Originating-IP': '127.0.0.1' },
      { 'X-Client-IP': '127.0.0.1' },
      { 'X-Real-IP': '127.0.0.1' },
      { 'True-Client-IP': '127.0.0.1' },
      { 'Cluster-Client-IP': '127.0.0.1' },
      { 'X-ProxyUser-Ip': '127.0.0.1' },
      { 'X-Original-Remote-Addr': '127.0.0.1' }
    ];

    // HTTP methods to test
    this.methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'];

    // Method override headers
    this.methodOverrideHeaders = [
      'X-HTTP-Method-Override',
      'X-HTTP-Method',
      'X-Method-Override'
    ];
  }

  async run(options) {
    console.log('[AuthBypass] Starting test with options:', options);

    if (!options.url) {
      UI.showToast('Please enter an endpoint URL');
      return;
    }

    this.results = [];

    try {
      const url = options.url;

      // 1. Get baseline responses
      const baselineHigh = options.tokenA ?
        await this.fetchUrl(url, { headers: { 'Authorization': options.tokenA } }) :
        await this.fetchUrl(url);

      const baselineLow = options.tokenB ?
        await this.fetchUrl(url, { headers: { 'Authorization': options.tokenB } }) :
        await this.fetchUrl(url);

      const baselineNone = await this.fetchUrl(url);

      // 2. IDOR Testing
      if (options.idorTest && options.idValues) {
        await this.testIDOR(url, options);
      }

      // 3. Method Override Testing
      if (options.methodTest) {
        await this.testMethodOverride(url, options, baselineHigh);
      }

      // 4. Header Bypass Testing
      if (options.headerTest) {
        await this.testHeaderBypass(url, options, baselineNone);
      }

      // 5. Path Traversal Testing
      if (options.pathTest) {
        await this.testPathTraversal(url, options);
      }

      this.renderResults();
      UI.showToast(`AuthBypass found ${this.results.length} potential issues`);

    } catch (error) {
      console.error('[AuthBypass] Error:', error);
      throw error;
    }
  }

  async testIDOR(url, options) {
    const ids = options.idValues.split(',').map(id => id.trim()).filter(id => id);
    const urlObj = new URL(url);
    const pathParts = urlObj.pathname.split('/');

    // Find ID patterns in URL
    const idPattern = /\/(\d+)(?:\/|$)/;
    const match = url.match(idPattern);

    if (!match && ids.length === 0) return;

    const originalId = match ? match[1] : null;
    const testIds = [...ids];

    // Add common test IDs
    testIds.push('1', '0', '-1', '999999', 'admin', 'null', 'undefined');

    for (const testId of testIds) {
      if (testId === originalId) continue;

      let testUrl = url;
      if (originalId) {
        testUrl = url.replace(`/${originalId}`, `/${testId}`);
      } else {
        // Try appending ID to URL
        testUrl = url.replace(/\/?$/, `/${testId}`);
      }

      // Test with low privilege token
      const headers = options.tokenB ? { 'Authorization': options.tokenB } : {};
      const response = await this.fetchUrl(testUrl, { headers });

      if (response.success && response.status === 200) {
        // Check if we got actual data (not error page)
        const hasData = response.body && response.body.length > 100 &&
          !response.body.toLowerCase().includes('not found') &&
          !response.body.toLowerCase().includes('unauthorized') &&
          !response.body.toLowerCase().includes('forbidden');

        if (hasData) {
          this.results.push({
            type: 'vuln',
            title: 'Potential IDOR Vulnerability',
            value: testUrl,
            subtitle: `Accessed resource with ID: ${testId}`,
            severity: 'high',
            details: { originalId, testId, status: response.status }
          });
        }
      }

      await this.sleep(100);
    }
  }

  async testMethodOverride(url, options, baseline) {
    // Test direct method changes
    for (const method of this.methods) {
      const response = await this.fetchUrl(url, { method });

      if (response.success && response.status === 200 && response.status !== baseline.status) {
        this.results.push({
          type: 'warning',
          title: `Method ${method} allowed`,
          value: `${method} ${url}`,
          subtitle: `Got ${response.status} instead of ${baseline.status}`,
          severity: 'medium',
          details: { method, status: response.status }
        });
      }
    }

    // Test method override headers
    for (const header of this.methodOverrideHeaders) {
      for (const method of ['PUT', 'DELETE', 'PATCH']) {
        const response = await this.fetchUrl(url, {
          method: 'POST',
          headers: { [header]: method }
        });

        if (response.success && response.status !== 405 && response.status !== 403) {
          this.results.push({
            type: 'warning',
            title: `Method Override: ${header}`,
            value: `${header}: ${method}`,
            subtitle: `Override to ${method} returned ${response.status}`,
            severity: 'medium',
            details: { header, method, status: response.status }
          });
        }
      }
    }
  }

  async testHeaderBypass(url, options, baselineNone) {
    // Only test if baseline returns 401/403
    if (baselineNone.status !== 401 && baselineNone.status !== 403) {
      return;
    }

    for (const headerObj of this.bypassHeaders) {
      const response = await this.fetchUrl(url, { headers: headerObj });

      if (response.success && response.status === 200) {
        const headerName = Object.keys(headerObj)[0];
        this.results.push({
          type: 'vuln',
          title: 'Header-Based Auth Bypass',
          value: `${headerName}: ${headerObj[headerName]}`,
          subtitle: `Bypassed ${baselineNone.status} with header`,
          severity: 'critical',
          details: { header: headerName, originalStatus: baselineNone.status }
        });
      }

      await this.sleep(50);
    }
  }

  async testPathTraversal(url, options) {
    const urlObj = new URL(url);
    const originalPath = urlObj.pathname;

    // Path variations to try
    const pathPayloads = [
      originalPath + '/',
      originalPath + '/.',
      originalPath + '//',
      originalPath + '/./',
      originalPath + '%2f',
      originalPath + '%252f',
      originalPath.replace(/([^\/])$/, '$1/..'),
      '//' + originalPath,
      '/./' + originalPath,
      '/../' + originalPath,
      originalPath + '?',
      originalPath + '#',
      originalPath + '%00',
      originalPath + '%0a',
      originalPath + '%0d',
      originalPath.toUpperCase(),
      originalPath + '.json',
      originalPath + '.html'
    ];

    const baseline = await this.fetchUrl(url);

    for (const pathPayload of pathPayloads) {
      const testUrl = `${urlObj.origin}${pathPayload}${urlObj.search}`;

      const response = await this.fetchUrl(testUrl);

      if (response.success) {
        const statusChanged = response.status !== baseline.status;
        const lengthDiff = Math.abs((response.body?.length || 0) - (baseline.body?.length || 0));

        if (statusChanged && response.status === 200 && baseline.status !== 200) {
          this.results.push({
            type: 'warning',
            title: 'Path Traversal Bypass',
            value: testUrl,
            subtitle: `Status changed: ${baseline.status} → ${response.status}`,
            severity: 'medium',
            details: { originalPath, payload: pathPayload, statusDiff: true }
          });
        } else if (lengthDiff > 500) {
          this.results.push({
            type: 'info',
            title: 'Path Variation Detected',
            value: testUrl,
            subtitle: `Response size differs by ${lengthDiff} bytes`,
            severity: 'low',
            details: { originalPath, payload: pathPayload, lengthDiff }
          });
        }
      }

      await this.sleep(50);
    }
  }

  async fetchUrl(url, options = {}) {
    try {
      return await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url,
        options: {
          method: options.method || 'GET',
          headers: options.headers || {},
          timeout: 10000
        }
      });
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  renderResults() {
    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    this.results.sort((a, b) =>
      (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5)
    );

    UI.renderResults('authResults', this.results);
    this.app.results.authbypass = this.results;
    this.app.updateStats();
  }
}
