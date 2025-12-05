/**
 * TryHarder Security Suite - CachePoison Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Web Cache Poisoning Detection
 */

import { UI } from '../utils/ui.js';

export class CachePoison {
  constructor(app) {
    this.app = app;
    this.results = [];

    // Cache poisoning test headers
    this.poisonHeaders = {
      // Host header attacks
      'X-Forwarded-Host': ['evil.com', 'localhost', '127.0.0.1'],
      'X-Forwarded-Server': ['evil.com'],
      'X-Original-URL': ['/admin', '/secret'],
      'X-Rewrite-URL': ['/admin'],
      'X-Host': ['evil.com'],

      // Protocol/port manipulation
      'X-Forwarded-Proto': ['http', 'https'],
      'X-Forwarded-Port': ['443', '80', '8080'],
      'X-Forwarded-Scheme': ['http', 'nothttps'],

      // Path manipulation
      'X-Original-Path': ['/test-cache-poison'],
      'X-Forwarded-Path': ['/test'],

      // Custom headers that might be cached
      'X-Custom-Header': ['cache-poison-test'],
      'X-Injected': ['<script>alert(1)</script>'],

      // HTTP request smuggling related
      'Transfer-Encoding': ['chunked', 'identity'],
      'Content-Length': ['0']
    };

    // Cache buster parameter
    this.cacheBuster = 'thcb';
  }

  async run(options) {
    console.log('[CachePoison] Starting detection with options:', options);

    if (!options.url) {
      UI.showToast('Please enter a URL');
      return;
    }

    this.results = [];

    try {
      // Normalize URL
      let url = options.url;
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
      }

      // Detect caching behavior
      if (options.detectCache) {
        await this.detectCaching(url);
      }

      // Test for unkeyed headers
      if (options.unkeyedHeaders) {
        await this.testUnkeyedHeaders(url);
      }

      // Test for parameter pollution
      if (options.paramPollution) {
        await this.testParameterPollution(url);
      }

      // Test for fat GET requests
      if (options.fatGet) {
        await this.testFatGet(url);
      }

      this.renderResults();
      UI.showToast(`CachePoison found ${this.results.length} findings`);

    } catch (error) {
      console.error('[CachePoison] Error:', error);
      throw error;
    }
  }

  async detectCaching(url) {
    try {
      // First request to establish baseline
      const cb1 = `${this.cacheBuster}=${Date.now()}`;
      const testUrl1 = url.includes('?') ? `${url}&${cb1}` : `${url}?${cb1}`;

      const response1 = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url: testUrl1,
        options: { timeout: 10000 }
      });

      if (!response1.success) return;

      const headers1 = response1.headers || {};

      // Check for cache-related headers
      const cacheHeaders = {
        'cache-control': null,
        'x-cache': null,
        'x-cache-hit': null,
        'cf-cache-status': null,
        'x-varnish': null,
        'x-proxy-cache': null,
        'age': null,
        'x-served-by': null,
        'x-cache-status': null,
        'x-fastly-request-id': null,
        'x-amz-cf-pop': null
      };

      let cacheDetected = false;
      const detectedHeaders = [];

      for (const [header, _] of Object.entries(cacheHeaders)) {
        const found = Object.keys(headers1).find(h => h.toLowerCase() === header);
        if (found) {
          cacheDetected = true;
          cacheHeaders[header] = headers1[found];
          detectedHeaders.push(`${header}: ${headers1[found]}`);
        }
      }

      if (cacheDetected) {
        this.results.push({
          type: 'info',
          title: 'Cache Layer Detected',
          value: detectedHeaders.slice(0, 3).join(', '),
          subtitle: `${detectedHeaders.length} cache-related headers found`,
          severity: 'info',
          details: { headers: cacheHeaders }
        });

        // Check cache status
        const cacheStatus = cacheHeaders['x-cache'] || cacheHeaders['cf-cache-status'] ||
                          cacheHeaders['x-cache-status'] || cacheHeaders['x-cache-hit'];

        if (cacheStatus) {
          const status = cacheStatus.toLowerCase();
          if (status.includes('hit')) {
            this.results.push({
              type: 'info',
              title: 'Cache HIT',
              value: cacheStatus,
              subtitle: 'Response served from cache',
              severity: 'info'
            });
          } else if (status.includes('miss')) {
            this.results.push({
              type: 'info',
              title: 'Cache MISS',
              value: cacheStatus,
              subtitle: 'Response not cached (or first request)',
              severity: 'info'
            });
          }
        }

        // Analyze Cache-Control
        if (cacheHeaders['cache-control']) {
          this.analyzeCacheControl(cacheHeaders['cache-control']);
        }
      } else {
        this.results.push({
          type: 'info',
          title: 'No Cache Headers',
          value: 'No obvious cache layer detected',
          subtitle: 'May still have caching (check behavior)',
          severity: 'info'
        });
      }

    } catch (e) {
      console.error('[CachePoison] Cache detection error:', e);
    }
  }

  analyzeCacheControl(value) {
    const directives = value.toLowerCase().split(',').map(d => d.trim());

    if (directives.includes('no-store')) {
      this.results.push({
        type: 'info',
        title: 'Cache-Control: no-store',
        value: value,
        subtitle: 'Response should not be cached',
        severity: 'info'
      });
    } else if (directives.includes('private')) {
      this.results.push({
        type: 'info',
        title: 'Cache-Control: private',
        value: value,
        subtitle: 'Only browser cache, not CDN/proxy',
        severity: 'info'
      });
    } else if (directives.includes('public')) {
      this.results.push({
        type: 'warning',
        title: 'Cache-Control: public',
        value: value,
        subtitle: 'Response can be cached by proxies',
        severity: 'low'
      });
    }

    // Check for max-age
    const maxAgeMatch = value.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1]);
      if (maxAge > 86400) {
        this.results.push({
          type: 'info',
          title: 'Long Cache Duration',
          value: `max-age=${maxAge} (${Math.round(maxAge/3600)}h)`,
          subtitle: 'Extended cache duration',
          severity: 'info'
        });
      }
    }
  }

  async testUnkeyedHeaders(url) {
    const cb = `${this.cacheBuster}=${Date.now()}`;
    const testUrl = url.includes('?') ? `${url}&${cb}` : `${url}?${cb}`;

    const testHeaders = [
      'X-Forwarded-Host',
      'X-Forwarded-Proto',
      'X-Original-URL',
      'X-Host',
      'X-Forwarded-Server'
    ];

    for (const header of testHeaders) {
      try {
        const uniqueValue = `poison-test-${Date.now()}`;

        const response = await chrome.runtime.sendMessage({
          action: 'proxyFetch',
          url: testUrl,
          options: {
            timeout: 10000,
            headers: {
              [header]: uniqueValue
            }
          }
        });

        if (response.success && response.body) {
          // Check if our injected value appears in the response
          if (response.body.includes(uniqueValue)) {
            this.results.push({
              type: 'vuln',
              title: 'Unkeyed Header Reflected',
              value: header,
              subtitle: 'Header value reflected in response - potential cache poisoning!',
              severity: 'high'
            });
          }

          // Check if common injection points show our value
          const bodyLower = response.body.toLowerCase();
          if (bodyLower.includes('poison-test-') ||
              bodyLower.includes('href="http://poison') ||
              bodyLower.includes("href='http://poison")) {
            this.results.push({
              type: 'warning',
              title: 'Possible Unkeyed Header',
              value: header,
              subtitle: 'Header may influence response content',
              severity: 'medium'
            });
          }
        }
      } catch (e) {
        // Skip failed tests
      }

      await this.sleep(200);
    }
  }

  async testParameterPollution(url) {
    const urlObj = new URL(url);
    const baseUrl = urlObj.origin + urlObj.pathname;
    const cb = Date.now();

    // Test duplicate parameters
    const testCases = [
      `?${this.cacheBuster}=${cb}&test=1&test=2`,
      `?test=normal&${this.cacheBuster}=${cb}&test=poison`,
      `?${this.cacheBuster}=${cb}&callback=test&callback=<script>`
    ];

    for (const params of testCases) {
      try {
        const testUrl = baseUrl + params;

        const response = await chrome.runtime.sendMessage({
          action: 'proxyFetch',
          url: testUrl,
          options: { timeout: 10000 }
        });

        if (response.success && response.body) {
          // Check for parameter pollution signs
          if (response.body.includes('test=2') || response.body.includes('test=poison')) {
            this.results.push({
              type: 'warning',
              title: 'Parameter Pollution Possible',
              value: testUrl,
              subtitle: 'Duplicate parameters may cause issues',
              severity: 'medium'
            });
            break;
          }
        }
      } catch (e) {
        // Skip
      }

      await this.sleep(200);
    }
  }

  async testFatGet(url) {
    const cb = `${this.cacheBuster}=${Date.now()}`;
    const testUrl = url.includes('?') ? `${url}&${cb}` : `${url}?${cb}`;

    try {
      // Send GET request with body (fat GET)
      const response = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url: testUrl,
        options: {
          method: 'GET',
          timeout: 10000,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: 'test=poisoned'
        }
      });

      // Note: Most browsers don't support GET with body
      // This is mainly for documentation purposes
      this.results.push({
        type: 'info',
        title: 'Fat GET Test',
        value: 'Limited browser support',
        subtitle: 'GET with body requires specialized tools',
        severity: 'info'
      });

    } catch (e) {
      // Expected to fail in browser context
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

    UI.renderResults('cacheResults', this.results);
    this.app.results.cachepoison = this.results;
    this.app.updateStats();
  }
}
