/**
 * TryHarder Security Suite - WaybackMiner Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Mine historical data from Wayback Machine
 */

import { UI } from '../utils/ui.js';

export class WaybackMiner {
  constructor(app) {
    this.app = app;
    this.results = [];

    // Interesting file extensions
    this.sensitiveExtensions = [
      '.sql', '.bak', '.backup', '.old', '.orig', '.temp', '.tmp',
      '.log', '.logs', '.conf', '.config', '.cfg', '.ini', '.env',
      '.json', '.xml', '.yaml', '.yml', '.toml',
      '.pem', '.key', '.crt', '.cer', '.p12', '.pfx',
      '.zip', '.tar', '.gz', '.rar', '.7z',
      '.dump', '.db', '.sqlite', '.mdb',
      '.php~', '.swp', '.swo', '.DS_Store', '.git'
    ];
  }

  async run(options) {
    console.log('[WaybackMiner] Starting with options:', options);

    if (!options.domain) {
      UI.showToast('Please enter a target domain');
      return;
    }

    this.results = [];

    try {
      const domain = this.normalizeDomain(options.domain);

      // Query Wayback CDX API
      const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=5000`;

      const response = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url: cdxUrl,
        options: { timeout: 30000 }
      });

      if (!response.success || !response.body) {
        UI.showToast('Failed to query Wayback Machine');
        return;
      }

      const data = JSON.parse(response.body);

      // Skip header row
      const records = data.slice(1);

      // Group results
      const groups = {
        urls: [],
        params: new Map(),
        files: [],
        endpoints: []
      };

      for (const record of records) {
        const [url, timestamp, status, mime] = record;

        // Extract URLs
        if (options.urls) {
          groups.urls.push({
            url,
            timestamp,
            status,
            archived: `https://web.archive.org/web/${timestamp}/${url}`
          });
        }

        // Extract parameters
        if (options.params) {
          const urlObj = new URL(url);
          const params = new URLSearchParams(urlObj.search);
          for (const param of params.keys()) {
            if (!groups.params.has(param)) {
              groups.params.set(param, new Set());
            }
            groups.params.get(param).add(url);
          }
        }

        // Check for sensitive files
        if (options.files) {
          const lowerUrl = url.toLowerCase();
          for (const ext of this.sensitiveExtensions) {
            if (lowerUrl.includes(ext)) {
              groups.files.push({ url, ext, archived: `https://web.archive.org/web/${timestamp}/${url}` });
              break;
            }
          }
        }

        // Check for API endpoints
        if (options.endpoints) {
          if (url.includes('/api/') || url.includes('/v1/') || url.includes('/v2/') ||
              url.includes('/graphql') || url.includes('/rest/')) {
            groups.endpoints.push({ url, archived: `https://web.archive.org/web/${timestamp}/${url}` });
          }
        }
      }

      // Build results
      if (options.urls && groups.urls.length > 0) {
        // Limit to unique URLs
        const uniqueUrls = [...new Set(groups.urls.map(u => u.url))].slice(0, 100);
        uniqueUrls.forEach(url => {
          this.results.push({
            type: 'info',
            title: 'Archived URL',
            value: url,
            subtitle: 'Found in Wayback Machine',
            severity: 'info'
          });
        });
      }

      if (options.params && groups.params.size > 0) {
        groups.params.forEach((urls, param) => {
          this.results.push({
            type: 'param',
            title: `Parameter: ${param}`,
            value: param,
            subtitle: `Found in ${urls.size} URLs`,
            severity: 'low'
          });
        });
      }

      if (options.files && groups.files.length > 0) {
        groups.files.forEach(file => {
          this.results.push({
            type: 'secret',
            title: `Sensitive File: ${file.ext}`,
            value: file.archived,
            subtitle: file.url,
            severity: 'medium'
          });
        });
      }

      if (options.endpoints && groups.endpoints.length > 0) {
        const uniqueEndpoints = [...new Set(groups.endpoints.map(e => e.url))].slice(0, 50);
        uniqueEndpoints.forEach(url => {
          this.results.push({
            type: 'endpoint',
            title: 'API Endpoint',
            value: url,
            subtitle: 'Found in Wayback Machine',
            severity: 'info'
          });
        });
      }

      this.renderResults();
      UI.showToast(`WaybackMiner found ${this.results.length} items`);

    } catch (error) {
      console.error('[WaybackMiner] Error:', error);
      throw error;
    }
  }

  normalizeDomain(domain) {
    domain = domain.replace(/^https?:\/\//, '');
    domain = domain.split('/')[0];
    domain = domain.replace(/^www\./, '');
    return domain.toLowerCase();
  }

  renderResults() {
    UI.renderResults('waybackResults', this.results);
    this.app.results.wayback = this.results;
    this.app.updateStats();
  }
}
