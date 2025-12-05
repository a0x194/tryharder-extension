/**
 * TryHarder Security Suite - JSHunter Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Extract endpoints, secrets, and sensitive data from JavaScript files
 */

import { UI } from '../utils/ui.js';

export class JSHunter {
  constructor(app) {
    this.app = app;
    this.results = {
      endpoints: [],
      secrets: [],
      domains: [],
      paths: [],
      emails: [],
      ips: []
    };

    // Regex patterns for detection
    this.patterns = {
      endpoints: [
        /["'`](\/api\/[^"'`\s<>]+)["'`]/gi,
        /["'`](\/v[0-9]+\/[^"'`\s<>]+)["'`]/gi,
        /["'`](\/graphql[^"'`\s<>]*)["'`]/gi,
        /["'`](\/rest\/[^"'`\s<>]+)["'`]/gi,
        /["'`](\/ajax\/[^"'`\s<>]+)["'`]/gi,
        /["'`](\/json\/[^"'`\s<>]+)["'`]/gi,
        /fetch\s*\(\s*["'`]([^"'`]+)["'`]/gi,
        /axios\s*[\.\(]\s*(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
        /\$\.(?:ajax|get|post)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
        /\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE)["'`]\s*,\s*["'`]([^"'`]+)["'`]/gi,
        /url\s*[:=]\s*["'`]([^"'`]+api[^"'`]+)["'`]/gi
      ],
      secrets: [
        /["'`]?(?:api[_-]?key|apikey)["'`]?\s*[:=]\s*["'`]([a-zA-Z0-9_\-]{20,})["'`]/gi,
        /["'`]?(?:secret[_-]?key|secretkey)["'`]?\s*[:=]\s*["'`]([a-zA-Z0-9_\-]{20,})["'`]/gi,
        /["'`]?(?:access[_-]?token|accesstoken)["'`]?\s*[:=]\s*["'`]([a-zA-Z0-9_\-\.]{20,})["'`]/gi,
        /["'`]?(?:auth[_-]?token|authtoken)["'`]?\s*[:=]\s*["'`]([a-zA-Z0-9_\-\.]{20,})["'`]/gi,
        /["'`]?(?:private[_-]?key|privatekey)["'`]?\s*[:=]\s*["'`]([^"'`]{20,})["'`]/gi,
        /["'`]?password["'`]?\s*[:=]\s*["'`]([^"'`]{6,})["'`]/gi,
        /(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["'`]?(AKIA[A-Z0-9]{16})["'`]?/gi,
        /(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["'`]?([a-zA-Z0-9+\/]{40})["'`]?/gi,
        /ghp_[a-zA-Z0-9]{36}/g, // GitHub personal access token
        /gho_[a-zA-Z0-9]{36}/g, // GitHub OAuth token
        /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g, // GitHub fine-grained PAT
        /sk-[a-zA-Z0-9]{48}/g, // OpenAI API key
        /sk_live_[a-zA-Z0-9]{24}/g, // Stripe live key
        /sk_test_[a-zA-Z0-9]{24}/g, // Stripe test key
        /sq0csp-[a-zA-Z0-9_\-]{43}/g, // Square access token
        /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g, // SendGrid
        /xox[baprs]-[a-zA-Z0-9\-]{10,}/g, // Slack token
        /ya29\.[a-zA-Z0-9_\-]{68,}/g, // Google OAuth token
        /eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*/g // JWT tokens
      ],
      domains: [
        /https?:\/\/([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/gi,
        /["'`]((?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+(?:com|org|net|io|co|dev|app|xyz|cloud|ai))["'`]/gi
      ],
      paths: [
        /["'`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+)["'`]/gi
      ],
      emails: [
        /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g
      ],
      ips: [
        /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
        /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b/g
      ]
    };
  }

  async run(options) {
    console.log('[JSHunter] Starting scan with options:', options);

    this.results = {
      endpoints: [],
      secrets: [],
      domains: [],
      paths: [],
      emails: [],
      ips: []
    };

    try {
      // Get current tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) {
        throw new Error('No active tab found');
      }

      // Get scripts from content script
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'getScripts' });
      const { scripts } = response;

      if (!scripts || scripts.length === 0) {
        UI.showToast('No scripts found on page');
        this.renderResults();
        return;
      }

      // Analyze inline scripts
      for (const script of scripts) {
        if (script.inline && script.content) {
          this.analyzeContent(script.content, 'inline');
        }
      }

      // Fetch and analyze external scripts if deep scan enabled
      if (options.deepScan) {
        const externalScripts = scripts.filter(s => s.src && !s.inline);
        for (const script of externalScripts) {
          try {
            // Only fetch same-origin or CORS-enabled scripts
            const response = await fetch(script.src);
            const content = await response.text();
            this.analyzeContent(content, script.src);
          } catch (e) {
            console.warn(`Could not fetch ${script.src}:`, e);
          }
        }
      }

      // Also analyze the page HTML
      const pageInfo = await chrome.tabs.sendMessage(tab.id, { action: 'getPageInfo' });
      if (pageInfo && pageInfo.documentElement) {
        this.analyzeContent(pageInfo.documentElement, 'HTML');
      }

      this.renderResults(options);

    } catch (error) {
      console.error('[JSHunter] Error:', error);
      throw error;
    }
  }

  analyzeContent(content, source) {
    if (!content) return;

    // Extract endpoints
    for (const pattern of this.patterns.endpoints) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const value = match[1] || match[0];
        if (value && !this.results.endpoints.some(e => e.value === value)) {
          this.results.endpoints.push({
            type: 'endpoint',
            title: 'API Endpoint',
            value: value,
            subtitle: `Found in ${source}`,
            severity: 'info'
          });
        }
      }
    }

    // Extract secrets
    for (const pattern of this.patterns.secrets) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const value = match[1] || match[0];
        if (value && value.length >= 8 && !this.results.secrets.some(s => s.value === value)) {
          // Determine secret type
          let secretType = 'Potential Secret';
          if (value.startsWith('AKIA')) secretType = 'AWS Access Key';
          else if (value.startsWith('ghp_') || value.startsWith('gho_')) secretType = 'GitHub Token';
          else if (value.startsWith('sk-')) secretType = 'OpenAI API Key';
          else if (value.startsWith('sk_live_')) secretType = 'Stripe Live Key';
          else if (value.startsWith('sk_test_')) secretType = 'Stripe Test Key';
          else if (value.startsWith('eyJ')) secretType = 'JWT Token';
          else if (value.startsWith('xox')) secretType = 'Slack Token';
          else if (value.startsWith('SG.')) secretType = 'SendGrid Key';

          this.results.secrets.push({
            type: 'secret',
            title: secretType,
            value: value.length > 50 ? value.substring(0, 47) + '...' : value,
            subtitle: `Found in ${source}`,
            severity: secretType === 'JWT Token' ? 'medium' : 'high'
          });
        }
      }
    }

    // Extract domains
    for (const pattern of this.patterns.domains) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const value = match[1] || match[0];
        const cleaned = value.replace(/^["'`]|["'`]$/g, '').replace(/https?:\/\//, '');
        if (cleaned && !this.results.domains.some(d => d.value === cleaned)) {
          this.results.domains.push({
            type: 'domain',
            title: 'Domain',
            value: cleaned,
            subtitle: `Found in ${source}`,
            severity: 'info'
          });
        }
      }
    }

    // Extract paths
    for (const pattern of this.patterns.paths) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const value = match[1] || match[0];
        if (value && value.length > 3 && !this.results.paths.some(p => p.value === value)) {
          this.results.paths.push({
            type: 'endpoint',
            title: 'Path',
            value: value,
            subtitle: `Found in ${source}`,
            severity: 'info'
          });
        }
      }
    }

    // Extract emails
    for (const pattern of this.patterns.emails) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const value = match[0];
        if (value && !this.results.emails.some(e => e.value === value)) {
          this.results.emails.push({
            type: 'info',
            title: 'Email Address',
            value: value,
            subtitle: `Found in ${source}`,
            severity: 'low'
          });
        }
      }
    }

    // Extract IPs
    for (const pattern of this.patterns.ips) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const value = match[0];
        // Filter out common false positives
        if (value && !value.startsWith('0.') && !value.startsWith('127.') &&
            value !== '0.0.0.0' && !this.results.ips.some(i => i.value === value)) {
          this.results.ips.push({
            type: 'info',
            title: 'IP Address',
            value: value,
            subtitle: `Found in ${source}`,
            severity: 'low'
          });
        }
      }
    }
  }

  renderResults(options = {}) {
    const groups = {};

    if (options.extractEndpoints !== false && this.results.endpoints.length > 0) {
      groups['API Endpoints'] = this.results.endpoints;
    }
    if (options.extractSecrets !== false && this.results.secrets.length > 0) {
      groups['Secrets & Keys'] = this.results.secrets;
    }
    if (options.extractDomains !== false && this.results.domains.length > 0) {
      groups['Domains'] = this.results.domains;
    }
    if (options.extractPaths !== false && this.results.paths.length > 0) {
      groups['Paths'] = this.results.paths;
    }
    if (this.results.emails.length > 0) {
      groups['Emails'] = this.results.emails;
    }
    if (this.results.ips.length > 0) {
      groups['IP Addresses'] = this.results.ips;
    }

    UI.renderGroupedResults('jsResults', groups);

    // Update app results
    const allResults = [
      ...this.results.endpoints,
      ...this.results.secrets,
      ...this.results.domains,
      ...this.results.paths,
      ...this.results.emails,
      ...this.results.ips
    ];

    this.app.results.jshunter = allResults;
    this.app.updateStats();

    const total = allResults.length;
    UI.showToast(`JSHunter found ${total} items`);
  }
}
