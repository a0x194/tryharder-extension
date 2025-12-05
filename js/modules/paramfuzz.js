/**
 * TryHarder Security Suite - ParamFuzz Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Discover hidden parameters and query strings
 */

import { UI } from '../utils/ui.js';
import { Storage } from '../utils/storage.js';

export class ParamFuzz {
  constructor(app) {
    this.app = app;
    this.results = [];
    this.isRunning = false;

    // Common parameter wordlists
    this.wordlists = {
      common: [
        'id', 'page', 'limit', 'offset', 'sort', 'order', 'filter', 'search', 'query', 'q',
        'name', 'email', 'user', 'username', 'password', 'pass', 'token', 'key', 'api_key',
        'file', 'path', 'url', 'redirect', 'return', 'callback', 'next', 'ref', 'source',
        'type', 'action', 'cmd', 'command', 'exec', 'method', 'function', 'func',
        'data', 'content', 'body', 'message', 'text', 'title', 'description', 'comment',
        'category', 'tag', 'status', 'state', 'mode', 'format', 'output', 'response',
        'start', 'end', 'from', 'to', 'date', 'time', 'year', 'month', 'day',
        'min', 'max', 'count', 'total', 'size', 'length', 'width', 'height',
        'include', 'exclude', 'fields', 'select', 'columns', 'expand', 'embed',
        'version', 'v', 'lang', 'language', 'locale', 'country', 'region',
        'access_token', 'auth', 'authorization', 'bearer', 'jwt', 'session', 'sid',
        'price', 'amount', 'quantity', 'qty', 'value', 'cost', 'discount', 'coupon'
      ],
      admin: [
        'admin', 'administrator', 'root', 'superuser', 'system', 'internal', 'private',
        'debug', 'test', 'dev', 'development', 'staging', 'production', 'prod',
        'config', 'configuration', 'settings', 'options', 'preferences', 'params',
        'role', 'roles', 'permission', 'permissions', 'privilege', 'privileges', 'access',
        'bypass', 'skip', 'override', 'force', 'ignore', 'disable', 'enable', 'allow',
        'hidden', 'secret', 'confidential', 'restricted', 'internal_only',
        'backdoor', 'master', 'god', 'sudo', 'elevation', 'escalate',
        'export', 'import', 'backup', 'restore', 'reset', 'delete', 'purge', 'truncate',
        'sql', 'query', 'execute', 'raw', 'direct', 'inject', 'payload',
        'shell', 'console', 'terminal', 'exec', 'run', 'spawn', 'process',
        'upload', 'download', 'read', 'write', 'create', 'modify', 'update'
      ],
      debug: [
        'debug', 'verbose', 'trace', 'log', 'logging', 'logger',
        'error', 'errors', 'exception', 'exceptions', 'stacktrace', 'stack',
        'dump', 'print', 'show', 'display', 'reveal', 'expose',
        'profile', 'profiler', 'profiling', 'benchmark', 'performance', 'timing',
        'cache', 'nocache', 'no_cache', 'clear_cache', 'refresh', 'reload',
        'mock', 'fake', 'stub', 'simulate', 'emulate',
        'dry_run', 'dryrun', 'preview', 'test_mode', 'sandbox',
        'env', 'environment', 'context', 'scope', 'namespace'
      ],
      api: [
        'api_version', 'api_key', 'api_secret', 'api_token', 'app_id', 'app_key',
        'client_id', 'client_secret', 'consumer_key', 'consumer_secret',
        'grant_type', 'scope', 'scopes', 'audience', 'resource',
        'response_type', 'redirect_uri', 'state', 'nonce', 'code_challenge',
        'per_page', 'page_size', 'cursor', 'after', 'before', 'since', 'until',
        'include_deleted', 'include_hidden', 'show_all', 'all',
        'webhook', 'webhook_url', 'callback_url', 'notify_url', 'return_url',
        'signature', 'sig', 'hash', 'checksum', 'hmac', 'digest'
      ]
    };
  }

  async run(options) {
    console.log('[ParamFuzz] Starting fuzz with options:', options);

    if (!options.url) {
      UI.showToast('Please enter a target URL');
      return;
    }

    this.results = [];
    this.isRunning = true;

    try {
      const settings = await Storage.getSettings();
      const baseUrl = this.normalizeUrl(options.url);
      const method = options.method || 'GET';

      // Build wordlist
      const wordlist = this.buildWordlist(options);
      if (wordlist.length === 0) {
        UI.showToast('No parameters to test');
        return;
      }

      // Get baseline response
      UI.updateProgress('paramProgress', 0, 'Getting baseline...');
      const baseline = await this.fetchWithRetry(baseUrl, { method });

      if (!baseline.success) {
        UI.showToast(`Failed to reach target: ${baseline.error}`);
        UI.hideProgress('paramProgress');
        return;
      }

      const baselineLength = baseline.body?.length || 0;
      const baselineStatus = baseline.status;

      // Fuzz parameters
      const total = wordlist.length;
      let found = 0;

      for (let i = 0; i < wordlist.length; i++) {
        if (!this.isRunning) break;

        const param = wordlist[i];
        const progress = Math.round(((i + 1) / total) * 100);
        UI.updateProgress('paramProgress', progress, `Testing: ${param}`);

        try {
          const testUrl = this.addParam(baseUrl, param, 'test123');
          const response = await this.fetchWithRetry(testUrl, { method });

          if (response.success) {
            // Check for differences
            const lengthDiff = Math.abs((response.body?.length || 0) - baselineLength);
            const statusDiff = response.status !== baselineStatus;
            const hasReflection = response.body?.includes('test123');
            const hasParamInResponse = response.body?.toLowerCase().includes(param.toLowerCase());

            // Score the finding
            let score = 0;
            let reason = [];

            if (statusDiff && response.status !== 404) {
              score += 3;
              reason.push(`Status changed: ${baselineStatus} → ${response.status}`);
            }
            if (hasReflection) {
              score += 2;
              reason.push('Value reflected in response');
            }
            if (lengthDiff > 100) {
              score += 1;
              reason.push(`Length diff: ${lengthDiff} bytes`);
            }
            if (hasParamInResponse && !hasReflection) {
              score += 1;
              reason.push('Param name found in response');
            }

            if (score >= 2) {
              found++;
              this.results.push({
                type: 'param',
                title: `Parameter: ${param}`,
                value: testUrl,
                subtitle: reason.join(', '),
                severity: score >= 4 ? 'high' : score >= 3 ? 'medium' : 'low',
                score,
                details: {
                  param,
                  status: response.status,
                  lengthDiff,
                  hasReflection
                }
              });
            }
          }

          // Rate limiting
          if (settings.delay > 0) {
            await this.sleep(settings.delay);
          }

        } catch (e) {
          console.warn(`Error testing ${param}:`, e);
        }
      }

      UI.hideProgress('paramProgress');
      this.renderResults();
      UI.showToast(`ParamFuzz found ${found} potential parameters`);

    } catch (error) {
      console.error('[ParamFuzz] Error:', error);
      UI.hideProgress('paramProgress');
      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  buildWordlist(options) {
    let wordlist = [];

    if (options.common) wordlist = wordlist.concat(this.wordlists.common);
    if (options.admin) wordlist = wordlist.concat(this.wordlists.admin);
    if (options.debug) wordlist = wordlist.concat(this.wordlists.debug);
    if (options.api) wordlist = wordlist.concat(this.wordlists.api);

    // Add custom params
    if (options.customList) {
      const custom = options.customList.split('\n')
        .map(p => p.trim())
        .filter(p => p.length > 0);
      wordlist = wordlist.concat(custom);
    }

    // Remove duplicates
    return [...new Set(wordlist)];
  }

  normalizeUrl(url) {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    // Remove existing query string for clean fuzzing
    const urlObj = new URL(url);
    return `${urlObj.origin}${urlObj.pathname}`;
  }

  addParam(url, param, value) {
    const separator = url.includes('?') ? '&' : '?';
    return `${url}${separator}${encodeURIComponent(param)}=${encodeURIComponent(value)}`;
  }

  async fetchWithRetry(url, options = {}, retries = 2) {
    for (let i = 0; i <= retries; i++) {
      try {
        const response = await chrome.runtime.sendMessage({
          action: 'proxyFetch',
          url,
          options: {
            ...options,
            timeout: 5000
          }
        });
        return response;
      } catch (e) {
        if (i === retries) {
          return { success: false, error: e.message };
        }
        await this.sleep(1000);
      }
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  renderResults() {
    // Sort by score
    this.results.sort((a, b) => (b.score || 0) - (a.score || 0));

    UI.renderResults('paramResults', this.results);

    // Update app results
    this.app.results.paramfuzz = this.results;
    this.app.updateStats();
  }

  stop() {
    this.isRunning = false;
  }
}
