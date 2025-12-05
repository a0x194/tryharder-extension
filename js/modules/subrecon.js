/**
 * TryHarder Security Suite - SubRecon Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Subdomain enumeration and alive checking
 */

import { UI } from '../utils/ui.js';
import { Storage } from '../utils/storage.js';

export class SubRecon {
  constructor(app) {
    this.app = app;
    this.results = [];
    this.isRunning = false;

    // Common subdomain prefixes
    this.wordlist = [
      'www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'store', 'api', 'dev', 'staging',
      'test', 'beta', 'alpha', 'demo', 'app', 'apps', 'mobile', 'm', 'cdn', 'static',
      'assets', 'images', 'img', 'media', 'video', 'download', 'downloads', 'upload',
      'portal', 'login', 'auth', 'secure', 'ssl', 'vpn', 'remote', 'gateway',
      'dashboard', 'panel', 'control', 'console', 'manage', 'management',
      'support', 'help', 'docs', 'documentation', 'wiki', 'forum', 'community',
      'status', 'monitor', 'health', 'metrics', 'analytics', 'stats',
      'smtp', 'pop', 'imap', 'webmail', 'email', 'mx', 'ns', 'dns',
      'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'cache',
      'web', 'web1', 'web2', 'server', 'server1', 'server2', 'node', 'node1',
      'prod', 'production', 'stage', 'uat', 'qa', 'sandbox', 'internal',
      'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci', 'build',
      'aws', 'azure', 'cloud', 'gcp', 's3', 'storage', 'backup',
      'api1', 'api2', 'v1', 'v2', 'graphql', 'rest', 'soap', 'rpc',
      'news', 'events', 'calendar', 'jobs', 'careers', 'about', 'contact',
      'payment', 'pay', 'checkout', 'cart', 'order', 'orders', 'invoice',
      'crm', 'erp', 'hr', 'finance', 'sales', 'marketing',
      'proxy', 'edge', 'lb', 'loadbalancer', 'nginx', 'apache',
      'search', 'elastic', 'solr', 'kibana', 'grafana', 'prometheus'
    ];

    // Subdomain takeover signatures
    this.takeoverSignatures = {
      'GitHub': ['There isn\'t a GitHub Pages site here'],
      'Heroku': ['No such app', 'no-such-app'],
      'AWS S3': ['NoSuchBucket', 'The specified bucket does not exist'],
      'Azure': ['404 Web Site not found'],
      'Shopify': ['Sorry, this shop is currently unavailable'],
      'Tumblr': ['There\'s nothing here'],
      'WordPress': ['Do you want to register'],
      'Ghost': ['The thing you were looking for is no longer here'],
      'Surge': ['project not found'],
      'Bitbucket': ['Repository not found'],
      'Pantheon': ['The gods are wise'],
      'Fastly': ['Fastly error: unknown domain'],
      'Zendesk': ['Help Center Closed']
    };
  }

  async run(options) {
    console.log('[SubRecon] Starting enumeration with options:', options);

    if (!options.domain) {
      UI.showToast('Please enter a target domain');
      return;
    }

    this.results = [];
    this.isRunning = true;

    const domain = this.normalizeDomain(options.domain);

    try {
      const settings = await Storage.getSettings();
      let subdomains = new Set();

      // 1. Query crt.sh
      if (options.crtsh) {
        UI.updateProgress('subProgress', 10, 'Querying crt.sh...');
        const crtshResults = await this.queryCrtSh(domain);
        crtshResults.forEach(sub => subdomains.add(sub));
      }

      // 2. Wordlist enumeration
      if (options.wordlist) {
        UI.updateProgress('subProgress', 30, 'Running wordlist...');
        this.wordlist.forEach(prefix => {
          subdomains.add(`${prefix}.${domain}`);
        });
      }

      // 3. Alive checking
      const subdomainList = Array.from(subdomains);
      const aliveResults = [];

      if (options.aliveCheck && subdomainList.length > 0) {
        const total = subdomainList.length;
        let checked = 0;

        for (const subdomain of subdomainList) {
          if (!this.isRunning) break;

          checked++;
          const progress = 30 + Math.round((checked / total) * 60);
          UI.updateProgress('subProgress', progress, `Checking: ${subdomain}`);

          const result = await this.checkAlive(subdomain, options.takeover);
          if (result.alive) {
            aliveResults.push(result);

            this.results.push({
              type: 'domain',
              title: subdomain,
              value: subdomain,
              subtitle: `${result.status} - ${result.ip || 'No IP'}${result.takeover ? ' [TAKEOVER POSSIBLE]' : ''}`,
              severity: result.takeover ? 'high' : 'info',
              details: result
            });
          }

          // Rate limiting
          if (settings.delay > 0) {
            await this.sleep(settings.delay);
          }
        }
      } else {
        // Just list them without checking
        subdomainList.forEach(subdomain => {
          this.results.push({
            type: 'domain',
            title: subdomain,
            value: subdomain,
            subtitle: 'Not checked',
            severity: 'info'
          });
        });
      }

      UI.hideProgress('subProgress');
      this.renderResults();
      UI.showToast(`SubRecon found ${this.results.length} subdomains`);

    } catch (error) {
      console.error('[SubRecon] Error:', error);
      UI.hideProgress('subProgress');
      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  normalizeDomain(domain) {
    // Remove protocol and path
    domain = domain.replace(/^https?:\/\//, '');
    domain = domain.split('/')[0];
    domain = domain.split(':')[0];
    // Remove www prefix
    domain = domain.replace(/^www\./, '');
    return domain.toLowerCase();
  }

  async queryCrtSh(domain) {
    const subdomains = [];

    try {
      const response = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url: `https://crt.sh/?q=%25.${domain}&output=json`,
        options: { timeout: 15000 }
      });

      if (response.success && response.body) {
        const data = JSON.parse(response.body);
        data.forEach(entry => {
          const names = entry.name_value.split('\n');
          names.forEach(name => {
            name = name.toLowerCase().trim();
            if (name.endsWith(domain) && !name.startsWith('*')) {
              subdomains.push(name);
            }
          });
        });
      }
    } catch (e) {
      console.warn('crt.sh query failed:', e);
    }

    return [...new Set(subdomains)];
  }

  async checkAlive(subdomain, checkTakeover = false) {
    const result = {
      subdomain,
      alive: false,
      status: null,
      ip: null,
      takeover: false,
      takeoverService: null
    };

    try {
      // Try HTTPS first, then HTTP
      for (const protocol of ['https', 'http']) {
        const response = await chrome.runtime.sendMessage({
          action: 'proxyFetch',
          url: `${protocol}://${subdomain}`,
          options: { timeout: 5000 }
        });

        if (response.success) {
          result.alive = true;
          result.status = response.status;

          // Check for takeover signatures
          if (checkTakeover && response.body) {
            for (const [service, signatures] of Object.entries(this.takeoverSignatures)) {
              for (const sig of signatures) {
                if (response.body.includes(sig)) {
                  result.takeover = true;
                  result.takeoverService = service;
                  break;
                }
              }
              if (result.takeover) break;
            }
          }

          break;
        }
      }
    } catch (e) {
      // Not alive
    }

    return result;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  renderResults() {
    // Sort: takeover first, then by name
    this.results.sort((a, b) => {
      if (a.severity === 'high' && b.severity !== 'high') return -1;
      if (b.severity === 'high' && a.severity !== 'high') return 1;
      return a.title.localeCompare(b.title);
    });

    UI.renderResults('subResults', this.results);

    // Update app results
    this.app.results.subrecon = this.results;
    this.app.updateStats();
  }

  stop() {
    this.isRunning = false;
  }
}
