/**
 * TryHarder Security Suite - WebTechFP Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Website Technology Fingerprinting
 */

import { UI } from '../utils/ui.js';

export class WebTechFP {
  constructor(app) {
    this.app = app;
    this.results = [];

    // Technology signatures
    this.signatures = {
      // JavaScript frameworks
      frameworks: {
        'React': {
          patterns: ['react', '_reactRootContainer', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
          headers: [],
          scripts: ['react.js', 'react.min.js', 'react.production.min.js']
        },
        'Vue.js': {
          patterns: ['__vue__', '__VUE__', 'Vue.config'],
          headers: [],
          scripts: ['vue.js', 'vue.min.js', 'vue.runtime']
        },
        'Angular': {
          patterns: ['ng-version', 'ng-app', '__ng_'],
          headers: [],
          scripts: ['angular.js', 'angular.min.js', '@angular/core']
        },
        'jQuery': {
          patterns: ['jQuery', 'jquery'],
          headers: [],
          scripts: ['jquery.js', 'jquery.min.js', 'jquery-']
        },
        'Next.js': {
          patterns: ['__NEXT_DATA__', '_next/static', 'next/router'],
          headers: ['x-nextjs-cache', 'x-nextjs-matched-path'],
          scripts: ['_next/']
        },
        'Nuxt.js': {
          patterns: ['__NUXT__', '_nuxt/'],
          headers: [],
          scripts: ['_nuxt/']
        },
        'Svelte': {
          patterns: ['svelte-'],
          headers: [],
          scripts: ['svelte']
        }
      },

      // CMS/Platforms
      cms: {
        'WordPress': {
          patterns: ['wp-content', 'wp-includes', 'wp-json'],
          headers: ['x-powered-by: wp', 'link: <.*wp-json'],
          scripts: ['wp-includes', 'wp-content']
        },
        'Drupal': {
          patterns: ['Drupal.settings', 'drupal.js', '/sites/default/'],
          headers: ['x-drupal-cache', 'x-generator: drupal'],
          scripts: ['drupal']
        },
        'Joomla': {
          patterns: ['/components/com_', '/media/jui/', 'Joomla!'],
          headers: [],
          scripts: ['joomla']
        },
        'Shopify': {
          patterns: ['Shopify.theme', 'cdn.shopify.com', 'myshopify.com'],
          headers: ['x-shopify-stage'],
          scripts: ['cdn.shopify.com']
        },
        'Magento': {
          patterns: ['Mage.Cookies', '/static/version', 'mage/'],
          headers: [],
          scripts: ['mage/', 'magento']
        },
        'Ghost': {
          patterns: ['ghost-', 'ghost/'],
          headers: ['x-ghost-'],
          scripts: ['ghost']
        }
      },

      // Web servers
      servers: {
        'nginx': {
          headers: ['server: nginx']
        },
        'Apache': {
          headers: ['server: apache']
        },
        'IIS': {
          headers: ['server: microsoft-iis', 'x-powered-by: asp.net']
        },
        'Cloudflare': {
          headers: ['server: cloudflare', 'cf-ray']
        },
        'AWS': {
          headers: ['x-amz-', 'x-amzn-', 'server: amazons3']
        },
        'Vercel': {
          headers: ['x-vercel-', 'server: vercel']
        },
        'Netlify': {
          headers: ['x-nf-', 'server: netlify']
        }
      },

      // Security/WAF
      security: {
        'Cloudflare WAF': {
          headers: ['cf-ray', 'cf-cache-status']
        },
        'AWS WAF': {
          headers: ['x-amzn-waf']
        },
        'Akamai': {
          headers: ['x-akamai-', 'akamai-']
        },
        'Sucuri': {
          headers: ['x-sucuri-']
        },
        'Imperva': {
          headers: ['x-iinfo']
        }
      },

      // Analytics
      analytics: {
        'Google Analytics': {
          patterns: ['google-analytics.com/analytics.js', 'gtag(', 'ga('],
          scripts: ['google-analytics.com', 'googletagmanager.com']
        },
        'Google Tag Manager': {
          patterns: ['googletagmanager.com/gtm.js'],
          scripts: ['googletagmanager.com']
        },
        'Facebook Pixel': {
          patterns: ['connect.facebook.net', 'fbq('],
          scripts: ['connect.facebook.net']
        },
        'Hotjar': {
          patterns: ['hotjar.com', 'hj('],
          scripts: ['static.hotjar.com']
        },
        'Mixpanel': {
          patterns: ['mixpanel.com', 'mixpanel.init'],
          scripts: ['cdn.mxpnl.com']
        }
      }
    };
  }

  async run(options) {
    console.log('[WebTechFP] Starting fingerprinting with options:', options);

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

      // Fetch the page
      const response = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url,
        options: { timeout: 15000 }
      });

      if (!response.success) {
        UI.showToast('Failed to fetch target');
        return;
      }

      const html = response.body || '';
      const headers = response.headers || {};

      // Detect technologies
      if (options.frameworks) {
        this.detectCategory('frameworks', 'Framework', html, headers);
      }

      if (options.cms) {
        this.detectCategory('cms', 'CMS/Platform', html, headers);
      }

      if (options.servers) {
        this.detectCategory('servers', 'Server/CDN', html, headers);
      }

      if (options.security) {
        this.detectCategory('security', 'Security/WAF', html, headers);
      }

      if (options.analytics) {
        this.detectCategory('analytics', 'Analytics', html, headers);
      }

      // Extract additional info
      this.extractMetaInfo(html);
      this.extractScriptSources(html);
      this.analyzeHeaders(headers);

      this.renderResults();
      UI.showToast(`WebTechFP detected ${this.results.length} technologies`);

    } catch (error) {
      console.error('[WebTechFP] Error:', error);
      throw error;
    }
  }

  detectCategory(category, categoryName, html, headers) {
    const sigs = this.signatures[category];
    const htmlLower = html.toLowerCase();
    const headerStr = JSON.stringify(headers).toLowerCase();

    for (const [techName, sig] of Object.entries(sigs)) {
      let detected = false;
      let confidence = 0;
      const evidence = [];

      // Check patterns in HTML
      if (sig.patterns) {
        for (const pattern of sig.patterns) {
          if (htmlLower.includes(pattern.toLowerCase())) {
            detected = true;
            confidence += 30;
            evidence.push(`Pattern: ${pattern}`);
          }
        }
      }

      // Check headers
      if (sig.headers) {
        for (const headerPattern of sig.headers) {
          if (headerStr.includes(headerPattern.toLowerCase())) {
            detected = true;
            confidence += 40;
            evidence.push(`Header: ${headerPattern}`);
          }
        }
      }

      // Check script sources
      if (sig.scripts) {
        for (const script of sig.scripts) {
          if (htmlLower.includes(script.toLowerCase())) {
            detected = true;
            confidence += 30;
            evidence.push(`Script: ${script}`);
          }
        }
      }

      if (detected) {
        confidence = Math.min(confidence, 100);
        this.results.push({
          type: 'tech',
          title: techName,
          value: categoryName,
          subtitle: `Confidence: ${confidence}% | ${evidence.slice(0, 2).join(', ')}`,
          severity: 'info',
          details: { category: categoryName, confidence, evidence }
        });
      }
    }
  }

  extractMetaInfo(html) {
    // Extract generator meta tag
    const generatorMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
    if (generatorMatch) {
      this.results.push({
        type: 'tech',
        title: 'Generator',
        value: generatorMatch[1],
        subtitle: 'From meta generator tag',
        severity: 'info'
      });
    }

    // Extract powered-by meta
    const poweredMatch = html.match(/<meta[^>]*name=["']powered-by["'][^>]*content=["']([^"']+)["']/i);
    if (poweredMatch) {
      this.results.push({
        type: 'tech',
        title: 'Powered By',
        value: poweredMatch[1],
        subtitle: 'From meta tag',
        severity: 'info'
      });
    }

    // Check for common CDN patterns
    const cdnPatterns = [
      { pattern: 'cdnjs.cloudflare.com', name: 'cdnjs' },
      { pattern: 'unpkg.com', name: 'unpkg' },
      { pattern: 'jsdelivr.net', name: 'jsDelivr' },
      { pattern: 'maxcdn.bootstrapcdn.com', name: 'Bootstrap CDN' },
      { pattern: 'ajax.googleapis.com', name: 'Google CDN' },
      { pattern: 'code.jquery.com', name: 'jQuery CDN' }
    ];

    for (const cdn of cdnPatterns) {
      if (html.includes(cdn.pattern)) {
        this.results.push({
          type: 'info',
          title: 'CDN Used',
          value: cdn.name,
          subtitle: cdn.pattern,
          severity: 'info'
        });
      }
    }
  }

  extractScriptSources(html) {
    // Extract external script sources
    const scriptRegex = /<script[^>]*src=["']([^"']+)["']/gi;
    const scripts = new Set();
    let match;

    while ((match = scriptRegex.exec(html)) !== null) {
      const src = match[1];
      if (src.startsWith('http') || src.startsWith('//')) {
        try {
          const url = new URL(src, 'https://example.com');
          scripts.add(url.hostname);
        } catch (e) {
          // Skip invalid URLs
        }
      }
    }

    if (scripts.size > 0) {
      this.results.push({
        type: 'info',
        title: 'External Script Domains',
        value: `${scripts.size} domains`,
        subtitle: [...scripts].slice(0, 5).join(', '),
        severity: 'info',
        details: { domains: [...scripts] }
      });
    }
  }

  analyzeHeaders(headers) {
    // Check server header
    const serverHeader = Object.keys(headers).find(h => h.toLowerCase() === 'server');
    if (serverHeader) {
      this.results.push({
        type: 'tech',
        title: 'Server',
        value: headers[serverHeader],
        subtitle: 'From Server header',
        severity: 'info'
      });
    }

    // Check X-Powered-By
    const poweredBy = Object.keys(headers).find(h => h.toLowerCase() === 'x-powered-by');
    if (poweredBy) {
      this.results.push({
        type: 'tech',
        title: 'X-Powered-By',
        value: headers[poweredBy],
        subtitle: 'Technology disclosure',
        severity: 'low'
      });
    }

    // Check for interesting headers
    const interestingHeaders = [
      'x-aspnet-version', 'x-aspnetmvc-version', 'x-runtime',
      'x-version', 'x-generator', 'x-cms'
    ];

    for (const headerName of interestingHeaders) {
      const found = Object.keys(headers).find(h => h.toLowerCase() === headerName);
      if (found) {
        this.results.push({
          type: 'warning',
          title: `Header: ${found}`,
          value: headers[found],
          subtitle: 'Version disclosure',
          severity: 'low'
        });
      }
    }

    // Detect programming language from headers
    const xPowered = headers[poweredBy]?.toLowerCase() || '';
    if (xPowered.includes('php')) {
      this.results.push({
        type: 'tech',
        title: 'Programming Language',
        value: 'PHP',
        subtitle: 'Detected from headers',
        severity: 'info'
      });
    } else if (xPowered.includes('asp.net')) {
      this.results.push({
        type: 'tech',
        title: 'Programming Language',
        value: 'ASP.NET',
        subtitle: 'Detected from headers',
        severity: 'info'
      });
    }
  }

  renderResults() {
    // Group by type for better display
    this.results.sort((a, b) => {
      const typeOrder = { tech: 0, warning: 1, info: 2 };
      return (typeOrder[a.type] || 3) - (typeOrder[b.type] || 3);
    });

    UI.renderResults('techResults', this.results);
    this.app.results.webtechfp = this.results;
    this.app.updateStats();
  }
}
