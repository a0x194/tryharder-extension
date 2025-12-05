/**
 * TryHarder Security Suite - Content Script
 * Author: a0x194 (https://github.com/a0x194)
 * Platform: TryHarder (https://www.tryharder.space)
 *
 * This script runs in the context of web pages to extract data
 */

// Listen for messages from popup/background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case 'getPageInfo':
      sendResponse(getPageInfo());
      break;
    case 'getScripts':
      sendResponse(getPageScripts());
      break;
    case 'getLinks':
      sendResponse(getPageLinks());
      break;
    case 'getForms':
      sendResponse(getPageForms());
      break;
    case 'getCookies':
      sendResponse(getPageCookies());
      break;
    case 'getTechnologies':
      sendResponse(detectTechnologies());
      break;
    case 'extractFromDOM':
      sendResponse(extractFromDOM(request.patterns));
      break;
    default:
      sendResponse({ error: 'Unknown action' });
  }
  return true;
});

// Get basic page information
function getPageInfo() {
  return {
    url: window.location.href,
    origin: window.location.origin,
    hostname: window.location.hostname,
    pathname: window.location.pathname,
    search: window.location.search,
    hash: window.location.hash,
    title: document.title,
    referrer: document.referrer,
    documentElement: document.documentElement.outerHTML.substring(0, 50000)
  };
}

// Get all scripts on the page
function getPageScripts() {
  const scripts = [];
  const scriptElements = document.querySelectorAll('script');

  scriptElements.forEach((script, index) => {
    const src = script.src;
    const inline = !src;
    const content = inline ? script.textContent : null;

    scripts.push({
      index,
      src: src || null,
      inline,
      content: content ? content.substring(0, 100000) : null,
      type: script.type || 'text/javascript',
      async: script.async,
      defer: script.defer
    });
  });

  return { scripts, count: scripts.length };
}

// Get all links on the page
function getPageLinks() {
  const links = [];
  const seen = new Set();

  // Anchor tags
  document.querySelectorAll('a[href]').forEach(a => {
    const href = a.href;
    if (href && !seen.has(href)) {
      seen.add(href);
      links.push({
        href,
        text: a.textContent.trim().substring(0, 100),
        internal: a.hostname === window.location.hostname
      });
    }
  });

  // Link tags
  document.querySelectorAll('link[href]').forEach(link => {
    const href = link.href;
    if (href && !seen.has(href)) {
      seen.add(href);
      links.push({
        href,
        rel: link.rel,
        type: link.type
      });
    }
  });

  return { links, count: links.length };
}

// Get all forms on the page
function getPageForms() {
  const forms = [];

  document.querySelectorAll('form').forEach((form, index) => {
    const inputs = [];
    form.querySelectorAll('input, textarea, select').forEach(input => {
      inputs.push({
        name: input.name,
        type: input.type,
        id: input.id,
        value: input.type === 'password' ? '[HIDDEN]' : input.value
      });
    });

    forms.push({
      index,
      action: form.action,
      method: form.method,
      enctype: form.enctype,
      inputs
    });
  });

  return { forms, count: forms.length };
}

// Get cookies (accessible ones)
function getPageCookies() {
  const cookies = [];
  const cookieString = document.cookie;

  if (cookieString) {
    cookieString.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.trim().split('=');
      cookies.push({
        name,
        value: rest.join('=')
      });
    });
  }

  return { cookies, count: cookies.length };
}

// Technology detection
function detectTechnologies() {
  const tech = {
    frameworks: [],
    libraries: [],
    cms: [],
    analytics: [],
    cdn: [],
    server: [],
    other: []
  };

  // JavaScript Frameworks
  if (window.React || document.querySelector('[data-reactroot]')) tech.frameworks.push('React');
  if (window.Vue || document.querySelector('[data-v-]')) tech.frameworks.push('Vue.js');
  if (window.angular || document.querySelector('[ng-app]')) tech.frameworks.push('AngularJS');
  if (window.ng) tech.frameworks.push('Angular');
  if (window.jQuery || window.$) tech.libraries.push('jQuery');
  if (window._ || window.lodash) tech.libraries.push('Lodash');
  if (window.moment) tech.libraries.push('Moment.js');
  if (window.axios) tech.libraries.push('Axios');
  if (window.Backbone) tech.frameworks.push('Backbone.js');
  if (window.Ember) tech.frameworks.push('Ember.js');
  if (window.Svelte) tech.frameworks.push('Svelte');
  if (window.Alpine) tech.frameworks.push('Alpine.js');

  // CSS Frameworks (check classes)
  const html = document.documentElement.outerHTML;
  if (html.includes('bootstrap') || document.querySelector('.container-fluid')) tech.libraries.push('Bootstrap');
  if (html.includes('tailwind') || document.querySelector('[class*="tw-"]')) tech.libraries.push('Tailwind CSS');
  if (document.querySelector('.mui-') || document.querySelector('[class*="MuiButton"]')) tech.libraries.push('Material-UI');

  // CMS Detection
  const meta = document.querySelector('meta[name="generator"]');
  if (meta) {
    const content = meta.content.toLowerCase();
    if (content.includes('wordpress')) tech.cms.push('WordPress');
    if (content.includes('drupal')) tech.cms.push('Drupal');
    if (content.includes('joomla')) tech.cms.push('Joomla');
    if (content.includes('shopify')) tech.cms.push('Shopify');
  }

  // WordPress specific
  if (document.querySelector('link[href*="wp-content"]') || html.includes('wp-content')) {
    if (!tech.cms.includes('WordPress')) tech.cms.push('WordPress');
  }

  // Analytics
  if (window.ga || window.gtag || html.includes('google-analytics') || html.includes('googletagmanager')) {
    tech.analytics.push('Google Analytics');
  }
  if (html.includes('facebook.net/en_US/fbevents.js')) tech.analytics.push('Facebook Pixel');
  if (window.mixpanel) tech.analytics.push('Mixpanel');
  if (window.amplitude) tech.analytics.push('Amplitude');
  if (html.includes('hotjar')) tech.analytics.push('Hotjar');

  // CDN Detection from script/link sources
  const srcs = [...document.querySelectorAll('script[src], link[href]')].map(el => el.src || el.href);
  const cdnPatterns = {
    'Cloudflare': /cdnjs\.cloudflare\.com|cloudflare/,
    'jsDelivr': /cdn\.jsdelivr\.net/,
    'unpkg': /unpkg\.com/,
    'Google CDN': /ajax\.googleapis\.com/,
    'Microsoft CDN': /ajax\.aspnetcdn\.com/,
    'AWS CloudFront': /cloudfront\.net/,
    'Akamai': /akamai/
  };

  srcs.forEach(src => {
    for (const [cdn, pattern] of Object.entries(cdnPatterns)) {
      if (pattern.test(src) && !tech.cdn.includes(cdn)) {
        tech.cdn.push(cdn);
      }
    }
  });

  return tech;
}

// Extract data from DOM using patterns
function extractFromDOM(patterns = {}) {
  const results = {
    endpoints: [],
    secrets: [],
    emails: [],
    ips: [],
    urls: []
  };

  const html = document.documentElement.outerHTML;

  // Default patterns if none provided
  const defaultPatterns = {
    endpoints: [
      /["'](\/api\/[^"'\s]+)["']/g,
      /["'](\/v[0-9]+\/[^"'\s]+)["']/g,
      /["'](\/graphql[^"'\s]*)["']/g,
      /fetch\s*\(\s*["']([^"']+)["']/g,
      /axios\s*\.\s*(get|post|put|delete)\s*\(\s*["']([^"']+)["']/g
    ],
    secrets: [
      /['"](api[_-]?key|apikey|secret|token|password|auth)['"]\s*[:=]\s*['"]([^'"]+)['"]/gi,
      /['"]([a-z0-9]{32,})['"]/ // Generic long strings
    ],
    emails: [
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
    ],
    ips: [
      /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
    ]
  };

  const patternsToUse = { ...defaultPatterns, ...patterns };

  for (const [type, regexes] of Object.entries(patternsToUse)) {
    if (results[type]) {
      regexes.forEach(regex => {
        let match;
        while ((match = regex.exec(html)) !== null) {
          const value = match[1] || match[0];
          if (!results[type].includes(value)) {
            results[type].push(value);
          }
        }
      });
    }
  }

  return results;
}

console.log('[TryHarder] Content script loaded on', window.location.hostname);
