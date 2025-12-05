/**
 * TryHarder Security Suite - Background Service Worker
 * Author: a0x194 (https://github.com/a0x194)
 * Platform: TryHarder (https://www.tryharder.space)
 */

// Store results globally
const globalResults = {
  jshunter: [],
  paramfuzz: [],
  subrecon: [],
  sqlidetect: [],
  authbypass: [],
  wayback: [],
  headeraudit: [],
  apirecon: [],
  portrush: [],
  gitleaks: [],
  certwatch: [],
  dnstracer: [],
  webtechfp: [],
  cachepoison: [],
  protodetect: []
};

// Settings
let settings = {
  delay: 100,
  concurrent: 5,
  timeout: 10000,
  followRedirects: true,
  autoFill: true,
  customHeaders: {}
};

// Load settings on startup
chrome.storage.local.get(['settings'], (result) => {
  if (result.settings) {
    settings = { ...settings, ...result.settings };
  }
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case 'getResults':
      sendResponse({ results: globalResults });
      break;
    case 'updateSettings':
      settings = { ...settings, ...request.settings };
      chrome.storage.local.set({ settings });
      sendResponse({ success: true });
      break;
    case 'getSettings':
      sendResponse({ settings });
      break;
    case 'clearResults':
      if (request.tool) {
        globalResults[request.tool] = [];
      } else {
        Object.keys(globalResults).forEach(key => globalResults[key] = []);
      }
      sendResponse({ success: true });
      break;
    case 'addResult':
      if (request.tool && globalResults[request.tool]) {
        globalResults[request.tool].push(request.result);
      }
      sendResponse({ success: true });
      break;
    case 'fetchUrl':
      fetchWithTimeout(request.url, request.options)
        .then(response => sendResponse({ success: true, data: response }))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true; // Keep channel open for async response
    case 'proxyFetch':
      proxyFetch(request.url, request.options)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true;
    default:
      sendResponse({ error: 'Unknown action' });
  }
  return true;
});

// Fetch with timeout
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeout || settings.timeout);

  try {
    const fetchOptions = {
      ...options,
      signal: controller.signal,
      headers: {
        ...settings.customHeaders,
        ...options.headers
      }
    };

    if (!settings.followRedirects) {
      fetchOptions.redirect = 'manual';
    }

    const response = await fetch(url, fetchOptions);
    clearTimeout(timeout);

    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });

    let body = '';
    try {
      body = await response.text();
    } catch (e) {
      // Body read error
    }

    return {
      status: response.status,
      statusText: response.statusText,
      headers,
      body,
      url: response.url
    };
  } catch (error) {
    clearTimeout(timeout);
    throw error;
  }
}

// Proxy fetch for CORS bypass
async function proxyFetch(url, options = {}) {
  try {
    const response = await fetchWithTimeout(url, options);
    return { success: true, ...response };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Context menu for quick scanning
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'tryharder-scan',
    title: 'TryHarder: Quick Scan',
    contexts: ['page', 'link']
  });

  chrome.contextMenus.create({
    id: 'tryharder-jshunter',
    parentId: 'tryharder-scan',
    title: 'JSHunter - Analyze JS',
    contexts: ['page']
  });

  chrome.contextMenus.create({
    id: 'tryharder-headeraudit',
    parentId: 'tryharder-scan',
    title: 'HeaderAudit - Check Headers',
    contexts: ['page', 'link']
  });

  chrome.contextMenus.create({
    id: 'tryharder-webtechfp',
    parentId: 'tryharder-scan',
    title: 'WebTechFP - Fingerprint',
    contexts: ['page', 'link']
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const url = info.linkUrl || info.pageUrl;

  chrome.storage.local.set({
    quickScan: {
      tool: info.menuItemId.replace('tryharder-', ''),
      url
    }
  });

  // Open popup
  chrome.action.openPopup();
});

console.log('[TryHarder] Background service worker initialized');
