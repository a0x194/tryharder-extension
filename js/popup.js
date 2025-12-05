/**
 * TryHarder Security Suite - Main Popup Script
 * Author: a0x194 (https://github.com/a0x194)
 * Platform: TryHarder (https://www.tryharder.space)
 *
 * 15 Security Tools in One Extension:
 * Tier 1: JSHunter, ParamFuzz, SubRecon, SQLiDetect, AuthBypass
 * Tier 2: WaybackMiner, HeaderAudit, APIRecon, PortRush, GitLeaks
 * Tier 3: CertWatch, DNSTracer, WebTechFP, CachePoison, ProtoDetect
 */

import { JSHunter } from './modules/jshunter.js';
import { ParamFuzz } from './modules/paramfuzz.js';
import { SubRecon } from './modules/subrecon.js';
import { SQLiDetect } from './modules/sqlidetect.js';
import { AuthBypass } from './modules/authbypass.js';
import { WaybackMiner } from './modules/wayback.js';
import { HeaderAudit } from './modules/headeraudit.js';
import { APIRecon } from './modules/apirecon.js';
import { PortRush } from './modules/portrush.js';
import { GitLeaks } from './modules/gitleaks.js';
import { CertWatch } from './modules/certwatch.js';
import { DNSTracer } from './modules/dnstracer.js';
import { WebTechFP } from './modules/webtechfp.js';
import { CachePoison } from './modules/cachepoison.js';
import { ProtoDetect } from './modules/protodetect.js';
import { UI } from './utils/ui.js';
import { Storage } from './utils/storage.js';
import { Export } from './utils/export.js';

class TryHarderSuite {
  constructor() {
    this.currentTool = 'jshunter';
    this.results = {};
    this.stats = { findings: 0, high: 0, medium: 0, low: 0 };
    this.isScanning = false;

    // Initialize modules
    this.tools = {
      jshunter: new JSHunter(this),
      paramfuzz: new ParamFuzz(this),
      subrecon: new SubRecon(this),
      sqlidetect: new SQLiDetect(this),
      authbypass: new AuthBypass(this),
      wayback: new WaybackMiner(this),
      headeraudit: new HeaderAudit(this),
      apirecon: new APIRecon(this),
      portrush: new PortRush(this),
      gitleaks: new GitLeaks(this),
      certwatch: new CertWatch(this),
      dnstracer: new DNSTracer(this),
      webtechfp: new WebTechFP(this),
      cachepoison: new CachePoison(this),
      protodetect: new ProtoDetect(this)
    };

    this.init();
  }

  async init() {
    // Get current tab info
    await this.updateCurrentTab();

    // Setup event listeners
    this.setupNavigation();
    this.setupToolButtons();
    this.setupModals();
    this.setupPortPreset();

    // Load saved results
    await this.loadResults();

    // Check for quick scan from context menu
    await this.checkQuickScan();

    console.log('[TryHarder] Suite initialized');
  }

  async updateCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        this.currentTab = tab;
        document.getElementById('targetUrl').textContent = tab.url;

        // Auto-fill URL inputs if setting is enabled
        const settings = await Storage.getSettings();
        if (settings.autoFill) {
          this.autoFillUrls(tab.url);
        }
      }
    } catch (e) {
      console.error('Error getting current tab:', e);
    }
  }

  autoFillUrls(url) {
    const urlInputs = [
      'paramTargetUrl', 'sqliUrl', 'authTargetUrl', 'headerUrl',
      'apiUrl', 'gitUrl', 'techUrl', 'cacheUrl'
    ];

    urlInputs.forEach(id => {
      const input = document.getElementById(id);
      if (input && !input.value) {
        input.value = url;
      }
    });

    // Extract domain for domain inputs
    try {
      const domain = new URL(url).hostname;
      const domainInputs = ['subDomain', 'waybackDomain', 'certDomain', 'dnsDomain', 'portHost', 'protoHost'];
      domainInputs.forEach(id => {
        const input = document.getElementById(id);
        if (input && !input.value) {
          input.value = domain;
        }
      });
    } catch (e) {}
  }

  setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');

    navItems.forEach(item => {
      item.addEventListener('click', () => {
        const tool = item.dataset.tool;
        this.switchTool(tool);

        // Update active state
        navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
      });
    });
  }

  switchTool(tool) {
    this.currentTool = tool;

    // Hide all panels
    document.querySelectorAll('.tool-panel').forEach(panel => {
      panel.classList.remove('active');
    });

    // Show selected panel
    const panel = document.getElementById(`panel-${tool}`);
    if (panel) {
      panel.classList.add('active');
    }
  }

  setupToolButtons() {
    // JSHunter
    document.getElementById('jsHunterScan')?.addEventListener('click', () => {
      this.runTool('jshunter');
    });

    // ParamFuzz
    document.getElementById('paramFuzzScan')?.addEventListener('click', () => {
      this.runTool('paramfuzz');
    });

    // SubRecon
    document.getElementById('subReconScan')?.addEventListener('click', () => {
      this.runTool('subrecon');
    });

    // SQLiDetect
    document.getElementById('sqliScan')?.addEventListener('click', () => {
      this.runTool('sqlidetect');
    });

    // AuthBypass
    document.getElementById('authBypassScan')?.addEventListener('click', () => {
      this.runTool('authbypass');
    });

    // WaybackMiner
    document.getElementById('waybackScan')?.addEventListener('click', () => {
      this.runTool('wayback');
    });

    // HeaderAudit
    document.getElementById('headerAuditScan')?.addEventListener('click', () => {
      this.runTool('headeraudit');
    });

    // APIRecon
    document.getElementById('apiReconScan')?.addEventListener('click', () => {
      this.runTool('apirecon');
    });

    // PortRush
    document.getElementById('portRushScan')?.addEventListener('click', () => {
      this.runTool('portrush');
    });

    // GitLeaks
    document.getElementById('gitLeaksScan')?.addEventListener('click', () => {
      this.runTool('gitleaks');
    });

    // CertWatch
    document.getElementById('certWatchScan')?.addEventListener('click', () => {
      this.runTool('certwatch');
    });

    // DNSTracer
    document.getElementById('dnsTracerScan')?.addEventListener('click', () => {
      this.runTool('dnstracer');
    });

    // WebTechFP
    document.getElementById('webTechScan')?.addEventListener('click', () => {
      this.runTool('webtechfp');
    });

    // CachePoison
    document.getElementById('cachePoisonScan')?.addEventListener('click', () => {
      this.runTool('cachepoison');
    });

    // ProtoDetect
    document.getElementById('protoDetectScan')?.addEventListener('click', () => {
      this.runTool('protodetect');
    });
  }

  async runTool(toolName) {
    if (this.isScanning) {
      UI.showToast('A scan is already running');
      return;
    }

    const tool = this.tools[toolName];
    if (!tool) {
      console.error(`Tool ${toolName} not found`);
      return;
    }

    this.isScanning = true;
    this.setStatus('scanning', 'Scanning...');

    try {
      const options = this.getToolOptions(toolName);
      await tool.run(options);
    } catch (error) {
      console.error(`Error running ${toolName}:`, error);
      this.setStatus('error', 'Error occurred');
      UI.showToast(`Error: ${error.message}`);
    } finally {
      this.isScanning = false;
      this.setStatus('ready', 'Ready');
    }
  }

  getToolOptions(toolName) {
    const options = {};

    switch (toolName) {
      case 'jshunter':
        options.extractEndpoints = document.getElementById('jsExtractEndpoints')?.checked;
        options.extractSecrets = document.getElementById('jsExtractSecrets')?.checked;
        options.extractDomains = document.getElementById('jsExtractDomains')?.checked;
        options.extractPaths = document.getElementById('jsExtractPaths')?.checked;
        options.deepScan = document.getElementById('jsDeepScan')?.checked;
        break;

      case 'paramfuzz':
        options.url = document.getElementById('paramTargetUrl')?.value;
        options.method = document.getElementById('paramMethod')?.value || 'GET';
        options.common = document.getElementById('paramCommon')?.checked;
        options.admin = document.getElementById('paramAdmin')?.checked;
        options.debug = document.getElementById('paramDebug')?.checked;
        options.api = document.getElementById('paramApi')?.checked;
        options.customList = document.getElementById('paramCustomList')?.value;
        break;

      case 'subrecon':
        options.domain = document.getElementById('subDomain')?.value;
        options.crtsh = document.getElementById('subCrtSh')?.checked;
        options.wordlist = document.getElementById('subWordlist')?.checked;
        options.aliveCheck = document.getElementById('subAliveCheck')?.checked;
        options.takeover = document.getElementById('subTakeover')?.checked;
        break;

      case 'sqlidetect':
        options.url = document.getElementById('sqliUrl')?.value;
        options.errorBased = document.getElementById('sqliErrorBased')?.checked;
        options.timeBased = document.getElementById('sqliTimeBased')?.checked;
        options.boolBased = document.getElementById('sqliBoolBased')?.checked;
        options.union = document.getElementById('sqliUnion')?.checked;
        break;

      case 'authbypass':
        options.url = document.getElementById('authTargetUrl')?.value;
        options.tokenA = document.getElementById('authTokenA')?.value;
        options.tokenB = document.getElementById('authTokenB')?.value;
        options.idorTest = document.getElementById('authIdorTest')?.checked;
        options.methodTest = document.getElementById('authMethodTest')?.checked;
        options.headerTest = document.getElementById('authHeaderTest')?.checked;
        options.pathTest = document.getElementById('authPathTest')?.checked;
        options.idValues = document.getElementById('authIdValues')?.value;
        break;

      case 'wayback':
        options.domain = document.getElementById('waybackDomain')?.value;
        options.urls = document.getElementById('waybackUrls')?.checked;
        options.params = document.getElementById('waybackParams')?.checked;
        options.files = document.getElementById('waybackFiles')?.checked;
        options.endpoints = document.getElementById('waybackEndpoints')?.checked;
        break;

      case 'headeraudit':
        options.url = document.getElementById('headerUrl')?.value;
        break;

      case 'apirecon':
        options.url = document.getElementById('apiUrl')?.value;
        options.swagger = document.getElementById('apiSwagger')?.checked;
        options.graphql = document.getElementById('apiGraphql')?.checked;
        options.common = document.getElementById('apiCommon')?.checked;
        options.versions = document.getElementById('apiVersions')?.checked;
        break;

      case 'portrush':
        options.host = document.getElementById('portHost')?.value;
        options.preset = document.getElementById('portPreset')?.value;
        options.customPorts = document.getElementById('customPorts')?.value;
        break;

      case 'gitleaks':
        options.url = document.getElementById('gitUrl')?.value;
        options.gitFolder = document.getElementById('gitFolder')?.checked;
        options.configFiles = document.getElementById('gitConfig')?.checked;
        options.envFiles = document.getElementById('gitEnv')?.checked;
        options.backupFiles = document.getElementById('gitBackup')?.checked;
        break;

      case 'certwatch':
        options.domain = document.getElementById('certDomain')?.value;
        options.certificates = document.getElementById('certInfo')?.checked ?? true;
        options.ctLogs = document.getElementById('certSan')?.checked ?? true;
        options.analyze = document.getElementById('certCrtsh')?.checked ?? true;
        break;

      case 'dnstracer':
        options.domain = document.getElementById('dnsDomain')?.value;
        options.records = true;
        options.recordTypes = [];
        if (document.getElementById('dnsA')?.checked) options.recordTypes.push('A', 'AAAA');
        if (document.getElementById('dnsMx')?.checked) options.recordTypes.push('MX');
        if (document.getElementById('dnsTxt')?.checked) options.recordTypes.push('TXT');
        if (document.getElementById('dnsNs')?.checked) options.recordTypes.push('NS', 'SOA');
        if (document.getElementById('dnsCname')?.checked) options.recordTypes.push('CNAME', 'CAA');
        options.security = true;
        options.subdomains = document.getElementById('dnsSubdomains')?.checked ?? true;
        break;

      case 'webtechfp':
        options.url = document.getElementById('techUrl')?.value;
        options.frameworks = document.getElementById('techHeaders')?.checked ?? true;
        options.cms = document.getElementById('techHtml')?.checked ?? true;
        options.servers = document.getElementById('techJs')?.checked ?? true;
        options.security = document.getElementById('techCookies')?.checked ?? true;
        options.analytics = true;
        break;

      case 'cachepoison':
        options.url = document.getElementById('cacheUrl')?.value;
        options.detectCache = true;
        options.unkeyedHeaders = document.getElementById('cacheUnkeyed')?.checked ?? true;
        options.paramPollution = document.getElementById('cacheParam')?.checked ?? true;
        options.fatGet = document.getElementById('cacheXForward')?.checked ?? false;
        break;

      case 'protodetect':
        options.host = document.getElementById('protoHost')?.value;
        options.detectProtocols = document.getElementById('protoHttp')?.checked ?? true;
        options.adminInterfaces = document.getElementById('protoWs')?.checked ?? true;
        options.commonServices = document.getElementById('protoGrpc')?.checked ?? true;
        options.websocket = true;
        options.ports = document.getElementById('protoPort')?.value?.split(',').map(p => parseInt(p.trim())).filter(p => p > 0) || [];
        break;
    }

    return options;
  }

  setupModals() {
    // Settings modal
    const settingsBtn = document.getElementById('settingsBtn');
    const settingsModal = document.getElementById('settingsModal');
    const closeSettings = document.getElementById('closeSettings');
    const saveSettings = document.getElementById('saveSettings');
    const resetSettings = document.getElementById('resetSettings');

    settingsBtn?.addEventListener('click', async () => {
      const settings = await Storage.getSettings();
      document.getElementById('settingDelay').value = settings.delay || 100;
      document.getElementById('settingConcurrent').value = settings.concurrent || 5;
      document.getElementById('settingTimeout').value = settings.timeout || 10000;
      document.getElementById('settingFollowRedirects').checked = settings.followRedirects !== false;
      document.getElementById('settingAutoFill').checked = settings.autoFill !== false;
      document.getElementById('settingHeaders').value = JSON.stringify(settings.customHeaders || {}, null, 2);
      settingsModal.classList.add('active');
    });

    closeSettings?.addEventListener('click', () => {
      settingsModal.classList.remove('active');
    });

    saveSettings?.addEventListener('click', async () => {
      try {
        const headers = JSON.parse(document.getElementById('settingHeaders').value || '{}');
        await Storage.saveSettings({
          delay: parseInt(document.getElementById('settingDelay').value) || 100,
          concurrent: parseInt(document.getElementById('settingConcurrent').value) || 5,
          timeout: parseInt(document.getElementById('settingTimeout').value) || 10000,
          followRedirects: document.getElementById('settingFollowRedirects').checked,
          autoFill: document.getElementById('settingAutoFill').checked,
          customHeaders: headers
        });
        settingsModal.classList.remove('active');
        UI.showToast('Settings saved');
      } catch (e) {
        UI.showToast('Invalid JSON in custom headers');
      }
    });

    resetSettings?.addEventListener('click', async () => {
      await Storage.saveSettings({});
      settingsModal.classList.remove('active');
      UI.showToast('Settings reset to defaults');
    });

    // Export modal
    const exportBtn = document.getElementById('exportBtn');
    const exportModal = document.getElementById('exportModal');
    const closeExport = document.getElementById('closeExport');

    exportBtn?.addEventListener('click', () => {
      exportModal.classList.add('active');
    });

    closeExport?.addEventListener('click', () => {
      exportModal.classList.remove('active');
    });

    // Export format buttons
    document.querySelectorAll('.export-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const format = btn.dataset.format;
        Export.exportResults(this.results, format);
        exportModal.classList.remove('active');
      });
    });

    // Close modals on outside click
    [settingsModal, exportModal].forEach(modal => {
      modal?.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.classList.remove('active');
        }
      });
    });
  }

  setupPortPreset() {
    const portPreset = document.getElementById('portPreset');
    const customPortsGroup = document.getElementById('customPortsGroup');

    portPreset?.addEventListener('change', () => {
      if (portPreset.value === 'custom') {
        customPortsGroup.style.display = 'block';
      } else {
        customPortsGroup.style.display = 'none';
      }
    });
  }

  async loadResults() {
    this.results = await Storage.getResults();
    this.updateStats();
  }

  async saveResults() {
    await Storage.saveResults(this.results);
  }

  addResult(tool, result) {
    if (!this.results[tool]) {
      this.results[tool] = [];
    }
    this.results[tool].push(result);
    this.updateStats();
    this.saveResults();
  }

  updateStats() {
    let findings = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    Object.values(this.results).forEach(toolResults => {
      if (Array.isArray(toolResults)) {
        toolResults.forEach(result => {
          findings++;
          switch (result.severity) {
            case 'critical':
            case 'high':
              high++;
              break;
            case 'medium':
              medium++;
              break;
            case 'low':
            case 'info':
              low++;
              break;
          }
        });
      }
    });

    this.stats = { findings, high, medium, low };

    document.getElementById('statFindings').textContent = findings;
    document.getElementById('statHigh').textContent = high;
    document.getElementById('statMedium').textContent = medium;
    document.getElementById('statLow').textContent = low;
  }

  setStatus(type, text) {
    const dot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');

    dot.className = 'status-dot';
    if (type === 'scanning') {
      dot.classList.add('scanning');
    } else if (type === 'error') {
      dot.classList.add('error');
    }

    statusText.textContent = text;
  }

  async checkQuickScan() {
    const { quickScan } = await chrome.storage.local.get(['quickScan']);
    if (quickScan) {
      await chrome.storage.local.remove(['quickScan']);

      // Switch to the tool
      this.switchTool(quickScan.tool);
      document.querySelector(`.nav-item[data-tool="${quickScan.tool}"]`)?.classList.add('active');

      // Run the tool if URL is valid
      if (quickScan.url) {
        this.autoFillUrls(quickScan.url);
        setTimeout(() => this.runTool(quickScan.tool), 500);
      }
    }
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.tryharder = new TryHarderSuite();
});
