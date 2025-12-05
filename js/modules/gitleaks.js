/**
 * TryHarder Security Suite - GitLeaks Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Find exposed .git folders and sensitive repo data
 */

import { UI } from '../utils/ui.js';

export class GitLeaks {
  constructor(app) {
    this.app = app;
    this.results = [];

    // Git-related paths to check
    this.gitPaths = [
      '/.git/HEAD',
      '/.git/config',
      '/.git/index',
      '/.git/logs/HEAD',
      '/.git/COMMIT_EDITMSG',
      '/.git/description',
      '/.git/info/exclude',
      '/.git/objects/',
      '/.git/refs/heads/master',
      '/.git/refs/heads/main'
    ];

    // Config files
    this.configPaths = [
      '/.gitignore',
      '/.gitmodules',
      '/.gitattributes',
      '/config.php',
      '/config.json',
      '/config.yml',
      '/config.yaml',
      '/settings.json',
      '/settings.yml',
      '/application.properties',
      '/application.yml',
      '/database.yml',
      '/secrets.yml',
      '/credentials.json',
      '/wp-config.php',
      '/wp-config.php.bak',
      '/configuration.php',
      '/LocalSettings.php'
    ];

    // Environment files
    this.envPaths = [
      '/.env',
      '/.env.local',
      '/.env.development',
      '/.env.production',
      '/.env.staging',
      '/.env.example',
      '/.env.bak',
      '/.env.old',
      '/env.js',
      '/env.json'
    ];

    // Backup files
    this.backupPaths = [
      '/backup.sql',
      '/backup.zip',
      '/backup.tar.gz',
      '/dump.sql',
      '/database.sql',
      '/db.sql',
      '/data.sql',
      '/.htaccess',
      '/.htpasswd',
      '/web.config',
      '/phpinfo.php',
      '/info.php',
      '/test.php',
      '/debug.php',
      '/admin.php.bak',
      '/index.php.bak',
      '/robots.txt',
      '/sitemap.xml'
    ];
  }

  async run(options) {
    console.log('[GitLeaks] Starting scan with options:', options);

    if (!options.url) {
      UI.showToast('Please enter a URL');
      return;
    }

    this.results = [];

    try {
      const baseUrl = this.normalizeUrl(options.url);
      let pathsToCheck = [];

      if (options.gitFolder) pathsToCheck = pathsToCheck.concat(this.gitPaths);
      if (options.configFiles) pathsToCheck = pathsToCheck.concat(this.configPaths);
      if (options.envFiles) pathsToCheck = pathsToCheck.concat(this.envPaths);
      if (options.backupFiles) pathsToCheck = pathsToCheck.concat(this.backupPaths);

      // Check each path
      for (const path of pathsToCheck) {
        const url = baseUrl + path;

        try {
          const response = await chrome.runtime.sendMessage({
            action: 'proxyFetch',
            url,
            options: { timeout: 5000 }
          });

          if (response.success && response.status === 200) {
            const finding = this.analyzeFinding(path, response.body, response.headers);

            if (finding.valid) {
              this.results.push({
                type: finding.type,
                title: finding.title,
                value: url,
                subtitle: finding.description,
                severity: finding.severity,
                details: { path, size: response.body?.length }
              });
            }
          }
        } catch (e) {
          // Skip failed requests
        }

        await this.sleep(50);
      }

      // Try to extract git objects if .git/HEAD was found
      const gitHeadFound = this.results.some(r => r.details?.path?.includes('.git/HEAD'));
      if (gitHeadFound && options.gitFolder) {
        await this.extractGitInfo(baseUrl);
      }

      this.renderResults();
      UI.showToast(`GitLeaks found ${this.results.length} exposed files`);

    } catch (error) {
      console.error('[GitLeaks] Error:', error);
      throw error;
    }
  }

  normalizeUrl(url) {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    const urlObj = new URL(url);
    return urlObj.origin;
  }

  analyzeFinding(path, body, headers) {
    const result = {
      valid: false,
      type: 'info',
      title: 'Unknown',
      description: '',
      severity: 'low'
    };

    const lowerPath = path.toLowerCase();
    const bodyLower = (body || '').toLowerCase();
    const contentType = headers?.['content-type'] || '';

    // Git files
    if (lowerPath.includes('.git/')) {
      if (lowerPath.includes('head') && body?.startsWith('ref: refs/')) {
        result.valid = true;
        result.type = 'vuln';
        result.title = 'Git Repository Exposed';
        result.description = 'Full .git folder accessible - source code leak!';
        result.severity = 'critical';
      } else if (lowerPath.includes('config') && body?.includes('[core]')) {
        result.valid = true;
        result.type = 'secret';
        result.title = 'Git Config Exposed';
        result.description = 'Git configuration with potential credentials';
        result.severity = 'high';
      } else if (body && !contentType.includes('text/html')) {
        result.valid = true;
        result.type = 'warning';
        result.title = 'Git File Exposed';
        result.description = `Git file accessible: ${path}`;
        result.severity = 'high';
      }
    }
    // Environment files
    else if (lowerPath.includes('.env')) {
      if (body && body.includes('=') && !contentType.includes('text/html')) {
        result.valid = true;
        result.type = 'secret';
        result.title = 'Environment File Exposed';
        result.description = 'Environment file with potential secrets';
        result.severity = 'critical';
      }
    }
    // Config files
    else if (lowerPath.includes('config') || lowerPath.includes('settings')) {
      if (body && !contentType.includes('text/html') &&
          (bodyLower.includes('password') || bodyLower.includes('secret') ||
           bodyLower.includes('key') || bodyLower.includes('database'))) {
        result.valid = true;
        result.type = 'secret';
        result.title = 'Config File Exposed';
        result.description = 'Configuration file with sensitive data';
        result.severity = 'high';
      }
    }
    // Backup files
    else if (lowerPath.includes('.sql') || lowerPath.includes('backup') || lowerPath.includes('dump')) {
      if (body && (bodyLower.includes('insert into') || bodyLower.includes('create table') ||
          contentType.includes('application/') || body.length > 1000)) {
        result.valid = true;
        result.type = 'secret';
        result.title = 'Database Backup Exposed';
        result.description = 'Database dump file accessible';
        result.severity = 'critical';
      }
    }
    // PHP Info
    else if (lowerPath.includes('phpinfo') || lowerPath.includes('info.php')) {
      if (bodyLower.includes('php version') || bodyLower.includes('configuration')) {
        result.valid = true;
        result.type = 'warning';
        result.title = 'PHPInfo Exposed';
        result.description = 'PHP configuration information leaked';
        result.severity = 'medium';
      }
    }
    // htaccess/htpasswd
    else if (lowerPath.includes('.htpasswd')) {
      if (body && body.includes(':')) {
        result.valid = true;
        result.type = 'secret';
        result.title = '.htpasswd Exposed';
        result.description = 'Password hash file accessible';
        result.severity = 'critical';
      }
    }
    // Generic sensitive files
    else if (body && body.length > 100 && !contentType.includes('text/html')) {
      result.valid = true;
      result.type = 'info';
      result.title = 'File Exposed';
      result.description = `File accessible: ${path}`;
      result.severity = 'low';
    }

    return result;
  }

  async extractGitInfo(baseUrl) {
    try {
      // Try to get branch name from HEAD
      const headResponse = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url: baseUrl + '/.git/HEAD',
        options: { timeout: 3000 }
      });

      if (headResponse.success && headResponse.body) {
        const branchMatch = headResponse.body.match(/ref: refs\/heads\/(.+)/);
        if (branchMatch) {
          this.results.push({
            type: 'info',
            title: 'Git Branch',
            value: branchMatch[1],
            subtitle: 'Current branch name',
            severity: 'info'
          });
        }
      }

      // Try to get commit log
      const logResponse = await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url: baseUrl + '/.git/logs/HEAD',
        options: { timeout: 3000 }
      });

      if (logResponse.success && logResponse.body) {
        const commits = logResponse.body.split('\n').filter(l => l.trim());
        if (commits.length > 0) {
          this.results.push({
            type: 'info',
            title: 'Git Commits Found',
            value: `${commits.length} commits in log`,
            subtitle: 'Commit history accessible',
            severity: 'medium'
          });
        }
      }
    } catch (e) {
      // Skip
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  renderResults() {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    this.results.sort((a, b) =>
      (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5)
    );

    UI.renderResults('gitResults', this.results);
    this.app.results.gitleaks = this.results;
    this.app.updateStats();
  }
}
