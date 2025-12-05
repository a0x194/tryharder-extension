/**
 * TryHarder Security Suite - APIRecon Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * API endpoint discovery & documentation detection
 */

import { UI } from '../utils/ui.js';

export class APIRecon {
  constructor(app) {
    this.app = app;
    this.results = [];

    // Common API documentation paths
    this.swaggerPaths = [
      '/swagger.json', '/swagger/v1/swagger.json', '/swagger/v2/swagger.json',
      '/api-docs', '/api-docs.json', '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
      '/openapi.json', '/openapi.yaml', '/openapi/v1.json', '/openapi/v2.json',
      '/docs', '/documentation', '/api/docs', '/api/documentation',
      '/swagger-ui.html', '/swagger-ui/', '/swagger-ui/index.html',
      '/redoc', '/api/swagger', '/api/openapi'
    ];

    // GraphQL paths
    this.graphqlPaths = [
      '/graphql', '/graphiql', '/v1/graphql', '/api/graphql',
      '/playground', '/graphql/playground', '/altair',
      '/graphql-explorer', '/__graphql'
    ];

    // Common API paths
    this.apiPaths = [
      '/api', '/api/v1', '/api/v2', '/api/v3',
      '/v1', '/v2', '/v3',
      '/rest', '/rest/v1', '/rest/v2',
      '/json', '/jsonapi',
      '/api/health', '/api/status', '/health', '/status', '/ping',
      '/api/version', '/version', '/api/info', '/info',
      '/api/users', '/api/user', '/users', '/user',
      '/api/admin', '/admin', '/admin/api',
      '/api/config', '/config', '/configuration',
      '/api/debug', '/debug', '/_debug',
      '/api/metrics', '/metrics', '/_metrics',
      '/actuator', '/actuator/health', '/actuator/info', '/actuator/env'
    ];
  }

  async run(options) {
    console.log('[APIRecon] Starting discovery with options:', options);

    if (!options.url) {
      UI.showToast('Please enter a URL');
      return;
    }

    this.results = [];

    try {
      const baseUrl = this.normalizeUrl(options.url);
      let pathsToCheck = [];

      if (options.swagger) pathsToCheck = pathsToCheck.concat(this.swaggerPaths);
      if (options.graphql) pathsToCheck = pathsToCheck.concat(this.graphqlPaths);
      if (options.common) pathsToCheck = pathsToCheck.concat(this.apiPaths);

      // Add version variations
      if (options.versions) {
        const versionPaths = [];
        for (const path of pathsToCheck) {
          for (let v = 1; v <= 5; v++) {
            versionPaths.push(path.replace(/v\d/, `v${v}`));
            versionPaths.push(`/v${v}${path}`);
          }
        }
        pathsToCheck = pathsToCheck.concat(versionPaths);
      }

      // Remove duplicates
      pathsToCheck = [...new Set(pathsToCheck)];

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
            const type = this.detectType(path, response.body, response.headers);

            this.results.push({
              type: type.icon,
              title: type.name,
              value: url,
              subtitle: `${response.status} - ${type.description}`,
              severity: type.severity,
              details: { path, type: type.name }
            });
          }
        } catch (e) {
          // Skip failed requests
        }

        await this.sleep(50);
      }

      // Also check for GraphQL introspection
      if (options.graphql) {
        await this.checkGraphQLIntrospection(baseUrl);
      }

      this.renderResults();
      UI.showToast(`APIRecon found ${this.results.length} endpoints`);

    } catch (error) {
      console.error('[APIRecon] Error:', error);
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

  detectType(path, body, headers) {
    const lowerPath = path.toLowerCase();
    const contentType = headers?.['content-type'] || '';
    const bodyLower = (body || '').toLowerCase().substring(0, 1000);

    // Swagger/OpenAPI
    if (lowerPath.includes('swagger') || lowerPath.includes('openapi') ||
        bodyLower.includes('"swagger"') || bodyLower.includes('"openapi"')) {
      return {
        name: 'Swagger/OpenAPI',
        description: 'API documentation found',
        icon: 'endpoint',
        severity: 'high'
      };
    }

    // GraphQL
    if (lowerPath.includes('graphql') || lowerPath.includes('graphiql') ||
        bodyLower.includes('graphql') || bodyLower.includes('__schema')) {
      return {
        name: 'GraphQL',
        description: 'GraphQL endpoint found',
        icon: 'endpoint',
        severity: 'high'
      };
    }

    // Actuator
    if (lowerPath.includes('actuator')) {
      return {
        name: 'Spring Actuator',
        description: 'Management endpoint exposed',
        icon: 'warning',
        severity: 'high'
      };
    }

    // Debug endpoints
    if (lowerPath.includes('debug') || lowerPath.includes('_debug')) {
      return {
        name: 'Debug Endpoint',
        description: 'Debug interface accessible',
        icon: 'warning',
        severity: 'high'
      };
    }

    // Health/Status
    if (lowerPath.includes('health') || lowerPath.includes('status') || lowerPath.includes('ping')) {
      return {
        name: 'Health Check',
        description: 'Service health endpoint',
        icon: 'info',
        severity: 'info'
      };
    }

    // Metrics
    if (lowerPath.includes('metrics')) {
      return {
        name: 'Metrics',
        description: 'Metrics endpoint accessible',
        icon: 'warning',
        severity: 'medium'
      };
    }

    // Config
    if (lowerPath.includes('config') || lowerPath.includes('env')) {
      return {
        name: 'Configuration',
        description: 'Configuration endpoint exposed',
        icon: 'secret',
        severity: 'high'
      };
    }

    // Generic API
    return {
      name: 'API Endpoint',
      description: 'API path accessible',
      icon: 'endpoint',
      severity: 'info'
    };
  }

  async checkGraphQLIntrospection(baseUrl) {
    const graphqlEndpoints = ['/graphql', '/api/graphql', '/v1/graphql'];
    const introspectionQuery = {
      query: '{ __schema { types { name } } }'
    };

    for (const endpoint of graphqlEndpoints) {
      try {
        const response = await chrome.runtime.sendMessage({
          action: 'proxyFetch',
          url: baseUrl + endpoint,
          options: {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(introspectionQuery),
            timeout: 5000
          }
        });

        if (response.success && response.body?.includes('__schema')) {
          this.results.push({
            type: 'vuln',
            title: 'GraphQL Introspection Enabled',
            value: baseUrl + endpoint,
            subtitle: 'Full schema introspection is possible',
            severity: 'high'
          });
          break;
        }
      } catch (e) {
        // Skip
      }
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  renderResults() {
    const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
    this.results.sort((a, b) =>
      (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
    );

    UI.renderResults('apiResults', this.results);
    this.app.results.apirecon = this.results;
    this.app.updateStats();
  }
}
