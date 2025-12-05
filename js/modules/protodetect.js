/**
 * TryHarder Security Suite - ProtoDetect Module
 * Author: a0x194 (https://github.com/a0x194)
 *
 * Protocol & Service Detection on Non-Standard Ports
 */

import { UI } from '../utils/ui.js';

export class ProtoDetect {
  constructor(app) {
    this.app = app;
    this.results = [];

    // Protocol signatures and detection patterns
    this.protocols = {
      // HTTP variants
      http: {
        ports: [80, 8080, 8000, 8888, 3000, 5000, 9000],
        test: 'http',
        signatures: ['HTTP/', '<!DOCTYPE', '<html', 'Content-Type']
      },
      https: {
        ports: [443, 8443, 9443],
        test: 'https',
        signatures: ['HTTP/', '<!DOCTYPE', '<html']
      },

      // Database protocols (via HTTP error messages)
      mysql: {
        ports: [3306],
        errorPatterns: ['mysql', 'mariadb', 'Access denied']
      },
      postgresql: {
        ports: [5432],
        errorPatterns: ['postgresql', 'pg_hba.conf']
      },
      mongodb: {
        ports: [27017, 27018],
        errorPatterns: ['mongodb', 'mongo']
      },
      redis: {
        ports: [6379],
        errorPatterns: ['redis', 'NOAUTH']
      },
      elasticsearch: {
        ports: [9200, 9300],
        test: 'http',
        signatures: ['elasticsearch', 'lucene', 'cluster_name']
      },

      // Common services
      ssh: {
        ports: [22, 2222],
        signatures: ['SSH-', 'OpenSSH']
      },
      ftp: {
        ports: [21],
        signatures: ['220 ', 'FTP']
      },
      smtp: {
        ports: [25, 587, 465],
        signatures: ['220 ', 'SMTP', 'ESMTP']
      },

      // Web services
      websocket: {
        test: 'ws',
        signatures: ['websocket', 'upgrade']
      },
      graphql: {
        test: 'http',
        paths: ['/graphql', '/api/graphql'],
        signatures: ['__schema', 'graphql']
      },
      grpc: {
        ports: [50051],
        signatures: ['grpc', 'application/grpc']
      }
    };

    // Admin/management interfaces
    this.adminInterfaces = {
      'phpMyAdmin': {
        paths: ['/phpmyadmin/', '/pma/', '/mysql/', '/db/'],
        signatures: ['phpMyAdmin', 'pma_']
      },
      'Adminer': {
        paths: ['/adminer/', '/adminer.php'],
        signatures: ['Adminer', 'adminer']
      },
      'pgAdmin': {
        paths: ['/pgadmin/', '/pgadmin4/'],
        signatures: ['pgAdmin', 'pgadmin']
      },
      'Kibana': {
        paths: ['/', '/_plugin/kibana/'],
        ports: [5601],
        signatures: ['kibana', 'kbn-name']
      },
      'Jenkins': {
        paths: ['/', '/jenkins/'],
        ports: [8080],
        signatures: ['Jenkins', 'jenkins-session', 'X-Jenkins']
      },
      'Grafana': {
        paths: ['/login', '/'],
        ports: [3000],
        signatures: ['grafana', 'Grafana']
      },
      'Prometheus': {
        paths: ['/metrics', '/graph'],
        ports: [9090],
        signatures: ['prometheus', 'Prometheus']
      },
      'RabbitMQ': {
        paths: ['/', '/api/'],
        ports: [15672],
        signatures: ['RabbitMQ', 'rabbitmq']
      },
      'Docker': {
        paths: ['/v1.40/containers/json', '/version', '/_ping'],
        ports: [2375, 2376],
        signatures: ['docker', 'Docker', 'ApiVersion']
      },
      'Kubernetes': {
        paths: ['/api', '/api/v1', '/healthz'],
        ports: [6443, 8443, 10250],
        signatures: ['kubernetes', 'k8s']
      }
    };
  }

  async run(options) {
    console.log('[ProtoDetect] Starting detection with options:', options);

    if (!options.host) {
      UI.showToast('Please enter a target host');
      return;
    }

    this.results = [];

    try {
      const host = this.normalizeHost(options.host);

      // Detect protocols on specified ports
      if (options.detectProtocols) {
        await this.detectProtocols(host, options.ports || []);
      }

      // Scan for admin interfaces
      if (options.adminInterfaces) {
        await this.scanAdminInterfaces(host);
      }

      // Check common service ports
      if (options.commonServices) {
        await this.checkCommonServices(host);
      }

      // WebSocket detection
      if (options.websocket) {
        await this.detectWebSocket(host);
      }

      this.renderResults();
      UI.showToast(`ProtoDetect found ${this.results.length} services`);

    } catch (error) {
      console.error('[ProtoDetect] Error:', error);
      throw error;
    }
  }

  normalizeHost(host) {
    host = host.replace(/^https?:\/\//, '');
    host = host.split('/')[0];
    host = host.split(':')[0];
    return host;
  }

  async detectProtocols(host, customPorts) {
    // Combine custom ports with default interesting ports
    const portsToCheck = new Set([
      ...customPorts,
      80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 9090
    ]);

    for (const port of portsToCheck) {
      await this.probePort(host, port);
      await this.sleep(100);
    }
  }

  async probePort(host, port) {
    const protocols = port === 443 || port === 8443 ? ['https'] : ['http', 'https'];

    for (const protocol of protocols) {
      try {
        const url = `${protocol}://${host}:${port}/`;

        const response = await chrome.runtime.sendMessage({
          action: 'proxyFetch',
          url,
          options: { timeout: 5000 }
        });

        if (response.success) {
          const service = this.identifyService(response.body, response.headers, port);

          this.results.push({
            type: 'service',
            title: service.name,
            value: `${host}:${port}`,
            subtitle: `${protocol.toUpperCase()} - ${service.description}`,
            severity: service.severity,
            details: { port, protocol, service: service.name }
          });

          // Don't try other protocols if this one worked
          break;
        }
      } catch (e) {
        // Port/protocol combination not accessible
      }
    }
  }

  identifyService(body, headers, port) {
    const bodyLower = (body || '').toLowerCase();
    const headerStr = JSON.stringify(headers || {}).toLowerCase();

    // Check for known services
    for (const [name, config] of Object.entries(this.adminInterfaces)) {
      if (config.ports && config.ports.includes(port)) {
        for (const sig of config.signatures) {
          if (bodyLower.includes(sig.toLowerCase()) || headerStr.includes(sig.toLowerCase())) {
            return {
              name: name,
              description: 'Management interface detected',
              severity: 'high'
            };
          }
        }
      }
    }

    // Check Elasticsearch
    if (bodyLower.includes('cluster_name') && bodyLower.includes('version')) {
      return {
        name: 'Elasticsearch',
        description: 'Search engine API',
        severity: 'high'
      };
    }

    // Check for API responses
    if (bodyLower.includes('"status"') || bodyLower.includes('"data"') ||
        bodyLower.includes('"error"')) {
      return {
        name: 'API Endpoint',
        description: 'JSON API detected',
        severity: 'medium'
      };
    }

    // Generic HTTP service
    return {
      name: 'HTTP Service',
      description: `Web service on port ${port}`,
      severity: 'info'
    };
  }

  async scanAdminInterfaces(host) {
    for (const [name, config] of Object.entries(this.adminInterfaces)) {
      const ports = config.ports || [80, 443, 8080];

      for (const port of ports) {
        for (const path of (config.paths || ['/'])) {
          try {
            const protocol = port === 443 || port === 8443 ? 'https' : 'http';
            const url = `${protocol}://${host}:${port}${path}`;

            const response = await chrome.runtime.sendMessage({
              action: 'proxyFetch',
              url,
              options: { timeout: 5000 }
            });

            if (response.success && response.status === 200) {
              const body = response.body || '';
              const matched = config.signatures.some(sig =>
                body.toLowerCase().includes(sig.toLowerCase())
              );

              if (matched) {
                this.results.push({
                  type: 'admin',
                  title: name,
                  value: url,
                  subtitle: 'Admin interface exposed!',
                  severity: 'critical'
                });
              }
            }
          } catch (e) {
            // Skip
          }

          await this.sleep(50);
        }
      }
    }
  }

  async checkCommonServices(host) {
    const serviceChecks = [
      { name: 'Elasticsearch', port: 9200, path: '/' },
      { name: 'Kibana', port: 5601, path: '/' },
      { name: 'Grafana', port: 3000, path: '/login' },
      { name: 'Prometheus', port: 9090, path: '/graph' },
      { name: 'Jenkins', port: 8080, path: '/' },
      { name: 'RabbitMQ Management', port: 15672, path: '/' },
      { name: 'CouchDB', port: 5984, path: '/' },
      { name: 'Consul', port: 8500, path: '/v1/agent/self' },
      { name: 'etcd', port: 2379, path: '/version' },
      { name: 'Memcached Stats', port: 11211, path: '/' },
      { name: 'Redis Commander', port: 8081, path: '/' },
      { name: 'Mongo Express', port: 8081, path: '/' },
      { name: 'Traefik Dashboard', port: 8080, path: '/dashboard/' },
      { name: 'Portainer', port: 9000, path: '/' },
      { name: 'Kubernetes Dashboard', port: 8443, path: '/' }
    ];

    for (const service of serviceChecks) {
      try {
        const protocol = service.port === 8443 || service.port === 443 ? 'https' : 'http';
        const url = `${protocol}://${host}:${service.port}${service.path}`;

        const response = await chrome.runtime.sendMessage({
          action: 'proxyFetch',
          url,
          options: { timeout: 3000 }
        });

        if (response.success && response.status === 200) {
          this.results.push({
            type: 'service',
            title: service.name,
            value: url,
            subtitle: `Service accessible on port ${service.port}`,
            severity: 'medium'
          });
        }
      } catch (e) {
        // Service not accessible
      }

      await this.sleep(50);
    }
  }

  async detectWebSocket(host) {
    const wsPaths = ['/', '/ws', '/websocket', '/socket.io/', '/sockjs/'];
    const ports = [80, 443, 8080, 3000];

    for (const port of ports) {
      for (const path of wsPaths) {
        try {
          const protocol = port === 443 ? 'wss' : 'ws';
          const wsUrl = `${protocol}://${host}:${port}${path}`;

          // We can't actually test WebSocket from extension context easily
          // But we can check if the HTTP endpoint responds with upgrade headers

          const httpProtocol = port === 443 ? 'https' : 'http';
          const httpUrl = `${httpProtocol}://${host}:${port}${path}`;

          const response = await chrome.runtime.sendMessage({
            action: 'proxyFetch',
            url: httpUrl,
            options: {
              timeout: 3000,
              headers: {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
              }
            }
          });

          if (response.success) {
            const headers = response.headers || {};
            const upgradeHeader = Object.keys(headers).find(h =>
              h.toLowerCase() === 'upgrade'
            );

            if (upgradeHeader || response.status === 101) {
              this.results.push({
                type: 'service',
                title: 'WebSocket Endpoint',
                value: wsUrl,
                subtitle: 'WebSocket service detected',
                severity: 'info'
              });
              break;
            }
          }
        } catch (e) {
          // Skip
        }
      }

      await this.sleep(50);
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

    UI.renderResults('protoResults', this.results);
    this.app.results.protodetect = this.results;
    this.app.updateStats();
  }
}
