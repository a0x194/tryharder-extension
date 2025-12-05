/**
 * TryHarder Security Suite - UI Utilities
 * Author: a0x194 (https://github.com/a0x194)
 */

export const UI = {
  /**
   * Show a toast notification
   */
  showToast(message, duration = 3000) {
    const existing = document.querySelector('.copy-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'copy-toast';
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => toast.remove(), duration);
  },

  /**
   * Copy text to clipboard
   */
  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      this.showToast('Copied to clipboard');
      return true;
    } catch (e) {
      console.error('Copy failed:', e);
      return false;
    }
  },

  /**
   * Render results to a container
   */
  renderResults(containerId, results, template = 'default') {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!results || results.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M12 16v-4"></path>
            <path d="M12 8h.01"></path>
          </svg>
          <p>No results found</p>
        </div>
      `;
      return;
    }

    let html = '';

    results.forEach(result => {
      html += this.renderResultItem(result);
    });

    container.innerHTML = html;

    // Add click handlers for copy buttons
    container.querySelectorAll('.result-action-btn[data-action="copy"]').forEach(btn => {
      btn.addEventListener('click', () => {
        const value = btn.dataset.value;
        this.copyToClipboard(value);
      });
    });
  },

  /**
   * Render a single result item
   */
  renderResultItem(result) {
    const iconClass = result.type || 'info';
    const icon = this.getIcon(iconClass);
    const severity = result.severity ? `<span class="severity ${result.severity}">${result.severity}</span>` : '';

    return `
      <div class="result-item">
        <div class="result-icon ${iconClass}">${icon}</div>
        <div class="result-content">
          <div class="result-title">${this.escapeHtml(result.title || result.name || 'Finding')}</div>
          ${result.subtitle ? `<div class="result-subtitle">${this.escapeHtml(result.subtitle)}</div>` : ''}
          ${result.value ? `<div class="result-value">${this.escapeHtml(result.value)}</div>` : ''}
          ${severity}
        </div>
        <div class="result-actions">
          ${result.value ? `
            <button class="result-action-btn" data-action="copy" data-value="${this.escapeHtml(result.value)}" title="Copy">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
            </button>
          ` : ''}
        </div>
      </div>
    `;
  },

  /**
   * Render grouped results
   */
  renderGroupedResults(containerId, groups) {
    const container = document.getElementById(containerId);
    if (!container) return;

    let html = '';

    for (const [groupName, results] of Object.entries(groups)) {
      if (results && results.length > 0) {
        html += `
          <div class="result-group">
            <div class="result-group-header">
              ${groupName}
              <span class="result-group-count">${results.length}</span>
            </div>
        `;

        results.forEach(result => {
          html += this.renderResultItem(result);
        });

        html += '</div>';
      }
    }

    if (!html) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M12 16v-4"></path>
            <path d="M12 8h.01"></path>
          </svg>
          <p>No results found</p>
        </div>
      `;
      return;
    }

    container.innerHTML = html;

    // Add click handlers for copy buttons
    container.querySelectorAll('.result-action-btn[data-action="copy"]').forEach(btn => {
      btn.addEventListener('click', () => {
        const value = btn.dataset.value;
        this.copyToClipboard(value);
      });
    });
  },

  /**
   * Update progress bar
   */
  updateProgress(progressId, percent, text = null) {
    const progressBar = document.getElementById(progressId);
    const progressFill = document.getElementById(progressId + 'Fill');
    const progressText = document.getElementById(progressId + 'Text');

    if (progressBar) {
      progressBar.style.display = 'block';
    }
    if (progressFill) {
      progressFill.style.width = `${percent}%`;
    }
    if (progressText) {
      progressText.textContent = text || `${percent}%`;
    }
  },

  /**
   * Hide progress bar
   */
  hideProgress(progressId) {
    const progressBar = document.getElementById(progressId);
    if (progressBar) {
      progressBar.style.display = 'none';
    }
  },

  /**
   * Get icon SVG for result type
   */
  getIcon(type) {
    const icons = {
      endpoint: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>',
      secret: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>',
      param: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>',
      warning: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
      vuln: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>',
      info: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>',
      domain: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>',
      port: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line></svg>',
      header: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
      tech: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>'
    };

    return icons[type] || icons.info;
  },

  /**
   * Escape HTML to prevent XSS
   */
  escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
};
