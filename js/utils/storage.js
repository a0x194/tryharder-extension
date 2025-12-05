/**
 * TryHarder Security Suite - Storage Utilities
 * Author: a0x194 (https://github.com/a0x194)
 */

export const Storage = {
  /**
   * Get settings from storage
   */
  async getSettings() {
    try {
      const { settings } = await chrome.storage.local.get(['settings']);
      return settings || {
        delay: 100,
        concurrent: 5,
        timeout: 10000,
        followRedirects: true,
        autoFill: true,
        customHeaders: {}
      };
    } catch (e) {
      console.error('Error getting settings:', e);
      return {};
    }
  },

  /**
   * Save settings to storage
   */
  async saveSettings(settings) {
    try {
      await chrome.storage.local.set({ settings });
      // Also notify background script
      chrome.runtime.sendMessage({ action: 'updateSettings', settings });
      return true;
    } catch (e) {
      console.error('Error saving settings:', e);
      return false;
    }
  },

  /**
   * Get all results from storage
   */
  async getResults() {
    try {
      const { results } = await chrome.storage.local.get(['results']);
      return results || {};
    } catch (e) {
      console.error('Error getting results:', e);
      return {};
    }
  },

  /**
   * Save results to storage
   */
  async saveResults(results) {
    try {
      await chrome.storage.local.set({ results });
      return true;
    } catch (e) {
      console.error('Error saving results:', e);
      return false;
    }
  },

  /**
   * Clear all results
   */
  async clearResults() {
    try {
      await chrome.storage.local.remove(['results']);
      return true;
    } catch (e) {
      console.error('Error clearing results:', e);
      return false;
    }
  },

  /**
   * Get results for a specific tool
   */
  async getToolResults(tool) {
    const results = await this.getResults();
    return results[tool] || [];
  },

  /**
   * Save results for a specific tool
   */
  async saveToolResults(tool, toolResults) {
    const results = await this.getResults();
    results[tool] = toolResults;
    return this.saveResults(results);
  }
};
