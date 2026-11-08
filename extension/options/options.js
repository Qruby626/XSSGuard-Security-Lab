/**
 * options/options.js
 * 
 * Logic for XSSGuard Extension Settings.
 * 
 * Responsibilities:
 * 1. Loads and validates host configuration parameters.
 * 2. Persists host URL and dashboard path using chrome.storage.sync.
 * 3. Provides clean fallback to defaults.
 * 
 * Invariants:
 * - Pure configuration interface.
 * - Does not store credentials, nonces, cookies, or security evidence.
 */

(function () {
  'use strict';

  const DEFAULT_HOST = 'http://localhost:5000';
  const DEFAULT_PATH = '/xssguard/';

  const formEl = document.getElementById('options-form');
  const hostUrlInput = document.getElementById('host-url');
  const dashboardPathInput = document.getElementById('dashboard-path');
  const btnReset = document.getElementById('btn-reset');
  const statusMsgEl = document.getElementById('status-msg');

  /**
   * Display status notification.
   * @param {string} msg
   * @param {'success'|'error'} type
   */
  function showStatus(msg, type) {
    if (!statusMsgEl) return;
    statusMsgEl.textContent = msg;
    statusMsgEl.className = 'status-msg ' + (type === 'success' ? 'success' : 'error');
    statusMsgEl.style.display = 'block';

    setTimeout(() => {
      statusMsgEl.style.display = 'none';
    }, 3500);
  }

  /**
   * Load saved settings or fall back to defaults.
   */
  function loadSettings() {
    chrome.storage.sync.get(
      {
        hostBaseUrl: DEFAULT_HOST,
        dashboardPath: DEFAULT_PATH
      },
      (items) => {
        if (hostUrlInput) hostUrlInput.value = items.hostBaseUrl || DEFAULT_HOST;
        if (dashboardPathInput) dashboardPathInput.value = items.dashboardPath || DEFAULT_PATH;
      }
    );
  }

  /**
   * Save configuration to chrome.storage.sync after validation.
   * @param {Event} e
   */
  function saveSettings(e) {
    e.preventDefault();

    let host = (hostUrlInput ? hostUrlInput.value : '').trim();
    let path = (dashboardPathInput ? dashboardPathInput.value : '').trim();

    // Basic format validation
    if (!/^https?:\/\/[^/]+/i.test(host)) {
      showStatus('Host Base URL must start with http:// or https:// (e.g. http://localhost:5000)', 'error');
      return;
    }

    if (!path.startsWith('/')) {
      path = '/' + path;
    }
    if (!path.endsWith('/')) {
      path = path + '/';
    }

    // Strip trailing slashes from host URL
    host = host.replace(/\/+$/, '');

    chrome.storage.sync.set(
      {
        hostBaseUrl: host,
        dashboardPath: path
      },
      () => {
        if (chrome.runtime.lastError) {
          showStatus('Failed to save settings: ' + chrome.runtime.lastError.message, 'error');
        } else {
          showStatus('Settings saved successfully.', 'success');
          if (hostUrlInput) hostUrlInput.value = host;
          if (dashboardPathInput) dashboardPathInput.value = path;
        }
      }
    );
  }

  /**
   * Reset inputs to default values.
   */
  function resetSettings() {
    if (hostUrlInput) hostUrlInput.value = DEFAULT_HOST;
    if (dashboardPathInput) dashboardPathInput.value = DEFAULT_PATH;
    chrome.storage.sync.set(
      {
        hostBaseUrl: DEFAULT_HOST,
        dashboardPath: DEFAULT_PATH
      },
      () => {
        showStatus('Settings reset to defaults.', 'success');
      }
    );
  }

  document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    if (formEl) formEl.addEventListener('submit', saveSettings);
    if (btnReset) btnReset.addEventListener('click', resetSettings);
  });
})();
