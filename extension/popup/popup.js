/**
 * popup/popup.js
 * 
 * Logic for XSSGuard Security Monitor Action Popup.
 * 
 * Responsibilities:
 * 1. Identifies the active tab.
 * 2. Fetches read-only CSP & violation telemetry from the background Service Worker.
 * 3. Renders observed CSP header status and nonce presence.
 * 4. Renders native browser CSP violation events observed on the tab.
 * 5. Provides a launcher button to open the host application's XSSGuard Dashboard.
 * 
 * Invariants:
 * - Passive visualizer only.
 * - No security decision making or threat scoring.
 * - Uses strictly approved terminology:
 *   - "CSP: Present" / "CSP: Not Observed"
 *   - "Nonce Observed: Present" / "Nonce Observed: None"
 */

(function () {
  'use strict';

  // DOM Elements
  const tabUrlEl = document.getElementById('tab-url');
  const mainContentEl = document.getElementById('main-content');
  const noTelemetryBoxEl = document.getElementById('no-telemetry-box');
  const noTelemetryMsgEl = document.getElementById('no-telemetry-msg');
  const badgeCspEl = document.getElementById('badge-csp');
  const badgeNonceEl = document.getElementById('badge-nonce');
  const violationCountEl = document.getElementById('violation-count');
  const violationsListEl = document.getElementById('violations-list');
  const emptyMsgEl = document.getElementById('empty-msg');
  const btnDashboardEl = document.getElementById('btn-open-dashboard');
  const btnOptionsEl = document.getElementById('btn-options');

  /**
   * Display fallback notice when no telemetry is available.
   * @param {string} msg
   */
  function showNoTelemetry(msg) {
    if (mainContentEl) mainContentEl.style.display = 'none';
    if (noTelemetryBoxEl) noTelemetryBoxEl.style.display = 'flex';
    if (noTelemetryMsgEl) noTelemetryMsgEl.textContent = msg || 'No CSP telemetry recorded for this tab.';
  }

  /**
   * Render telemetry data retrieved from Service Worker.
   * @param {object} telemetry
   */
  function renderTelemetry(telemetry) {
    if (!telemetry) {
      showNoTelemetry('No CSP telemetry recorded for this tab.');
      return;
    }

    if (mainContentEl) mainContentEl.style.display = 'flex';
    if (noTelemetryBoxEl) noTelemetryBoxEl.style.display = 'none';

    // 1. CSP Header Observation Status
    if (telemetry.hasCsp) {
      badgeCspEl.textContent = 'CSP: Present';
      badgeCspEl.className = 'status-badge badge-success';
    } else {
      badgeCspEl.textContent = 'CSP: Not Observed';
      badgeCspEl.className = 'status-badge badge-none';
    }

    // 2. Nonce Observation Status
    if (telemetry.nonceStatus === 'Present') {
      badgeNonceEl.textContent = 'Nonce Observed: Present';
      badgeNonceEl.className = 'status-badge badge-success';
    } else {
      badgeNonceEl.textContent = 'Nonce Observed: None';
      badgeNonceEl.className = 'status-badge badge-none';
    }


    // 3. CSP Violations Feed
    const violations = telemetry.violations || [];
    violationCountEl.textContent = String(violations.length);

    if (violations.length > 0) {
      violationCountEl.className = 'count-badge has-violations';
      emptyMsgEl.style.display = 'none';
      violationsListEl.style.display = 'flex';
      violationsListEl.innerHTML = '';

      violations.forEach((v) => {
        const li = document.createElement('li');
        li.className = 'violation-item';

        const row = document.createElement('div');
        row.className = 'violation-row';

        const directiveSpan = document.createElement('span');
        directiveSpan.className = 'violation-directive';
        directiveSpan.textContent = v.violatedDirective || v.effectiveDirective || 'CSP Violation';

        const timeSpan = document.createElement('span');
        timeSpan.className = 'violation-time';
        timeSpan.textContent = v.receivedAt || '';

        row.appendChild(directiveSpan);
        row.appendChild(timeSpan);

        const uriDiv = document.createElement('div');
        uriDiv.className = 'violation-uri';
        uriDiv.textContent = 'Blocked: ' + (v.blockedURI || 'inline script');

        li.appendChild(row);
        li.appendChild(uriDiv);
        violationsListEl.appendChild(li);
      });
    } else {
      violationCountEl.className = 'count-badge';
      emptyMsgEl.style.display = 'block';
      violationsListEl.style.display = 'none';
    }
  }

  // -------------------------------------------------------------------------
  // Inisialisasi Popup
  // -------------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', () => {
    // Open Options Page
    if (btnOptionsEl) {
      btnOptionsEl.addEventListener('click', () => {
        if (chrome.runtime.openOptionsPage) {
          chrome.runtime.openOptionsPage();
        } else {
          window.open(chrome.runtime.getURL('options/options.html'));
        }
      });
    }

    // Open Dashboard Button Handler
    if (btnDashboardEl) {
      btnDashboardEl.addEventListener('click', () => {
        chrome.storage.sync.get(
          {
            hostBaseUrl: 'http://localhost:5000',
            dashboardPath: '/xssguard/'
          },
          (items) => {
            let host = (items.hostBaseUrl || 'http://localhost:5000').trim().replace(/\/+$/, '');
            let path = (items.dashboardPath || '/xssguard/').trim();
            if (!path.startsWith('/')) {
              path = '/' + path;
            }
            const dashboardUrl = host + path;
            chrome.tabs.create({ url: dashboardUrl });
          }
        );
      });
    }

    // Identify Active Tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0 || !tabs[0].id) {
        showNoTelemetry('No active tab identified.');
        return;
      }

      const activeTab = tabs[0];
      const rawUrl = activeTab.url || '';

      if (tabUrlEl) {
        tabUrlEl.textContent = rawUrl || 'about:blank';
        tabUrlEl.title = rawUrl;
      }

      // Check if URL belongs to monitored local hosts
      const isMonitoredHost =
        rawUrl.startsWith('http://localhost') ||
        rawUrl.startsWith('http://127.0.0.1');

      if (!isMonitoredHost) {
        showNoTelemetry('No CSP telemetry recorded for this tab (not a monitored local host).');
        return;
      }

      // Query Service Worker for tab telemetry
      chrome.runtime.sendMessage(
        {
          type: 'GET_TAB_TELEMETRY',
          tabId: activeTab.id
        },
        (response) => {
          if (chrome.runtime.lastError || !response || !response.telemetry) {
            // Service worker has not recorded headers yet or page had no CSP header
            showNoTelemetry('No CSP telemetry recorded for this tab.');
            return;
          }
          renderTelemetry(response.telemetry);
        }
      );
    });
  });
})();
