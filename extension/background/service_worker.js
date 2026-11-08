/**
 * background/service_worker.js
 * 
 * Background Service Worker for XSSGuard Chrome Extension (Manifest V3).
 * 
 * Responsibilities:
 * 1. Read-only observation of HTTP response headers via chrome.webRequest.onHeadersReceived.
 * 2. Parses Content-Security-Policy header to identify CSP presence and nonce tokens.
 * 3. Maintains ephemeral, in-memory telemetry state per tab.
 * 4. Receives passive CSP violation reports dispatched by content_listener.js.
 * 5. Serves tab telemetry to the Popup UI upon request.
 * 6. Updates extension toolbar badge with violation count / observed CSP indicator.
 * 
 * Invariants:
 * - Read-only observation by design.
 * - No blocking handlers, no BlockingResponse, no cancel/redirect.
 * - No modification of request headers, response headers, or response body.
 * - No network blocking or XSS blocking.
 */

importScripts('/utils/csp_parser.js');

// Ephemeral in-memory store for tab telemetry
// Key: tabId (number) -> Value: TabTelemetry (object)
const tabTelemetryStore = new Map();

/**
 * Update the extension toolbar action badge for a tab.
 * @param {number} tabId
 * @param {number} violationCount
 * @param {boolean} hasCsp
 */
function updateBadge(tabId, violationCount, hasCsp) {
  if (tabId < 0) return;

  try {
    if (violationCount > 0) {
      chrome.action.setBadgeText({ text: String(violationCount), tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#dc3545', tabId: tabId }); // Red badge for violations
    } else if (hasCsp) {
      chrome.action.setBadgeText({ text: 'CSP', tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#198754', tabId: tabId }); // Green badge: CSP header observed
    } else {
      chrome.action.setBadgeText({ text: '', tabId: tabId });
    }
  } catch (err) {
    // Ignore badge update errors if tab was closed
  }
}

/**
 * Retrieve or initialize telemetry for a tab.
 * @param {number} tabId
 * @returns {object}
 */
function getOrCreateTelemetry(tabId) {
  if (!tabTelemetryStore.has(tabId)) {
    tabTelemetryStore.set(tabId, {
      url: '',
      hasCsp: false,
      cspStatus: 'Missing',
      nonceStatus: 'None',
      reportUri: null,
      directives: {},
      violations: [],
      lastUpdated: Date.now()
    });
  }
  return tabTelemetryStore.get(tabId);
}

// ---------------------------------------------------------------------------
// 1. Read-Only HTTP Response Header Observation
// ---------------------------------------------------------------------------
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!details || details.tabId < 0) {
      return;
    }

    // Only main_frame responses define the tab's primary CSP telemetry.
    // Subresource responses (script, stylesheet, image, xhr, sub_frame, etc.)
    // must not overwrite the main document's CSP status, nonce observation, or URL.
    if (details.type !== 'main_frame') {
      return;
    }

    const tabId = details.tabId;

    let cspHeaderValue = null;
    if (details.responseHeaders) {
      for (let i = 0; i < details.responseHeaders.length; i++) {
        const header = details.responseHeaders[i];
        if (header.name && header.name.toLowerCase() === 'content-security-policy') {
          cspHeaderValue = header.value;
          break;
        }
      }
    }

    const parsed = CspParser.parseCsp(cspHeaderValue);

    const telemetry = {
      url: details.url || '',
      hasCsp: parsed.hasCsp,
      cspStatus: parsed.hasCsp ? 'Enforced' : 'Missing',
      nonceStatus: parsed.nonceObserved, // 'Present' or 'None'
      reportUri: parsed.reportUri,
      directives: parsed.directives,
      violations: [],
      lastUpdated: Date.now()
    };

    tabTelemetryStore.set(tabId, telemetry);
    updateBadge(tabId, 0, parsed.hasCsp);
  },
  {
    urls: [
      'http://localhost/*',
      'http://127.0.0.1/*'
    ]
  },
  ['responseHeaders']
);

// ---------------------------------------------------------------------------
// 2. Tab Lifecycle Cleanup
// ---------------------------------------------------------------------------
chrome.tabs.onRemoved.addListener((tabId) => {
  tabTelemetryStore.delete(tabId);
});

chrome.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
  tabTelemetryStore.delete(removedTabId);
});

// ---------------------------------------------------------------------------
// 3. Message Passing Hub (Content Script & Popup Communication)
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) {
    return false;
  }

  // Receive passive CSP violation event from content_listener.js
  if (message.type === 'CSP_VIOLATION_OBSERVED') {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId !== null && tabId >= 0) {
      const telemetry = getOrCreateTelemetry(tabId);

      const violationRecord = {
        blockedURI: message.violation.blockedURI || 'inline',
        violatedDirective: message.violation.violatedDirective || '',
        effectiveDirective: message.violation.effectiveDirective || '',
        documentURI: message.violation.documentURI || '',
        timeStamp: message.violation.timeStamp || Date.now(),
        receivedAt: new Date().toLocaleTimeString()
      };

      telemetry.violations.unshift(violationRecord);
      if (telemetry.violations.length > 50) {
        telemetry.violations = telemetry.violations.slice(0, 50);
      }
      telemetry.lastUpdated = Date.now();

      updateBadge(tabId, telemetry.violations.length, telemetry.hasCsp);
    }
    sendResponse({ status: 'received' });
    return true;
  }

  // Serve telemetry to popup UI upon request
  if (message.type === 'GET_TAB_TELEMETRY') {
    const tabId = message.tabId;
    const telemetry = tabTelemetryStore.get(tabId) || null;
    sendResponse({ telemetry: telemetry });
    return true;
  }

  return false;
});
