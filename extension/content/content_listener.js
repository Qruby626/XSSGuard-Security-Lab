/**
 * content/content_listener.js
 * 
 * Content script for passive CSP violation telemetry.
 * 
 * Responsibilities:
 * - Runs at "document_start" to register the event listener as early as possible.
 * - Listens for native browser 'securitypolicyviolation' events.
 * - Dispatches violation telemetry data to the extension Service Worker via chrome.runtime.sendMessage.
 * 
 * Invariants:
 * - Passive telemetry listener only.
 * - No payload scanning or regex evaluation.
 * - No DOM modification or script rewriting.
 * - No nonce creation, validation, or injection.
 * - No independent blocking or security decisions.
 */

(function () {
  'use strict';

  // Prevent duplicate registration in nested execution contexts
  if (window.__xssguard_listener_registered) {
    return;
  }
  window.__xssguard_listener_registered = true;

  window.addEventListener('securitypolicyviolation', function (event) {
    const violationData = {
      blockedURI: event.blockedURI || '',
      violatedDirective: event.violatedDirective || '',
      effectiveDirective: event.effectiveDirective || '',
      documentURI: event.documentURI || window.location.href,
      timeStamp: event.timeStamp || Date.now()
    };

    try {
      chrome.runtime.sendMessage({
        type: 'CSP_VIOLATION_OBSERVED',
        violation: violationData
      }, function () {
        // Silently consume errors if extension background worker is sleeping or restarting
        if (chrome.runtime.lastError) {
          // No-op: observational limitation, not a security failure
        }
      });
    } catch (err) {
      // Passive listener must never interfere with host application execution
    }
  }, true);
})();
