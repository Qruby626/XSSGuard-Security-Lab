/**
 * utils/csp_parser.js
 * 
 * Pure string parser for Content-Security-Policy response headers.
 * Extracts directives and observes presence of nonce tokens.
 * 
 * Invariants:
 * - Read-only string parsing only.
 * - No cryptographic nonce validation.
 * - No XSS payload detection or regex rules.
 * - Nonce observation status is strictly "Present" or "None".
 */

(function (global) {
  'use strict';

  /**
   * Parse a Content-Security-Policy header string into structured directives.
   * @param {string|null|undefined} cspHeader - Raw CSP header string.
   * @returns {object} Parsed telemetry object.
   */
  function parseCsp(cspHeader) {
    if (!cspHeader || typeof cspHeader !== 'string' || !cspHeader.trim()) {
      return {
        hasCsp: false,
        rawHeader: '',
        directives: {},
        hasScriptSrc: false,
        nonceObserved: 'None',
        nonceToken: null,
        reportUri: null
      };
    }

    const trimmed = cspHeader.trim();
    const directives = {};
    const parts = trimmed.split(';');

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i].trim();
      if (!part) continue;

      const tokens = part.split(/\s+/);
      const directiveName = tokens[0].toLowerCase();
      const directiveValues = tokens.slice(1);

      directives[directiveName] = directiveValues;
    }

    // Check script-src directive
    const scriptSrcTokens = directives['script-src'] || [];
    const hasScriptSrc = Object.prototype.hasOwnProperty.call(directives, 'script-src');

    // Check report-uri directive
    const reportUriTokens = directives['report-uri'] || [];
    const reportUri = reportUriTokens.length > 0 ? reportUriTokens[0] : null;

    // Observe presence of nonce token in script-src
    let nonceObserved = 'None';
    let nonceToken = null;

    for (let j = 0; j < scriptSrcTokens.length; j++) {
      const token = scriptSrcTokens[j];
      // Strip outer quotes if present: 'nonce-...' or "nonce-..."
      const cleanToken = token.replace(/^['"]|['"]$/g, '');
      if (cleanToken.toLowerCase().startsWith('nonce-')) {
        nonceObserved = 'Present';
        nonceToken = cleanToken.slice(6); // Extract the token string after 'nonce-'
        break;
      }
    }

    return {
      hasCsp: true,
      rawHeader: trimmed,
      directives: directives,
      hasScriptSrc: hasScriptSrc,
      nonceObserved: nonceObserved,
      nonceToken: nonceToken,
      reportUri: reportUri
    };
  }

  const CspParser = {
    parseCsp: parseCsp
  };

  global.CspParser = CspParser;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = CspParser;
  }
})(typeof self !== 'undefined' ? self : this);
