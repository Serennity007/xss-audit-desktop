# XSS Security Audit Report

> **Fictional example:** This report demonstrates formatting and classification only. It is not the result of a real audit, and no reproduction steps were executed.

**Date**: Not applicable — fictional example

**Audited by**: Security Auditor

**Scope**: Fictional `example-react-app`; `src/` only

**Exclusions / Unread Files**: All paths outside this example; no real repository was scanned

**Analysis Type**: Static analysis; no dynamic verification performed

## Executive Summary

- Total locations examined: 1
- High severity vulnerabilities: 1
- Medium severity vulnerabilities: 0
- Low severity issues: 0
- Requires manual review: 0

## High Severity Vulnerabilities

### 1. Preview - Unsanitized URL Data in Raw HTML Rendering

**File**: `src/components/Preview.tsx:8` (fictional path)

**Description**:

A URL query parameter is rendered through React's `dangerouslySetInnerHTML` without an HTML sanitization step. In this fictional code path, an attacker can supply markup that the browser parses as HTML.

**Impact**:

A victim who opens an attacker-crafted URL could execute attacker-controlled JavaScript in the application's origin. A restrictive CSP could reduce impact, but no CSP assessment is included in this fictional example.

**Data Flow**:

`window.location.search` → `URLSearchParams.get("html")` → `dangerouslySetInnerHTML`

**Source**: The `html` URL query parameter.

**Sink**: React `dangerouslySetInnerHTML` on a `div` element.

**Missing Validation**: No context-appropriate HTML sanitizer is applied before the raw HTML sink.

**Confidence**: High for the illustrated static data flow.

**Verification Status**: Static data flow established; dynamic verification not performed.

**Reproduction Notes**: Theoretical only. A test payload could place an HTML element with an event handler in the `html` query parameter. This step was not executed and is not evidence against a real application.

**Vulnerable Code**:

```tsx
const html = new URLSearchParams(window.location.search).get("html") ?? "";
return <div dangerouslySetInnerHTML={{ __html: html }} />;
```

**Fix / Recommendation**:

Prefer rendering text instead of raw HTML. If rich HTML is required, sanitize the final HTML with a maintained, context-appropriate sanitizer and an explicit profile, then avoid unsafe transformations after sanitization. Review the effective sanitizer configuration and add CSP as defense-in-depth.

## Medium/Low Severity Vulnerabilities

None in this fictional example.

## Requires Manual Review

None in this fictional example.

## Search Results Summary

Matches are review leads, not confirmed vulnerabilities. The single match below has a complete illustrated source-to-sink path.

| Layer | Focus | Matches Found | Vulnerabilities |
|-------|-------|---------------|-----------------|
| 1 | DOM/HTML sinks | 1 | 1 |
| 2 | Attr/event sinks | 0 | 0 |
| 3 | URL/navigation & validation bypass | 0 | 0 |
| 4 | Config/content models & JSON-in-script | 0 | 0 |
| 5 | Props spreading/gadgets | 0 | 0 |
| 6 | Untrusted sources + postMessage sender | 0 | 0 |
| 7 | Prototype pollution | 0 | 0 |
| 8 | JS execution sinks | 0 | 0 |
| 9 | CSS/style sinks | 0 | 0 |
| 10 | SVG/XML | 0 | 0 |
| 11 | Markdown/pipelines & mXSS | 0 | 0 |
| 12 | Framework HTML rendering & trust hooks | 0 | 0 |
| 13 | Trusted Types & CSP | 0 | 0 |
| 14 | Framework attribute binding & client template injection | 0 | 0 |
