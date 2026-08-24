"""
DOM risk pattern definitions.
Each entry has a pattern to search for and a description
explaining why it is potentially risky.
"""

DOM_RISKS = [
    {
        "pattern": "document.write(",
        "desc": "document.write() can overwrite the entire page and is a common XSS sink",
        "fix": "Replace with safer DOM manipulation methods like createElement and appendChild",
    },
    {
        "pattern": "innerHTML",
        "desc": "innerHTML renders HTML directly — unsafe when used with user input",
        "fix": "Use innerText for plain text, or sanitize with DOMPurify before using innerHTML",
    },
    {
        "pattern": "outerHTML",
        "desc": "outerHTML replaces the element entirely — same risks as innerHTML",
        "fix": "Use safer DOM methods or sanitize input before assigning",
    },
    {
        "pattern": "eval(",
        "desc": "eval() executes arbitrary JavaScript — extremely dangerous with user input",
        "fix": "Avoid eval() entirely — use JSON.parse() for data or refactor the logic",
    },
    {
        "pattern": "setTimeout(",
        "desc": "setTimeout() can execute strings as code if passed a string argument",
        "fix": "Always pass a function reference, not a string: setTimeout(() => {}, 1000)",
    },
    {
        "pattern": "setInterval(",
        "desc": "setInterval() has the same string execution risk as setTimeout()",
        "fix": "Always pass a function reference, not a string",
    },
    {
        "pattern": "location.hash",
        "desc": "location.hash reads attacker-controlled URL fragments — common DOM XSS source",
        "fix": "Sanitize or encode location.hash before using it in the DOM",
    },
    {
        "pattern": "document.URL",
        "desc": "document.URL is attacker-controlled and a common DOM XSS source",
        "fix": "Sanitize or encode document.URL before using it in the DOM",
    },
    {
        "pattern": "document.referrer",
        "desc": "document.referrer is attacker-influenced and a potential DOM XSS source",
        "fix": "Sanitize document.referrer before rendering it in the page",
    },
    {
        "pattern": "postMessage(",
        "desc": "postMessage() without origin validation allows cross-origin message injection",
        "fix": "Always validate event.origin against an allowlist before processing postMessage data",
    },
    {
        "pattern": "__proto__",
        "desc": "__proto__ assignment is a prototype pollution vector",
        "fix": "Never assign to __proto__; use Object.create(null) for plain dictionaries",
    },
    {
        "pattern": "constructor.prototype",
        "desc": "constructor.prototype manipulation can pollute the prototype chain",
        "fix": "Avoid setting properties via user-controlled key paths; validate object keys",
    },
    {
        "pattern": "window.location =",
        "desc": "Direct window.location assignment with user data is an open redirect source",
        "fix": "Validate and allowlist redirect targets before assigning to window.location",
    },
    {
        "pattern": "location.href =",
        "desc": "location.href assignment with user data is an open redirect source",
        "fix": "Validate redirect targets against an allowlist before using location.href",
    },
    {
        "pattern": "dangerouslySetInnerHTML",
        "desc": "React dangerouslySetInnerHTML bypasses React's built-in XSS protections",
        "fix": "Avoid dangerouslySetInnerHTML with user input; use DOMPurify if unavoidable",
    },
    {
        "pattern": ".html(",
        "desc": "jQuery .html() renders arbitrary HTML — XSS sink when used with user input",
        "fix": "Use .text() for plain text content; sanitize with DOMPurify before .html()",
    },
    {
        "pattern": "localStorage.setItem(",
        "desc": "Sensitive data stored in localStorage is accessible to any same-origin JS",
        "fix": "Do not store authentication tokens, PII, or secrets in localStorage",
    },
    {
        "pattern": "sessionStorage.setItem(",
        "desc": "Sensitive data in sessionStorage is accessible to same-origin JS",
        "fix": "Do not store authentication tokens or sensitive data in sessionStorage",
    },
    {
        "pattern": "` ${",
        "desc": "Template literal with variable interpolation — review for injection if input is user-controlled",
        "fix": "Ensure user-controlled data inserted via template literals is sanitized before DOM insertion",
    },
]
