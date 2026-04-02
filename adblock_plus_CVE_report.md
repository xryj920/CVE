# Vulnerability Report: Premium Authorization Bypass in Adblock Plus Chrome Extension

---

## 1. Summary

A missing origin validation vulnerability in Adblock Plus Chrome Extension (`cfhdojbkjhnklbpkdaibdccddilifddb`, v4.36.1) allows any JavaScript running in the context of `accounts.adblockplus.org` to forge a `payment_success` postMessage event and activate the Premium subscription without any payment. Combined with the absence of binding between the submitted `userId` and a verified payment session in the extension background, the entire Premium authorization chain can be bypassed in approximately 30 seconds with a single line of JavaScript.

---

## 2. Affected Product

| Field | Details |
|-------|---------|
| Product | Adblock Plus – free ad blocker |
| Vendor | Eyeo GmbH |
| Extension ID | `cfhdojbkjhnklbpkdaibdccddilifddb` |
| Tested Version | 4.36.1 |
| Platform | Google Chrome |
| Affected Users | ~41 million (Chrome); ~500 million cumulative downloads across all platforms |
| Injection Scope | `https://accounts.adblockplus.org/*`, `https://*.myaccount.adblockplus.org/*` |

---

## 3. Vulnerability Details

### 3.1 Vulnerability Type

- **CWE-346**: Origin Validation Error
- **CWE-284**: Improper Access Control
- **OWASP Category**: A01:2021 – Broken Access Control
- **Attack Pattern**: Confused Deputy / Business Logic Bypass

### 3.2 Root Cause

The vulnerability exists across three layers that each independently fail to enforce authorization:

**Layer 1 — Frontend (`premium.preload.js:368`): Missing origin validation**

The content script registers a `window.message` listener that validates only the structure of the message payload, while completely ignoring `event.origin`, `event.source`, and any form of session binding or nonce:

```js
// premium.preload.js:368 — actual source code
function activation_onMessage(event) {
    const { data } = event;
    if (data.version !== 1 ||
        data.command !== "payment_success" ||
        !data.userId) {
        console.error("Received invalid message");
        return;
    }
    window.removeEventListener("message", activation_onMessage);
    void activateLicense(data.userId, event.origin);
    // ❌ event.origin is passed along but never validated
}

async function activateLicense(userId, origin) {
    try {
        const isSuccess = await activate(userId);
        if (!isSuccess) {
            throw new Error("Error in background page");
        }
        const payload = { ack: true };
        window.postMessage(payload, origin);
    } catch (ex) {
        console.error("Failed to activate Premium license", ex);
    }
}
```

Missing validations:

| Check | Present in Code |
|-------|----------------|
| `event.origin` matches trusted payment domain | ❌ Not checked |
| `event.source` is a trusted iframe/window | ❌ Not checked |
| One-time token / nonce / session signature | ❌ Does not exist |
| Sender is the legitimate payment page | ❌ Not checked |

**Layer 2 — Extension Background (`background.js:6788`): userId not bound to payment session**

Upon receiving `premium.activate`, the background script only checks that `userId` is non-empty, then immediately persists it to local preferences and initiates `license_check` — with no verification that the `userId` originated from a legitimate payment flow:

```js
// background.js:6788 — actual source code
background.port.on("premium.activate", async (msg) => {
    if (!(0, messaging.Tg)(msg)) {
        return false;
    }
    if (!msg.userId) {
        return false;
    }
    void prefs.Prefs.set("premium_user_id", msg.userId);  // persisted immediately
    await checkLicense();
    return true;
});
```

The `checkLicense()` function at `background.js:6671` then uses this persisted value directly:

```js
// background.js:6671 — actual source code
const userId = prefs.Prefs.get("premium_user_id");
if (!userId) { return; }

const requestData = {
    cmd: "license_check",
    u: userId,   // any userId from any source reaches this point
    v: "1"
};
const requestUrl = prefs.Prefs.get("premium_license_check_url");
const response = await fetch(requestUrl, {
    method: "POST",
    cache: "no-cache",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestData)
});

const newLicense = (await response.json());
if (newLicense.status !== "active") {
    throw new InvalidLicenseError(...)
}
activateLicense(oldLicense, newLicense);
```

### 3.3 Two-Layer Failure Summary

| Layer | Issue | Evidence Type |
|-------|-------|--------------|
| `premium.preload.js` | `event.origin` not validated | ✅ Source code |
| `background.js` | `userId` not bound to payment session before persisting | ✅ Source code |

Either layer enforcing proper validation would break the exploit chain. Currently, both fail independently.

---

## 4. Attack Vector

### 4.1 Prerequisites

- Adblock Plus extension installed in the browser (standard user setup)
- Access to `https://accounts.adblockplus.org` (publicly accessible, no login required)
- Ability to execute JavaScript in the browser console (standard browser feature)

### 4.2 Attack Flow

```
Normal (legitimate) flow:
  User completes payment
    → Payment system triggers postMessage
    → Extension validates message (content only, not origin)
    → Background persists userId, calls license_check
    → Server confirms valid payment → Premium activated

Attack flow:
  Attacker visits https://accounts.adblockplus.org (no login needed)
    → premium.preload.js is injected into page
    → Attacker opens browser DevTools console
    → Executes one line of JavaScript (see PoC below)
    → Extension accepts message without origin check
    → Background persists arbitrary userId, calls license_check
    → Server does not reject the forged userId → Premium activated
```

---

## 5. Proof of Concept
<img width="3705" height="984" alt="PoC for main attack step" src="https://github.com/user-attachments/assets/40038ae8-e3d5-4b98-b5f9-b080fecb5f8f" />
<img width="1743" height="1041" alt="Attack success for Premium without payment" src="https://github.com/user-attachments/assets/ab1f12e5-deb4-4d85-9173-59e33e906738" />
### 5.1 PoC Code

```javascript
window.postMessage({
    version: 1,
    command: "payment_success",
    userId: "aaa"
}, "*");
```

### 5.2 Reproduction Steps

1. Install Adblock Plus (`cfhdojbkjhnklbpkdaibdccddilifddb`) from the Chrome Web Store
2. Navigate to `https://accounts.adblockplus.org`
3. Open DevTools → Console tab (`F12`)
4. Paste the PoC code above and press Enter
5. Open the Adblock Plus options page (`chrome-extension://cfhdojbkjhnklbpkdaibdccddilifddb/options.html`)
6. Observe: Premium is now active — "Welcome to Adblock Plus Premium" is displayed, all paid features are unlocked

### 5.3 Verified Test Environment

| Field | Value |
|-------|-------|
| Browser | Google Chrome (latest) |
| Extension Version | 4.36.2 |
| Account Required | No |
| Payment Required | No |
| Steps Required | 3 |
| Time to Exploit | ~30 seconds |
| Reproducibility | 100% — confirmed stable across multiple attempts |

---

## 6. Impact Assessment

### 6.1 Direct Impact

**On end users:**
- Any user can permanently activate Premium features without payment
- No user credentials or personal data are at risk

**On Eyeo GmbH:**
- The Premium subscription model is entirely bypassed
- All paid features (cookie banner blocking, enhanced distraction control, etc.) are freely accessible to anyone
- Financial impact scales directly with the size of the user base

### 6.2 Exploitation Difficulty

This vulnerability requires no specialized tools, no account registration, no prior knowledge of the target system, and no network interception. The entire attack surface is accessible to any user through standard browser functionality.

### 6.3 Affected User Scale

| Platform | Users |
|----------|-------|
| Chrome | ~41 million |
| All platforms (cumulative downloads) | ~500 million |

---

## 7. Recommended Fixes

### 7.1 Frontend Fix (Required)

Add strict origin validation in `activation_onMessage` before processing any message:

```js
function activation_onMessage(event) {
    // Validate origin before processing
    const TRUSTED_ORIGINS = [
        "https://accounts.adblockplus.org",
        "https://pay.adblockplus.org"  // or whichever origin the payment iframe uses
    ];
    if (!TRUSTED_ORIGINS.includes(event.origin)) return;

    const { data } = event;
    if (data.version !== 1 ||
        data.command !== "payment_success" ||
        !data.userId) {
        console.error("Received invalid message");
        return;
    }
    window.removeEventListener("message", activation_onMessage);
    void activateLicense(data.userId, event.origin);
}
```

### 7.2 Background Fix (Required)

Before persisting `userId` and calling `checkLicense`, the background script should verify that the activation request originated from a legitimate payment session — for example, by binding a one-time token issued at payment initiation:

```js
background.port.on("premium.activate", async (msg) => {
    if (!(0, messaging.Tg)(msg)) return false;
    if (!msg.userId) return false;

    // Verify the activation token matches one issued during this payment session
    if (!isValidPaymentToken(msg.sessionToken)) return false;

    void prefs.Prefs.set("premium_user_id", msg.userId);
    await checkLicense();
    return true;
});
```

### 7.3 Defense in Depth (Recommended)

- Issue a cryptographically random, single-use nonce at payment session initiation; require it to be present and valid in the `premium.activate` message
- Log all Premium activation events server-side; alert on patterns inconsistent with legitimate purchases
- Ensure the Premium activation state cannot be set locally without a server-signed confirmation token

8.1 Remediation Status
The vulnerability has been confirmed as patched in a version of the extension released after the initial report date. The PoC code described in Section 5 no longer produces the described effect in the current version of the extension.
The researcher has retained the original CRX file of the vulnerable version at the time of disclosure as evidence of the vulnerability's existence. This artifact is available upon request for internal vendor documentation, CVE verification, or academic peer review purposes.
