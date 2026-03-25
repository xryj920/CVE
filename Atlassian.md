**Title:** OAuth Authorization Code Interception with Full Account Takeover Demonstrated — Bitbucket Token Theft via Missing PKCE and Hardcoded Secret in Atlassian VS Code Extension

**Summary:**

The Atlassian VS Code extension (Atlassian.atlascode) is vulnerable to an OAuth Authorization Code Interception attack specifically within its Bitbucket Cloud authentication flow. While the extension correctly implements PKCE (Proof Key for Code Exchange) for Jira Cloud authentication, the Bitbucket flow fails to use PKCE and relies on a hardcoded `client_secret` embedded within the extension's source code. Combined with a fixed local callback port (`127.0.0.1:31415`), a malicious process running on the victim's machine can pre-bind to the port, intercept the authorization code, and exchange it for a full Bitbucket access token using the exposed secret.

**This submission now includes a fully executed PoC with screenshots demonstrating successful token theft and verified account access.**

------

**Affected Component:**

- Extension ID: `Atlassian.atlascode`
- Affected File: `extension/build/extension/extension.js` (inside the bundled extension package)
- Class/Strategy: `BitbucketStrategy`

------

**Technical Details & Evidence:**

**1. Hardcoded Credentials and Fixed Callback URL**

In `extension.js`, the `OAuthStrategyData.BitbucketProd` object contains hardcoded secrets and a static callback URL:

```javascript
// Found in BitbucketProd configuration:
clientID: "3hasX42a7Ugka2FJja",
clientSecret: "st7a4WtBYVh7L2mZMU8V5ehDtvQcWs9S",
callbackURL: "http://127.0.0.1:31415/" + A.BitbucketCloud
```

Because the extension is distributed as a `.vsix` package, any user can unpack it and extract these credentials. The `client_secret` is therefore fully public to anyone who installs the extension.

**2. Lack of PKCE in Bitbucket Flow**

The `BitbucketStrategy` implementation only sends `client_id` and `state`, omitting the `code_challenge` required for PKCE:

```javascript
// BitbucketStrategy.authorizeUrl(r)
// Missing code_challenge / code_challenge_method
authorizeUrl(r) {
    ...
    append("client_id", this.data.clientID);
    append("response_type", "code");
    append("state", r);
    ...
}
```

In contrast, the `JiraStrategy` in the same file correctly implements PKCE by including `code_challenge` and `code_verifier`, proving that this is a deliberate design decision for Jira but an overlooked gap in the Bitbucket implementation. The absence of PKCE means the authorization code alone is sufficient to obtain a token — there is no `code_verifier` binding the code to the legitimate client.

**3. Insecure Token Exchange**

Since PKCE is absent, the token exchange relies entirely on the `client_secret`. The `refreshHeaders()` method uses HTTP Basic Auth to inject the hardcoded `clientID:clientSecret` pair. Per RFC 6749 and OAuth 2.0 Security Best Current Practice (RFC 9700), native applications and browser-based clients must not use `client_secret` as they cannot be kept confidential. This extension violates this requirement directly.

------

**Steps to Reproduce (Fully Executed):**

**Environment:**

- OS: Windows
- VS Code with Atlassian extension installed
- Python 3.11

**Step 1 — Pre-bind to the fixed callback port:**

A Python script binds to `127.0.0.1:31415` before the victim initiates login. This simulates a malicious background process already running on the victim's machine.

**Step 2 — Victim initiates Bitbucket login:**

The victim clicks "Sign in to Bitbucket" in the Atlassian extension panel in VS Code. The extension opens the browser to the Bitbucket OAuth authorization page.

**Step 3 — Authorization code intercepted:**

After the victim approves the authorization in the browser, Bitbucket redirects to `http://127.0.0.1:31415/bbcloud?code=...`. The attacker's listener captures the request before the legitimate extension can receive it.

> **[Screenshot 1]** — Browser showing `127.0.0.1:31415/bbcloud` with "Authentication Successful" page served by the attacker's listener, confirming the redirect was fully intercepted.

**Step 4 — Token exchange using hardcoded secret:**

The intercepted authorization code is submitted to `https://bitbucket.org/site/oauth2/access_token` using the hardcoded `client_id` and `client_secret` via HTTP Basic Auth:

```bash
curl -X POST -u "3hasX42a7Ugka2FJja:st7a4WtBYVh7L2mZMU8V5ehDtvQcWs9S" \
  https://bitbucket.org/site/oauth2/access_token \
  -d grant_type=authorization_code \
  -d code=[INTERCEPTED_CODE]
```

**Step 5 — Full account takeover verified:**

The token exchange succeeds and returns a fully valid `access_token` and `refresh_token`. The access token is then used to call the Bitbucket API and retrieve the victim's account information.

> **[Screenshot 2]** — Terminal output showing the complete attack chain:
>
> - Authorization code successfully intercepted: `cMSAvpQTewuJwVaxen`
> - Access token and refresh token successfully obtained
> - Scopes granted: `account pullrequest:write snippet:write issue:write project pipeline team`
> - API call to `/2.0/user` returns victim account: **Dr King (ghadv7595)**, UUID: `{b43fbc7f-7e08-4542-9be4-d7849b24f667}`

------

**Impact:**

An attacker who can run any low-privileged process on the victim's machine — including malware, a malicious npm package, or any unprivileged application — can fully compromise the victim's Bitbucket account. As demonstrated above, the obtained token carries the following scopes:

- `account` — Full account read access
- `pullrequest:write` — Create, approve, and merge pull requests
- `snippet:write` — Read and modify code snippets
- `issue:write` — Create and modify issues
- `project` — Access project metadata
- `pipeline` — Trigger and read CI/CD pipelines
- `team` — Access team/workspace membership

This enables a range of high-severity attacks including unauthorized source code access, supply chain compromise via malicious commits or PR approvals, and persistent access via the `refresh_token` even after the victim revokes their VS Code session.

------

**Recommended Remediation:**

1. **Implement PKCE (RFC 7636):** Standardize the Bitbucket OAuth flow to match the Jira implementation by generating a `code_verifier` and sending a `code_challenge` with every authorization request. This ensures that even if the authorization code is intercepted, it cannot be exchanged without the corresponding verifier.
2. **Use a Dynamic Loopback Port:** Replace the hardcoded port `31415` with a dynamic port assignment (bind to port `0` and let the OS assign an available port). This prevents any malicious process from reliably pre-binding to the callback address.
3. **Remove the Hardcoded Client Secret:** Transition the Bitbucket flow to a public client model (as recommended by RFC 9700 for native apps), where no `client_secret` is required or stored. The secret currently embedded in the extension bundle provides no real security and can be extracted by any user.

