# WebAuthn / FIDO2

#WebAuthn #FIDO2 #Passkeys #Passwordless #MFA #PhishingResistant #PublicKeyCrypto #Authentication #Standard #CTAP

## What is it?

**WebAuthn** (the W3C browser API) plus **CTAP** (the FIDO Alliance authenticator protocol) together make up **FIDO2** — the standard behind **passkeys** and hardware security keys (YubiKey, Face ID / Touch ID / Windows Hello). It replaces or augments passwords with a **public-key credential**: the authenticator holds a private key that *never leaves the device* and proves possession by signing a server challenge. Its headline property is **phishing resistance** — every signature is bound to the site's **origin**, so a lookalike domain (even a pixel-perfect AiTM proxy) cannot obtain a valid assertion. You meet it as "Sign in with a passkey," security-key MFA, and Entra/Okta passwordless. This note is the standard and where its security *actually* rests; the (unusual) attack surface is under [[#Weak points]].

**Roles:** the **Relying Party (RP)** = the web app; the **Authenticator** = platform (phone/laptop TPM + biometric) or roaming (USB/NFC key); the **WebAuthn API** (`navigator.credentials`) drives it, speaking **CTAP2** to external authenticators. A **passkey** is a *discoverable* FIDO2 credential, often **synced** across a user's devices (iCloud Keychain, Google Password Manager).

---

## How it works

Two ceremonies, both public-key challenge/response.

### Registration (attestation)

| Step | What happens |
|---|---|
| 1 | RP sends a challenge + user/RP info (`navigator.credentials.create()`) |
| 2 | User verifies (biometric/PIN); the authenticator generates a **keypair scoped to the RP's origin** |
| 3 | Authenticator returns the **public key** + optional **attestation** (proof of authenticator model) |
| 4 | RP stores the public key + credential ID against the account |

### Authentication (assertion)

```mermaid
sequenceDiagram
    autonumber
    participant RP as Relying Party
    actor U as User + Authenticator
    RP-->>U: challenge (navigator.credentials.get)
    Note over U: Browser checks the request origin matches the RP,<br/>then the user verifies (biometric / PIN)
    Note over U: Authenticator signs (challenge + origin + counter)<br/>with the private key — which never leaves the device
    U->>RP: assertion (signature + authenticatorData + clientDataJSON)
    Note over RP: Verify signature with the stored public key;<br/>check challenge, origin / rpId, UV flag, signCount
    RP-->>U: authenticated
```

The security lives in what gets signed and checked: **`clientDataJSON`** carries the challenge, the **`origin`**, and the type; **`authenticatorData`** carries the `rpIdHash`, the **UP/UV flags** (user present / user verified), and the **signCount**. The RP must validate all of them — the origin check is the phishing resistance, the challenge is the replay resistance, the counter catches cloned authenticators.

---

## Trust model — where it rests (and where deployments weaken it)

The crypto is sound: the private key stays on the authenticator and every assertion is bound to a fresh challenge and the RP's origin. So attacks don't break WebAuthn head-on — they move to the **edges**: the fallbacks, the enrollment, and the sync fabric.

| The property that makes it strong | How a deployment weakens it | Result |
|---|---|---|
| **Origin / rpId binding** (anti-phishing) | RP doesn't validate `origin` / `rpIdHash` in the assertion | Phishing resistance lost |
| **Fresh challenge** (anti-replay) | RP reuses or doesn't verify the challenge | Assertion replay |
| **WebAuthn is the *only* path** | Offered *alongside* password / OTP / SMS | **Downgrade / fallback** — the #1 real bypass (see below) |
| Only the real user can **enroll** | Attacker registers *their* authenticator via a hijacked session or a lured "add a passkey" flow (malicious extension) | **Malicious passkey registration** → persistent ATO |
| Private key is **device-bound** | **Synced** passkeys ride iCloud/Google — the sync account becomes the target | Compromise the cloud account, get the passkey |
| **signCount** checked | RP ignores it | Cloned-authenticator detection lost |
| **User verification** required | RP accepts `UV=0` (presence only) | Weaker assurance than assumed |
| Recovery is **as strong as** WebAuthn | Recovery falls back to email/OTP/SMS | The whole chain is only as strong as its weakest reset path |

> [!warning]
> **Phishing resistance is a property of the entire auth chain, not of the strongest method in it.** Adding passkeys changes nothing if a password-reset or SMS-recovery flow still exists — attackers just go there. Demonstrated live in 2025: an **Entra ID FIDO downgrade** where an Evilginx AiTM proxy spoofs an *unsupported* user-agent (e.g. Safari on Windows), Entra silently offers a weaker method, and the passkey is never used. The **cross-device (QR/hybrid) flow** is another fallback being abused.

---

## Weak points

- [[Class notes/HTB Academy/CWES Claude/Broken Auth|Broken Auth]] — the practical angle: hunt the **fallback/downgrade** path and the **enrollment/recovery** flows (that's where WebAuthn is actually beaten), plus the AiTM/MFA-fatigue context.
- [[OAuth-OIDC]] — WebAuthn is usually the *authenticator* inside an OIDC login; whatever token the RP issues afterward still lives and dies by OAuth/OIDC rules, so **token theft downstream bypasses the passkey entirely**.

**Tooling / testing:** Chrome DevTools **WebAuthn virtual authenticator** (register/test flows without hardware), [[Tools/Web/Burpsuite|Burp Suite]] to probe whether the RP validates `origin`/challenge/counter and to map the weaker fallback methods.

---

## See also

[[OAuth-OIDC]] / [[JWT]] (what the RP hands you *after* a successful passkey login), [[SAML]] (the older federation standard passkeys often front)  ·  Index: [[_Standards & Protocols]]

*Created: 2026-07-31*
*Updated: 2026-07-31*
*Model: claude-opus-4-8*
