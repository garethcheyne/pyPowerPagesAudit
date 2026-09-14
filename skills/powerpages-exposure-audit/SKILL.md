---
name: powerpages-exposure-audit
description: "Audit a Microsoft Power Pages site for data exposure using the ppaudit tool, interpret its findings, and plan remediation. WHEN: \"audit my Power Pages site\", \"is my portal leaking data\", \"check anonymous access\", \"Power Pages security review\", \"what can anonymous users read\", \"table permission review\", \"portal data leak\", \"run ppaudit\", \"interpret audit findings\", \"fix Power Pages exposure\", \"column permission profile\", \"Webapi site setting\", \"web role anonymous\". DO NOT USE FOR: deploying Power Pages sites, general Dataverse development, non-Power-Pages Azure security."
license: MIT
metadata:
  version: "1.0.0"
---

# Power Pages exposure audit

Run `ppaudit` against a Power Pages site, read what it returns, and turn findings
into a remediation plan.

The tool answers one question two ways: **what data can an unauthenticated
visitor read, and why is it exposed?**

## Before anything else

Authenticated scanning and writing are only appropriate on environments the user
owns or is engaged to assess. If the target is unclear, ask. Do not scan a
production portal the user has not named.

`--apply` is the only command that writes to Dataverse. Everything else is
read-only. Never pass `--apply` without the user explicitly asking for it in that
turn.

## Routing

| User intent | Go to |
|---|---|
| Run an audit | [Running the tool](#running-the-tool) |
| "What does this finding mean?" | [Reading findings](#reading-findings) |
| "How do I fix it?" | [Remediation](#remediation) |
| "Is this actually exploitable?" | [The exposure chain](#the-exposure-chain) |
| Query the JSON for specifics | [Inspecting the data](#inspecting-the-data) |
| Tidy permission names | [Naming](#naming) |

## Running the tool

Working directory is the repo root, where `instances.yaml` and `.env` live.

```bash
python -m ppaudit full --markdown reports/audit.md --json reports/audit.json --html reports/audit.html
```

| Command | Does |
|---|---|
| `scan` | Anonymous outside-in probe. No credentials. Proves exposure. |
| `audit` | Authenticated read of the Dataverse configuration. Explains exposure. |
| `full` | Both, then correlates each external leak to its root-cause permission. |
| `naming` | Proposes self-describing names for permissions and column profiles. |

Prefer `full` — the correlation is where the value is. Use `audit` alone when the
portal URL is unreachable or out of scope.

Targets come from `instances.yaml` (auto-discovered), with `${...}` secrets
resolved from `.env`. Every instance is audited in turn. Pass `--url` /
`--org-url` to bypass the config file.

Exit code is non-zero when anything **High** or above is found, so it can gate a
pipeline.

### If it fails

| Symptom | Cause |
|---|---|
| `Missing credentials` | `.env` not found or placeholders unresolved. Check `tenant_id`/`client_id`/`client_secret`. |
| `Token request failed (401)` | Secret expired, or app registration not in this tenant. |
| `Query failed (403)` | App user exists but lacks read on the config tables. |
| `no instances.yaml found` | Wrong working directory, or pass `--instances PATH`. |
| `<generation> not in use` | Normal. Only one of `adx_`/`mspp_` holds configuration. |

## The exposure chain

Anonymous read of a Dataverse table through Power Pages needs **all** of:

1. **A channel** — the Web API (`Webapi/<table>/enabled = true`), an entity list
   OData feed, or a page whose Liquid/FetchXML queries the table.
2. **A table permission** granting Read.
3. **Bound to a web role flagged Anonymous Users role.**
4. **Global scope** — every row. `Contact`/`Account`/`Self`/`Parent` resolve
   against the signed-in contact, which an anonymous visitor does not have, so
   these usually return nothing.
5. **No page permission** on the page serving it, if the channel is a page.

Break any link and the exposure stops. That is what makes remediation cheap —
often a single page permission is enough while the permission model is reworked.

Two traps this catches that a permission-only review misses:

- **Hand-rolled Liquid endpoints.** A page containing `{% fetchxml %}` is a data
  channel even when `Webapi/<table>/enabled` is false. Look for `/api/...` paths.
  A path containing `auth` means nothing on its own — check for an actual rule.
- **`Parent` scope.** It delegates to the parent permission, so `Parent>Account`
  and `Parent>Contact` reach completely different row sets while looking
  identical in a list.

## Reading findings

Severity is a function of **channel × data class**, not of the permission alone.

| | Queryable channel open | Render-only (page bounds it) |
|---|---|---|
| Personal data | Critical | High |
| Business data | High | Medium |
| Portal CMS content | Low | Info |

Confirmed externally by the scanner is always Critical.

Anonymous **write/create/delete** is Critical regardless of scope.

Key finding types:

| Title | Means |
|---|---|
| `Unprotected page renders anonymously-readable data` | The full chain is present. Highest value — has a URL to open. |
| `Anonymous global read of a table` | Permission exists. Check the channel before panicking. |
| `Anonymous data modification permitted` | Write channel open to the public. |
| `Form on an unprotected page writes to a table` | Entity form reachable unauthenticated. |
| `Web API publishes every column of a table` | `fields = *`. New columns are exposed automatically. |
| `One web role serves both anonymous and signed-in users` | Both flags set. The two audiences cannot be separated. |
| `Entity list publishes an OData feed` | A channel separate from the Web API. |

**Always verify before reporting a breach.** The reference scanner matches
generously by design — it points, it does not prove. Open the URL in the finding
and see what actually returns. A `403`/empty result means the chain is broken
somewhere the tool could not see.

## Inspecting the data

The JSON carries more than the rendered reports. Useful slices:

```python
import json
d = json.load(open("reports/audit.json", encoding="utf-8"))

d["counts"]                              # severity totals
[f for f in d["findings"] if f["severity"] == "Critical"]
d["context"]["references"]               # table -> where it is rendered, with URLs
d["context"]["access_matrix"]            # role x table effective access
d["context"]["dataverse_models"]         # full configuration inventory
d["context"]["anon_exposed_tables"]      # externally confirmed by the scanner
```

Findings carry `evidence` with `url`, `page_record` and `content_record` — the
live page and the two Dataverse records behind it.

Answer "what can the public read?" from `access_matrix` filtered to
`anonymous: true`, not from the findings list.

## Remediation

Order of preference, cheapest and safest first:

1. **Add a page permission.** A `Restrict Read` web page access control rule on
   the page (or an ancestor — they cascade) closes the channel immediately
   without touching the permission model. Best first move under incident
   pressure.
2. **Narrow the scope.** `Global` to `Contact`/`Account`/`Self` on the table
   permission. Verify what legitimately depends on it first.
3. **Unbind the anonymous role.** Removes public access while leaving the
   permission for signed-in roles.
4. **Replace the `fields` wildcard.** `Webapi/<table>/fields = *` to an explicit
   column list, so columns added later are not exposed automatically.
5. **Add a column permission profile.** Restricts which columns the Web API
   returns. A profile with an all-column default of `C/R/U` and no explicit
   column list restricts nothing — check for that.
6. **Delete dormant permissions.** Ones bound to no web role grant nothing today
   but are one binding away from taking effect.

Do not delete a permission before checking what renders it. Use the
`Where the data is rendered` section — it names the pages and templates.

Never change `Global` to something narrower on a table the site's public pages
genuinely need (product catalogues, published articles, CMS content). Add a page
permission instead.

### Official guidance

Link, do not paraphrase:

- Table permissions and access types — <https://learn.microsoft.com/power-pages/security/table-permissions>
- Assign to web roles — <https://learn.microsoft.com/power-pages/security/assign-table-permissions>
- Page permissions — <https://learn.microsoft.com/power-pages/security/page-security>
- Column permissions — <https://learn.microsoft.com/power-pages/security/column-permissions>
- Web API configuration — <https://learn.microsoft.com/power-pages/configure/webapi-how-to>
- Replace the fields wildcard — <https://learn.microsoft.com/troubleshoot/power-platform/power-pages/migrate-web-api-wildcard>
- Security best practices — <https://learn.microsoft.com/power-pages/security/security-best-practices>

## Naming

`python -m ppaudit naming` proposes names built from the grant itself, so the
record list is readable without opening each one.

```text
Blogs Global            ->  adx_blogpost [R] (Global) **ANON**
Case notes (self)       ->  annotation [R/W/C/D/A] (Parent>Contact)
Edit User Profile       ->  contact [all:R/U] +columns
```

`**ANON**` marks anything bound to an Anonymous Users role. `Parent>Contact`
resolves the delegation chain. `all:` on a profile is the default applied to
columns *not* explicitly listed.

Dry run by default. `--apply` writes, and only ever sets the name field. Before
applying, check nothing looks permissions up by name — Liquid, plugins and
deployment scripts sometimes do.

## Scope and limits

- Both `adx_` (standard) and `mspp_` (enhanced) configuration models are read;
  the tool detects which is in use.
- Not read: `adx_webfile`, `adx_invitation`, enhanced-model column security
  profiles. File attachment exposure is out of scope.
- Reference matching is regex over Liquid/FetchXML/JS. It finds candidates for a
  human to confirm; it does not execute or prove anything.
- The audit reflects configuration at the moment it ran. Environments change
  under active remediation — re-run before quoting numbers.
