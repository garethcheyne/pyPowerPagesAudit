# Power Pages exposure audit

**Environment:** Contoso Community Portal (Demo)  
**Portal:** `https://portal.contoso.example`  
**Dataverse:** `https://contoso-demo.crm.dynamics.com`  
**Run (UTC):** 2026-09-15T02:30:00+00:00  
**Audited as:** Dataverse user `a1b2c3d4-0000-4000-8000-00000000abcd`  
**Power Pages version:** `9.3.2405.10` (MicrosoftPortalBase)  
**Configuration model(s) detected:** Standard data model (`adx_*`)  

> Authorised security assessment. This document describes the configuration that governs public access to Dataverse data through the Power Pages site named above.

## 1. Executive summary

| Severity | Findings | What it means |
|---|---|---|
| Critical | 5 | Data is exposed to the public internet, or anonymous users can modify data. Fix now. |
| High | 5 | Exposure is proven or near-certain. Fix in this cycle. |
| Medium | 11 | Weakens the security posture or makes exposure likely under a small change. |
| Low | 6 | Hygiene and least-privilege issues; review and tidy. |
| Info | 6 | Context recorded so the reviewer can verify intent. |

### Issues requiring action

Where the evidence settles it, a finding is marked **Confirmed exposed** (the scanner read it from the internet), **Not mitigated** (a queryable `/_api` channel, a visitor-steered query, or a live write channel), **Partly mitigated** (reachable only through a page or a form, which bounds what comes back) or **Mitigated** (a filter bounds the query, or nothing exercises the permission). Findings with no marking are ones the evidence does not settle — read them. The note after each says what the verdict rests on, and findings that name a page show its URL. Severity already accounts for all of this.

- **[Critical]** Anonymous global read of a table — `contact` **Not mitigated.** _(queryable on /_api; every column published)_
- **[Critical]** Unprotected page renders anonymously-readable data — `contact` **Not mitigated.** _(queryable on /_api; no filter in the query)_  
  <https://portal.contoso.example/events/speakers>
- **[Critical]** Unprotected page renders anonymously-readable data — `contact` **Not mitigated.** _(queryable on /_api; no filter in the query)_  
  <https://portal.contoso.example/stores>
- **[Critical]** External leak tied to configured permissions — `contacts` **Confirmed exposed.** _(confirmed from the internet)_
- **[Critical]** Whole table readable anonymously via Web API — `contacts` **Confirmed exposed.** _(confirmed from the internet)_
- **[High]** One web role serves both anonymous and signed-in users — `Legacy Public Access`
- **[High]** Form on an unprotected page writes to a table — `contact`
- **[High]** Unprotected page renders anonymously-readable data — `cr7f3_eventregistration` **Not mitigated.** _(not on /_api, page render only; query steered by request input)_  
  <https://portal.contoso.example/events/registration>
- **[High]** Entity list publishes an OData feed — `incident`
- **[High]** Form on an unprotected page writes to a table — `lead`

### Configuration inventory

| Model | Websites | Web roles | Table permissions | Column permission profiles | Web API tables enabled |
|---|---|---|---|---|---|
| Standard data model | Contoso Community Portal | 4 | 10 | 2 | 2 |

## 2. Anonymous access

Everything bound to a web role flagged as the **Anonymous Users role** is reachable by anyone on the internet, with no sign-in. `Global` scope means every row in the table; `Contact`/`Account`/`Parent`/`Self` scope resolves against the signed-in contact, which an anonymous visitor does not have.

| Table | Permission | Scope | Privileges | Web API | Published fields | Column profile | Columns reachable |
|---|---|---|---|---|---|---|---|
| `account` | [Account access](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000110) | Account | Read, Write | no | (no setting) | (none) | (no Web API site setting; exposure depends on another channel) |
| `adx_blogpost` | [Blogs Global](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000103) | Global | Read | no | (no setting) | (none) | (no Web API site setting; exposure depends on another channel) |
| `contact` | [Store locator](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000101) | Global | Read | yes | * | (none) | ALL columns (Webapi fields = *) |
| `cr7f3_eventregistration` | [Event registrations](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000104) | Global | Read | no | (no setting) | (none) | (no Web API site setting; exposure depends on another channel) |
| `lead` | [Lead capture](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000105) | Global | Create | no | (no setting) | (none) | (no read privilege) |
| `product` | [Products](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000102) | Global | Read | no | (no setting) | (none) | (no Web API site setting; exposure depends on another channel) |

### Authenticated Users role

Anything granted to the Authenticated Users role is available to every signed-in contact. Where self-registration is open, that is effectively the public as well.

> These rows come from `Legacy Public Access`, which carries the Anonymous **and** Authenticated Users role flags, so the two audiences are the same set of permissions. See the finding *One web role serves both anonymous and signed-in users*.

| Table | Permission | Scope | Privileges | Web API | Columns reachable |
|---|---|---|---|---|---|
| `account` | Account access | Account | Read, Write | no | (no Web API site setting; exposure depends on another channel) |
| `annotation` | Case notes | Parent | Read, Write, Create, Delete, Append | no | (no Web API site setting; exposure depends on another channel) |
| `incident` | My cases | Contact | Read, Write, Create, Append | yes | title, ticketnumber, statuscode, description |

## 3. External scan (unauthenticated, outside-in)

Result of probing the live site with no credentials. This is proof, not inference: anything listed here was actually returned to an anonymous caller at scan time.

| Metric | Value |
|---|---|
| Tables probed | 3 |
| Tables that returned data anonymously | 1 |

**Tables read anonymously:**

`contacts`

| Severity | Finding | Table | Evidence |
|---|---|---|---|
| Critical | Whole table readable anonymously via Web API | `contacts` | columns=5; surface=api; rows_reachable=4812 |
| Medium | OData $metadata is anonymously readable | — | tables_in_metadata=6 |

## 4. Where the data is rendered

Found by scanning the site's Liquid web templates, web page copy and scripts, content snippets and entity list FetchXML. Where the Web API is off, a page is the only channel, so the page is what bounds the exposure — not the permission.

**Portal** is the live page, to see what it actually returns. **Dataverse** is the record holding the Liquid or FetchXML, which is what you edit to change it. **Query bounds** is what the query does to limit its own result — with the Web API off a filtered query is usually publishing by design, while `visitor input` means the query is built from request parameters and the visitor steers it.

### `contact`

| Source | Portal | Dataverse | How | Line | Query bounds | Columns |
|---|---|---|---|---|---|---|
| Web page copy — Speaker contact sheet | [View page](https://portal.contoso.example/events/speaker-contacts) | [Edit record](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000713) | FetchXML <entity> | 4 | unfiltered | `emailaddress1`, `fullname`, `telephone1` |
| Web page copy — Speakers | [View page](https://portal.contoso.example/events/speakers) | [Edit record](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000705) | FetchXML <entity> | 4 | unfiltered | `emailaddress1`, `fullname`, `telephone1` |
| Web page JavaScript — Store locator | [View page](https://portal.contoso.example/stores) | [Edit record](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000706) | Web API call in page script | 1 | unfiltered | `emailaddress1`, `fullname` |

<details><summary>Query — Speaker contact sheet (line 4)</summary>

```xml
<fetch>
  <entity name="contact">
    <attribute name="fullname" />
    <attribute name="emailaddress1" />
    <attribute name="telephone1" />
  </entity>
</fetch>
```

</details>

<details><summary>Query — Speakers (line 4)</summary>

```xml
<fetch>
  <entity name="contact">
    <attribute name="fullname" />
    <attribute name="emailaddress1" />
    <attribute name="telephone1" />
  </entity>
</fetch>
```

</details>

<details><summary>Query — Store locator (line 1)</summary>

```xml
fetch('/_api/contacts?$select=fullname,emailaddress1,address1_city')
  .then(r => r.json())
  .then(d => renderStores(d.value));
```

</details>

### `cr7f3_eventregistration`

| Source | Portal | Dataverse | How | Line | Query bounds | Columns |
|---|---|---|---|---|---|---|
| Web template (Liquid) — Event lookup | [View page](https://portal.contoso.example/events/registration) | [Edit record](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webtemplate&id=00000000-0000-4000-8000-000000000601) | FetchXML <entity> | 3 | **visitor input** | — |

<details><summary>Query — Event lookup (line 3)</summary>

```xml
<fetch top="1">
  <entity name="cr7f3_eventregistration">
    <attribute name="cr7f3_fullname" />
    <attribute name="cr7f3_email" />
    <attribute name="cr7f3_mobilephone" />
    <filter>
      <condition attribute="cr7f3_reference" operator="eq" value="{{ request.params['ref'] }}" />
    </filter>
  </entity>
</fetch>
```

</details>

### `product`

| Source | Portal | Dataverse | How | Line | Query bounds | Columns |
|---|---|---|---|---|---|---|
| Web template (Liquid) — Product catalogue | [View page](https://portal.contoso.example/products) | [Edit record](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webtemplate&id=00000000-0000-4000-8000-000000000602) | FetchXML <entity> | 3 | FetchXML <filter>, FetchXML <condition>, row limit | — |

<details><summary>Query — Product catalogue (line 3)</summary>

```xml
<fetch count="50">
  <entity name="product">
    <attribute name="name" />
    <attribute name="price" />
    <filter><condition attribute="statecode" operator="eq" value="0" /></filter>
  </entity>
</fetch>
```

</details>

## 5. Configuration detail — Standard data model (`adx_*`)

Classic Portals configuration held in physical adx_* tables.

### Websites

| Website | Id |
|---|---|
| [Contoso Community Portal](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_website&id=3f1c9a52-0000-4000-8000-000000000001) | `3f1c9a52-0000-4000-8000-000000000001` |

### Web roles

`Anonymous Users role` is the public internet. `Authenticated Users role` applies to every signed-in contact. Named roles apply only where assigned. Record names link to the configuration record in Dataverse.

| Web role | Type | Website | Table permissions | Column profiles | Page rules |
|---|---|---|---|---|---|
| [Legacy Public Access](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webrole&id=00000000-0000-4000-8000-000000000004) | Anonymous AND Authenticated Users role | Contoso Community Portal | 1 | 0 | 0 |
| [Anonymous Users](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webrole&id=00000000-0000-4000-8000-000000000001) | Anonymous Users role | Contoso Community Portal | 5 | 0 | 0 |
| [Authenticated Users](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webrole&id=00000000-0000-4000-8000-000000000002) | Authenticated Users role | Contoso Community Portal | 2 | 1 | 1 |
| [Case Managers](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webrole&id=00000000-0000-4000-8000-000000000003) | Named role | Contoso Community Portal | 1 | 1 | 0 |

### Table permissions

Each record grants privileges on one table to the web roles bound to it, limited by its access type (scope).

| Table | Permission | Scope | Privileges | Web roles | Website | Web API |
|---|---|---|---|---|---|---|
| `account` | [Account access](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000110) | Account | Read, Write | Legacy Public Access | Contoso Community Portal | no |
| `adx_blogpost` | [Blogs Global](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000103) | Global | Read | Anonymous Users | Contoso Community Portal | no |
| `annotation` | [Case notes](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000107) | Parent | Read, Write, Create, Delete, Append | Authenticated Users | Contoso Community Portal | no |
| `contact` | [Store locator](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000101) | Global | Read | Anonymous Users | Contoso Community Portal | yes |
| `cr7f3_eventregistration` | [Event registrations](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000104) | Global | Read | Anonymous Users | Contoso Community Portal | no |
| `incident` | [Case queue](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000108) | Global | Read, Write, Append, AppendTo | Case Managers | Contoso Community Portal | yes |
| `incident` | [My cases](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000106) | Contact | Read, Write, Create, Append | Authenticated Users | Contoso Community Portal | yes |
| `lead` | [Lead capture](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000105) | Global | Create | Anonymous Users | Contoso Community Portal | no |
| `product` | [Products](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000102) | Global | Read | Anonymous Users | Contoso Community Portal | no |
| `systemuser` | [Staff list](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000109) | Global | Read | **(unbound)** | Contoso Community Portal | no |

### Column permissions

Column permission profiles narrow a table permission to named columns, for the web roles the profile is bound to. They apply to the Power Pages Web API only. Where no profile is bound, every column published by `Webapi/<table>/fields` is available to any role holding the table permission.

| Profile | Table | Web roles | All-column permissions | Explicit columns |
|---|---|---|---|---|
| [Settings WebAdmin](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_columnpermissionprofile&id=00000000-0000-4000-8000-000000000202) | `contact` | Case Managers | Create, Read, Update | 0 |
| [Case editing](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_columnpermissionprofile&id=00000000-0000-4000-8000-000000000201) | `incident` | Authenticated Users | Read | 2 |

#### Per-column grants

| Profile | Table | Column | Permissions | Web roles |
|---|---|---|---|---|
| Case editing | `incident` | `description` | Read, Update | Authenticated Users |
| Case editing | `incident` | `title` | Read, Update | Authenticated Users |

### Web API site settings

`Webapi/<table>/enabled` switches the `/_api/<table>` endpoint on; `Webapi/<table>/fields` lists the columns it publishes. `*` publishes every column, including any added later.

| Table | Enabled | Published fields | Roles with a table permission | Column profiles | Setting |
|---|---|---|---|---|---|
| `contact` | yes | * | Anonymous Users | Settings WebAdmin | [enabled](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_sitesetting&id=00000000-0000-4000-8000-000000000301) [fields](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_sitesetting&id=00000000-0000-4000-8000-000000000302) |
| `incident` | yes | title,ticketnumber,statuscode,description | Authenticated Users, Case Managers | Case editing | [enabled](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_sitesetting&id=00000000-0000-4000-8000-000000000303) [fields](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_sitesetting&id=00000000-0000-4000-8000-000000000304) |

### OData feeds (entity lists)

An entity list with the OData feed enabled serves data through `/_odata/...`, a separate channel from the Web API with its own exposure.

| Entity list | Table | OData entity set | Fields | Website |
|---|---|---|---|---|
| [Open cases](https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitylist&id=00000000-0000-4000-8000-000000000401) | `incident` | OpenCases | (view columns) | Contoso Community Portal |

### Web page access rules

Page rules decide which roles can see or change a page. A page with no restricting rule is public.

| Page | Rule | Right | Scope | Web roles |
|---|---|---|---|---|
| My cases (/my-cases) | Signed-in customers only | RestrictRead | All content | Authenticated Users |

### Security-relevant site settings

| Setting | Value | Website |
|---|---|---|
| `Authentication/Registration/OpenRegistrationEnabled` | true | Contoso Community Portal |
| `Authentication/Registration/RequiresConfirmation` | false | Contoso Community Portal |

## 6. All findings

### Critical

#### Anonymous global read of a table — `contact`

Table permission 'Store locator' grants READ with GLOBAL scope on 'contact' to anonymous web role(s) Anonymous Users. Global scope means every row, not just a signed-in contact's own records. The Web API is enabled for this table, so a visitor can compose their own query at /_api/contacts with fields = * — filtering, paging and column selection are all under their control, not the site's. Referenced by Web page JavaScript 'Store locator'; Web page copy 'Speaker contact sheet'; Web page copy 'Speakers'. Inspect: https://portal.contoso.example/events/speaker-contacts, https://portal.contoso.example/events/speakers, https://portal.contoso.example/stores A visitor can query every row of a table holding personal data. Remove the Global scope or the anonymous binding now. Columns reachable: ALL columns (Webapi fields = *).

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| permission | Store locator |
| scope | Global |
| roles | Anonymous Users |
| website | Contoso Community Portal |
| channel | queryable |
| config_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000101 |
| webapi_enabled | True |
| webapi_fields | * |
| rendered_at | https://portal.contoso.example/events/speaker-contacts, https://portal.contoso.example/events/speakers, https://portal.contoso.example/stores |
| rendered_by_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000705, https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000706, https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000713 |
| referenced_by | Web page JavaScript: Store locator; Web page copy: Speaker contact sheet; Web page copy: Speakers |
| column_profiles | (none) |
| sensitive_columns | (none detected) |
| sensitive_table | True |

#### Unprotected page renders anonymously-readable data — `contact`

'https://portal.contoso.example/events/speakers' renders 'contact' via FetchXML <entity> (line 4), and no web page access control rule covers it (its own or any ancestor's). The Web API is also enabled for this table, so a visitor can query it directly rather than only seeing what the page chooses to emit. Columns matching personal-data patterns appear in the same query block: emailaddress1, fullname, telephone1. The Web API makes this directly queryable, so the permission is the only limit. Restrict the published columns or the permission.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| url | https://portal.contoso.example/events/speakers |
| page | Speakers |
| channel | Web API + page |
| query_constraints | (none detected) |
| visitor_controlled_input | False |
| occurrences | 1 |
| page_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000705 |
| content_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000705 |
| how | FetchXML <entity> (line 4) |
| sensitive_columns | emailaddress1, fullname, telephone1 |
| page_permission | none (inherited rules checked) |

**Query as written** — judge whether it bounds the result:

```xml
<fetch>
  <entity name="contact">
    <attribute name="fullname" />
    <attribute name="emailaddress1" />
    <attribute name="telephone1" />
  </entity>
</fetch>
```

#### Unprotected page renders anonymously-readable data — `contact`

'https://portal.contoso.example/stores' renders 'contact' via Web API call in page script (line 1), and no web page access control rule covers it (its own or any ancestor's). The Web API is also enabled for this table, so a visitor can query it directly rather than only seeing what the page chooses to emit. Columns matching personal-data patterns appear in the same query block: emailaddress1, fullname. The Web API makes this directly queryable, so the permission is the only limit. Restrict the published columns or the permission.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| url | https://portal.contoso.example/stores |
| page | Store locator |
| channel | Web API + page |
| query_constraints | (none detected) |
| visitor_controlled_input | False |
| occurrences | 1 |
| page_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000706 |
| content_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000706 |
| how | Web API call in page script (line 1) |
| sensitive_columns | emailaddress1, fullname |
| page_permission | none (inherited rules checked) |

**Query as written** — judge whether it bounds the result:

```xml
fetch('/_api/contacts?$select=fullname,emailaddress1,address1_city')
  .then(r => r.json())
  .then(d => renderStores(d.value));
```

#### External leak tied to configured permissions — `contacts`

The anonymous scanner read 'contacts' from the internet and the Dataverse configuration explains it:

[Standard data model] Store locator (read=True, scope=Global, roles=Anonymous Users)

Anonymous role(s) involved: Anonymous Users.

_Source: `correlation`_

| Evidence | Value |
|---|---|
| root_cause_permissions | 1 |
| anonymous_roles | Anonymous Users |

#### Whole table readable anonymously via Web API — `contacts`

GET /_api/contacts returned rows with no authentication. Every column of every in-scope record is downloadable.

_Source: `anon-api`_

| Evidence | Value |
|---|---|
| columns | 5 |
| surface | api |
| rows_reachable | 4812 |

### High

#### One web role serves both anonymous and signed-in users — `Legacy Public Access`

Web role 'Legacy Public Access' has both the Anonymous Users role and the Authenticated Users role flags set. Every permission intended for signed-in contacts on this role is therefore also granted to the public internet, and the two audiences can no longer be separated without splitting the role. Clear one flag and move the permissions to the audience they were meant for.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| role | Legacy Public Access |
| table_permissions | 1 |

#### Form on an unprotected page writes to a table — `contact`

Entity form 'Update my details' is in Edit mode against 'contact' and sits on 1 page(s) with no web page access control rule. Unauthenticated visitors can reach the form; whether they can submit depends on the table permission behind it, so confirm the two agree. Forms are the write channel a permission-only review misses.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| form | Update my details |
| mode | Edit |
| pages | https://portal.contoso.example/profile |
| form_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entityform&id=00000000-0000-4000-8000-000000000502 |

#### Unprotected page renders anonymously-readable data — `cr7f3_eventregistration`

'https://portal.contoso.example/events/registration' renders 'cr7f3_eventregistration' via FetchXML <entity> (line 3), and no web page access control rule covers it (its own or any ancestor's). The query reads visitor-supplied input (request parameters), so the visitor — not the page — influences which rows come back. Because the query is built from request input, treat this as a queryable endpoint: check the parameter is validated and cannot be used to widen the result or inject conditions.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| url | https://portal.contoso.example/events/registration |
| page | Registration |
| channel | page render (server-side) |
| query_constraints | FetchXML <condition>, FetchXML <filter>, row limit |
| visitor_controlled_input | True |
| occurrences | 1 |
| page_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000704 |
| content_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webtemplate&id=00000000-0000-4000-8000-000000000601 |
| how | FetchXML <entity> (line 3) |
| sensitive_columns | (none detected) |
| page_permission | none (inherited rules checked) |

**Query as written** — judge whether it bounds the result:

```xml
<fetch top="1">
  <entity name="cr7f3_eventregistration">
    <attribute name="cr7f3_fullname" />
    <attribute name="cr7f3_email" />
    <attribute name="cr7f3_mobilephone" />
    <filter>
      <condition attribute="cr7f3_reference" operator="eq" value="{{ request.params['ref'] }}" />
    </filter>
  </entity>
</fetch>
```

#### Entity list publishes an OData feed — `incident`

Entity list 'Open cases' has the OData feed enabled, serving 'incident' at /_odata/OpenCases. The OData feed is a separate channel from the Web API and is a frequent cause of exposure that a Web API-only review misses. Confirm the page hosting this list is access-controlled and the underlying table permission is correctly scoped.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| entity_set | OpenCases |
| fields | (view columns) |
| website | Contoso Community Portal |

#### Form on an unprotected page writes to a table — `lead`

Entity form 'Contact us' is in Insert mode against 'lead' and sits on 1 page(s) with no web page access control rule. Unauthenticated visitors can reach the form; whether they can submit depends on the table permission behind it, so confirm the two agree. Forms are the write channel a permission-only review misses.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| form | Contact us |
| mode | Insert |
| pages | https://portal.contoso.example/contact-us |
| form_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entityform&id=00000000-0000-4000-8000-000000000501 |

### Medium

#### Multiple Anonymous Users roles

More than one web role is flagged as the Anonymous Users role: Anonymous Users, Legacy Public Access. Every permission bound to any of them applies to unauthenticated visitors, which makes the public surface hard to reason about.

_Source: `dataverse:adx`_

#### OData $metadata is anonymously readable

The portal's full table/column schema is exposed to unauthenticated callers, giving an attacker a map of every entity set to target.

_Source: `anon-odata`_

| Evidence | Value |
|---|---|
| tables_in_metadata | 6 |

#### Power Pages solutions are behind the rest of the environment

2 installed Power Pages solution(s) are well behind the rest of this environment. The oldest is MicrosoftPortalBase 9.3.2205.12 (~52 months old), while the newest portal solution here is only ~28 months old — so this environment has already received more recent portal releases that these packages missed. The website host updates itself, but Dataverse solutions do not, and Microsoft does not certify an unsupported solution version to run against a current host — so fixes shipped in between are absent.

_Source: `dataverse`_

| Evidence | Value |
|---|---|
| MicrosoftPortalBase | 9.3.2205.12 (~52 months) |
| MicrosoftPortalCommunity | 9.3.2206.4 (~51 months) |
| newest_portal_solution_here | ~28 months old |

#### Site setting weakens the security posture — `Authentication/Registration/OpenRegistrationEnabled = true`

Authentication/Registration/OpenRegistrationEnabled = true. Anyone on the internet can self-register a portal account. Combined with anything granted to the Authenticated Users role, that data is effectively public.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| setting | Authentication/Registration/OpenRegistrationEnabled |
| value | true |
| impact | anyone can self-register |
| website | Contoso Community Portal |

#### Site setting weakens the security posture — `Authentication/Registration/RequiresConfirmation = false`

Authentication/Registration/RequiresConfirmation = false. Registration does not require email confirmation, so accounts can be created against addresses the registrant does not control.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| setting | Authentication/Registration/RequiresConfirmation |
| value | false |
| impact | email addresses go unverified |
| website | Contoso Community Portal |

#### Anonymous data modification permitted — `account`

Table permission 'Account access' grants Write on 'account' to anonymous web role(s) Legacy Public Access with Account scope. The Web API is off for this table and no form on the site writes to it, so nothing exercises this permission today. Write/Delete is granted to the anonymous role, but nothing on the site writes to this table today — no Web API, no form. Dormant, but one page or form away from live. Remove it unless it is deliberate.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| permission | Account access |
| scope | Account |
| privileges | Read, Write |
| roles | Legacy Public Access |
| website | Contoso Community Portal |
| write_channel | none |
| config_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000110 |
| webapi_enabled | False |
| column_profiles | (none) |

#### Anonymous read with Account scope — `account`

Table permission 'Account access' grants READ on 'account' to anonymous role(s) Legacy Public Access but with Account scope. Scoped permissions resolve against the signed-in contact or account, which an anonymous visitor does not have, so this normally returns nothing. Review it anyway: granting anything to the anonymous role is rarely intended, and scope misuse is a common misconfiguration.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| permission | Account access |
| scope | Account |
| roles | Legacy Public Access |
| website | Contoso Community Portal |
| contact_relationship | (none) |
| account_relationship | contact_customer_accounts |

#### Authenticated-role access with open self-registration — `annotation`

'Case notes' grants Read, Write, Create, Delete, Append privileges with Parent scope to the Authenticated Users role (Authenticated Users). Open registration is enabled, so any member of the public can create an account and inherit this access. Treat it as near-public exposure.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| permission | Case notes |
| scope | Parent |
| privileges | Read, Write, Create, Delete, Append |
| website | Contoso Community Portal |
| webapi_enabled | False |

#### Anonymous global read of a table — `cr7f3_eventregistration`

Table permission 'Event registrations' grants READ with GLOBAL scope on 'cr7f3_eventregistration' to anonymous web role(s) Anonymous Users. Global scope means every row, not just a signed-in contact's own records. The Web API is off and no OData feed is published, so a visitor cannot run their own query. The data is only reachable where a page renders it, so the real exposure is whatever those pages choose to show. Referenced by Web template (Liquid) 'Event lookup'. Inspect: https://portal.contoso.example/events/registration A page renders this table to anonymous visitors. Global scope means the permission imposes no limit, so review the page and its FetchXML to confirm the filtering is deliberate. Columns reachable: (no Web API site setting; exposure depends on another channel).

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| permission | Event registrations |
| scope | Global |
| roles | Anonymous Users |
| website | Contoso Community Portal |
| channel | render-only |
| config_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000104 |
| webapi_enabled | False |
| webapi_fields | (off) |
| rendered_at | https://portal.contoso.example/events/registration |
| rendered_by_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webtemplate&id=00000000-0000-4000-8000-000000000601 |
| referenced_by | Web template (Liquid): Event lookup |
| column_profiles | (none) |
| sensitive_columns | (none detected) |
| sensitive_table | False |

#### Authenticated-role access with open self-registration — `incident`

'My cases' grants Read, Write, Create, Append privileges with Contact scope to the Authenticated Users role (Authenticated Users). Open registration is enabled, so any member of the public can create an account and inherit this access. Treat it as near-public exposure.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| permission | My cases |
| scope | Contact |
| privileges | Read, Write, Create, Append |
| website | Contoso Community Portal |
| webapi_enabled | True |

#### Anonymous global read of a table — `product`

Table permission 'Products' grants READ with GLOBAL scope on 'product' to anonymous web role(s) Anonymous Users. Global scope means every row, not just a signed-in contact's own records. The Web API is off and no OData feed is published, so a visitor cannot run their own query. The data is only reachable where a page renders it, so the real exposure is whatever those pages choose to show. Referenced by Web template (Liquid) 'Product catalogue'. Inspect: https://portal.contoso.example/products A page renders this table to anonymous visitors. Global scope means the permission imposes no limit, so review the page and its FetchXML to confirm the filtering is deliberate. Columns reachable: (no Web API site setting; exposure depends on another channel).

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| permission | Products |
| scope | Global |
| roles | Anonymous Users |
| website | Contoso Community Portal |
| channel | render-only |
| config_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000102 |
| webapi_enabled | False |
| webapi_fields | (off) |
| rendered_at | https://portal.contoso.example/products |
| rendered_by_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webtemplate&id=00000000-0000-4000-8000-000000000602 |
| referenced_by | Web template (Liquid): Product catalogue |
| column_profiles | (none) |
| sensitive_columns | (none detected) |
| sensitive_table | False |

### Low

#### Multiple Authenticated Users roles

More than one web role is flagged as the Authenticated Users role: Authenticated Users, Legacy Public Access. All of them apply to every signed-in contact.

_Source: `dataverse:adx`_

#### Published files are publicly reachable

1 of 2 web file(s) hang off a page with no Restrict Read rule, so they are downloadable without signing in. Web files are served from their own URL and are not governed by table permissions, so a locked-down permission model does not protect them. Confirm none carries internal or personal data.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| unprotected | 1 |
| total | 2 |
| examples | price-list.pdf |

#### Unpublished pages would expose data once published

1 page(s) query anonymously-readable table(s) and have no page permission, but their publishing state is not a visible one, so the site does not serve them to visitors today. They are one publishing-state change away from being live exposure, and that change is routine content work rather than a security decision. Add the page permission now, while it costs nothing: Speaker contact sheet (Draft) → contact.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| pages | 1 |
| tables | contact |

#### Profile grants Create/Update on all columns — `contact`

Profile 'Settings WebAdmin' sets All Column Permissions to Create, Read, Update, which applies to every column not explicitly listed. Prefer explicit per-column grants so new columns are not silently writable.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| profile | Settings WebAdmin |
| roles | Case Managers |

#### Anonymous record creation permitted — `lead`

Table permission 'Lead capture' grants Create on 'lead' to anonymous web role(s) Anonymous Users with Global scope. Create adds records but reads none back, so it cannot be used to retrieve data — treat it as an integrity/abuse risk, not a data breach. A basic/advanced form (Contact us) writes to this table, placed on a site page. Confirm that page is the intended public one, not gated content. Create is reached only through a form — the ordinary 'contact us' / 'request a quote' pattern, where a public form creates a lead or case by design. Create exposes no data. Confirm the form validates input and has spam/bot protection.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| permission | Lead capture |
| scope | Global |
| privileges | Create |
| roles | Anonymous Users |
| website | Contoso Community Portal |
| write_channel | form |
| config_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000105 |
| webapi_enabled | False |
| column_profiles | (none) |

#### Table permission bound to no web role — `systemuser`

'Staff list' (Global scope, Read) is not bound to any web role. It grants nothing today, but it is live configuration one binding away from taking effect. Remove it or bind it deliberately.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| website | Contoso Community Portal |

### Info

#### Anonymous Users role identified — `Anonymous Users`

Web role 'Anonymous Users' is the Anonymous Users role for Contoso Community Portal. Everything bound to it is reachable by the public internet. It currently carries 5 table permission(s).

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| role | Anonymous Users |
| table_permissions | 5 |

#### Anonymous Users role identified — `Legacy Public Access`

Web role 'Legacy Public Access' is the Anonymous Users role for Contoso Community Portal. Everything bound to it is reachable by the public internet. It currently carries 1 table permission(s).

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| role | Legacy Public Access |
| table_permissions | 1 |

#### Standard data model configuration read

Classic Portals configuration held in physical adx_* tables.

1 website(s), 4 web role(s), 10 table permission(s), 2 column permission profile(s), 2 Web API-enabled table(s), 1 entity list(s), 1 page access rule(s).

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| websites | Contoso Community Portal |

#### Anonymous global read of a table — `adx_blogpost`

Table permission 'Blogs Global' grants READ with GLOBAL scope on 'adx_blogpost' to anonymous web role(s) Anonymous Users. Global scope means every row, not just a signed-in contact's own records. The Web API is off and no OData feed is published, so a visitor cannot run their own query. The data is only reachable where a page renders it, so the real exposure is whatever those pages choose to show. No Liquid template, page copy, entity list or page script in this site was found to reference the table, so nothing appears to render it today. Treat the permission as dormant configuration: it grants access that only becomes live when someone adds a page that uses it. This is portal content that the site reads anonymously in order to render pages, with no query channel open. Expected configuration. Columns reachable: (no Web API site setting; exposure depends on another channel).

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| permission | Blogs Global |
| scope | Global |
| roles | Anonymous Users |
| website | Contoso Community Portal |
| channel | render-only |
| config_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_entitypermission&id=00000000-0000-4000-8000-000000000103 |
| webapi_enabled | False |
| webapi_fields | (off) |
| rendered_at | (no page reference found) |
| rendered_by_record | (none found) |
| referenced_by | (none found) |
| column_profiles | (none) |
| sensitive_columns | (none detected) |
| sensitive_table | False |

#### Web API enabled for table — `incident`

Published columns: title, ticketnumber, statuscode, description. Access is governed by the table permissions on this entity.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| fields | 4 |
| sensitive_columns | (none detected) |
| roles_with_permission | Authenticated Users, Case Managers |
| column_profiles | Case editing |

#### Unprotected page renders anonymously-readable data — `product`

'https://portal.contoso.example/products' renders 'product' via FetchXML <entity> (line 3), and no web page access control rule covers it (its own or any ancestor's). The Web API is off for this table, so this is a server-side render: the page emits only what its query selects, and that query is constrained (FetchXML <condition>, FetchXML <filter>, row limit). This looks deliberate. Confirm the filter restricts on the right thing and cannot be satisfied by an anonymous visitor, then treat it as published-by-design.

_Source: `dataverse:adx`_

| Evidence | Value |
|---|---|
| url | https://portal.contoso.example/products |
| page | Products |
| channel | page render (server-side) |
| query_constraints | FetchXML <condition>, FetchXML <filter>, row limit |
| visitor_controlled_input | False |
| occurrences | 1 |
| page_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webpage&id=00000000-0000-4000-8000-000000000702 |
| content_record | https://contoso-demo.crm.dynamics.com/main.aspx?pagetype=entityrecord&etn=adx_webtemplate&id=00000000-0000-4000-8000-000000000602 |
| how | FetchXML <entity> (line 3) |
| sensitive_columns | (none detected) |
| page_permission | none (inherited rules checked) |

**Query as written** — judge whether it bounds the result:

```xml
<fetch count="50">
  <entity name="product">
    <attribute name="name" />
    <attribute name="price" />
    <filter><condition attribute="statecode" operator="eq" value="0" /></filter>
  </entity>
</fetch>
```

## 7. How exposure works (reference for reviewers)

For an anonymous visitor to read a Dataverse row through Power Pages, all of the following must line up:

1. **A channel serves the table** — the Web API (`Webapi/<table>/enabled = true`, queried at `/_api/<table>`), an entity list with the OData feed enabled (`/_odata/<set>`), an entity form, or a Liquid `fetchxml` / `entityview` tag on a page.
2. **A table permission grants `Read`** on that table.
3. **That permission is bound to a web role flagged as the Anonymous Users role.**
4. **Scope is `Global`.** Global means all rows. `Contact` / `Account` / `Parent` / `Self` resolve against the signed-in contact, which an anonymous visitor does not have — so those normally return nothing, though scope misuse is a common misconfiguration and they still warrant review.

Column reach is then decided by, in order: the table permission (does the role get the table at all), `Webapi/<table>/fields` (which columns the Web API publishes — `*` means all, including columns added later), and column permission profiles bound to the role (which narrow it further). Column permissions apply to the Web API only, and are **not** enforced on sites using the enhanced authorization model — those use column security profiles instead.

Two configuration models exist and either can grant access: the **standard data model** (`adx_*` physical tables) and the **enhanced data model** (`mspp_*` virtual tables over `powerpagesite` / `powerpagecomponent`). Environments upgraded in place often carry both, and permissions left behind in the other model are easy to miss.

### Review checklist

- [ ] Every table permission bound to an anonymous role is intended, and its scope is deliberate.
- [ ] No anonymous role has `Write`, `Create` or `Delete` anywhere.
- [ ] Every `Webapi/<table>/fields` setting lists explicit columns rather than `*`.
- [ ] Tables carrying personal data have a column permission profile, or an explicit field list, that excludes sensitive columns.
- [ ] Entity lists with the OData feed enabled sit on access-controlled pages.
- [ ] Table permissions bound to no web role are removed, not left dormant.
- [ ] Self-registration settings match intent, given what the Authenticated Users role can reach.
- [ ] If both configuration models are present, they agree.
