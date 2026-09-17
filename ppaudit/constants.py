"""Shared constants for the Power Pages / Dataverse exposure audit.

Two generations of the Power Pages configuration schema exist and this tool
supports both, side by side:

* **Standard data model** — the classic Portals configuration, physical
  Dataverse tables prefixed ``adx_``.
* **Enhanced data model** — the current Power Pages configuration, *virtual*
  Dataverse tables prefixed ``mspp_`` backed by ``powerpagesite`` /
  ``powerpagecomponent``.

An environment may contain either or both. The audit detects which generations
are readable and inspects each one independently.

Field names are declared as ordered *candidate* lists rather than fixed
strings. Loaders fetch whole config rows (these tables are tiny) and resolve
each logical field against the first candidate actually present on the row.
That keeps the audit working across schema drift and across both generations
without emitting ``$select`` clauses that 400 on the wrong generation.
"""

from __future__ import annotations

# --- Power Pages Web API / OData surface -------------------------------------

# Anonymous OData metadata document. If this is readable without auth, the
# schema of every portal-exposed table leaks even before any row does.
ODATA_METADATA_PATH = "/_odata/$metadata"
ODATA_TABLE_PATH = "/_odata/{table}"
WEBAPI_TABLE_PATH = "/_api/{table}"

# Power Pages Web API error returned when a table permission blocks the
# whole-table read but the request is otherwise valid. Seeing this (rather
# than a flat 403/401) means the endpoint is live and worth probing per-column.
ERR_TABLE_PERMISSION_DENIED = "90040101"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

# Tables worth probing directly even when /_odata/$metadata is locked down.
# A locked metadata document does not imply locked data: individual entity
# sets can still answer /_api/<name>. These are the high-value Dataverse and
# portal tables that carry personal or configuration data.
COMMON_TABLES = [
    "contacts",
    "accounts",
    "annotations",
    "activitypointers",
    "emails",
    "leads",
    "opportunities",
    "incidents",
    "systemusers",
    "teams",
    "businessunits",
    "adx_invitations",
    "adx_inviteredemptions",
    "adx_portalcomments",
    "feedbacks",
    "salesorders",
    "quotes",
    "invoices",
    "cases",
    "knowledgearticles",
    "subjects",
]

# --- Dataverse configuration entities ----------------------------------------

CONFIG_SCHEMAS: dict[str, dict] = {
    "adx": {
        "label": "Standard data model",
        "description": "Classic Portals configuration held in physical adx_* tables.",
        "prefix": "adx",
        "sets": {
            "website": "adx_websites",
            "webrole": "adx_webroles",
            "entitypermission": "adx_entitypermissions",
            "columnpermissionprofile": "adx_columnpermissionprofiles",
            "columnpermission": "adx_columnpermissions",
            "sitesetting": "adx_sitesettings",
            "entitylist": "adx_entitylists",
            "entityform": "adx_entityforms",
            "webpage": "adx_webpages",
            "webpageaccessrule": "adx_webpageaccesscontrolrules",
            "webtemplate": "adx_webtemplates",
            "pagetemplate": "adx_pagetemplates",
            "contentsnippet": "adx_contentsnippets",
            "webform": "adx_webforms",
            "webformstep": "adx_webformsteps",
            "webfile": "adx_webfiles",
            "publishingstate": "adx_publishingstates",
        },
        "nav": {
            "entitypermission_webrole": "adx_entitypermission_webrole",
            "columnpermissionprofile_webrole": "adx_columnpermissionprofile_webrole",
            "webpageaccessrule_webrole": "adx_webpageaccesscontrolrule_webrole",
        },
    },
    "mspp": {
        "label": "Enhanced data model",
        "description": (
            "Current Power Pages configuration surfaced as mspp_* virtual tables "
            "over powerpagesite / powerpagecomponent."
        ),
        "prefix": "mspp",
        "sets": {
            "website": "mspp_websites",
            "webrole": "mspp_webroles",
            "entitypermission": "mspp_entitypermissions",
            "columnpermissionprofile": "mspp_columnpermissionprofiles",
            "columnpermission": "mspp_columnpermissions",
            "sitesetting": "mspp_sitesettings",
            "entitylist": "mspp_entitylists",
            "entityform": "mspp_entityforms",
            "webpage": "mspp_webpages",
            "webpageaccessrule": "mspp_webpageaccesscontrolrules",
            "webtemplate": "mspp_webtemplates",
            "pagetemplate": "mspp_pagetemplates",
            "contentsnippet": "mspp_contentsnippets",
            "webform": "mspp_webforms",
            "webformstep": "mspp_webformsteps",
            "webfile": "mspp_webfiles",
            "publishingstate": "mspp_publishingstates",
            # Enhanced sites use column *security* profiles instead of column
            # permissions; absent on standard sites, so the fetch is non-fatal.
            "columnsecurityprofile": "mspp_columnsecurityprofiles",
        },
        "nav": {
            "entitypermission_webrole": "mspp_entitypermission_webrole",
            "columnpermissionprofile_webrole": "mspp_columnpermissionprofile_webrole",
            "webpageaccessrule_webrole": "mspp_webpageaccesscontrolrule_webrole",
        },
    },
}

# Logical field -> ordered candidate logical names ("{p}" = schema prefix).
# The first candidate actually present on a fetched row wins.
FIELD_CANDIDATES: dict[str, list[str]] = {
    # web role
    "role_id": ["{p}_webroleid"],
    "role_name": ["{p}_name"],
    "role_anonymous": ["{p}_anonymoususersrole"],
    "role_authenticated": ["{p}_authenticatedusersrole"],
    "role_description": ["{p}_description"],
    # table permission. Note adx_entityname is the *record label* on this table
    # (its primary field) while adx_entitylogicalname carries the target entity,
    # which is the reverse of adx_entitylist and adx_entityform.
    "perm_id": ["{p}_entitypermissionid"],
    "perm_name": ["{p}_entitypermissionname", "{p}_entityname", "{p}_name"],
    "perm_entity": ["{p}_entitylogicalname", "{p}_entityname"],
    "perm_scope": ["{p}_scope"],
    "perm_read": ["{p}_read"],
    "perm_write": ["{p}_write"],
    "perm_create": ["{p}_create"],
    "perm_delete": ["{p}_delete"],
    "perm_append": ["{p}_append"],
    "perm_appendto": ["{p}_appendto"],
    "perm_parent": ["_{p}_parententitypermission_value"],
    "perm_contact_rel": ["{p}_contactrelationship"],
    "perm_account_rel": ["{p}_accountrelationship"],
    "perm_parent_rel": ["{p}_parentrelationship"],
    # column permission profile
    "cpp_id": ["{p}_columnpermissionprofileid"],
    "cpp_name": ["{p}_profilename", "{p}_name"],
    "cpp_table": ["{p}_tablename", "{p}_entityname", "{p}_entitylogicalname"],
    "cpp_all": ["{p}_allcolumnpermissions"],
    # column permission
    "cp_id": ["{p}_columnpermissionid"],
    "cp_column": ["{p}_columnname", "{p}_attributelogicalname", "{p}_name"],
    "cp_permissions": ["{p}_permissions"],
    "cp_profile_ref": ["_{p}_columnpermissionprofileid_value"],
    # site setting
    "setting_id": ["{p}_sitesettingid"],
    "setting_name": ["{p}_name"],
    "setting_value": ["{p}_value"],
    # entity list (OData feed channel)
    "list_id": ["{p}_entitylistid"],
    "list_name": ["{p}_name"],
    "list_entity": ["{p}_entityname", "{p}_entitylogicalname"],
    "list_odata_enabled": ["{p}_odata_enabled"],
    "list_odata_entityset": ["{p}_odata_entitysetname"],
    "list_odata_entitytype": ["{p}_odata_entitytypename"],
    "list_odata_fields": ["{p}_odata_fields"],
    "list_odata_view": ["{p}_odata_view"],
    "list_view": ["{p}_view"],
    "list_filter": ["{p}_filtercriteria"],
    "list_settings": ["{p}_settings"],
    # entity form (create/edit channel)
    "form_id": ["{p}_entityformid"],
    "form_name": ["{p}_name"],
    "form_entity": ["{p}_entityname", "{p}_entitylogicalname"],
    "form_mode": ["{p}_mode"],
    # web page
    "page_id": ["{p}_webpageid"],
    "page_name": ["{p}_name"],
    "page_partialurl": ["{p}_partialurl"],
    "page_parent": ["_{p}_parentpageid_value"],
    "page_copy": ["{p}_copy"],
    "page_customjs": ["{p}_customjavascript"],
    "page_customcss": ["{p}_customcss"],
    "page_title": ["{p}_title"],
    "page_pagetemplate_ref": ["_{p}_pagetemplateid_value"],
    "page_entitylist_ref": ["_{p}_entitylistid_value"],
    "page_entityform_ref": ["_{p}_entityformid_value"],
    "page_webform_ref": ["_{p}_webformid_value"],
    "page_isroot": ["{p}_isroot"],
    "page_rootpage_ref": ["_{p}_rootwebpageid_value"],
    "page_language_ref": ["_{p}_webpagelanguageid_value"],
    "page_language_label": ["_{p}_webpagelanguageid_value@OData.Community.Display.V1.FormattedValue"],
    "page_publishingstate_ref": ["_{p}_publishingstateid_value"],
    "page_publishingstate_label": ["_{p}_publishingstateid_value@OData.Community.Display.V1.FormattedValue"],
    # web template (Liquid source)
    "template_id": ["{p}_webtemplateid"],
    "template_name": ["{p}_name"],
    "template_source": ["{p}_source"],
    # page template (binds a web template to pages)
    "pagetemplate_id": ["{p}_pagetemplateid"],
    "pagetemplate_name": ["{p}_name"],
    "pagetemplate_template_ref": ["_{p}_webtemplateid_value"],
    "pagetemplate_rewriteurl": ["{p}_rewriteurl"],
    # content snippet (Liquid-capable content block)
    "snippet_id": ["{p}_contentsnippetid"],
    "snippet_name": ["{p}_name"],
    "snippet_value": ["{p}_value"],
    # web file (published attachment)
    "file_id": ["{p}_webfileid"],
    "file_name": ["{p}_name"],
    "file_partialurl": ["{p}_partialurl"],
    "file_parentpage": ["_{p}_parentpageid_value"],
    "file_publishingstate_ref": ["_{p}_publishingstateid_value"],
    "file_publishingstate_label": ["_{p}_publishingstateid_value@OData.Community.Display.V1.FormattedValue"],
    # publishing state. Draft content is not served to ordinary visitors, and
    # states are renameable, so visibility must come from the flag, not the name.
    "pubstate_id": ["{p}_publishingstateid"],
    "pubstate_name": ["{p}_name"],
    "pubstate_visible": ["{p}_isvisible"],
    "pubstate_default": ["{p}_isdefault"],
    # column security profile (enhanced model)
    "csp_id": ["{p}_columnsecurityprofileid"],
    "csp_name": ["{p}_name"],
    # web page access control rule
    "rule_id": ["{p}_webpageaccesscontrolruleid"],
    "rule_name": ["{p}_name"],
    "rule_right": ["{p}_right"],
    "rule_scope": ["{p}_scope"],
    "rule_page_ref": ["_{p}_webpageid_value"],
    # shared
    "website_ref": ["_{p}_websiteid_value"],
    "website_id": ["{p}_websiteid"],
    "website_name": ["{p}_name"],
    "website_domain": ["{p}_primarydomainname"],
}

# --- Option-set labels --------------------------------------------------------

SCOPE_GLOBAL = "Global"
SCOPE_CONTACT = "Contact"
SCOPE_ACCOUNT = "Account"
SCOPE_PARENT = "Parent"
SCOPE_SELF = "Self"

# adx_scope / mspp_scope ("Access Type"). Global is the dangerous one on an
# anonymous role: it grants every row. Contact/Account/Parent/Self resolve
# against the signed-in contact, which an anonymous visitor does not have.
SCOPE_FALLBACK_LABELS = {
    756150000: SCOPE_GLOBAL,
    756150001: SCOPE_CONTACT,
    756150002: SCOPE_ACCOUNT,
    756150003: SCOPE_PARENT,
    756150004: SCOPE_SELF,
}

# adx_/mspp_ column-permission multi-select choice values.
COLUMN_PERMISSION_LABELS = {
    746610000: "Create",
    746610001: "Read",
    746610002: "Update",
}

# adx_/mspp_ web page access control rule "right".
PAGE_RULE_RIGHT_LABELS = {
    756150000: "GrantChange",
    756150001: "RestrictRead",
}

# --- Site settings ------------------------------------------------------------

WEBAPI_ENABLED_PREFIX = "Webapi/"          # Webapi/<entity>/enabled = true
WEBAPI_FIELDS_SUFFIX = "/fields"           # Webapi/<entity>/fields = * | col,col
WEBAPI_ENABLED_SUFFIX = "/enabled"

# Site-setting namespaces that materially change who can reach data.
SECURITY_SETTING_PREFIXES = [
    "Authentication/",
    "Webapi/",
    "Site/Headers/",
    "HTTP/",
    "PortalTracing/",
    "Search/",
    "Diagnostics/",
    "Security/",
    "Connector/",
]

# Settings whose *value* is worth judging, not merely listing.
# lowercased name -> (values considered risky, why it matters, the consequence in
# a few words). The short form goes on the summary line: several of these
# findings share one title, and a reader should not have to open each to learn
# which setting is at fault and what it costs.
NOTABLE_SETTINGS: dict[str, tuple[set[str], str, str]] = {
    "authentication/registration/openregistrationenabled": (
        {"true"},
        "Anyone on the internet can self-register a portal account. Combined with "
        "anything granted to the Authenticated Users role, that data is effectively "
        "public.",
        "anyone can self-register",
    ),
    "authentication/registration/localloginenabled": (
        {"true"},
        "Local username/password sign-in is enabled alongside federated login.",
        "local passwords accepted",
    ),
    "authentication/registration/externalloginenabled": (
        {"true"},
        "External identity providers can be used to register.",
        "external identity providers can register",
    ),
    "authentication/registration/requiresconfirmation": (
        {"false"},
        "Registration does not require email confirmation, so accounts can be created "
        "against addresses the registrant does not control.",
        "email addresses go unverified",
    ),
    "authentication/registration/captchaenabled": (
        {"false"},
        "Registration is not CAPTCHA-protected; bulk automated account creation is "
        "possible.",
        "no CAPTCHA on registration",
    ),
    "portaltracing/enabled": (
        {"true"},
        "Portal tracing is on. Diagnostic output can disclose internal detail.",
        "diagnostics may disclose internals",
    ),
    "site/enabledefaulthtmlencoding": (
        {"false"},
        "Default HTML encoding is disabled, raising stored-XSS risk in Liquid output.",
        "stored-XSS risk in Liquid output",
    ),
}

# --- Sensitivity heuristics ---------------------------------------------------

# Substrings suggesting a column carries personal or sensitive data. Used to
# raise severity when such a column is readable broadly or anonymously.
SENSITIVE_COLUMN_HINTS = [
    "password", "secret", "token", "apikey", "api_key",
    "ssn", "socialsecurity", "nationalid", "taxid", "ird", "nhi",
    "passport", "licence", "license", "driver",
    "dob", "birth",
    "salary", "income", "credit", "card", "cvv", "iban", "bic", "bank",
    "routing",
    "email", "phone", "mobile", "telephone", "fax",
    "address", "street", "city", "postcode", "postalcode",
    "firstname", "lastname", "fullname", "surname", "givenname",
    "gender", "ethnic", "health", "medical", "diagnosis",
]

# CMS tables the portal itself reads anonymously in order to render pages.
# Anonymous read here is the product working as designed, not a data leak, so
# it must not be graded like business data.
PORTAL_CONTENT_TABLES = {
    "adx_ad", "adx_adplacement", "adx_blog", "adx_blogpost", "adx_blogpostcomment",
    "adx_communityforum", "adx_communityforumaccesspermission",
    "adx_communityforumannouncement", "adx_communityforumpost",
    "adx_communityforumthread", "adx_communityforumthreadtype",
    "adx_contentaccesslevel", "adx_contentsnippet", "adx_idea", "adx_ideaforum",
    "adx_pagealert", "adx_pagenotification", "adx_pagetemplate", "adx_poll",
    "adx_polloption", "adx_pollplacement", "adx_publishingstate",
    "adx_redirect", "adx_shortcut", "adx_sitemarker", "adx_sitesetting",
    "adx_tag", "adx_webfile", "adx_weblink", "adx_weblinkset", "adx_webpage",
    "adx_webpageaccesscontrolrule", "adx_website", "adx_websitelanguage",
    "adx_webtemplate", "annotation_webfile", "powerpagecomponent",
    "mspp_webpage", "mspp_webfile", "mspp_weblink", "mspp_weblinkset",
    "mspp_contentsnippet", "mspp_webtemplate", "mspp_pagetemplate",
    "mspp_sitemarker", "mspp_publishingstate", "mspp_redirect", "mspp_shortcut",
}

# Tables that almost always carry personal data in a Dynamics/Dataverse org.
SENSITIVE_TABLES = {
    "contact", "account", "lead", "opportunity", "incident", "email",
    "annotation", "activitypointer", "systemuser", "adx_invitation",
    "adx_portalcomment", "feedback", "salesorder", "quote", "invoice",
    "knowledgearticle", "msdyn_customerasset", "msdyn_workorder",
}

# --- Dataverse API ------------------------------------------------------------

DATAVERSE_API_VERSION = "v9.2"
AAD_TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

# Formatted-value annotation suffix: lets us read option-set labels from the
# server instead of trusting hardcoded integers.
FORMATTED_VALUE = "@OData.Community.Display.V1.FormattedValue"
