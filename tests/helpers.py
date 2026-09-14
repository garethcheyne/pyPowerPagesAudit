"""Synthetic configuration builders.

Built by hand rather than recorded from a real environment: the tests must be
safe to ship in a public repo, and a hand-built model lets each test state the
exact shape it is exercising.
"""

from __future__ import annotations

from ppaudit.model import (
    ColumnPermission,
    ColumnPermissionProfile,
    EntityForm,
    EntityList,
    PageAccessRule,
    SchemaModel,
    SiteSetting,
    TablePermission,
    WebApiTable,
    WebPage,
    WebRole,
    Website,
)

ORG = "https://contoso.crm.dynamics.com"


def role(name, *, anon=False, auth=False, rid=None):
    return WebRole(id=rid or f"role-{name}", name=name,
                   is_anonymous=anon, is_authenticated=auth, website_id="site-1")


def permission(name, table, scope, *, read=True, write=False, create=False,
               delete=False, append=False, appendto=False, roles=(), pid=None,
               parent_id="", contact_rel="", account_rel="", parent_rel=""):
    return TablePermission(
        id=pid or f"perm-{name}", name=name, table=table, scope=scope,
        read=read, write=write, create=create, delete=delete,
        append=append, appendto=appendto, roles=list(roles),
        website_id="site-1", parent_id=parent_id,
        contact_relationship=contact_rel, account_relationship=account_rel,
        parent_relationship=parent_rel)


def page(pid, name, partial, *, parent="", copy="", js="", template_id="",
         list_id="", form_id=""):
    return WebPage(id=pid, name=name, partial_url=partial, parent_id=parent,
                   copy=copy, custom_js=js, page_template_id=template_id,
                   entity_list_id=list_id, entity_form_id=form_id,
                   website_id="site-1")


def rule(name, page_id, right="Restrict Read", roles=()):
    return PageAccessRule(id=f"rule-{name}", name=name, right=right,
                          scope="All content", page_id=page_id,
                          roles=list(roles), website_id="site-1")


def build_model(**overrides) -> SchemaModel:
    model = SchemaModel(
        generation="adx",
        label="Standard data model",
        org_url=ORG,
        entity_sets={
            "website": "adx_websites",
            "webrole": "adx_webroles",
            "entitypermission": "adx_entitypermissions",
            "columnpermissionprofile": "adx_columnpermissionprofiles",
            "sitesetting": "adx_sitesettings",
            "entitylist": "adx_entitylists",
            "entityform": "adx_entityforms",
            "webpage": "adx_webpages",
            "webtemplate": "adx_webtemplates",
        },
        perm_name_field="adx_entityname",
        cpp_name_field="adx_profilename",
        websites=[Website(id="site-1", name="contoso.example")],
    )
    for key, value in overrides.items():
        setattr(model, key, value)
    return model


def sample_model() -> SchemaModel:
    """A small site: one anonymous role, a public page and a protected one."""
    model = build_model(
        roles=[role("Anonymous", anon=True), role("Members", auth=True), role("Staff")],
        permissions=[
            permission("contacts", "contact", "Global", roles=["Anonymous"]),
            permission("products", "product", "Global", roles=["Anonymous"]),
            permission("own cases", "incident", "Contact", roles=["Members"]),
        ],
        pages=[
            page("page-pub", "Public API", "api",
                 copy='{% fetchxml q %}<fetch><entity name="contact">'
                      '<attribute name="emailaddress1" /></entity></fetch>{% endfetchxml %}'),
            page("page-locked", "Members", "members",
                 copy='{% fetchxml q %}<fetch><entity name="incident" />'
                      '</fetch>{% endfetchxml %}'),
            page("page-child", "Child", "detail", parent="page-locked",
                 copy='{% fetchxml q %}<fetch><entity name="contact">'
                      '<attribute name="emailaddress1" /></entity></fetch>{% endfetchxml %}'),
        ],
        page_rules=[rule("lock members", "page-locked", roles=["Members"])],
        webapi=[WebApiTable(entity="contact", enabled=True,
                            fields_raw="emailaddress1,firstname",
                            enabled_setting_id="set-1", fields_setting_id="set-2")],
        profiles=[
            ColumnPermissionProfile(
                id="prof-1", name="Edit profile", table="contact",
                all_permissions=["Read", "Update"], roles=["Members"],
                website_id="site-1",
                columns=[ColumnPermission(id="col-1", column="firstname",
                                          permissions=["Read", "Update"])]),
            ColumnPermissionProfile(
                id="prof-2", name="Wide open", table="incident",
                all_permissions=["Create", "Read", "Update"], roles=["Members"],
                website_id="site-1"),
        ],
        entity_lists=[EntityList(id="list-1", name="Cases", table="incident",
                                 odata_enabled=True, website_id="site-1")],
        entity_forms=[EntityForm(id="form-1", name="Contact us", table="lead",
                                 mode="Insert", website_id="site-1")],
        settings=[SiteSetting(id="set-3", name="Site/EnableDiagnostics",
                              value="true", website_id="site-1")],
    )
    model.resolve_page_paths()
    return model
