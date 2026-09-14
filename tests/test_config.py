"""Config loading: .env parsing, placeholder resolution, the YAML fallback."""

from __future__ import annotations

import pytest

from ppaudit import config


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in ("tenant_id", "TENANT_ID", "client_id", "CLIENT_ID",
                "client_secret", "CLIENT_SECRET"):
        monkeypatch.delenv(key, raising=False)


SAMPLE = """\
# Comment line
instances:
  - name: Contoso (Production)
    dataverse_url: https://contoso.crm.dynamics.com/
    portal_url: https://www.example.com
  - name: Dev
    dataverse_url: https://dev.crm.dynamics.com/
    portal_url: https://dev.example.com

tenant_id: ${tenant_id}
client_id: ${client_id}
client_secret: ${client_secret}
"""


def test_fallback_parser_reads_the_documented_shape():
    data = config._parse_yaml(SAMPLE)
    assert len(data["instances"]) == 2
    assert data["instances"][0]["name"] == "Contoso (Production)"
    assert data["instances"][1]["portal_url"] == "https://dev.example.com"
    assert data["tenant_id"] == "${tenant_id}"


def test_fallback_parser_strips_trailing_comments():
    data = config._parse_yaml("tenant_id: abc  # inline note\n")
    assert data["tenant_id"] == "abc"


def test_url_containing_a_colon_survives():
    data = config._parse_yaml("instances:\n  - dataverse_url: https://x.example/\n")
    assert data["instances"][0]["dataverse_url"] == "https://x.example/"


def test_expand_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("TENANT_ID", "from-upper")
    assert config._expand("${tenant_id}") == "from-upper"


def test_expand_leaves_unknown_placeholders_alone():
    assert config._expand("${nope}") == "${nope}"


def test_dotenv_tolerates_indentation_and_quotes(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('  tenant_id= "abc"\n  client_id=\'def\'\nexport client_secret=ghi\n')
    values = config.load_dotenv(env)
    assert values == {"tenant_id": "abc", "client_id": "def", "client_secret": "ghi"}


def test_existing_environment_wins_over_dotenv(tmp_path, monkeypatch):
    monkeypatch.setenv("tenant_id", "already-set")
    env = tmp_path / ".env"
    env.write_text("tenant_id=from-file\n")
    config.load_dotenv(env)
    import os
    assert os.environ["tenant_id"] == "already-set"


def test_load_config_resolves_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("tenant_id", "T")
    monkeypatch.setenv("client_id", "C")
    monkeypatch.setenv("client_secret", "S")
    path = tmp_path / "instances.yaml"
    path.write_text(SAMPLE, encoding="utf-8")
    cfg = config.load_config(path, env_path=str(tmp_path / "missing.env"))
    assert (cfg.tenant_id, cfg.client_id, cfg.client_secret) == ("T", "C", "S")
    assert [i.name for i in cfg.instances] == ["Contoso (Production)", "Dev"]


def test_unresolved_credentials_become_empty_not_literal(tmp_path):
    path = tmp_path / "instances.yaml"
    path.write_text(SAMPLE, encoding="utf-8")
    cfg = config.load_config(path, env_path=str(tmp_path / "missing.env"))
    assert cfg.tenant_id == ""
    assert "missing" in config.credentials_summary(cfg)


def test_trailing_slashes_are_stripped(tmp_path):
    path = tmp_path / "instances.yaml"
    path.write_text(SAMPLE, encoding="utf-8")
    inst = config.load_config(path, env_path=str(tmp_path / "x.env")).instances[0]
    assert inst.dataverse_url == "https://contoso.crm.dynamics.com"
    assert inst.portal_url == "https://www.example.com"


def test_slug_is_filesystem_safe(tmp_path):
    path = tmp_path / "instances.yaml"
    path.write_text(SAMPLE, encoding="utf-8")
    inst = config.load_config(path, env_path=str(tmp_path / "x.env")).instances[0]
    assert inst.slug == "contoso-production"


def test_missing_file_raises_a_clear_error(tmp_path):
    with pytest.raises(config.ConfigError):
        config.load_config(tmp_path / "nope.yaml")


def test_instances_without_urls_are_rejected(tmp_path):
    path = tmp_path / "instances.yaml"
    path.write_text("instances:\n  - name: Empty\n", encoding="utf-8")
    with pytest.raises(config.ConfigError):
        config.load_config(path, env_path=str(tmp_path / "x.env"))
