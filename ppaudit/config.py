"""Configuration loading: ``.env`` secrets and ``instances.yaml`` targets.

A single ``instances.yaml`` names the environments to audit, pairing each
Dataverse org URL with the portal it fronts, and carries the app-registration
credentials. Credentials are written as ``${tenant_id}`` style placeholders and
resolved from the process environment or a ``.env`` file, so the YAML stays
safe to commit.

    instances:
      - name: Contoso (Production)
        dataverse_url: https://contoso.crm.dynamics.com
        portal_url: https://www.example.com
    tenant_id: ${tenant_id}
    client_id: ${client_id}
    client_secret: ${client_secret}
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

ENV_FILENAMES = (".env", "sample .env")
CONFIG_FILENAMES = ("instances.yaml", "instances.yml", "sample_instances.yaml")

_PLACEHOLDER = re.compile(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


class ConfigError(RuntimeError):
    pass


@dataclass
class Instance:
    """One environment to audit: a Dataverse org and the portal it serves."""

    name: str
    dataverse_url: str = ""
    portal_url: str = ""
    website: str = ""

    @property
    def slug(self) -> str:
        s = re.sub(r"[^A-Za-z0-9]+", "-", self.name).strip("-").lower()
        return s or "instance"


@dataclass
class Config:
    instances: list[Instance] = field(default_factory=list)
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    source: str = ""


def load_dotenv(path: str | os.PathLike[str] | None = None, *, override: bool = False) -> dict[str, str]:
    """Load ``KEY=value`` pairs into ``os.environ``; returns what was parsed.

    Tolerates the indented, quoted style people actually write. Existing
    environment variables win unless ``override`` is set.
    """
    candidates = [Path(path)] if path else [Path.cwd() / n for n in ENV_FILENAMES]
    values: dict[str, str] = {}
    for candidate in candidates:
        if not candidate.is_file():
            continue
        for raw in candidate.read_text(encoding="utf-8-sig").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.lower().startswith("export "):
                line = line[7:]
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if not key:
                continue
            values[key] = val
            if override or key not in os.environ:
                os.environ[key] = val
        break  # first file found wins
    return values


def _expand(value: str) -> str:
    """Resolve ``${name}`` / ``$name`` from the environment, case-insensitively.

    Dataverse config is habitually written lower-case while the shell exports
    upper-case, so try both before giving up and leaving the text untouched.
    """

    def repl(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        for key in (name, name.upper(), name.lower()):
            if key in os.environ:
                return os.environ[key]
        return match.group(0)

    return _PLACEHOLDER.sub(repl, value)


def _unresolved(value: str) -> bool:
    return bool(_PLACEHOLDER.search(value))


def _parse_yaml(text: str) -> dict:
    """Parse the instances file, preferring PyYAML when it is installed.

    The fallback understands only the shape documented above — a top-level map
    of scalars plus an ``instances`` list of maps — which is all this file is.
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        pass
    else:
        return yaml.safe_load(text) or {}

    data: dict = {}
    current_list: list[dict] | None = None
    current_item: dict | None = None
    list_indent = 0

    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if stripped.startswith("- "):
            if current_list is None:
                continue
            current_item = {}
            current_list.append(current_item)
            list_indent = indent
            stripped = stripped[2:].strip()
            if not stripped:
                continue
            key, _, val = stripped.partition(":")
            current_item[key.strip()] = _scalar(val)
            continue

        key, _, val = stripped.partition(":")
        key, val = key.strip(), _scalar(val)

        if current_item is not None and indent > list_indent:
            current_item[key] = val
            continue

        current_list = current_item = None
        if val == "":
            current_list = []
            data[key] = current_list
        else:
            data[key] = val
    return data


def _strip_comment(line: str) -> str:
    return re.sub(r"(^|\s)#.*$", "", line).rstrip()


def _scalar(val: str) -> str:
    val = val.strip().strip('"').strip("'")
    return val


def find_config(explicit: str | None = None) -> Path | None:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise ConfigError(f"instances file not found: {p}")
        return p
    for name in CONFIG_FILENAMES:
        p = Path.cwd() / name
        if p.is_file():
            return p
    return None


def load_config(path: str | os.PathLike[str] | None = None, *, env_path: str | None = None) -> Config:
    """Load ``.env`` then ``instances.yaml`` and return the resolved config."""
    load_dotenv(env_path)
    found = find_config(str(path) if path else None)
    if found is None:
        raise ConfigError(
            "no instances.yaml found in the current directory; pass --instances PATH"
        )

    data = _parse_yaml(found.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ConfigError(f"{found}: expected a mapping at the top level")

    cfg = Config(
        tenant_id=_expand(str(data.get("tenant_id") or "")),
        client_id=_expand(str(data.get("client_id") or "")),
        client_secret=_expand(str(data.get("client_secret") or "")),
        source=str(found),
    )
    for key in ("tenant_id", "client_id", "client_secret"):
        if _unresolved(getattr(cfg, key)):
            setattr(cfg, key, "")

    raw_instances = data.get("instances") or []
    if not isinstance(raw_instances, list):
        raise ConfigError(f"{found}: 'instances' must be a list")
    for idx, item in enumerate(raw_instances, 1):
        if not isinstance(item, dict):
            continue
        inst = Instance(
            name=str(item.get("name") or f"instance-{idx}"),
            dataverse_url=_expand(str(item.get("dataverse_url") or item.get("org_url") or "")).rstrip("/"),
            portal_url=_expand(str(item.get("portal_url") or item.get("url") or "")).rstrip("/"),
            website=str(item.get("website") or ""),
        )
        if not inst.dataverse_url and not inst.portal_url:
            continue
        cfg.instances.append(inst)

    if not cfg.instances:
        raise ConfigError(f"{found}: no usable instances (each needs a dataverse_url or portal_url)")
    return cfg


def credentials_summary(cfg: Config) -> str:
    missing = [k for k in ("tenant_id", "client_id", "client_secret") if not getattr(cfg, k)]
    if missing:
        return "missing: " + ", ".join(missing)
    return f"tenant {cfg.tenant_id[:8]}…, client {cfg.client_id[:8]}…"
