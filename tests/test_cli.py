"""Interactive selection: asked only at a terminal, never silently widened."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from ppaudit import cli, prompts
from ppaudit.config import ConfigError, Instance
from ppaudit.report import Report

SITES = [
    Instance(name="Contoso (Production)", dataverse_url="https://prod.crm.dynamics.com",
             portal_url="https://www.contoso.example"),
    Instance(name="Contoso (Test)", dataverse_url="https://test.crm.dynamics.com"),
]


def _args(**overrides):
    base = dict(command="scan", instance=None, no_input=False, prompted=[],
                instances=None, env=None, website="")
    base.update(overrides)
    return argparse.Namespace(**base)


@pytest.fixture
def answers(monkeypatch):
    """Feed scripted answers to input() and pretend a terminal is attached."""
    queue: list[str] = []

    def fake_input(_prompt=""):
        if not queue:
            raise EOFError
        return queue.pop(0)

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(prompts, "interactive",
                        lambda args=None: not getattr(args, "no_input", False))
    return queue


def test_instance_flag_selects_by_name_or_slug():
    picked = cli._select_instances(_args(instance=["contoso-test"]), SITES)
    assert [i.name for i in picked] == ["Contoso (Test)"]
    picked = cli._select_instances(_args(instance=["Contoso (Production)"]), SITES)
    assert [i.name for i in picked] == ["Contoso (Production)"]


def test_unknown_instance_lists_what_is_available():
    with pytest.raises(ConfigError, match="Available: 'Contoso \\(Production\\)'"):
        cli._select_instances(_args(instance=["staging"]), SITES)


def test_several_sites_prompt_and_record_the_choice(answers):
    answers.append("2")
    args = _args()
    picked = cli._select_instances(args, SITES)
    assert [i.name for i in picked] == ["Contoso (Test)"]
    assert args.prompted == ["--instance", "Contoso (Test)"]


def test_all_sites_is_an_explicit_option(answers):
    answers.append("3")
    assert cli._select_instances(_args(), SITES) == SITES


def test_enter_does_not_default_to_every_site(answers):
    answers.extend(["", "9", "1"])     # blank and out-of-range are re-asked
    picked = cli._select_instances(_args(), SITES)
    assert [i.name for i in picked] == ["Contoso (Production)"]


def test_no_input_keeps_the_non_interactive_behaviour(answers):
    assert cli._select_instances(_args(no_input=True), SITES) == SITES
    assert answers == []


def test_a_single_site_is_never_asked_about(answers):
    assert cli._select_instances(_args(), SITES[:1]) == SITES[:1]


def test_end_of_input_cancels_rather_than_guessing(answers):
    with pytest.raises(prompts.Aborted):
        cli._select_instances(_args(), SITES)


def test_output_prompt_defaults_to_an_html_report(answers):
    answers.append("")
    args = _args(json=None, markdown=None, html=None)
    cli._prompt_outputs(args)
    assert args.html == "reports/audit.html" and args.json is None


def test_output_prompt_is_skipped_when_a_report_flag_was_given(answers):
    args = _args(json="out.json", markdown=None, html=None)
    cli._prompt_outputs(args)
    assert args.html is None


def test_wizard_needs_confirmation_before_writing_names(answers):
    answers.extend(["4", "2", "n"])
    assert cli._wizard() == ["naming"]
    answers.extend(["4", "2", "y"])
    assert cli._wizard() == ["naming", "--apply"]


def test_reports_go_in_a_per_instance_folder_named_by_run():
    assert cli._out_path("reports/audit.html", "contoso-prod", "20260916-142530") == \
        str(Path("reports/contoso-prod/audit-20260916-142530.html"))


def test_two_sites_in_one_run_cannot_overwrite_each_other():
    stamp = "20260916-142530"
    first = cli._out_path("reports/audit.json", "contoso-prod", stamp)
    second = cli._out_path("reports/audit.json", "contoso-test", stamp)
    assert first != second


def test_emit_creates_the_instance_folder(tmp_path):
    report = Report(target="https://contoso.example")
    args = _args(no_color=True, html=None, markdown=None,
                 json=str(tmp_path / "reports" / "audit.json"))
    cli._emit(report, args, "contoso-prod", "20260916-142530")
    written = tmp_path / "reports" / "contoso-prod" / "audit-20260916-142530.json"
    assert written.is_file()
    assert json.loads(written.read_text(encoding="utf-8"))["target"] == \
        "https://contoso.example"


def test_a_url_target_is_named_after_its_host(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)          # no instances.yaml or .env here
    args = _args(command="scan", url="https://www.contoso.example/", org_url=None)
    instances, cfg = cli._resolve_targets(args)
    assert cfg is None
    assert instances[0].slug == "www-contoso-example"


def test_bare_command_without_a_terminal_prints_help(monkeypatch, capsys):
    monkeypatch.setattr(prompts, "interactive", lambda args=None: False)
    assert cli.main([]) == 2
    assert "scan" in capsys.readouterr().err
