"""Interactive prompts for when the command line leaves something unsaid.

The CLI asks only when a person is at the terminal and a choice is genuinely
missing — which site, which reports, what to run at all. Piped or scheduled
runs (CI, cron, an agent) never see a prompt: they keep the documented
non-interactive behaviour, and ``--no-input`` forces that from a terminal too.

Plain ``input()`` rather than a TUI library, so it works the same in Windows
Terminal, a VS Code terminal and over SSH, with no extra dependency.
"""

from __future__ import annotations

import sys


class Aborted(Exception):
    """The user cancelled, or input ended before a choice was made."""


def interactive(args=None) -> bool:
    if getattr(args, "no_input", False):
        return False
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        raise Aborted from None


def choose(question: str, options: list[tuple[str, str]],
           default: int | None = None) -> int:
    """Pick one of ``options`` (label, hint) by number; returns its index.

    With ``default=None`` there is no default and Enter re-asks — used where a
    silent default could point the tool at the wrong environment.
    """
    if not options:
        raise Aborted("nothing to choose from")
    print(f"\n{question}")
    width = max(len(label) for label, _ in options)
    for number, (label, hint) in enumerate(options, 1):
        print(f"  {number}) {label:<{width}}" + (f"   {hint}" if hint else ""))
    suffix = f" [{default + 1}]" if default is not None else ""
    while True:
        raw = _ask(f"Choose 1-{len(options)}{suffix}: ").strip()
        if not raw and default is not None:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        print(f"  Enter a number from 1 to {len(options)}.")


def confirm(question: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        raw = _ask(f"{question} [{hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  Answer y or n.")


def text(question: str, example: str = "") -> str:
    """A required free-text answer."""
    hint = f" (e.g. {example})" if example else ""
    while True:
        raw = _ask(f"{question}{hint}: ").strip()
        if raw:
            return raw
        print("  A value is required; press Ctrl+C to cancel.")
