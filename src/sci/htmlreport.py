"""Self-contained HTML report (iOS-style). The page loads nothing from the network; report data is embedded as inert JSON."""
from __future__ import annotations

from importlib import resources

from dci.models import Report
from dci import report as dci_report

_PLACEHOLDER = "__SCI_DATA__"


def _template() -> str:
    return resources.files("sci").joinpath("ui/index.html").read_text(encoding="utf-8")


def _embed(json_text: str) -> str:
    # Inside <script type="application/json"> only "</script" and "<!--" can break out; escape every angle bracket and & anyway.
    return (json_text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def render(json_text: str | None = None) -> str:
    page = _template()
    return page.replace(_PLACEHOLDER, _embed(json_text), 1) if json_text else page


def to_html(r: Report) -> str:
    return render(dci_report.to_json(r))
