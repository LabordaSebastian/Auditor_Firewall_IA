"""Pruebas estructurales de la UI por pestañas (MEJ-09 / RF-13): paneles, ids y visor del reporte."""
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.web.app import WEB_DIR, app

HTML = (WEB_DIR / "templates" / "index.html").read_text(encoding="utf-8")
JS = (WEB_DIR / "static" / "js" / "app.js").read_text(encoding="utf-8")
TABS = ["postura", "whatif", "topologia", "herramientas", "reporte"]


class _Dom(HTMLParser):
    """Registra cada id con su cadena de ancestros con id (para saber en qué panel vive)."""

    def __init__(self):
        super().__init__()
        self.stack, self.ids, self.parents, self.attrs = [], [], {}, {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in {"meta", "link", "input", "br", "img"}:
            if a.get("id"):
                self.ids.append(a["id"]); self.parents[a["id"]] = [s for s in self.stack if s]; self.attrs[a["id"]] = a
            return
        self.stack.append(a.get("id"))
        if a.get("id"):
            self.ids.append(a["id"]); self.attrs[a["id"]] = a
            self.parents[a["id"]] = [s for s in self.stack[:-1] if s]

    def handle_endtag(self, tag):
        if self.stack and tag not in {"meta", "link", "input", "br", "img"}:
            self.stack.pop()


@pytest.fixture(scope="module")
def dom() -> _Dom:
    d = _Dom(); d.feed(HTML); return d


def test_every_tab_has_button_and_panel(dom):
    for t in TABS:
        assert f"tab-{t}" in dom.ids and f"panel-{t}" in dom.ids, t
        assert dom.attrs[f"tab-{t}"]["aria-controls"] == f"panel-{t}"
        assert dom.attrs[f"panel-{t}"]["role"] == "tabpanel"
    assert dom.attrs["mainNav"]["role"] == "tablist"
    assert "active" in dom.attrs["panel-postura"]["class"]                       # única activa de inicio
    assert sum("active" in dom.attrs[f"panel-{t}"]["class"] for t in TABS) == 1
    assert "hidden" in dom.attrs["tab-whatif"]                                   # oculta hasta haber hallazgos con planes


def test_ids_are_unique(dom):
    dupes = {i for i in dom.ids if dom.ids.count(i) > 1}
    assert not dupes, dupes


@pytest.mark.parametrize("element,panel", [
    ("donutSev", "postura"), ("findings", "postura"), ("filters", "postura"),
    ("wiTable", "whatif"), ("wiRun", "whatif"), ("wiReset", "whatif"),
    ("topoCanvas", "topologia"), ("simResult", "topologia"), ("btnSim", "topologia"),
    ("btnShadow", "herramientas"), ("btnMatrix", "herramientas"), ("btnReach", "herramientas"), ("btnTf", "herramientas"),
    ("reportView", "reporte"),
])
def test_each_tool_lives_in_the_expected_panel(dom, element, panel):
    assert f"panel-{panel}" in dom.parents[element], (element, dom.parents[element])


def test_hero_and_downloads_stay_outside_tabs(dom):
    for el in ("hostName", "gaugeNow", "gaugeProj", "btnPdf", "btnMd", "btnRem", "btnRoll", "btnSanView"):
        assert not any(p.startswith("panel-") for p in dom.parents.get(el, [])), el


def test_every_id_referenced_by_js_exists():
    """Mover secciones a pestañas no debe dejar `$('id')` apuntando a elementos inexistentes."""
    referenced = set(re.findall(r"\$\('([A-Za-z0-9_]+)'\)", JS)) | set(re.findall(r"getElementById\('([A-Za-z0-9_]+)'\)", JS))
    html_ids = set(re.findall(r'id="([A-Za-z0-9_\-]+)"', HTML))
    js_created = set(re.findall(r'id="([A-Za-z0-9_\-]+)"', JS))
    js_dynamic = {"tab-" + t for t in TABS} | {"panel-" + t for t in TABS}
    missing = referenced - html_ids - js_created - js_dynamic
    assert not missing, missing


def test_tabs_module_and_report_viewer_present():
    for token in (
        "const Tabs", "show(name", "reset()", "function renderReport", "function repFinding",
        "Topo.activate", "pendingLoad", "codebox has-bar", "codebox-bar", "rep-hero-banner",
        "paper-mode", "rep-evidence", "risk-cell",
    ):
        assert token in JS, token
    assert "TAB_IDS = ['postura', 'whatif', 'topologia', 'herramientas', 'reporte']" in JS
    # El reporte ejecutivo es 100 % informativo: sin planes A/B ni bloques de comandos de corrección
    rep_fn = JS.split("function repFinding(h)", 1)[1].split("function printReport()", 1)[0]
    assert "plan_a_recomendado" not in rep_fn and "plan_b_conservador" not in rep_fn
    assert "comandos_cli_implementacion" not in rep_fn and "comandos_cli_rollback" not in rep_fn


def test_assets_are_versioned_and_served():
    assert "styles.css?v=4." in HTML and "app.js?v=4." in HTML
    c = TestClient(app)
    assert c.get("/static/css/styles.css").status_code == 200 and ".mainnav" in c.get("/static/css/styles.css").text
    assert c.get("/").status_code == 200
