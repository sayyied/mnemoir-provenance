from importlib import resources

from mnemoir_provenance.local_ui_adapter import LocalUIAdapter


def test_public_dossier_ui_and_recall_metadata(seeded_db):
    html = resources.files("mnemoir_provenance.ui").joinpath("index.html").read_text(encoding="utf-8")
    css = resources.files("mnemoir_provenance.ui").joinpath("app.css").read_text(encoding="utf-8")
    js = resources.files("mnemoir_provenance.ui").joinpath("app.js").read_text(encoding="utf-8")
    for route in ("home", "recall", "memory", "council", "system"):
        assert f'data-route="{route}"' in html
        assert f"render{route.title()}" in js
    assert "No claim without support" in js
    assert "trapDialogFocus" in js
    assert "prefers-reduced-motion" in css
    assert "[hidden]{display:none!important}" in css
    assert ".route-nav{position:static;display:grid;grid-template-columns:repeat(3,minmax(0,1fr))" in css
    assert "body:has(dialog[open]){overflow:hidden}" in css
    assert "data-home-state" in js
    assert "semantic-lifecycle" in css and "semantic-policy" in css and "semantic-evidence" in css
    assert "semanticBlock(\"Recent lifecycle receipts\"" in js
    assert "Recall updated. No supported answer" in js
    assert "Approve and create version" in js
    assert "linear-gradient" not in css
    recall = LocalUIAdapter(seeded_db).view("recall", query="source grounded memory")["data"]["recall"]
    assert recall["result_count"] >= 1
    result = recall["cited_results"][0]
    assert result["source_label"] == "Synthetic demo source"
    assert result["source_health"] == "healthy"
    assert result["authority_level"] == "primary"
    assert result["provenance_trail"]
