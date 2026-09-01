import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_accessibility_contract():
    templates = {
        path.name: path.read_text(encoding="utf-8")
        for path in (ROOT / "templates").glob("*.html")
    }
    markup = "\n".join(templates.values())
    css = (ROOT / "static/css/style.css").read_text(encoding="utf-8")
    javascript = (ROOT / "static/js/app.js").read_text(encoding="utf-8")

    assert 'class="skip-link" href="#main-content"' in templates["layout.html"]
    assert 'id="main-content" tabindex="-1"' in templates["layout.html"]
    assert "aria-current=\"page\"" in templates["layout.html"]
    assert "focus-visible" in css and "outline: 3px solid #fbbf24" in css
    assert all('scope="col"' in tag for tag in re.findall(r"<th\b[^>]*>", markup))
    assert markup.count('role="region"') == markup.count('tabindex="0"') >= 13
    assert markup.count('role="img"') >= 4

    for form_id, error_id in (
        ("admin-user-form", "admin-user-status"),
        ("detection-exception-form", "detection-exception-status"),
        ("suppression-policy-form", "suppression-policy-status"),
        ("analytics-range-form", "analytics-error"),
        ("asset-form", "asset-form-error"),
    ):
        assert re.search(
            rf'<form[^>]*id="{form_id}"[^>]*aria-describedby="{error_id}"', markup
        )

    assert 'aria-labelledby="asset-dialog-title"' in templates["assets.html"]
    assert "dialogTrigger?.focus()" in javascript
    assert 'aria-expanded="false" aria-controls="filter-panel"' in templates["logs.html"]
    assert 'aria-pressed="true"' in templates["logs.html"]
    assert 'setAttribute("aria-expanded"' in javascript
    assert 'setAttribute("aria-pressed"' in javascript
    assert '"LIVE STREAM" : "PAUSED"' in javascript
    assert "--color-blue: #60a5fa" in css and "color: var(--bg-sidebar)" in css
    assert all(marker in css for marker in (
        "@media (max-width: 1100px)", "@media (max-width: 700px)",
        "@media (max-width: 480px)", "@media (prefers-reduced-motion: reduce)",
    ))


if __name__ == "__main__":
    test_accessibility_contract()
    print("M29.3 dashboard accessibility passed")
