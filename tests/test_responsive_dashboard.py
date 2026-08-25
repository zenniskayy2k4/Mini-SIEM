from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_responsive_dashboard_contract():
    css = (ROOT / "static/css/style.css").read_text(encoding="utf-8")
    layout = (ROOT / "templates/layout.html").read_text(encoding="utf-8")
    dashboard = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
    settings = (ROOT / "templates/settings.html").read_text(encoding="utf-8")
    assets = (ROOT / "templates/assets.html").read_text(encoding="utf-8")
    logs = (ROOT / "templates/logs.html").read_text(encoding="utf-8")
    login = (ROOT / "templates/login.html").read_text(encoding="utf-8")

    assert 'name="viewport"' in layout and 'name="viewport"' in login
    assert "@media (max-width: 1100px)" in css
    assert "@media (max-width: 700px)" in css
    assert "@media (max-width: 480px)" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "100dvh" in css

    assert 'class="logo-label"' in layout
    assert layout.count('class="nav-label"') == 6
    assert 'class="logout-label"' in layout

    assert dashboard.count('class="table-responsive') == 2
    assert settings.count('class="table-responsive') == 4
    assert assets.count('class="table-responsive') == 1
    assert 'class="asset-dialog"' in assets
    assert 'class="table-scroll-area"' in logs
    assert ".table-responsive .mini-table" in css
    assert "min-width: 1080px" in css
    assert "overflow: auto" in css


if __name__ == "__main__":
    test_responsive_dashboard_contract()
    print("responsive dashboard tests passed")
