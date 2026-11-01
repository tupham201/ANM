from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_streamlit_app_renders_without_exceptions():
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    app = AppTest.from_file(app_path, default_timeout=15).run()

    assert not app.exception
    assert len(app.tabs) == 3
    assert app.title[0].value == "Thư điện tử mã hóa lai và ký số"
