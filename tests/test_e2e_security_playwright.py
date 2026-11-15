"""End-to-End (E2E) Security & Functional Test Suite for Secure Hybrid Email Lab.

Automated tests using Playwright Python (pytest-playwright) to verify:
1. Happy path: RSA key generation, AES-256-GCM + RSA-OAEP encryption, RSA-PSS signing and verification.
2. Man-in-the-Middle (MITM) 1-bit tampering detection via AES-GCM Auth Tag.
3. Sender Public Key impersonation rejection via RSA-PSS signature verification.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from src.key_manager import generate_rsa_keypair, save_public_key

SERVER_PORT = 8501
BASE_URL = f"http://localhost:{SERVER_PORT}"
SCREENSHOTS_DIR = Path("tests/screenshots")
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="session")
def streamlit_app():
    """Start Streamlit server in headless mode and wait until HTTP 200 response."""
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "app.py",
        f"--server.port={SERVER_PORT}",
        "--server.headless=true",
        "--browser.gatherUsageStats=false",
    ]
    env = os.environ.copy()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    health_url = f"{BASE_URL}/_stcore/health"
    start_time = time.time()
    ready = False
    while time.time() - start_time < 30:
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            raise RuntimeError(
                f"Streamlit server died unexpectedly:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            )
        try:
            with urllib.request.urlopen(health_url, timeout=1) as response:
                if response.status == 200:
                    ready = True
                    break
        except (urllib.error.URLError, ConnectionResetError, OSError):
            time.sleep(0.5)

    if not ready:
        proc.terminate()
        proc.wait(timeout=5)
        raise TimeoutError("Streamlit server failed to start within 30 seconds.")

    yield BASE_URL

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def fake_public_key_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate a fake RSA-2048 public key (Mallory) for impersonation testing."""
    tmp_dir = tmp_path_factory.mktemp("keys")
    fake_key_file = tmp_dir / "mallory_public.pem"
    _, mallory_public = generate_rsa_keypair(2048)
    save_public_key(mallory_public, fake_key_file)
    return fake_key_file


def test_tc01_happy_path_send_decrypt_and_verify(page: Page, streamlit_app: str):
    """TC-01: Happy Path - Send, Decrypt and Verify Digital Signature.

    1. Open Streamlit and navigate to Tab '01 · Khóa'.
    2. Click 'Tạo cặp khóa Alice & Bob', verify SHA-256 fingerprints appear.
    3. Switch to Tab '02 · Gửi thư', compose message, select 'Hộp thư mô phỏng cục bộ', and click 'Ký, mã hóa và gửi'.
    4. Switch to Tab '03 · Thẩm định', select sent message, click 'Giải mã và thẩm định'.
    5. Assert valid signature banner ('CHỮ KÝ SỐ HỢP LỆ') and verify decrypted body matches 100%.
    6. Capture screenshot at tests/screenshots/TC01_happy_path_verified.png.
    """
    page.goto(streamlit_app)

    # 1. Tab '01 · Khóa'
    tab1 = page.get_by_role("tab", name="01 · Khóa")
    expect(tab1).to_be_visible(timeout=15000)
    tab1.click()

    btn_create_keys = page.get_by_role("button", name="Tạo cặp khóa Alice & Bob")
    expect(btn_create_keys).to_be_visible(timeout=10000)
    btn_create_keys.click()

    expect(page.get_by_text("Khóa Alice đã sẵn sàng")).to_be_visible(timeout=15000)
    expect(page.get_by_text("Khóa Bob đã sẵn sàng")).to_be_visible(timeout=15000)

    # 2. Tab '02 · Gửi thư'
    tab2 = page.get_by_role("tab", name="02 · Gửi thư")
    tab2.click()

    secret_subject = "Hợp đồng chuyển giao công nghệ mật mã E2E"
    secret_body = "Giá trị hợp đồng là 500 triệu VNĐ. Tài liệu này chỉ dành riêng cho Bob."

    input_subject = page.get_by_label("Tiêu đề")
    expect(input_subject).to_be_visible(timeout=10000)
    input_subject.fill(secret_subject)

    input_body = page.get_by_label("Nội dung thư")
    input_body.fill(secret_body)

    radio_local = page.get_by_text("Hộp thư mô phỏng cục bộ")
    if radio_local.is_visible():
        radio_local.click()

    btn_send = page.get_by_role("button", name="Ký, mã hóa và gửi")
    btn_send.click()

    expect(page.get_by_text("Payload đã được gửi tới")).to_be_visible(timeout=15000)

    # 3. Tab '03 · Thẩm định'
    tab3 = page.get_by_role("tab", name="03 · Thẩm định")
    tab3.click()

    btn_decrypt = page.get_by_role("button", name="Giải mã và thẩm định")
    expect(btn_decrypt).to_be_visible(timeout=15000)
    btn_decrypt.click()

    # 4. Assertions
    expect(page.get_by_text("CHỮ KÝ SỐ HỢP LỆ")).to_be_visible(timeout=15000)
    decrypted_body_area = page.get_by_label("Nội dung đã giải mã")
    expect(decrypted_body_area).to_be_visible(timeout=15000)
    expect(decrypted_body_area).to_have_value(secret_body)

    # 5. Screenshot
    page.screenshot(path=str(SCREENSHOTS_DIR / "TC01_happy_path_verified.png"), full_page=True)


def test_tc02_mitm_tampering_1bit_attack(page: Page, streamlit_app: str):
    """TC-02: Man-in-the-Middle (MITM) 1-bit Tampering Attack Simulation.

    1. Open Streamlit, initialize keys at Tab '01 · Khóa'.
    2. Compose and send a message at Tab '02 · Gửi thư'.
    3. Navigate to Tab '03 · Thẩm định' and click 'Mô phỏng sửa 1 bit (MITM)'.
    4. Assert that AES-256-GCM AEAD detects tampering and displays 'AES-GCM ĐÃ CHẶN CUỘC TẤN CÔNG',
       and verify that plaintext is NOT disclosed.
    5. Capture screenshot at tests/screenshots/TC02_mitm_tampering_blocked.png.
    """
    page.goto(streamlit_app)

    # 1. Tab '01 · Khóa'
    tab1 = page.get_by_role("tab", name="01 · Khóa")
    expect(tab1).to_be_visible(timeout=15000)
    tab1.click()
    page.get_by_role("button", name="Tạo cặp khóa Alice & Bob").click()
    expect(page.get_by_text("Khóa Alice đã sẵn sàng")).to_be_visible(timeout=15000)

    # 2. Tab '02 · Gửi thư'
    tab2 = page.get_by_role("tab", name="02 · Gửi thư")
    tab2.click()

    secret_body = "Thông tin tài chính tuyệt mật không được phép thay đổi."
    page.get_by_label("Tiêu đề").fill("Thư kiểm tra tính toàn vẹn")
    page.get_by_label("Nội dung thư").fill(secret_body)
    page.get_by_role("button", name="Ký, mã hóa và gửi").click()
    expect(page.get_by_text("Payload đã được gửi tới")).to_be_visible(timeout=15000)

    # 3. Tab '03 · Thẩm định'
    tab3 = page.get_by_role("tab", name="03 · Thẩm định")
    tab3.click()

    btn_mitm = page.get_by_role("button", name="Mô phỏng sửa 1 bit (MITM)")
    expect(btn_mitm).to_be_visible(timeout=15000)
    btn_mitm.click()

    # 4. Assertions
    expect(page.get_by_text("AES-GCM ĐÃ CHẶN CUỘC TẤN CÔNG")).to_be_visible(timeout=15000)
    expect(page.get_by_label("Nội dung đã giải mã")).not_to_be_visible()

    # 5. Screenshot
    page.screenshot(path=str(SCREENSHOTS_DIR / "TC02_mitm_tampering_blocked.png"), full_page=True)


def test_tc03_sender_public_key_impersonation_attack(
    page: Page, streamlit_app: str, fake_public_key_path: Path
):
    """TC-03: Sender Public Key Impersonation Attack Simulation.

    1. Open Streamlit, initialize keys at Tab '01 · Khóa'.
    2. Compose and send a message at Tab '02 · Gửi thư'.
    3. Navigate to Tab '03 · Thẩm định'.
    4. Expand 'Sử dụng khóa PEM tùy chỉnh', upload fake public key (Mallory) into 'Public Key người gửi'.
    5. Click 'Giải mã và thẩm định'.
    6. Assert that RSA-PSS signature verification rejects the key and displays 'CHỮ KÝ KHÔNG HỢP LỆ'.
    7. Capture screenshot at tests/screenshots/TC03_impersonation_rejected.png.
    """
    page.goto(streamlit_app)

    # 1. Tab '01 · Khóa'
    tab1 = page.get_by_role("tab", name="01 · Khóa")
    expect(tab1).to_be_visible(timeout=15000)
    tab1.click()
    page.get_by_role("button", name="Tạo cặp khóa Alice & Bob").click()
    expect(page.get_by_text("Khóa Alice đã sẵn sàng")).to_be_visible(timeout=15000)

    # 2. Tab '02 · Gửi thư'
    tab2 = page.get_by_role("tab", name="02 · Gửi thư")
    tab2.click()
    page.get_by_label("Tiêu đề").fill("Thư kiểm tra mạo danh người gửi")
    page.get_by_label("Nội dung thư").fill("Nội dung được ký bởi Alice.")
    page.get_by_role("button", name="Ký, mã hóa và gửi").click()
    expect(page.get_by_text("Payload đã được gửi tới")).to_be_visible(timeout=15000)

    # 3. Tab '03 · Thẩm định'
    tab3 = page.get_by_role("tab", name="03 · Thẩm định")
    tab3.click()

    tab3_panel = page.get_by_role("tabpanel", name="03 · Thẩm định")

    # Open expander "Sử dụng khóa PEM tùy chỉnh" inside Tab 3
    expander_trigger = tab3_panel.get_by_text("Sử dụng khóa PEM tùy chỉnh")
    expect(expander_trigger).to_be_visible(timeout=10000)
    expander_trigger.click()

    # Upload fake public key to "Public Key người gửi"
    uploader = tab3_panel.locator('div[data-testid="stFileUploader"]').filter(
        has_text="Public Key người gửi"
    )
    expect(uploader).to_be_visible(timeout=10000)
    file_input = uploader.locator('input[type="file"]')
    file_input.set_input_files(str(fake_public_key_path))

    # Wait until Streamlit acknowledges uploaded file
    expect(uploader.get_by_text(fake_public_key_path.name)).to_be_visible(timeout=10000)

    # Click 'Giải mã và thẩm định'
    btn_decrypt = page.get_by_role("button", name="Giải mã và thẩm định")
    btn_decrypt.click()

    # 4. Assert that signature is invalid
    expect(page.get_by_text("CHỮ KÝ KHÔNG HỢP LỆ")).to_be_visible(timeout=15000)

    # 5. Screenshot
    page.screenshot(path=str(SCREENSHOTS_DIR / "TC03_impersonation_rejected.png"), full_page=True)
