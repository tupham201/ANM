"""Streamlit interface for the Secure Hybrid Email laboratory."""

from __future__ import annotations

import base64
import copy
import json
import time
from pathlib import Path

import streamlit as st
from cryptography.exceptions import InvalidTag

from src.config import CONTACTS_DIR, KEYS_DIR, MAX_ATTACHMENT_BYTES, get_mail_config
from src.crypto_engine import (
    decrypt_secure_payload,
    encrypt_secure_payload,
    envelope_from_json,
    envelope_to_json,
)
from src.key_manager import (
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
    private_key_to_pem,
    public_key_fingerprint,
    public_key_to_pem,
    safe_contact_name,
    save_private_key,
    save_public_key,
)
from src.mail_service import fetch_secure_emails, send_secure_email, verify_smtp_connection


st.set_page_config(
    page_title="Secure Hybrid Email Lab",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="auto",
)


st.markdown(
    """
    <style>
    :root {
      --ink: #13231f;
      --ink-soft: #52625d;
      --forest: #075c49;
      --forest-deep: #073d34;
      --mint: #c8f169;
      --paper: #f3f0e8;
      --surface: #fbfaf6;
      --line: #d7d8cf;
      --line-strong: #b8beb5;
      --danger: #b84132;
      --danger-soft: #f9e6e1;
      --success-soft: #e3f3e8;
      --radius-sm: 6px;
      --radius-md: 12px;
      --shadow: 0 18px 50px rgba(24, 48, 41, .08);
    }

    html { scroll-behavior: smooth; }
    .stApp {
      background: var(--paper);
      color: var(--ink);
      font-family: "Aptos", "Trebuchet MS", sans-serif;
    }
    .block-container { max-width: 1180px; padding-top: 3.25rem; padding-bottom: 5rem; }
    [data-testid="stHeader"] { background: rgba(243, 240, 232, .86); backdrop-filter: blur(12px); }
    [data-testid="stToolbar"] { right: 1rem; }

    h1, h2, h3 {
      color: var(--ink);
      font-family: "Aptos Display", "Aptos", "Trebuchet MS", sans-serif;
      font-weight: 650;
      letter-spacing: -.025em;
    }
    h1 { max-width: 760px; font-size: 3rem !important; line-height: 1.06 !important; }
    h2 { margin-top: .25rem !important; font-size: 2rem !important; }
    h3 { font-size: 1.15rem !important; letter-spacing: -.015em; }
    p, label, [data-testid="stCaptionContainer"] { line-height: 1.55; }

    [data-testid="stSidebar"] {
      background: #09251f;
      border-right: 1px solid rgba(255, 255, 255, .08);
    }
    [data-testid="stSidebar"] > div:first-child { padding-top: 2rem; }
    [data-testid="stSidebar"] * { color: #eaf2ee; }
    [data-testid="stSidebar"] code { color: #c8f169; background: rgba(255,255,255,.06); }
    [data-testid="stSidebar"] hr { border-color: rgba(255,255,255,.12); }
    .crypto-list { margin: 0; padding: .25rem 0; list-style: none; }
    .crypto-list li { padding: .42rem 0; border-bottom: 1px solid rgba(255,255,255,.09); color: #dce9e4; font-size: .82rem; }
    .crypto-list li:last-child { border-bottom: 0; }
    .crypto-list strong { display: inline-block; min-width: 7.7rem; color: var(--mint); font: 600 .77rem/1.3 Consolas, monospace; }
    .brand-mark {
      display: inline-flex;
      align-items: center;
      gap: .65rem;
      margin-bottom: .35rem;
      font: 700 1.05rem/1 "Aptos", sans-serif;
      letter-spacing: .13em;
    }
    .brand-mark::before {
      content: "";
      width: 12px;
      height: 12px;
      background: var(--mint);
      box-shadow: 6px 6px 0 rgba(200, 241, 105, .32);
      transform: rotate(45deg);
    }
    .sidebar-label {
      margin: 1.25rem 0 .65rem;
      color: #9fb4ad;
      font: 600 .68rem/1.2 Consolas, monospace;
      letter-spacing: .12em;
      text-transform: uppercase;
    }
    .status-line {
      display: flex;
      align-items: center;
      gap: .6rem;
      padding: .55rem 0;
      color: #eaf2ee;
      font-size: .88rem;
    }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #f0ad4e; box-shadow: 0 0 0 4px rgba(240,173,78,.12); }
    .status-dot.ready { background: #79d99a; box-shadow: 0 0 0 4px rgba(121,217,154,.12); }
    .status-dot.muted { background: #72857f; box-shadow: none; }

    .hero-copy { max-width: 68ch; margin: .65rem 0 0; color: var(--ink-soft); font-size: 1.04rem; line-height: 1.68; }
    .trust-strip { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: 1.1rem; }
    .trust-chip { border: 1px solid var(--line-strong); border-radius: 999px; padding: .38rem .7rem; background: rgba(251,250,246,.65); color: #40514b; font: 600 .7rem/1.2 Consolas, monospace; }

    .metric-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      margin: 2.25rem 0 2.75rem;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      background: rgba(251, 250, 246, .76);
      box-shadow: var(--shadow);
    }
    .metric { padding: 1.15rem 1.25rem; border-right: 1px solid var(--line); }
    .metric:last-child { border-right: 0; }
    .metric b { display: block; color: var(--forest); font: 650 1.45rem/1.2 "Bahnschrift", sans-serif; letter-spacing: -.02em; }
    .metric span { color: #66736e; font: 600 .67rem/1.4 Consolas, monospace; letter-spacing: .06em; }

    .section-intro { margin-bottom: 1.4rem; }
    .section-intro p { max-width: 730px; margin: .3rem 0 0; color: var(--ink-soft); }
    .section-number { color: var(--forest); font: 700 .7rem/1.3 Consolas, monospace; letter-spacing: .12em; text-transform: uppercase; }

    div[data-testid="stTabs"] div[role="tablist"] {
      display: grid !important;
      grid-template-columns: repeat(3, minmax(0, 1fr)) !important;
      gap: .4rem !important;
      margin-top: .9rem;
      padding: .4rem !important;
      border: 0 !important;
      border-radius: 16px !important;
      background: #e3e8e2 !important;
      box-shadow: inset 0 0 0 1px rgba(19, 35, 31, .06) !important;
    }
    div[data-testid="stTabs"] div[data-testid="stTab"] {
      min-height: 52px !important;
      width: 100% !important;
      padding: 0 1rem !important;
      border: 0 !important;
      border-radius: 12px !important;
      color: #53635e !important;
      font-weight: 700 !important;
      justify-content: center !important;
      transition: color 180ms ease, background-color 180ms ease, box-shadow 220ms cubic-bezier(.16, 1, .3, 1), transform 220ms cubic-bezier(.16, 1, .3, 1);
    }
    div[data-testid="stTabs"] div[data-testid="stTab"]:hover { color: var(--forest-deep) !important; background: rgba(251,250,246,.58) !important; }
    div[data-testid="stTabs"] div[data-testid="stTab"][aria-selected="true"] {
      background: var(--surface) !important;
      color: var(--forest-deep) !important;
      box-shadow: 0 5px 16px rgba(19, 53, 44, .1) !important;
      transform: translateY(-1px) !important;
    }
    div[data-testid="stTabs"] div[role="tabpanel"] {
      padding-top: 2.25rem;
      animation: panel-reveal 240ms cubic-bezier(.16, 1, .3, 1);
    }
    @keyframes panel-reveal {
      from { opacity: .72; clip-path: inset(0 0 8% 0); }
      to { opacity: 1; clip-path: inset(0 0 0 0); }
    }

    [data-testid="stTextInput"] input,
    [data-testid="stTextArea"] textarea,
    [data-baseweb="select"] > div,
    [data-testid="stFileUploaderDropzone"] {
      border-color: var(--line-strong) !important;
      border-radius: var(--radius-sm) !important;
      background: var(--surface) !important;
    }
    [data-testid="stTextInput"] input:focus,
    [data-testid="stTextArea"] textarea:focus,
    [data-baseweb="select"] > div:focus-within {
      border-color: var(--forest) !important;
      box-shadow: 0 0 0 3px rgba(7,92,73,.12) !important;
    }
    [data-testid="stFileUploaderDropzone"] { padding: 1.1rem; }
    [data-testid="stExpander"] { border: 1px solid var(--line); border-radius: var(--radius-sm); background: rgba(251,250,246,.55); }
    [data-testid="stMetric"] { padding: .9rem 1rem; border-left: 3px solid var(--forest); background: rgba(251,250,246,.7); }
    [data-testid="stMetricValue"] { font-family: "Bahnschrift", sans-serif; font-size: 1.2rem; }

    div[data-testid="stButton"] > button,
    div[data-testid="stDownloadButton"] > button {
      min-height: 44px;
      border-radius: var(--radius-sm);
      border-color: var(--line-strong);
      font-weight: 700;
      transition: transform .16s ease, box-shadow .16s ease, background .16s ease;
    }
    div[data-testid="stButton"] > button:hover,
    div[data-testid="stDownloadButton"] > button:hover { transform: translateY(-1px); border-color: var(--forest); color: var(--forest); }
    div[data-testid="stButton"] > button:focus-visible,
    div[data-testid="stDownloadButton"] > button:focus-visible { outline: 3px solid rgba(7,92,73,.24); outline-offset: 2px; }
    div[data-testid="stButton"] > button[kind="primary"] { background: var(--forest); border-color: var(--forest); color: white; box-shadow: 0 8px 20px rgba(7,92,73,.18); }
    div[data-testid="stButton"] > button[kind="primary"]:hover { background: var(--forest-deep); color: white; }
    div[data-testid="stButton"] > button:disabled { transform: none; opacity: .55; }

    [data-testid="stAlert"] { border-radius: var(--radius-sm); border-width: 1px; }
    .ok-banner, .bad-banner { margin: 1rem 0; padding: 1rem 1.15rem; border-radius: var(--radius-sm); line-height: 1.55; }
    .ok-banner { border: 1px solid #84b795; background: var(--success-soft); color: #174e2c; }
    .bad-banner { border: 1px solid #d89184; background: var(--danger-soft); color: #812c21; }
    .ok-banner b, .bad-banner b { display: inline-block; margin-bottom: .2rem; font-family: "Aptos", sans-serif; letter-spacing: .01em; }
    [data-testid="stCode"] { border: 1px solid rgba(255,255,255,.08); border-radius: var(--radius-sm); }
    hr { border-color: var(--line) !important; }

    ::selection { background: #b8e8d6; color: var(--ink); }
    * { scrollbar-color: var(--line-strong) transparent; scrollbar-width: thin; }

    .section-intro h2 { margin-bottom: .35rem !important; }
    .section-intro p { max-width: 68ch; }
    .panel-label { margin: 0 0 .65rem; color: var(--forest); font-size: .76rem; font-weight: 750; letter-spacing: .04em; text-transform: uppercase; }
    .empty-state { padding: 2.25rem 1.5rem; border: 1px dashed var(--line-strong); border-radius: var(--radius-md); text-align: center; background: rgba(251,250,246,.55); }
    .empty-state h3 { margin: 0 0 .45rem; }
    .empty-state p { max-width: 52ch; margin: 0 auto; color: var(--ink-soft); }
    .result-header { margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--line); }

    @media (max-width: 850px) {
      .block-container { padding: 2.25rem 1rem 3.5rem; }
      h1 { font-size: 2.45rem !important; }
      .metric-row { grid-template-columns: 1fr 1fr; }
      .metric:nth-child(2) { border-right: 0; }
      .metric:nth-child(-n+2) { border-bottom: 1px solid var(--line); }
      [data-testid="stTabs"] [data-testid="stTab"] { min-height: 48px; padding: 0 .5rem; font-size: .8rem; }
    }
    @media (max-width: 520px) {
      h1 { font-size: 2.15rem !important; }
      .metric-row { grid-template-columns: 1fr; }
      .metric { border-right: 0; border-bottom: 1px solid var(--line); }
      .metric:last-child { border-bottom: 0; }
      [data-testid="stTabs"] [role="tablist"] { gap: .25rem; padding: .3rem; }
      [data-testid="stTabs"] [data-testid="stTab"] { white-space: nowrap; }
    }
    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
      *, *::before, *::after { animation: none !important; transition: none !important; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def initialize_state() -> None:
    defaults = {
        "alice_private": None,
        "alice_public": None,
        "bob_private": None,
        "bob_public": None,
        "mailbox": [],
        "gmail_messages": [],
        "last_payload": None,
        "decryption_result": None,
        "selected_message_id": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def demo_keys_ready() -> bool:
    return all(
        st.session_state[key] is not None
        for key in ("alice_private", "alice_public", "bob_private", "bob_public")
    )


def contact_files() -> list[Path]:
    if not CONTACTS_DIR.exists():
        return []
    return sorted(CONTACTS_DIR.glob("*.pem"), key=lambda path: path.name.lower())


def attachment_to_payload(uploaded_file) -> dict[str, str] | None:
    if uploaded_file is None:
        return None
    data = uploaded_file.getvalue()
    if len(data) > MAX_ATTACHMENT_BYTES:
        raise ValueError("Tệp đính kèm vượt quá giới hạn 10 MB.")
    return {
        "name": Path(uploaded_file.name).name[:180],
        "mime_type": uploaded_file.type or "application/octet-stream",
        "data": base64.b64encode(data).decode("ascii"),
    }


def get_private_key(default_key, uploaded_file, password: str):
    if uploaded_file is not None:
        return load_private_key(uploaded_file.getvalue(), password or None)
    if default_key is None:
        raise ValueError("Chưa có khóa bí mật. Hãy tạo khóa hoặc tải tệp PEM lên.")
    return default_key


def get_public_key(default_key, uploaded_file):
    if uploaded_file is not None:
        return load_public_key(uploaded_file.getvalue())
    if default_key is None:
        raise ValueError("Chưa có khóa công khai. Hãy tạo khóa hoặc tải tệp PEM lên.")
    return default_key


initialize_state()
mail_config = get_mail_config()


with st.sidebar:
    st.markdown('<div class="brand-mark">CIPHERMAIL</div>', unsafe_allow_html=True)
    st.caption("SECURE HYBRID EMAIL LAB · NHÓM 14")
    st.divider()
    st.markdown('<div class="sidebar-label">Trạng thái hệ thống</div>', unsafe_allow_html=True)
    key_status = "ready" if demo_keys_ready() else ""
    key_text = "Khóa Alice/Bob sẵn sàng" if demo_keys_ready() else "Chưa tạo khóa Alice/Bob"
    gmail_status = "ready" if mail_config.is_configured else "muted"
    gmail_text = "Gmail đã cấu hình" if mail_config.is_configured else "Gmail chưa cấu hình"
    st.markdown(
        f'<div class="status-line"><span class="status-dot {key_status}"></span>{key_text}</div>'
        f'<div class="status-line"><span class="status-dot {gmail_status}"></span>{gmail_text}</div>',
        unsafe_allow_html=True,
    )
    if mail_config.is_configured:
        st.caption(mail_config.gmail_user)
    st.divider()
    st.markdown('<div class="sidebar-label">Crypto suite</div>', unsafe_allow_html=True)
    st.markdown(
        '<ul class="crypto-list">'
        '<li><strong>AES-256-GCM</strong> Nội dung</li>'
        '<li><strong>RSA-OAEP</strong> Khóa phiên</li>'
        '<li><strong>RSA-PSS</strong> Chữ ký</li>'
        '<li><strong>SHA-256</strong> Băm</li>'
        '</ul>',
        unsafe_allow_html=True,
    )
    st.caption("Khóa riêng và `.env` không được đưa lên GitHub.")


st.title("Thư điện tử mã hóa lai và ký số")
st.markdown(
    '<p class="hero-copy">Ứng dụng bảo vệ thư điện tử bằng chữ ký số RSA-PSS, mã hóa nội dung AES-256-GCM và bọc khóa phiên RSA-OAEP.</p>',
    unsafe_allow_html=True,
)
st.markdown(
    """
    <div class="trust-strip" aria-label="Các thuật toán và giao thức chính">
      <span class="trust-chip">AES-256-GCM</span>
      <span class="trust-chip">RSA-OAEP</span>
      <span class="trust-chip">RSA-PSS</span>
      <span class="trust-chip">SMTP / IMAP</span>
    </div>
    """,
    unsafe_allow_html=True,
)


tab_keys, tab_compose, tab_inbox = st.tabs(
    ["01 · Khóa", "02 · Gửi thư", "03 · Thẩm định"]
)


with tab_keys:
    st.markdown(
        '<div class="section-intro"><h2>Tạo danh tính cho Alice và Bob</h2>'
        '<p>Tạo hai cặp khóa RSA-2048. Khóa riêng dùng để ký hoặc giải mã; khóa công khai dùng để xác minh hoặc mã hóa.</p></div>',
        unsafe_allow_html=True,
    )

    left, right = st.columns(2, gap="large")
    with left:
        st.markdown("### Alice · Người gửi")
        alice_password = st.text_input(
            "Mật khẩu bảo vệ khóa Alice (không bắt buộc)",
            type="password",
            key="alice_key_password",
        )
        if st.session_state.alice_public:
            st.success("Khóa Alice đã sẵn sàng")
            st.code(public_key_fingerprint(st.session_state.alice_public), language=None)
            st.download_button(
                "Tải Alice Private Key",
                private_key_to_pem(st.session_state.alice_private, alice_password or None),
                "alice_private.pem",
                "application/x-pem-file",
                use_container_width=True,
            )
            st.download_button(
                "Tải Alice Public Key",
                public_key_to_pem(st.session_state.alice_public),
                "alice_public.pem",
                "application/x-pem-file",
                use_container_width=True,
            )
        else:
            st.info("Chưa có cặp khóa Alice")

    with right:
        st.markdown("### Bob · Người nhận")
        bob_password = st.text_input(
            "Mật khẩu bảo vệ khóa Bob (không bắt buộc)",
            type="password",
            key="bob_key_password",
        )
        if st.session_state.bob_public:
            st.success("Khóa Bob đã sẵn sàng")
            st.code(public_key_fingerprint(st.session_state.bob_public), language=None)
            st.download_button(
                "Tải Bob Private Key",
                private_key_to_pem(st.session_state.bob_private, bob_password or None),
                "bob_private.pem",
                "application/x-pem-file",
                use_container_width=True,
            )
            st.download_button(
                "Tải Bob Public Key",
                public_key_to_pem(st.session_state.bob_public),
                "bob_public.pem",
                "application/x-pem-file",
                use_container_width=True,
            )
        else:
            st.info("Chưa có cặp khóa Bob")

    save_to_disk = st.checkbox(
        "Lưu khóa vào thư mục `keys/` để dùng sau khi tải lại trang",
        help="Khóa riêng có mật khẩu sẽ an toàn hơn. Thư mục keys đã bị chặn khỏi Git.",
    )
    if st.button("Tạo cặp khóa Alice & Bob", type="primary", use_container_width=True):
        with st.spinner("Đang sinh hai cặp khóa RSA-2048 bằng CSPRNG..."):
            st.session_state.alice_private, st.session_state.alice_public = generate_rsa_keypair()
            st.session_state.bob_private, st.session_state.bob_public = generate_rsa_keypair()
            if save_to_disk:
                save_private_key(st.session_state.alice_private, KEYS_DIR / "alice_private.pem", alice_password or None)
                save_public_key(st.session_state.alice_public, KEYS_DIR / "alice_public.pem")
                save_private_key(st.session_state.bob_private, KEYS_DIR / "bob_private.pem", bob_password or None)
                save_public_key(st.session_state.bob_public, KEYS_DIR / "bob_public.pem")
        st.success("Đã tạo hai cặp khóa. Alice và Bob sẵn sàng cho bước mã hóa.")
        st.rerun()

    with st.expander("Quản lý danh bạ khóa công khai", expanded=False):
        contact_col, upload_col = st.columns([1, 2])
        with contact_col:
            contact_name = st.text_input("Tên liên hệ", placeholder="teacher hoặc bob_company")
        with upload_col:
            contact_key_file = st.file_uploader(
                "Public Key của liên hệ (.pem)", type=["pem"], key="contact_public_key"
            )
        if st.button("Lưu khóa vào danh bạ", disabled=not (contact_name and contact_key_file)):
            try:
                key = load_public_key(contact_key_file.getvalue())
                CONTACTS_DIR.mkdir(parents=True, exist_ok=True)
                destination = CONTACTS_DIR / f"{safe_contact_name(contact_name)}_public.pem"
                save_public_key(key, destination)
                st.success(f"Đã lưu `{destination.name}`")
            except (ValueError, TypeError) as exc:
                st.error(f"Không thể lưu khóa: {exc}")
        files = contact_files()
        st.caption(
            "Danh bạ hiện có: " + ", ".join(path.name for path in files)
            if files
            else "Danh bạ chưa có khóa công khai nào."
        )


with tab_compose:
    st.markdown(
        '<div class="section-intro"><h2>Alice bảo vệ và gửi thông điệp</h2>'
        '<p>Soạn nội dung ở bên trái; bên phải cho thấy chính xác chuỗi bảo vệ được áp dụng trước khi payload rời khỏi máy gửi.</p></div>',
        unsafe_allow_html=True,
    )
    editor_col, process_col = st.columns([1.55, 0.85], gap="large", vertical_alignment="top")
    with editor_col:
        st.markdown('<p class="panel-label">Nội dung cần bảo vệ</p>', unsafe_allow_html=True)
        address_left, address_right = st.columns(2)
        with address_left:
            sender_email = st.text_input(
                "Email người gửi",
                value=mail_config.gmail_user or "alice@example.com",
                key="sender_email",
            )
        with address_right:
            recipient_email = st.text_input(
                "Email người nhận",
                value=mail_config.gmail_user or "bob@example.com",
                key="recipient_email",
            )

        subject = st.text_input(
            "Tiêu đề", value="Hợp đồng chuyển giao công nghệ mật mã", max_chars=160
        )
        body = st.text_area(
            "Nội dung thư",
            value="Giá trị hợp đồng là 500 triệu VNĐ. Tài liệu này chỉ dành cho Bob.",
            height=210,
            max_chars=20_000,
        )
        attachment = st.file_uploader(
            "Tệp đính kèm (tối đa 10 MB)", key="compose_attachment"
        )

        with st.expander("Sử dụng khóa PEM tùy chỉnh", expanded=False):
            custom_sender_private = st.file_uploader(
                "Private Key người gửi", type=["pem"], key="custom_sender_private"
            )
            custom_sender_password = st.text_input(
                "Mật khẩu Private Key người gửi",
                type="password",
                key="custom_sender_password",
            )
            custom_recipient_public = st.file_uploader(
                "Public Key người nhận", type=["pem"], key="custom_recipient_public"
            )

    with process_col:
        st.markdown('<p class="panel-label">Thiết lập gửi</p>', unsafe_allow_html=True)
        transport_options = ["Hộp thư mô phỏng cục bộ"]
        if mail_config.is_configured:
            transport_options.append("Gmail thật qua SMTP STARTTLS")
        transport = st.radio("Kênh vận chuyển", transport_options)

        if mail_config.is_configured and st.button("Kiểm tra kết nối Gmail SMTP", use_container_width=True):
            try:
                with st.spinner("Đang bắt tay TLS và xác thực App Password..."):
                    verify_smtp_connection(mail_config)
                st.success(f"Kết nối thành công với {mail_config.gmail_user}")
            except Exception:
                st.error("Không thể kết nối Gmail. Kiểm tra `.env`, App Password và kết nối mạng.")

        if st.button("Ký, mã hóa và gửi", type="primary", use_container_width=True):
            if not sender_email.strip() or not recipient_email.strip() or not subject.strip() or not body.strip():
                st.error("Email, tiêu đề và nội dung không được để trống.")
            else:
                try:
                    sender_private = get_private_key(
                        st.session_state.alice_private,
                        custom_sender_private,
                        custom_sender_password,
                    )
                    recipient_public = get_public_key(
                        st.session_state.bob_public, custom_recipient_public
                    )
                    message = {
                        "subject": subject.strip(),
                        "body": body.strip(),
                        "attachment": attachment_to_payload(attachment),
                    }

                    progress = st.progress(0, text="SHA-256 + RSA-PSS: đang ký thông điệp")
                    time.sleep(0.1)
                    progress.progress(35, text="AES-256-GCM: đang mã hóa nội dung")
                    envelope = encrypt_secure_payload(
                        message,
                        sender_email.strip(),
                        recipient_email.strip(),
                        sender_private,
                        recipient_public,
                    )
                    progress.progress(70, text="RSA-OAEP: đã bọc khóa phiên")
                    payload_json = envelope_to_json(envelope)
                    time.sleep(0.1)

                    if transport.startswith("Gmail"):
                        send_secure_email(
                            recipient_email.strip(), subject.strip(), payload_json, mail_config
                        )
                        source = "Gmail SMTP"
                    else:
                        source = "Hộp thư cục bộ"

                    st.session_state.mailbox.insert(
                        0,
                        {
                            "id": f"local-{time.time_ns()}",
                            "subject": subject.strip(),
                            "from": sender_email.strip(),
                            "date": envelope["timestamp"],
                            "source": source,
                            "envelope": envelope,
                        },
                    )
                    st.session_state.last_payload = payload_json
                    progress.progress(100, text=f"Hoàn tất qua {source}")
                    st.success(f"Payload đã được gửi tới {recipient_email.strip()} qua {source}.")
                except (ValueError, TypeError) as exc:
                    st.error(f"Không thể tạo payload: {exc}")
                except Exception:
                    st.error("Gửi Gmail thất bại. Nội dung bí mật không được hiển thị hoặc ghi log.")

    if st.session_state.last_payload:
        st.download_button(
            "Tải secure-envelope.json",
            st.session_state.last_payload,
            "secure-envelope.json",
            "application/json",
        )
        with st.expander("Xem payload mã hóa"):
            st.code(st.session_state.last_payload, language="json")


with tab_inbox:
    st.markdown(
        '<div class="section-intro"><h2>Bob kiểm chứng và giải mã</h2>'
        '<p>Chọn payload cần xử lý, dùng khóa riêng của Bob để mở khóa phiên và dùng khóa công khai của Alice để xác minh nguồn gửi.</p></div>',
        unsafe_allow_html=True,
    )

    action_left, action_right = st.columns(2)
    with action_left:
        if st.button(
            "Tải thư bảo mật từ Gmail",
            disabled=not mail_config.is_configured,
            use_container_width=True,
        ):
            try:
                with st.spinner("Đang kết nối IMAP SSL và tải payload..."):
                    fetched = fetch_secure_emails(mail_config)
                for item in fetched:
                    item["source"] = "Gmail IMAP"
                st.session_state.gmail_messages = fetched
                st.success(f"Đã tải {len(fetched)} thư bảo mật từ Gmail.")
            except Exception:
                st.error("Không thể tải Gmail. Kiểm tra `.env`, App Password và IMAP.")
    with action_right:
        uploaded_envelope = st.file_uploader(
            "Hoặc tải secure-envelope.json", type=["json"], key="received_envelope"
        )

    messages = st.session_state.mailbox + st.session_state.gmail_messages
    if uploaded_envelope is not None:
        try:
            uploaded_data = envelope_from_json(uploaded_envelope.getvalue().decode("utf-8"))
            messages = [
                {
                    "id": "uploaded",
                    "subject": uploaded_data.get("sender", "Uploaded payload"),
                    "from": uploaded_data.get("sender", "Unknown"),
                    "date": uploaded_data.get("timestamp", ""),
                    "source": "JSON upload",
                    "envelope": uploaded_data,
                }
            ] + messages
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            st.error(f"JSON không hợp lệ: {exc}")

    if not messages:
        st.markdown(
            '<div class="empty-state"><h3>Chưa có payload để thẩm định</h3>'
            '<p>Hãy hoàn tất bước “Mã hóa & gửi thư”, tải thư từ Gmail hoặc nhập một tệp <code>secure-envelope.json</code>.</p></div>',
            unsafe_allow_html=True,
        )
    else:
        labels = [
            f"{index + 1:02d} · {item['source']} · {item['subject']} · {item['from']}"
            for index, item in enumerate(messages)
        ]
        selected_label = st.selectbox("Chọn thư cần xử lý", labels)
        selected = messages[labels.index(selected_label)]
        if st.session_state.selected_message_id != selected["id"]:
            st.session_state.selected_message_id = selected["id"]
            st.session_state.decryption_result = None
        envelope = selected["envelope"]

        detail_col, verify_col = st.columns([1.25, 0.9], gap="large", vertical_alignment="top")
        with detail_col:
            st.markdown('<p class="panel-label">Thông tin phong bì</p>', unsafe_allow_html=True)
            meta_left, meta_right = st.columns(2)
            meta_left.metric("Người gửi", envelope.get("sender", "Unknown"))
            meta_right.metric(
                "Mã hóa đối xứng",
                envelope.get("crypto_metadata", {}).get("sym_algo", "Unknown"),
            )

            with st.expander("Sử dụng khóa PEM tùy chỉnh", expanded=False):
                custom_recipient_private = st.file_uploader(
                    "Private Key người nhận", type=["pem"], key="custom_recipient_private"
                )
                custom_recipient_password = st.text_input(
                    "Mật khẩu Private Key người nhận",
                    type="password",
                    key="custom_recipient_password",
                )
                custom_sender_public = st.file_uploader(
                    "Public Key người gửi", type=["pem"], key="custom_sender_public"
                )

            with st.expander("Kiểm tra JSON payload gốc", expanded=False):
                st.code(envelope_to_json(envelope), language="json")

        with verify_col:
            st.markdown('<p class="panel-label">Thao tác thẩm định</p>', unsafe_allow_html=True)
            if st.button("Giải mã và thẩm định", type="primary", use_container_width=True):
                try:
                    recipient_private = get_private_key(
                        st.session_state.bob_private,
                        custom_recipient_private,
                        custom_recipient_password,
                    )
                    sender_public = get_public_key(
                        st.session_state.alice_public, custom_sender_public
                    )
                    st.session_state.decryption_result = decrypt_secure_payload(
                        envelope, recipient_private, sender_public
                    )
                except InvalidTag:
                    st.session_state.decryption_result = "tampered"
                except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                    st.error(f"Không thể giải mã: {exc}")

            if st.button("Mô phỏng sửa 1 bit (MITM)", use_container_width=True):
                try:
                    recipient_private = get_private_key(
                        st.session_state.bob_private,
                        custom_recipient_private,
                        custom_recipient_password,
                    )
                    sender_public = get_public_key(
                        st.session_state.alice_public, custom_sender_public
                    )
                    tampered = copy.deepcopy(envelope)
                    ciphertext = bytearray(base64.b64decode(tampered["payload"]["ciphertext"]))
                    ciphertext[len(ciphertext) // 2] ^= 1
                    tampered["payload"]["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
                    decrypt_secure_payload(tampered, recipient_private, sender_public)
                    st.error("Cảnh báo: payload bị sửa nhưng không bị phát hiện.")
                except InvalidTag:
                    st.markdown(
                        '<div class="bad-banner"><b>AES-GCM ĐÃ CHẶN CUỘC TẤN CÔNG</b><br>Bản mã bị thay đổi 1 bit nên Auth Tag không còn hợp lệ. Toàn bộ bản rõ đã bị từ chối.</div>',
                        unsafe_allow_html=True,
                    )
                except (ValueError, KeyError, TypeError) as exc:
                    st.error(f"Không thể chạy mô phỏng: {exc}")

        result = st.session_state.decryption_result
        if result == "tampered":
            st.markdown(
                '<div class="bad-banner"><b>CẢNH BÁO BẢO MẬT</b><br>Dữ liệu đã bị thay đổi hoặc thẻ AES-GCM không hợp lệ. Không hiển thị bản rõ.</div>',
                unsafe_allow_html=True,
            )
        elif result is not None:
            if result.signature_valid:
                st.markdown(
                    '<div class="ok-banner"><b>CHỮ KÝ SỐ HỢP LỆ</b><br>Danh tính người gửi được xác thực và nội dung toàn vẹn.</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    '<div class="bad-banner"><b>CHỮ KÝ KHÔNG HỢP LỆ</b><br>Không tin cậy nội dung đã giải mã.</div>',
                    unsafe_allow_html=True,
                )

            st.subheader(result.message.get("subject", "Không có tiêu đề"))
            st.text_area(
                "Nội dung đã giải mã",
                result.message.get("body", ""),
                height=180,
                disabled=True,
            )
            st.caption(f"Từ {result.sender} · Đến {result.recipient} · {result.timestamp}")
            decrypted_attachment = result.message.get("attachment")
            if decrypted_attachment:
                st.download_button(
                    f"Tải {decrypted_attachment['name']}",
                    base64.b64decode(decrypted_attachment["data"]),
                    decrypted_attachment["name"],
                    decrypted_attachment.get("mime_type", "application/octet-stream"),
                )
