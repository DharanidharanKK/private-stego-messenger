import base64
import os
import re
import struct
import tempfile
from datetime import datetime

import streamlit as st

MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
DEFAULT_PASSWORD = ""
PBKDF2_ITERATIONS = 390000
TRAILER_MAGIC = b"PRIVSTEG1"
PAYLOAD_MAGIC_V2 = b"PRIVMSG2"
LEGACY_PAYLOAD_MAGIC_V1 = b"PRIVMSG1"
SALT_SIZE = 16
LENGTH_SIZE = 8
CHUNK_SIZE = 4 * 1024 * 1024
LEGACY_FALLBACK_LIMIT = 200 * 1024 * 1024
SUPPORTED_EXTENSIONS = [
    "png", "jpg", "jpeg", "bmp", "webp", "gif",
    "wav", "mp3", "flac", "ogg", "m4a", "aac",
    "mp4", "mov", "mkv", "avi", "webm",
]

ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_MEMORY_COST_KIB = 262144  # 256 MB
ARGON2_HEADER_FORMAT = ">BHI"
ARGON2_HEADER_SIZE = struct.calcsize(ARGON2_HEADER_FORMAT)
AES_KEY_BYTES = 32
AES_NONCE_SIZE = 12

PASSWORD_MIN_LENGTH = 14
WEAK_PASSWORDS = {
    "password",
    "password123",
    "12345678",
    "123456789",
    "qwerty",
    "iloveyou",
    "admin",
    "letmein",
    "welcome",
    "jkb5955",
}

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except Exception as exc:  # pragma: no cover
    CRYPTO_IMPORT_ERROR = str(exc)
    CRYPTO_READY = False
else:
    CRYPTO_IMPORT_ERROR = ""
    CRYPTO_READY = True


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

        :root {
            --bg-1: #091017;
            --bg-2: #13212d;
            --panel: rgba(16, 27, 37, 0.82);
            --line: #2b4157;
            --accent: #53e1a6;
            --accent-2: #9be9cc;
            --text: #e6f4f1;
            --muted: #a7c2c9;
            --danger: #ff6b6b;
        }

        .stApp {
            background: radial-gradient(circle at 15% 10%, #1a2f41 0%, transparent 45%),
                        radial-gradient(circle at 85% 20%, #1f4037 0%, transparent 40%),
                        linear-gradient(140deg, var(--bg-1), var(--bg-2));
            color: var(--text);
            font-family: 'Space Grotesk', sans-serif;
        }

        .block-container {
            max-width: 960px;
            padding-top: 1.8rem;
            padding-bottom: 2rem;
        }

        h1, h2, h3 {
            color: var(--text);
            letter-spacing: 0.2px;
        }

        p, label, div {
            color: var(--text);
        }

        .stTextInput input, .stTextArea textarea {
            background: rgba(6, 12, 18, 0.72) !important;
            border: 1px solid var(--line) !important;
            color: var(--text) !important;
            font-family: 'JetBrains Mono', monospace !important;
            border-radius: 10px !important;
        }

        .stFileUploader {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 0.7rem;
        }

        .stButton button {
            border-radius: 10px;
            border: 1px solid var(--accent);
            background: linear-gradient(135deg, #16384b, #1a4a42);
            color: #f2fff9;
            font-weight: 700;
            letter-spacing: 0.3px;
        }

        .stDownloadButton button {
            border-radius: 10px;
            border: 1px solid var(--accent-2);
            background: linear-gradient(135deg, #174030, #27584f);
            color: #f6fffb;
            font-weight: 700;
        }

        .hint-box {
            border: 1px solid var(--line);
            border-left: 4px solid var(--accent);
            border-radius: 10px;
            background: var(--panel);
            padding: 0.9rem 1rem;
            margin: 0.5rem 0 1rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def cleanup_temp_file(path: str | None) -> None:
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def reset_uploaded_file(uploaded_file) -> None:
    try:
        uploaded_file.seek(0)
    except Exception:
        pass


def validate_password_strength(password: str) -> list[str]:
    issues: list[str] = []

    if len(password) < PASSWORD_MIN_LENGTH:
        issues.append(f"Use at least {PASSWORD_MIN_LENGTH} characters.")

    if not re.search(r"[a-z]", password):
        issues.append("Add at least one lowercase letter.")

    if not re.search(r"[A-Z]", password):
        issues.append("Add at least one uppercase letter.")

    if not re.search(r"\d", password):
        issues.append("Add at least one digit.")

    if not re.search(r"[^A-Za-z0-9]", password):
        issues.append("Add at least one special character.")

    if re.search(r"\s", password):
        issues.append("Do not include spaces.")

    if re.search(r"(.)\1{3,}", password):
        issues.append("Avoid repeating the same character 4+ times in a row.")

    if password.casefold() in WEAK_PASSWORDS:
        issues.append("Choose a less predictable password.")

    return issues


def derive_fernet_key_legacy(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def derive_key_argon2id(
    password: str,
    salt: bytes,
    iterations: int = ARGON2_ITERATIONS,
    lanes: int = ARGON2_LANES,
    memory_cost_kib: int = ARGON2_MEMORY_COST_KIB,
) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=AES_KEY_BYTES,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost_kib,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(secret_message: str, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    header = struct.pack(
        ARGON2_HEADER_FORMAT,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        ARGON2_MEMORY_COST_KIB,
    )
    key = derive_key_argon2id(password=password, salt=salt)
    nonce = os.urandom(AES_NONCE_SIZE)
    aad = PAYLOAD_MAGIC_V2 + header + salt
    ciphertext = AESGCM(key).encrypt(nonce, secret_message.encode("utf-8"), aad)
    return PAYLOAD_MAGIC_V2 + header + salt + nonce + ciphertext


def decrypt_message_v2(payload: bytes, password: str) -> str:
    min_payload = len(PAYLOAD_MAGIC_V2) + ARGON2_HEADER_SIZE + SALT_SIZE + AES_NONCE_SIZE
    if len(payload) < min_payload or not payload.startswith(PAYLOAD_MAGIC_V2):
        raise ValueError("Invalid hidden message format.")

    offset = len(PAYLOAD_MAGIC_V2)
    header = payload[offset: offset + ARGON2_HEADER_SIZE]
    iterations, lanes, memory_cost = struct.unpack(ARGON2_HEADER_FORMAT, header)
    offset += ARGON2_HEADER_SIZE

    salt = payload[offset: offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = payload[offset: offset + AES_NONCE_SIZE]
    offset += AES_NONCE_SIZE

    ciphertext = payload[offset:]
    if not ciphertext:
        raise ValueError("Encrypted payload is empty.")

    key = derive_key_argon2id(
        password=password,
        salt=salt,
        iterations=iterations,
        lanes=lanes,
        memory_cost_kib=memory_cost,
    )
    aad = payload[: len(PAYLOAD_MAGIC_V2) + ARGON2_HEADER_SIZE + SALT_SIZE]
    decrypted = AESGCM(key).decrypt(nonce, ciphertext, aad)
    return decrypted.decode("utf-8")


def decrypt_message_v1_legacy(payload: bytes, password: str) -> str:
    min_payload = len(LEGACY_PAYLOAD_MAGIC_V1) + SALT_SIZE
    if len(payload) < min_payload or not payload.startswith(LEGACY_PAYLOAD_MAGIC_V1):
        raise ValueError("Invalid hidden message format.")

    salt_start = len(LEGACY_PAYLOAD_MAGIC_V1)
    salt_end = salt_start + SALT_SIZE
    salt = payload[salt_start:salt_end]
    token = payload[salt_end:]

    if not token:
        raise ValueError("Encrypted payload is empty.")

    key = derive_fernet_key_legacy(password=password, salt=salt)
    decrypted = Fernet(key).decrypt(token)
    return decrypted.decode("utf-8")


def decrypt_message(payload: bytes, password: str) -> str:
    if payload.startswith(PAYLOAD_MAGIC_V2):
        return decrypt_message_v2(payload, password)
    if payload.startswith(LEGACY_PAYLOAD_MAGIC_V1):
        return decrypt_message_v1_legacy(payload, password)
    raise ValueError("Unsupported encrypted payload version.")


def embed_payload_to_temp_file(uploaded_file, payload: bytes) -> tuple[str, int]:
    extension = os.path.splitext(uploaded_file.name)[1] or ".bin"
    trailer = payload + struct.pack(">Q", len(payload)) + TRAILER_MAGIC
    total_written = 0
    reset_uploaded_file(uploaded_file)

    with tempfile.NamedTemporaryFile(delete=False, suffix=extension) as temp_output:
        while True:
            chunk = uploaded_file.read(CHUNK_SIZE)
            if not chunk:
                break
            temp_output.write(chunk)
            total_written += len(chunk)
        temp_output.write(trailer)
        total_written += len(trailer)
        temp_path = temp_output.name

    reset_uploaded_file(uploaded_file)
    return temp_path, total_written


def extract_payload_legacy(stego_file_bytes: bytes) -> bytes:
    marker_index = stego_file_bytes.rfind(TRAILER_MAGIC)
    if marker_index == -1:
        raise ValueError("No hidden message was found in this file.")

    length_start = marker_index + len(TRAILER_MAGIC)
    length_end = length_start + 4
    if length_end > len(stego_file_bytes):
        raise ValueError("Corrupted hidden payload header.")

    payload_len = int.from_bytes(stego_file_bytes[length_start:length_end], "big")
    payload_start = length_end
    payload_end = payload_start + payload_len

    if payload_len <= 0 or payload_end != len(stego_file_bytes):
        raise ValueError("Hidden payload length mismatch. File may be altered.")

    return stego_file_bytes[payload_start:payload_end]


def extract_payload(uploaded_file) -> bytes:
    footer_size = LENGTH_SIZE + len(TRAILER_MAGIC)
    reset_uploaded_file(uploaded_file)

    try:
        uploaded_file.seek(0, os.SEEK_END)
        total_size = uploaded_file.tell()
    except Exception as exc:
        raise ValueError(f"Could not read received file: {exc}") from exc

    if total_size < footer_size:
        raise ValueError("No hidden message was found in this file.")

    uploaded_file.seek(total_size - footer_size)
    footer = uploaded_file.read(footer_size)

    if footer[-len(TRAILER_MAGIC):] == TRAILER_MAGIC:
        payload_len = struct.unpack(">Q", footer[:LENGTH_SIZE])[0]
        payload_start = total_size - footer_size - payload_len
        if payload_len <= 0 or payload_start < 0:
            raise ValueError("Hidden payload length mismatch. File may be altered.")

        uploaded_file.seek(payload_start)
        payload = uploaded_file.read(payload_len)
        reset_uploaded_file(uploaded_file)
        if len(payload) != payload_len:
            raise ValueError("Could not read the full hidden payload.")
        return payload

    # Backward compatibility for old files created with the earlier trailer format.
    if total_size > LEGACY_FALLBACK_LIMIT:
        raise ValueError("No hidden message was found in this file.")

    reset_uploaded_file(uploaded_file)
    return extract_payload_legacy(uploaded_file.read())


def file_size_ok(uploaded_file) -> tuple[bool, str]:
    if uploaded_file is None:
        return False, "Please import a file first."

    if uploaded_file.size > MAX_FILE_SIZE:
        return (
            False,
            f"File is {format_bytes(uploaded_file.size)}. Maximum allowed size is {format_bytes(MAX_FILE_SIZE)}.",
        )

    return True, ""


def output_filename(input_name: str) -> str:
    base, ext = os.path.splitext(input_name)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base}_private_{stamp}{ext or '.bin'}"


def sender_panel() -> None:
    st.subheader("Sender: Encrypt + Hide Message")
    st.markdown(
        "<div class='hint-box'>Import an image/audio/video file, type your private message, set a password, and generate a private file to send.</div>",
        unsafe_allow_html=True,
    )

    sender_file = st.file_uploader(
        "Import cover file (image/audio/video, max 2 GB)",
        type=SUPPORTED_EXTENSIONS,
        key="sender_file",
    )
    secret_message = st.text_area(
        "Private message",
        height=180,
        placeholder="Type the secret information you want to send...",
        key="sender_message",
    )
    sender_password = st.text_input(
        "Password (set a new one for each message)",
        value=DEFAULT_PASSWORD,
        placeholder="Create a strong password",
        type="password",
        key="sender_password",
    )
    confirm_password = st.text_input(
        "Confirm password",
        value=DEFAULT_PASSWORD,
        placeholder="Re-enter password",
        type="password",
        key="sender_password_confirm",
    )
    st.caption(
        "Password rule: 14+ chars with uppercase, lowercase, digit, and symbol. "
        "Argon2id (256 MB) + AES-256-GCM encryption is used."
    )

    if st.button("Encrypt And Hide", key="encrypt_hide_button"):
        file_ok, file_error = file_size_ok(sender_file)
        if not file_ok:
            st.error(file_error)
            return

        if not secret_message.strip():
            st.error("Private message cannot be empty.")
            return

        if not sender_password:
            st.error("Password is required.")
            return

        password_issues = validate_password_strength(sender_password)
        if password_issues:
            st.error("Password does not meet security requirements.")
            for issue in password_issues:
                st.write(f"- {issue}")
            return

        if sender_password != confirm_password:
            st.error("Password and confirm password do not match.")
            return

        try:
            encrypted_payload = encrypt_message(secret_message.strip(), sender_password)
            output_path, output_size = embed_payload_to_temp_file(sender_file, encrypted_payload)
        except Exception as exc:
            st.error(f"Could not encrypt message: {exc}")
            return

        cleanup_temp_file(st.session_state.get("sender_output_path"))
        st.session_state["sender_output_path"] = output_path
        st.session_state["sender_output_name"] = output_filename(sender_file.name)
        st.session_state["sender_output_mime"] = sender_file.type or "application/octet-stream"
        st.session_state["sender_input_size"] = sender_file.size
        st.session_state["sender_output_size"] = output_size
        st.success("Private file generated. Share this file with the receiver.")

    output_path = st.session_state.get("sender_output_path")
    if output_path and os.path.exists(output_path):
        with open(output_path, "rb") as output_file:
            st.download_button(
                label="Download Private File",
                data=output_file,
                file_name=st.session_state.get("sender_output_name", "private_file.bin"),
                mime=st.session_state.get("sender_output_mime", "application/octet-stream"),
                key="download_private",
            )
        st.caption(
            f"Input size: {format_bytes(st.session_state.get('sender_input_size', 0))} | "
            f"Output size: {format_bytes(st.session_state.get('sender_output_size', 0))}"
        )


def receiver_panel() -> None:
    st.subheader("Receiver: Extract + Decrypt Message")
    st.markdown(
        "<div class='hint-box'>Import the file you received and enter the password shared by the sender to decrypt the hidden message.</div>",
        unsafe_allow_html=True,
    )

    receiver_file = st.file_uploader(
        "Import received file (image/audio/video, max 2 GB)",
        type=SUPPORTED_EXTENSIONS,
        key="receiver_file",
    )
    receiver_password = st.text_input(
        "Password",
        value=DEFAULT_PASSWORD,
        placeholder="Enter sender password",
        type="password",
        key="receiver_password",
    )

    if st.button("Decrypt Message", key="decrypt_button"):
        file_ok, file_error = file_size_ok(receiver_file)
        if not file_ok:
            st.error(file_error)
            return

        if not receiver_password:
            st.error("Password is required.")
            return

        try:
            payload = extract_payload(receiver_file)
            decrypted_message = decrypt_message(payload, receiver_password)
        except (InvalidTag, InvalidToken):
            st.error("Wrong password or file was modified. Message cannot be decrypted.")
            return
        except Exception as exc:
            st.error(f"Could not decrypt message: {exc}")
            return

        st.success("Message decrypted successfully.")
        st.text_area("Decrypted message", value=decrypted_message, height=220, key="receiver_output")


def app() -> None:
    st.set_page_config(page_title="Private Stego Messenger", page_icon="🔐", layout="centered")
    inject_styles()

    st.title("Private Stego Messenger")
    st.write(
        "Hide encrypted private information inside image, audio, or video files and unlock it only with the shared password."
    )
    st.caption("Supports files up to 2 GB. No default password is prefilled.")

    if not CRYPTO_READY:
        st.error(
            "Missing dependency: cryptography. Install with `pip install cryptography` and restart the app."
        )
        st.code(CRYPTO_IMPORT_ERROR)
        st.stop()

    st.info(
        "Important: send the output as a direct file attachment. Social media compression/transcoding can destroy hidden data."
    )

    sender_tab, receiver_tab = st.tabs(["Sender", "Receiver"])

    with sender_tab:
        sender_panel()

    with receiver_tab:
        receiver_panel()


if __name__ == "__main__":
    app()
