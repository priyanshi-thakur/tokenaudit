import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
import streamlit as st

st.set_page_config(page_title="TokenAudit | JWT Inspector & Verifier", layout="centered")

st.markdown("""
<style>
    .block-container { padding-top: 2.5rem; padding-bottom: 2.5rem; max-width: 760px; }
    h1, h2, h3 { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 600; color: #18221E; }
    p, label, .stMarkdown { font-family: "Segoe UI", system-ui, sans-serif; color: #18221E; }
    .stButton > button {
        background-color: #26463B;
        color: #FFFFFF;
        border: 1px solid #26463B;
        border-radius: 4px;
        padding: 0.45rem 1.2rem;
        font-weight: 500;
    }
    .stButton > button:hover {
        background-color: #1A3129;
        border-color: #1A3129;
        color: #FFFFFF;
    }
    .report-box {
        border-left: 4px solid #26463B;
        border-top: 1px solid #D8E2DC;
        border-right: 1px solid #D8E2DC;
        border-bottom: 1px solid #D8E2DC;
        background-color: #FFFFFF;
        padding: 1.2rem;
        border-radius: 4px;
        margin-top: 1rem;
        margin-bottom: 1rem;
    }
    .tag {
        display: inline-block;
        padding: 2px 9px;
        font-size: 0.78rem;
        font-weight: 600;
        background-color: #E5EFEA;
        color: #26463B;
        border: 1px solid #B5C9BF;
        border-radius: 3px;
        text-transform: uppercase;
    }
</style>
""", unsafe_allow_html=True)


def b64url_decode(segment: str) -> bytes:
    padding = "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def mint_hs256_jwt(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


def verify_hs_signature(signing_input: bytes, signature_b64: str, secret: str, alg: str):
    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in hash_map:
        return None
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hash_map[alg]).digest()
    actual_sig = b64url_decode(signature_b64)
    return hmac.compare_digest(expected_sig, actual_sig)


def format_utc(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError, OSError):
        return "Invalid timestamp"


def audit_jwt(token: str, secret: str = ""):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT: Expected exactly 3 dot-separated segments (header.payload.signature).")

    header_raw, payload_raw, sig_raw = parts
    header = json.loads(b64url_decode(header_raw).decode("utf-8"))
    payload = json.loads(b64url_decode(payload_raw).decode("utf-8"))

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("Decoded header or payload is not a valid JSON object.")

    now = time.time()
    findings = []
    status = "Valid Structure"

    alg = str(header.get("alg", "")).strip()
    if not alg:
        findings.append(("Critical", "Missing 'alg' claim in header."))
        status = "Security Issue"
    elif alg.lower() == "none":
        findings.append(("Critical", "Unsigned token ('alg': 'none') — vulnerable to signature bypass."))
        status = "Security Issue"
    elif alg in {"HS256", "HS384", "HS512"}:
        findings.append(("Info", f"Symmetric HMAC algorithm ({alg}). Requires strong secret management."))
    elif alg in {"RS256", "ES256", "PS256"}:
        findings.append(("Pass", f"Asymmetric signature algorithm ({alg}) detected."))
    else:
        findings.append(("Warning", f"Uncommon signing algorithm ({alg}). Verify server allowlist."))

    if "exp" not in payload:
        findings.append(("High", "Missing expiration ('exp') claim — token never expires."))
        if status == "Valid Structure":
            status = "Security Issue"
    else:
        exp_val = payload["exp"]
        if isinstance(exp_val, (int, float)):
            if exp_val < now:
                delta_min = int((now - exp_val) // 60)
                findings.append(("Expired", f"Token expired {delta_min} minute(s) ago ({format_utc(exp_val)})."))
                status = "Expired"
            else:
                rem_min = int((exp_val - now) // 60)
                findings.append(("Pass", f"Token is active; expires in {rem_min} minute(s) ({format_utc(exp_val)})."))
        else:
            findings.append(("High", "Non-numeric 'exp' claim detected."))

    if "nbf" in payload and isinstance(payload["nbf"], (int, float)) and payload["nbf"] > now:
        findings.append(("Warning", f"Token is not yet active ('nbf': {format_utc(payload['nbf'])})."))

    if "iat" in payload and isinstance(payload["iat"], (int, float)):
        findings.append(("Info", f"Issued at ('iat'): {format_utc(payload['iat'])}."))

    sensitive_keys = {"password", "secret", "ssn", "pin", "private_key", "api_key"}
    exposed = [k for k in payload.keys() if k.lower() in sensitive_keys]
    if exposed:
        findings.append(("High", f"Sensitive field names in unencrypted payload: {', '.join(exposed)}."))

    sig_result = "Not verified (enter HMAC secret to verify signature)"
    if not sig_raw:
        sig_result = "Empty signature segment"
    elif secret:
        if alg in {"HS256", "HS384", "HS512"}:
            signing_input = f"{header_raw}.{payload_raw}".encode("utf-8")
            is_valid = verify_hs_signature(signing_input, sig_raw, secret, alg)
            sig_result = "Verified (HMAC signature matches)" if is_valid else "Invalid Signature (Secret mismatch or tampered payload)"
            if not is_valid:
                status = "Invalid Signature"
        else:
            sig_result = f"HMAC verification skipped (token uses {alg}, not HS256/384/512)"

    return header, payload, status, sig_result, findings


if "sample_jwt" not in st.session_state:
    now_ts = int(time.time())
    st.session_state["sample_jwt"] = mint_hs256_jwt(
        {
            "sub": "user_8492",
            "role": "analyst",
            "iss": "auth.internal.local",
            "iat": now_ts - 300,
            "exp": now_ts + 1800,
        },
        "super-secret-signing-key",
    )

st.title("TokenAudit")
st.caption("Real-time JSON Web Token (JWT) decoding, claim lifecycle auditing, and HMAC signature verification.")

tab_inspect, tab_mint = st.tabs(["Inspect & Verify JWT", "Generate Test JWT"])

with tab_inspect:
    jwt_input = st.text_area("Encoded JWT (header.payload.signature)", value=st.session_state["sample_jwt"], height=120)
    secret_input = st.text_input("HMAC Secret Key (optional, for HS256/384/512 verification)", value="super-secret-signing-key", type="password")

    if st.button("Audit Token"):
        if not jwt_input.strip():
            st.warning("Paste a JWT to inspect.")
        else:
            try:
                header, payload, status, sig_result, findings = audit_jwt(jwt_input, secret_input)
                st.markdown(f"""
                <div class="report-box">
                    <span class="tag">{status}</span>
                    <h3 style="margin-top: 0.65rem; margin-bottom: 0.25rem;">Algorithm: {header.get('alg', 'Unknown')}</h3>
                    <p style="color: #3D4B45; font-size: 0.9rem; margin-bottom: 0;">Signature Check: <strong>{sig_result}</strong></p>
                </div>
                """, unsafe_allow_html=True)

                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("Decoded Header")
                    st.json(header)
                with col2:
                    st.subheader("Decoded Payload")
                    st.json(payload)

                st.subheader("Security & Claim Audit")
                for level, msg in findings:
                    st.write(f"- **[{level}]** {msg}")
            except Exception as exc:
                st.error(f"Token parsing failed: {exc}")

with tab_mint:
    st.write("Mint a real signed HS256 JWT with live UTC timestamps to test tampering or expiry detection.")
    sub_val = st.text_input("Subject ('sub')", value="priyanshi_sec")
    role_val = st.text_input("Role claim ('role')", value="admin")
    ttl_min = st.number_input("Expiration offset in minutes (use negative value to mint an expired token)", min_value=-120, max_value=1440, value=30)
    mint_secret = st.text_input("Signing Secret", value="super-secret-signing-key")

    if st.button("Generate JWT"):
        now_ts = int(time.time())
        new_token = mint_hs256_jwt(
            {
                "sub": sub_val,
                "role": role_val,
                "iat": now_ts,
                "exp": now_ts + int(ttl_min) * 60,
            },
            mint_secret,
        )
        st.session_state["sample_jwt"] = new_token
        st.code(new_token, language="text")
        st.caption("Copied into the 'Inspect & Verify JWT' tab input—switch tabs and click Audit Token to test it.")
