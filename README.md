# TokenAudit

A real-time JSON Web Token (JWT) decoder, claim lifecycle auditor, and HMAC signature verifier built with Python and Streamlit.

## Capabilities
- **Base64URL Decoding:** Parses real JWT headers and payloads into structured JSON.
- **Live Claim Lifecycle Checks:** Evaluates `exp` (expiration), `iat` (issued at), and `nbf` (not before) against live UTC time.
- **Cryptographic Signature Verification:** Verifies `HS256`, `HS384`, and `HS512` signatures using constant-time HMAC comparison (`hmac.compare_digest`), detecting payload tampering or secret mismatches.
- **Security Misconfiguration Audit:** Flags `alg: none` bypass risks, missing `exp` claims, and sensitive keys stored in unencrypted JWT payloads.
- **Live Token Generator:** Mints valid or expired HS256 tokens for interactive testing.