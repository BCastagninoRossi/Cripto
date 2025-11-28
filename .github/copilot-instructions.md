# Copilot Instructions

## Architecture & Data Flow
- Single FastAPI app defined in `app.py`; all routes share in-memory stores (`users`, `sessions`, `otp_codes`, `password_reset_sessions`, `email_verifications`, `audit_logs`).
- Helper utilities (`normalize_email`, `email_blind_index`, `find_user_by_username_or_email`, `log_event`) must be reused to keep lookups and telemetry consistent when adding logic.
- Security-sensitive flows: register → magic-link verify (`/verify-email`), password login → OTP verify (`/verify-otp`), password reset request → code verify → reset complete. Don't bypass intermediate states; each dict entry tracks expiry/usage.
- Sessions are cookie-based (`session_id`) with TTL defined by constants (`SESSION_TTL_SECONDS`, etc.); extend flows by calling `create_session` and `get_current_user` instead of crafting cookies manually.
- All sensitive strings are hashed: Argon2 for passwords, bcrypt for OTP/reset codes, `itsdangerous.URLSafeTimedSerializer` for email tokens. Maintain the same primitives to stay compatible with stored hashes.

## Developer Workflow
- Run locally with `uvicorn app:app --reload`; state clears on each restart because storage is in-memory.
- Required packages: `fastapi`, `uvicorn`, `itsdangerous`, `argon2-cffi`, `bcrypt`. Use a virtualenv (`venv/` already present) and install via `pip install -r requirements.txt` once such a file is added, or install the listed deps directly.
- Debug tokens/codes are printed to stdout with `[DEBUG] ...`; watch the terminal when testing email verification or OTP flows.
- No automated tests yet; manual verification is done via HTTP clients (curl, Thunder Client, etc.). Maintain predictable JSON responses to simplify manual flows.

## Conventions & Patterns
- User identifiers are case-insensitive and emails are normalized before hashing; always normalize before comparisons to avoid duplicates.
- Error responses intentionally stay generic ("Credenciales inválidas") to avoid account enumeration. Follow this pattern for new auth-related endpoints.
- Every significant state change should call `log_event` with a meaningful `event_type`; downstream tooling expects audit trails in `audit_logs`.
- OTP/password-reset records include `attempts_count` limits; if you add new retry logic, increment the counter and mark `record["used"]` when invalidating.
- New authenticated endpoints should use `Depends(get_current_user)` and avoid exposing secrets (mirror `/me`, which strips `password_hash`).
- Keep cookie settings aligned with the existing `response.set_cookie` call (httponly, strict samesite); mention in comments if development-only security tradeoffs are required.

## Integration Notes
- Email verification tokens rely on `EMAIL_TOKEN_SALT` and `serializer`; any additional token types should use dedicated salts/TTLs to prevent replay.
- Rate-limiting is currently handled via `failed_login_attempts` and `locked_until`; reuse the same structure for any new brute-force protections.
- Future persistence layers should mirror the dict schema shown in `users`/`sessions`; structure comments or dataclasses can help when migrating.
