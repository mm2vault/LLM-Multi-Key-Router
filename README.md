# LLM Multi-Key Router

Self-hosted multi-provider LLM gateway with encrypted API-key storage, key rotation, cooldowns, retry/failover, usage statistics, and a React dashboard.

## Providers
- OpenAI
- Anthropic
- Google Gemini
- DeepSeek
- OpenRouter

There is **no hard-coded number of keys per provider**. Add as many authorized keys as your database, hosting resources, and provider account limits can support.

## Current capabilities
- Add, list (masked), enable/disable, and delete provider keys
- Register custom OpenAI-compatible providers by display name and HTTPS base URL, then attach one or more API keys
- Persist provider definitions, labels, encrypted keys, cooldowns, and usage records in SQLite
- Track input/output/total tokens when the upstream provider returns usage metadata
- Capture common provider rate-limit response headers per key when supplied
- Encrypt secrets at rest with Fernet
- Select the least-recently-used eligible key
- Retry other keys when a key is rate-limited, unavailable, or fails authentication
- Cooldown handling and request statistics
- OpenAI-shaped non-streaming `POST /v1/chat/completions`
- Dark purple React admin dashboard
- Docker Compose deployment

## Current capabilities
- Username/password registration and sign-in with server-side sessions
- Admin account provisioned from private `ADMIN_USERNAME` and `ADMIN_PASSWORD` environment variables
- Admin-only user listing, disable/enable, role changes, account deletion, and request/token quota settings
- User-specific saved conversations; administrators can inspect all conversations
- Per-user usage tracking plus administrator-wide usage and recent request inspection
- Admin management of provider definitions and API keys, including add/edit/disable/delete
- Passwords are stored as PBKDF2 hashes; provider API secrets remain Fernet-encrypted
- Admin UI and member chat UI share one authenticated application

## Important limitations
- Streaming/SSE is not implemented yet. Requests with `stream: true` are not streamed.
- Token totals are based on upstream usage metadata. Provider quota/balance endpoints are not queried; rate-limit values appear only when the provider returns recognized response headers.
- Custom providers currently need an OpenAI-compatible `/chat/completions` API. Anthropic/Gemini-specific adapters are available only for built-in providers.
- Per-user quotas are lifetime counters at this stage, not daily/monthly billing periods. A value of `0` means unlimited.
- Public registration is currently enabled. Add CAPTCHA/email verification, IP-based rate limiting, abuse detection, and operational monitoring before opening signup widely.
- The app has no payment/billing system. Never treat token counters as provider invoices.
- Cross-provider fallback is a basic attempt sequence; model identifiers and request parameters are not universally compatible between providers. Specify the provider and a model valid for that provider.
- SQLite is suitable for a single-instance deployment. Use PostgreSQL and coordinated key leasing before scaling horizontally.

## Billing and fair-use
This router does not create free model capacity or bypass upstream rate limits. All usage is charged to the upstream API accounts whose keys you configure. Key rotation can distribute requests and recover from a limited key, but does not remove provider quotas, billing, or terms. Only use keys and accounts you are authorized to operate. To let many people chat, add per-user limits and abuse protection before making the service public.

## Setup

1. Copy `.env.example` to `.env`.
2. Generate a Fernet key:

   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

3. Put that value in `MASTER_ENCRYPTION_KEY`. Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` privately in your host environment. The password must be at least 12 characters. Never commit `.env` or real credentials. The admin account is created automatically at startup from these variables.
4. Start:

   ```bash
   docker compose up --build
   ```

5. Open http://localhost:5173 and sign in using the private admin username and password configured in your environment. New visitors can register member accounts.

Health endpoint: http://localhost:8000/health

## API

Register a member account:

```http
POST /auth/register
Content-Type: application/json

{"username":"member01","password":"a-long-unique-password"}
```

Sign in (the configured admin account uses the same endpoint):

```http
POST /auth/login
Content-Type: application/json

{"username":"your-admin-username","password":"your-private-admin-password"}
```

The response returns a bearer `token`. Use it for authenticated requests. Admin-only routes require an administrator session.

Add a custom OpenAI-compatible provider (admin only):

```http
POST /admin/providers
Authorization: Bearer <SESSION_TOKEN>
Content-Type: application/json

{"name":"My Gateway","base_url":"https://api.example.com/v1"}
```

The response includes a provider slug. Add a key for that slug:

```http
POST /admin/keys
Authorization: Bearer <SESSION_TOKEN>
Content-Type: application/json

{"provider":"my-gateway","label":"My Gateway key 01","api_key":"<YOUR_PROVIDER_KEY>"}
```

Set a user's quotas (0 means unlimited lifetime usage):

```http
PATCH /admin/users/<USER_ID>
Authorization: Bearer <ADMIN_SESSION_TOKEN>
Content-Type: application/json

{"quota_requests":1000,"quota_tokens":250000}
```

Chat:

```http
POST /v1/chat/completions
Authorization: Bearer <SESSION_TOKEN>
Content-Type: application/json

{
  "provider": "openai",
  "model": "gpt-4o-mini",
  "messages": [{"role":"user","content":"Hello"}]
}
```

Provider usage totals are recorded from provider response metadata. The model must exist for the chosen provider.

## Security checklist
- Keep `.env`, provider keys, admin password, and encryption master key out of Git.
- Back up `MASTER_ENCRYPTION_KEY`; without it stored keys cannot be decrypted.
- Use HTTPS and restrict CORS in production.
- Use a unique, strong admin password and rotate it through the host environment. The admin account is provisioned from `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
- Public registration is enabled in this starter. Add CAPTCHA/email verification, rate limiting, abuse detection, and backups before public launch.
- Quotas are lifetime totals in this version; 0 means unlimited. Provider account quotas and billing still apply.
- Do not promise unlimited model usage: upstream provider quotas and billing always apply.

## Local development

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_URL=http://localhost:8000` if the backend is hosted elsewhere.
