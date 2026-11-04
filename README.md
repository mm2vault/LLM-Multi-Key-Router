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

## Important limitations (current starter release)
- Streaming/SSE is not implemented yet. Requests with `stream: true` are not streamed.
- Token totals are based on upstream usage metadata. Provider quota/balance endpoints are not queried; rate-limit values appear only when the provider returns recognized response headers.
- Custom providers currently need an OpenAI-compatible `/chat/completions` API. Anthropic/Gemini-specific adapters are available only for the built-in providers.
- The dashboard is an **admin key-management console**, not yet a public multi-user chat service. Do not expose it to the public internet as-is.
- User registration, individual API tokens, per-user quotas, abuse controls, billing, and public signup are planned next.
- Cross-provider fallback is a basic attempt sequence; model identifiers and request parameters are not universally compatible between providers. Specify the provider and a model valid for that provider for reliable results.
- SQLite is suitable for a single-instance starter deployment. Use PostgreSQL and coordinated key leasing before scaling horizontally.

## Billing and fair-use
This router does not create free model capacity or bypass upstream rate limits. All usage is charged to the upstream API accounts whose keys you configure. Key rotation can distribute requests and recover from a limited key, but does not remove provider quotas, billing, or terms. Only use keys and accounts you are authorized to operate. To let many people chat, add per-user limits and abuse protection before making the service public.

## Setup

1. Copy `.env.example` to `.env`.
2. Generate a Fernet key:

   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

3. Put that value in `MASTER_ENCRYPTION_KEY`. Set `ADMIN_API_KEY` to a random secret of at least 32 characters. Never commit `.env`.
4. Start:

   ```bash
   docker compose up --build
   ```

5. Open http://localhost:5173 and unlock the dashboard with `ADMIN_API_KEY`.

Health endpoint: http://localhost:8000/health

## API

Add a custom OpenAI-compatible provider (admin only):

```http
POST /admin/providers
X-Admin-Key: <ADMIN_API_KEY>
Content-Type: application/json

{"name":"My Gateway","base_url":"https://api.example.com/v1"}
```

The response includes a provider slug. Add a key for that slug using the endpoint below:

```http
POST /admin/keys
X-Admin-Key: <ADMIN_API_KEY>
Content-Type: application/json

{"provider":"my-gateway","label":"My Gateway key 01","api_key":"<YOUR_PROVIDER_KEY>"}
```

Add a built-in provider key (admin only):

```http
POST /admin/keys
X-Admin-Key: <ADMIN_API_KEY>
Content-Type: application/json

{"provider":"openai","label":"Primary OpenAI","api_key":"<YOUR_PROVIDER_KEY>"}
```

Chat:

```http
POST /v1/chat/completions
Content-Type: application/json

{
  "provider": "openai",
  "model": "gpt-4o-mini",
  "messages": [{"role":"user","content":"Hello"}]
}
```

Supported provider values: `openai`, `anthropic`, `gemini`, `deepseek`, `openrouter`. The model must exist for the chosen provider.

## Security checklist
- Keep `.env`, provider keys, and the encryption master key out of Git.
- Back up `MASTER_ENCRYPTION_KEY`; without it stored keys cannot be decrypted.
- Use HTTPS and restrict CORS in production.
- Keep admin endpoints private. The admin secret is a bootstrap protection, not a complete multi-user identity system.
- Before public launch, implement user authentication, per-user API tokens, rate limits, spending caps, abuse protection, and audit controls.
- Do not promise unlimited usage: upstream provider quotas and billing always apply.

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
