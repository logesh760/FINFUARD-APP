# FinGuard AI Gateway — Backend Production Environment Configuration Guide

## 1. Environment Segmentation

| Setting | DEVELOPMENT | TEST | STAGING | PRODUCTION |
|---|---|---|---|---|
| `NODE_ENV` | `development` | `test` | `staging` | `production` |
| `PORT` | `8080` (or `3000`) | Dynamic (`0`) | `8080` | Container port (e.g. `8080`) |
| `GEMINI_API_KEY` | Developer API Key | Mock / Test Stub | Staging Project Key | Production Cloud Secret Key |
| `SESSION_SIGNING_SECRET`| Ephemeral dev secret | Fixed test secret | 32-byte HSM/Secret Key | 64-character Hex Secret from Secret Manager |
| `RATE_LIMIT_MAX_REQUESTS`| `120` | `1000` | `60` | `60` per minute per IP |
| `RATE_LIMIT_WINDOW_MS` | `60000` | `60000` | `60000` | `60000` (1 minute) |
| `REQUEST_TIMEOUT_MS` | `15000` | `5000` | `15000` | `15000` (15 seconds) |
| `ALLOWED_ORIGINS` | `*` or localhost | `*` | `https://staging.finguard.security` | Restrictive / Empty for pure mobile |
| `PUBLIC_GATEWAY_URL` | `http://localhost:8080` | `http://127.0.0.1:<port>` | `https://staging-api.finguard.security` | **NOT CONFIGURED** |

---

## 2. Production Secret Management

- **Zero In-Repo Secrets:** Real production values must never exist in repository code, `.env` files committed to git, or Dockerfiles.
- **Hosting Provider Secret Ingestion:**
  - **Google Cloud Run:** Map secrets directly from Google Cloud Secret Manager into environment variables:
    ```bash
    gcloud run deploy finguard-gateway \
      --image gcr.io/finguard/gateway:latest \
      --set-secrets GEMINI_API_KEY=finguard-gemini-key:latest \
      --set-secrets SESSION_SIGNING_SECRET=finguard-session-secret:latest \
      --set-env-vars NODE_ENV=production,PORT=8080,RATE_LIMIT_MAX_REQUESTS=60
    ```
  - **AWS ECS / Fargate:** Use AWS Secrets Manager / Parameter Store references in Task Definitions (`secrets: [{ name: "GEMINI_API_KEY", valueFrom: "arn:aws:secretsmanager:..." }]`).

---

## 3. Server-Side Controls & Verification

1. **HTTPS Enforcement:** Reverse proxy (Cloudflare / GCP Cloud Load Balancing) terminates TLS 1.3 with automated HSTS (`max-age=31536000; includeSubDomains; preload`). Cleartext HTTP connections must redirect automatically (HTTP 301).
2. **Production Domain Status:** **NOT CONFIGURED**. (Live DNS domain and SSL certificate must be provisioned during infrastructure rollout).
3. **Health Endpoint:** Public endpoint at `GET /health` returns JSON `{"status": "HEALTHY", "service": "FinGuard-AI-Gateway", ...}` for container liveness probes.
4. **API Authentication:** Enforced on all protected routes via short-lived HMAC-SHA256 session tokens issued at `POST /api/v1/auth/session`.
5. **CORS:** Controlled via `ALLOWED_ORIGINS`. Disallowed origins receive no Access-Control headers. Preflight `OPTIONS` requests respond with HTTP 204.
6. **Rate Limiting:** Sliding-window limiter restricts excessive requests per client/IP to 60 req/min. Exceeded quotas return HTTP 429 with `Retry-After`.
7. **Request Payload Limits:** Strict 10 KB request body limit enforced (`express.json({ limit: '10kb' })`). Exceeded requests return HTTP 413.
8. **Request Processing Timeout:** 15,000 ms timeout enforced per request. Stalled AI inferences return HTTP 504 `GATEWAY_TIMEOUT`.
9. **Zero-Leak Logging:** Error handlers and logging interceptors sanitize output, preventing token leakage, PII exposure, and raw stack trace dumps.
