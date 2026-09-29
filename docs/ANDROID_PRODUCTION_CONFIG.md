# FinGuard Security — Android Production Configuration Guide

## 1. Environment Segmentation

| Setting | DEVELOPMENT | TEST | STAGING | PRODUCTION |
|---|---|---|---|---|
| `gatewayBaseUrl` | `http://10.0.2.2:8080` (Emulator) | Mock Server URL / Localhost | `https://staging-api.finguard.security` | **NOT CONFIGURED** (Placeholder: `https://gateway.finguard.internal`) |
| `networkSecurityConfig` | Cleartext permitted for `10.0.2.2` | Test mock anchors | System CA anchors only | System CA anchors only (`cleartextTrafficPermitted=false`) |
| Certificate Validation | System CA | Robolectric default | Trusted System Roots | Strict System Trust Anchors |
| Local Deterministic Fallback | Active | Active | Active | Active (100% resilient) |
| Client Rate Limiter | 100 permits / min | Bypassed / Unlimited | 10 permits / min | 10 permits / min |
| Network Timeouts | 10s connect / read | Instantaneous (Mock) | 10s connect / read | 10s connect / read / write |
| Logcat Verbosity | Debug | Debug / Info | Warnings / Errors Only | Sanitize all logs via `SecureLogger` |

---

## 2. Production Domain Status

- **Production Domain Status:** **NOT CONFIGURED**.
- **Current Android Gateway Setting:** `https://gateway.finguard.internal` (Non-routable placeholder domain).
- **Required Action Before Live Store Launch:**
  1. Complete cloud deployment of the `backend/` microservice.
  2. Point your official DNS record to the deployed load balancer (e.g., `https://gateway.finguard.security`).
  3. Update `gatewayBaseUrl` in `GeminiThreatAnalyzer.kt`:
     ```kotlin
     var gatewayBaseUrl: String = "https://your-live-production-domain.com"
     ```
  4. Update `res/xml/network_security_config.xml`:
     ```xml
     <domain-config cleartextTrafficPermitted="false">
         <domain includeSubdomains="true">your-live-production-domain.com</domain>
         <trust-anchors>
             <certificates src="system" />
         </trust-anchors>
     </domain-config>
     ```

---

## 3. Client Security Controls Verification

1. **Strict HTTPS & Zero Cleartext:**
   - `android:usesCleartextTraffic="false"` declared in `AndroidManifest.xml`.
   - `network_security_config.xml` strictly forbids cleartext traffic across all base and domain configurations.
2. **Zero In-APK Secrets:**
   - No Gemini API key, backend master secret, or pre-shared authorization token resides in the APK or DEX files.
   - Authentication relies solely on short-lived (15-min) server-issued session tokens acquired over HTTPS.
3. **Local PII Redaction Before Egress:**
   - `PiiScrubber.scrub()` redacts all 16-digit cards, CVVs, OTPs, Aadhaar numbers, and VPAs before any packet leaves the phone.
4. **Autonomous Local Fallback:**
   - In the event of gateway unavailability, unconfigured production domain, DNS failure, 429 rate limiting, or network timeout, the on-device expert rule classifier runs autonomously to protect the user with zero downtime.
