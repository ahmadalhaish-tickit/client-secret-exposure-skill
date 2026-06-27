# client-secret-exposure — Claude Security Audit Skill

A Claude Code skill for a **full security audit** of any project — web (Next.js, React, Vue), mobile (Flutter, React Native, iOS, Android), or backend (Node, Express, Firebase).

## Install

```bash
/plugin marketplace add ahmadalhaish-tickit/tickit-claude-marketplace
/plugin install client-secret-exposure@tickit-claude-marketplace
```

## What it covers (17 security areas)

| # | Area | What it checks |
| --- | --- | --- |
| 1 | Secret exposure | `NEXT_PUBLIC_` vars in JS bundle, hardcoded strings in APK/IPA, secrets in git history |
| 2 | Dependency vulnerabilities | `npm audit`, `flutter pub outdated`, CVE triage |
| 3 | Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| 4 | Insecure storage | `localStorage` tokens, SharedPreferences, httpOnly cookies, Keychain/Keystore |
| 5 | Broken access control | IDOR — API routes without ownership checks |
| 6 | Input validation & XSS | `dangerouslySetInnerHTML`, open redirects, file uploads, zod/joi validation |
| 7 | Sensitive data in logs | PII in `console.log`, raw error objects returned to clients |
| 8 | Firebase Storage rules | Public buckets, missing auth, missing size/type limits |
| 9 | Rate limiting & bot protection | Auth endpoints, checkout, OTP, payment, reCAPTCHA on purchase flow |
| 10 | Authentication security | JWT weak secrets, missing expiry, account enumeration, bcrypt vs MD5 |
| 11 | Business logic | Price manipulation, ticket quantity bypass, race conditions, promo code abuse |
| 12 | Predictable IDs | Sequential integer IDs in URLs → replace with UUID/cuid2 |
| 13 | CI/CD pipeline secrets | Secrets in GitHub Actions logs, `.env` in git history |
| 14 | Certificate pinning | Flutter/RN MITM interception via Charles/Burp Suite |
| 15 | Deep link injection | Unvalidated route redirects, tokens in deep link URLs |
| 16 | Subresource Integrity | External CDN scripts without `integrity` hash |
| 17 | Exposed infrastructure | `.git` directory public, debug endpoints, health check info leakage |

## Usage

After installing, ask Claude:

```text
do a full security audit of this project
```

```text
check our Flutter app for hardcoded API keys and certificate pinning
```

```text
audit our API routes for broken access control and rate limiting
```

```text
is there anything that could let someone buy more tickets than the limit?
```

```text
what security headers and SRI are we missing?
```

## Full audit checklist

The skill includes a 17-section checklist — run it against any codebase for a structured security report.

## Platforms covered

- Web: Next.js, React, Vue, Angular
- Mobile: Flutter, React Native, iOS (Swift/ObjC), Android (Kotlin/Java)
- Backend: Node.js, Express, Firebase Cloud Functions
- Database: Firestore, Firebase Realtime DB, Firebase Storage
- CI/CD: GitHub Actions, Vercel, any pipeline

## License

MIT
