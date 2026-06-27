# client-secret-exposure — Claude Security Audit Skill

A Claude Code skill for a **full security audit** of any project — web (Next.js, React, Vue), mobile (Flutter, React Native, iOS, Android), or backend (Node, Express, Firebase).

## Install

```bash
/plugin marketplace add ahmadalhaish-tickit/tickit-claude-marketplace
/plugin install client-secret-exposure@tickit-claude-marketplace
```

## What it covers (8 security areas)

| Area | What it checks |
| --- | --- |
| **1. Secret exposure** | `NEXT_PUBLIC_` vars in JS bundle, hardcoded strings in APK/IPA binary, secrets in git history |
| **2. Dependency vulnerabilities** | `npm audit`, `flutter pub outdated`, CVE severity triage |
| **3. Security headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **4. Insecure storage** | Tokens in `localStorage` (use httpOnly cookies), tokens in SharedPreferences (use Keychain/Keystore) |
| **5. Broken access control** | IDOR — API routes that accept IDs without ownership checks |
| **6. Input validation & XSS** | `dangerouslySetInnerHTML`, open redirects, file upload, API body validation |
| **7. Sensitive data in logs** | PII in `console.log`, raw error objects returned to clients |
| **8. Firebase Storage rules** | Public buckets, missing auth requirement, missing size/type limits |

## Usage

After installing, ask Claude:

```text
do a full security audit of this project
```

```text
check our Flutter app for hardcoded API keys
```

```text
audit our API routes for broken access control
```

```text
is this key safe to put in the client bundle?
```

```text
what security headers are we missing?
```

## Full audit checklist

The skill includes a complete checklist covering all 8 areas — run it against any codebase to get a structured security report.

## Platforms covered

- Web: Next.js, React, Vue, Angular
- Mobile: Flutter, React Native, iOS (Swift/ObjC), Android (Kotlin/Java)
- Backend: Node.js, Express, Firebase Cloud Functions
- Database: Firestore, Firebase Realtime DB, Firebase Storage

## License

MIT
