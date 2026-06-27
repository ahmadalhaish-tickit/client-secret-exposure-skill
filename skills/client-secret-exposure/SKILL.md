---
name: client-secret-exposure
description: Use when doing a full security audit of any project — web (Next.js, React, Vue), mobile (Flutter, React Native, iOS, Android), or backend (Node, Express, Firebase). Triggers on leaked API keys, hardcoded credentials, NEXT_PUBLIC_ variables, missing auth on API routes, XSS risks, insecure token storage, vulnerable dependencies, missing security headers, broken access control, IDOR, sensitive data in logs, or any question about whether code is safe to ship.
---

# Full-Stack Security Audit

## Overview

Security issues fall into 7 categories. Work through each section for a complete audit. No single tool catches everything — this skill gives you the detection commands, the classification, and the fix for each.

---

## 1. Secret Exposure in Client Code

Any secret in code that runs on a user's device can be extracted. No hiding, no obfuscation — move it server-side or confirm it is public by design.

### Detection by Platform

**Web (Next.js / React / Vue):**
```bash
# NEXT_PUBLIC_ vars baked into the bundle
grep -oh "NEXT_PUBLIC_[A-Z_]*" .next/static/chunks/*.js | sort -u

# Search for a known key value
grep -rl "YOUR_KEY_VALUE" .next/static/

# Keys hardcoded in fetch/image URLs (visible in raw HTML)
grep -r "key=" src/ --include="*.tsx" --include="*.ts" --include="*.js"
```

**Flutter / Dart:**
```bash
unzip app-release.apk -d apk_out
strings apk_out/lib/arm64-v8a/libapp.so | grep -Ei "(key|secret|password|token|api)"
grep -r "apiKey\|secretKey\|password\|Bearer" lib/ --include="*.dart"
```

**React Native:**
```bash
unzip app-release.apk assets/index.android.bundle -d rn_out
grep -o '"[A-Za-z_]*[Kk]ey[^"]*"' rn_out/assets/index.android.bundle | head -20
```

**iOS / Android native:**
```bash
strings MyApp.ipa | grep -Ei "(key|secret|token|password)"
```

**Git history (any platform):**
```bash
git log -S "YOUR_KEY_VALUE" --all --oneline
git grep -E "(apiKey|secret|password|Bearer)" $(git rev-list --all)
```

### Classification

| Key Type | Safe in Client? | Reason |
|---|---|---|
| Stripe `pk_live_` / `pk_test_` | ✅ Yes | Publishable key — designed for client use |
| Google Analytics / GA4 ID | ✅ Yes | Tracking identifier, cannot access data |
| Google Tag Manager ID | ✅ Yes | Container ID, public by design |
| reCAPTCHA site key | ✅ Yes | Required client-side; secret key stays server |
| Intercom / Crisp App ID | ✅ Yes | Widget identifier only |
| Sentry DSN | ✅ Yes | Error reporting only; auth token is separate |
| Adjust / AppsFlyer tokens | ✅ Yes | Write-only attribution identifier |
| Firebase API key | ⚠️ Partial | Public by design; requires App Check + Security Rules |
| Google Maps API key | ⚠️ Needs restriction | Restrict in Cloud Console AND proxy server-side |
| Analytics write keys (Customer.io, Segment) | ⚠️ Medium | Attacker can inject fake events |
| Payment credentials (username / password / secret) | ❌ Never | Server-side only |
| OAuth client secrets | ❌ Never | Only Client IDs are safe client-side |
| Database connection strings | ❌ Never | Direct DB access from client is always wrong |
| Private API keys / service account keys | ❌ Never | Any key with write or admin scope |

### Fixes

**Backend-for-Frontend (BFF) proxy — works for every platform:**
```ts
// Next.js API route — browser calls this, key stays on server
export async function POST(request: NextRequest) {
  const key = process.env.PAYMENT_SECRET_KEY; // no NEXT_PUBLIC_
  const body = await request.json();
  const res = await fetch('https://api.payment-gateway.com/charge', {
    method: 'POST',
    headers: { Authorization: `Basic ${key}` },
    body: JSON.stringify(body),
  });
  return NextResponse.json(await res.json());
}
```

```dart
// Flutter — call YOUR backend, not the third-party API directly
final res = await http.post(
  Uri.parse('https://api.yourapp.com/payment/charge'),
  headers: {'Authorization': 'Bearer $userToken'},
  body: jsonEncode({'amount': amount}),
);
```

**Firebase — cannot be hidden, secure differently:**
1. Firebase App Check (Firebase Console → App Check → Register → monitoring mode → Enforce)
   - Web: reCAPTCHA Enterprise | Android: Play Integrity | iOS: DeviceCheck
2. Firestore Security Rules minimum: `allow read, write: if request.auth != null;`
3. Restrict the Firebase API key in Google Cloud Console to only needed APIs

**Base64 is not encryption** — `atob("...")` decodes in 2 seconds in any browser console. Rotate and proxy.

---

## 2. Dependency Vulnerabilities

Known CVEs in packages you use. Fastest way for an attacker to get in without writing any exploit.

**Detection:**
```bash
# Node / npm (web + backend)
npm audit
npm audit --audit-level=high   # show only high/critical

# Yarn
yarn audit

# Flutter / Dart
flutter pub outdated --major-versions
dart pub audit  # Dart 3.x

# iOS (CocoaPods)
pod outdated

# Android
./gradlew dependencyUpdates
```

**Fix:**
```bash
npm audit fix            # auto-fix compatible upgrades
npm audit fix --force    # force-upgrades (review changes first)
flutter pub upgrade
```

Check the CVE before updating — some advisories are low severity. Prioritise: **Remote Code Execution > Authentication Bypass > Data Exposure > everything else**.

---

## 3. Security Headers (Web)

Missing HTTP headers are the easiest security misconfiguration to find and fix. They block clickjacking, XSS, protocol downgrade, MIME sniffing.

**Detection:**
```bash
# Check headers of your live site
curl -I https://yourapp.com

# Or check locally
curl -I http://localhost:3000
```

**Headers to check for:**

| Header | What it blocks | Minimum value |
|---|---|---|
| `Content-Security-Policy` | XSS, injected scripts | `default-src 'self'` (then expand) |
| `Strict-Transport-Security` | HTTP downgrade attacks | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | Clickjacking | `DENY` or `SAMEORIGIN` |
| `X-Content-Type-Options` | MIME sniffing | `nosniff` |
| `Referrer-Policy` | Leaking URLs to third parties | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Camera/mic/location abuse | `camera=(), microphone=(), geolocation=()` |

**Fix in Next.js** (`next.config.js`):
```js
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://www.googletagmanager.com",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "connect-src 'self' https://firestore.googleapis.com",
    ].join('; '),
  },
];

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};
```

---

## 4. Insecure Client-Side Storage

Tokens and sensitive data stored in the wrong place are readable by any JavaScript on the page (XSS) or by other apps on the device.

**Detection — Web:**
```js
// Run in browser console — check what's stored
console.log(Object.keys(localStorage));
console.log(document.cookie);
// Look for: token, auth, session, user, jwt, refresh
```

```bash
# Search source for dangerous localStorage usage
grep -r "localStorage.setItem\|localStorage.getItem" src/ --include="*.ts" --include="*.tsx" --include="*.js"
grep -r "sessionStorage" src/
```

**Detection — Flutter / Android:**
```bash
# SharedPreferences stores as plain XML on Android
grep -r "SharedPreferences\|getSharedPreferences\|putString" android/ lib/ --include="*.dart" --include="*.java" --include="*.kt"
```

**Detection — iOS:**
```bash
grep -r "UserDefaults\|NSUserDefaults" . --include="*.swift" --include="*.m"
```

**Rules:**

| Data | Web | Mobile |
|---|---|---|
| Auth tokens (JWT, session) | `httpOnly` cookie only — never `localStorage` | Encrypted storage (`flutter_secure_storage`, iOS Keychain, Android Keystore) |
| User PII (name, email) | OK in `localStorage` if needed | OK in SharedPreferences (not sensitive) |
| Payment card data | Never store client-side | Never store client-side |
| Refresh tokens | `httpOnly` cookie | Encrypted storage only |

**Fix — Web (use httpOnly cookies instead of localStorage):**
```ts
// Server sets the cookie — JS cannot read it
response.cookies.set('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 60 * 60 * 24 * 7, // 7 days
});
```

**Fix — Flutter:**
```dart
// Use flutter_secure_storage instead of SharedPreferences for tokens
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
final storage = FlutterSecureStorage();
await storage.write(key: 'auth_token', value: token); // stored in Keychain/Keystore
```

---

## 5. Broken Access Control & IDOR

An API endpoint accepts an ID but doesn't verify the caller owns that resource. This is the #1 vulnerability in real apps (OWASP Top 10 #1).

**Example of the bug:**
```ts
// BROKEN — any authenticated user can read any ticket
export async function GET(req: NextRequest) {
  const ticketId = req.nextUrl.searchParams.get('id');
  const ticket = await db.tickets.findById(ticketId); // no ownership check
  return NextResponse.json(ticket);
}
```

**Fix:**
```ts
// CORRECT — verify the authenticated user owns this resource
export async function GET(req: NextRequest) {
  const userId = getUserIdFromSession(req); // from verified JWT/session
  const ticketId = req.nextUrl.searchParams.get('id');
  const ticket = await db.tickets.findOne({ id: ticketId, userId }); // ownership enforced in query
  if (!ticket) return NextResponse.json({ error: 'Not found' }, { status: 404 });
  return NextResponse.json(ticket);
}
```

**Detection — look for these patterns:**
```bash
# Find API routes that take an ID param but may lack auth checks
grep -r "params\|searchParams\|req\.query" src/app/api/ --include="*.ts" -l

# Find routes missing auth middleware
grep -rL "getSession\|getUserId\|authenticate\|verifyToken" src/app/api/ --include="*.ts"
```

**IDOR checklist for every API route:**
- [ ] Is the caller authenticated?
- [ ] Does the query filter by `userId` (or `orgId`, `teamId`)?
- [ ] Are admin-only routes protected by a role check?
- [ ] Can a user escalate their own permissions via the API?

**Firebase Firestore rules for IDOR:**
```js
// Users can only read/write their own documents
match /tickets/{ticketId} {
  allow read, write: if request.auth != null
    && resource.data.userId == request.auth.uid;
}
```

---

## 6. Input Validation & XSS

Unvalidated input from users reaches HTML, SQL, or shell commands.

**XSS Detection — Web:**
```bash
# Find dangerous patterns in React
grep -r "dangerouslySetInnerHTML" src/ --include="*.tsx" --include="*.jsx"
grep -r "innerHTML\s*=" src/ --include="*.ts" --include="*.js"

# Find unvalidated redirect URLs
grep -r "router\.push\|redirect\|window\.location" src/ --include="*.ts" --include="*.tsx"
```

**XSS Detection — Flutter:**
```bash
grep -r "HtmlWidget\|WebView\|evalJavascript\|runJavascriptReturningResult" lib/ --include="*.dart"
```

**XSS Fix — if you must render HTML:**
```ts
import DOMPurify from 'dompurify';
// Sanitize before rendering
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
```

**Unvalidated redirect fix:**
```ts
// BROKEN — attacker sends ?next=https://evil.com
const next = req.nextUrl.searchParams.get('next');
redirect(next);

// FIXED — whitelist allowed destinations
const ALLOWED = ['/dashboard', '/tickets', '/profile'];
const next = req.nextUrl.searchParams.get('next') ?? '/dashboard';
redirect(ALLOWED.includes(next) ? next : '/dashboard');
```

**File upload validation:**
```ts
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_SIZE = 5 * 1024 * 1024; // 5MB

if (!ALLOWED_TYPES.includes(file.type)) {
  return NextResponse.json({ error: 'Invalid file type' }, { status: 400 });
}
if (file.size > MAX_SIZE) {
  return NextResponse.json({ error: 'File too large' }, { status: 400 });
}
```

**API input validation (use zod or joi):**
```ts
import { z } from 'zod';
const schema = z.object({
  amount: z.number().positive().max(100000),
  currency: z.enum(['USD', 'EUR', 'GBP']),
});
const parsed = schema.safeParse(await req.json());
if (!parsed.success) return NextResponse.json({ error: 'Invalid input' }, { status: 400 });
```

---

## 7. Sensitive Data in Logs & Error Responses

Stack traces and PII leaked in API responses or server logs give attackers a map of your system.

**Detection:**
```bash
# Find console.log statements that may include sensitive data
grep -r "console\.log\|console\.error\|print(" src/ lib/ --include="*.ts" --include="*.tsx" --include="*.dart" | grep -i "user\|token\|password\|email\|phone\|card"

# Find API routes that return raw errors
grep -r "catch.*error\|catch.*err" src/app/api/ --include="*.ts" | grep "json(error\|json(err"
```

**Dangerous patterns:**
```ts
// BROKEN — exposes stack trace and internal details to client
catch (error) {
  return NextResponse.json({ error }, { status: 500 });
}

// BROKEN — logs PII
console.log('User logged in:', user); // contains email, phone, etc.
```

**Fix:**
```ts
// CORRECT — generic message to client, full error to server logs only
catch (error) {
  console.error('[payment/charge]', error); // server log — never reaches client
  return NextResponse.json({ error: 'Payment failed' }, { status: 500 });
}
```

**Firebase Cloud Functions:**
```ts
// Never return raw error objects
throw new functions.https.HttpsError('internal', 'Something went wrong');
// Not: throw error  ← exposes internal details
```

---

## 8. Firebase Storage Rules

Firestore rules and Storage rules are separate. Many projects secure Firestore but leave Storage wide open.

**Detection:**
- Firebase Console → Storage → Rules
- Look for: `allow read, write: if true;` — this means anyone on the internet can read and upload files

**Minimum rules:**
```js
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    // Only authenticated users can read
    match /{allPaths=**} {
      allow read: if request.auth != null;
      allow write: if request.auth != null
        && request.resource.size < 10 * 1024 * 1024  // 10MB max
        && request.resource.contentType.matches('image/.*'); // images only
    }
    // Public assets (logos, etc.) — read only
    match /public/{allPaths=**} {
      allow read;
      allow write: if false;
    }
  }
}
```

---

## CORS vs Real Server Enforcement

`Access-Control-Allow-Origin: yourapp.com` does **not** protect your API. curl, Postman, and any script bypass it completely.

| | CORS | App Check / Server Auth |
|---|---|---|
| Enforced by | Browser | Your server |
| Bypassed by curl / Postman | Yes | No |
| Real protection | No | Yes |

---

## Full Audit Checklist

Run through every item for a complete check:

### Secrets
- [ ] No `NEXT_PUBLIC_` vars contain secrets — verify in `.next/static/`
- [ ] No hardcoded strings in Flutter `lib/` or RN bundle
- [ ] No secrets in git history — `git log -S "key" --all`
- [ ] All payment credentials are server-side only
- [ ] Firebase secured with App Check + Security Rules

### Dependencies
- [ ] `npm audit` — zero high/critical findings
- [ ] `flutter pub outdated` — no major-version CVEs
- [ ] Dependencies reviewed after every major update

### Security Headers (web)
- [ ] `X-Frame-Options: DENY`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `Strict-Transport-Security` present
- [ ] `Content-Security-Policy` present (start with report-only)
- [ ] `Referrer-Policy` present

### Storage
- [ ] Auth tokens in `httpOnly` cookies, not `localStorage` (web)
- [ ] Auth tokens in encrypted storage — Keychain/Keystore (mobile)
- [ ] Firebase Storage rules require `request.auth != null`
- [ ] No card data or passwords stored client-side

### Access Control
- [ ] Every API route verifies the caller is authenticated
- [ ] Every resource query filters by `userId` or equivalent
- [ ] Admin routes have role checks
- [ ] Firebase Firestore rules enforce ownership per document

### Input Validation
- [ ] No `dangerouslySetInnerHTML` without DOMPurify
- [ ] All redirect targets validated against a whitelist
- [ ] File uploads validate type and size
- [ ] API request bodies validated with zod/joi/yup

### Logging
- [ ] No PII in `console.log` / `print`
- [ ] API catch blocks return generic messages — not raw error objects
- [ ] Cloud Functions use `HttpsError` with safe messages

### Post-fix (after finding any issue)
1. Rotate the exposed credential immediately
2. Remove from client code and environment config
3. Add as server-only env var in deployment platform
4. Clean git history with `git filter-repo` if committed
5. Restrict keys in vendor console (domain, IP, API scope)
6. Re-run detection commands to confirm clean
