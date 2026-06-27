---
name: client-secret-exposure
description: Use when doing a full security audit of any project — web (Next.js, React, Vue), mobile (Flutter, React Native, iOS, Android), or backend (Node, Express, Firebase, PostgreSQL, MySQL, MongoDB). Triggers on leaked API keys, SQL injection, hardcoded credentials, NEXT_PUBLIC_ variables, missing auth on API routes, XSS, insecure token storage, vulnerable dependencies, missing security headers, broken access control, IDOR, rate limiting, bot protection, JWT misconfigurations, business logic bugs, race conditions, sequential IDs, CI/CD secrets, certificate pinning, deep link injection, SRI, password hashing, database row-level security, SELECT * exposure, or exposed .git directories.
---

# Full-Stack Security Audit

Security issues fall into 17 categories. Work through each section for a complete audit. No single tool catches everything — this skill gives you the detection commands, the classification, and the fix for each.

---

## 1. Secret Exposure in Client Code

Any secret in code that runs on a user's device can be extracted. No hiding, no obfuscation — move it server-side or confirm it is public by design.

### Detection by Platform

**Web (Next.js / React / Vue):**
```bash
grep -oh "NEXT_PUBLIC_[A-Z_]*" .next/static/chunks/*.js | sort -u
grep -rl "YOUR_KEY_VALUE" .next/static/
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

**Git history:**
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

### Fix — Backend-for-Frontend (BFF) proxy

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

**Firebase:** App Check (Console → App Check → Register → monitoring → Enforce) + Firestore rules: `allow read, write: if request.auth != null;` + restrict API key in Google Cloud Console.

**Base64 is not encryption** — `atob("...")` decodes in 2 seconds in any browser console. Rotate and proxy.

---

## 2. Dependency Vulnerabilities

Known CVEs in packages you use. Fastest way for an attacker to get in without writing any exploit.

```bash
npm audit --audit-level=high    # Node / npm
yarn audit
flutter pub outdated --major-versions
dart pub audit                  # Dart 3.x
pod outdated                    # iOS CocoaPods
./gradlew dependencyUpdates     # Android
```

```bash
npm audit fix
npm audit fix --force           # review changes before using
flutter pub upgrade
```

Prioritise: **Remote Code Execution > Auth Bypass > Data Exposure > everything else**. Check the CVE details before upgrading — some advisories are low severity and require user interaction.

---

## 3. Security Headers (Web)

Missing HTTP headers are the easiest misconfiguration to find and fix.

```bash
curl -I https://yourapp.com
```

| Header | Blocks | Minimum value |
|---|---|---|
| `Content-Security-Policy` | XSS, injected scripts | `default-src 'self'` then expand |
| `Strict-Transport-Security` | HTTP downgrade | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | Clickjacking | `DENY` |
| `X-Content-Type-Options` | MIME sniffing | `nosniff` |
| `Referrer-Policy` | URL leakage | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Camera/mic/location abuse | `camera=(), microphone=(), geolocation=()` |

**Fix in Next.js (`next.config.js`):**
```js
module.exports = {
  async headers() {
    return [{
      source: '/(.*)',
      headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com; img-src 'self' data: https:; connect-src 'self' https://firestore.googleapis.com" },
      ],
    }];
  },
};
```

---

## 4. Insecure Client-Side Storage

Tokens in `localStorage` are readable by any JS on the page. Tokens in SharedPreferences are readable by other apps on rooted Android devices.

**Detection — Web:**
```js
// Browser console
console.log(Object.keys(localStorage)); // look for: token, auth, jwt, session, refresh
```
```bash
grep -r "localStorage.setItem" src/ --include="*.ts" --include="*.tsx" --include="*.js"
```

**Detection — Mobile:**
```bash
grep -r "SharedPreferences\|putString" android/ lib/ --include="*.dart" --include="*.kt"
grep -r "UserDefaults\|NSUserDefaults" . --include="*.swift"
```

| Data | Web | Mobile |
|---|---|---|
| Auth / session tokens | `httpOnly` cookie only | `flutter_secure_storage` / Keychain / Keystore |
| Refresh tokens | `httpOnly` cookie | Encrypted storage only |
| Payment card data | Never store | Never store |
| User PII (name, email) | OK in localStorage | OK in SharedPreferences |

**Fix — Web:**
```ts
response.cookies.set('session', token, {
  httpOnly: true, secure: true, sameSite: 'lax',
  maxAge: 60 * 60 * 24 * 7,
});
```

**Fix — Flutter:**
```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
final storage = FlutterSecureStorage();
await storage.write(key: 'auth_token', value: token); // Keychain on iOS, Keystore on Android
```

---

## 5. Broken Access Control & IDOR

API accepts an ID but doesn't verify the caller owns that resource. OWASP #1 most common critical vulnerability.

```bash
grep -r "params\|searchParams\|req\.query" src/app/api/ --include="*.ts" -l
grep -rL "getSession\|getUserId\|authenticate\|verifyToken" src/app/api/ --include="*.ts"
```

```ts
// BROKEN — any logged-in user can read any ticket
const ticket = await db.tickets.findById(ticketId);

// FIXED — query enforces ownership
const ticket = await db.tickets.findOne({ id: ticketId, userId: session.userId });
if (!ticket) return NextResponse.json({ error: 'Not found' }, { status: 404 });
```

**Firestore rules:**
```js
match /tickets/{ticketId} {
  allow read, write: if request.auth != null
    && resource.data.userId == request.auth.uid;
}
```

**Checklist per route:**
- [ ] Caller is authenticated
- [ ] Query filters by `userId` / `orgId`
- [ ] Admin routes check role
- [ ] User cannot escalate own permissions via API

---

## 6. Input Validation & XSS

Unvalidated user input reaches HTML, URLs, or file systems.

```bash
grep -r "dangerouslySetInnerHTML" src/ --include="*.tsx" --include="*.jsx"
grep -r "innerHTML\s*=" src/ --include="*.ts" --include="*.js"
grep -r "router\.push\|redirect\|window\.location" src/ --include="*.tsx"
grep -r "HtmlWidget\|WebView\|evalJavascript" lib/ --include="*.dart"
```

```ts
// XSS — sanitize before rendering HTML
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);

// Open redirect — whitelist destinations
const ALLOWED = ['/dashboard', '/tickets', '/profile'];
const next = searchParams.get('next') ?? '/dashboard';
redirect(ALLOWED.includes(next) ? next : '/dashboard');

// File uploads — validate type and size
if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) return error('Invalid type');
if (file.size > 5 * 1024 * 1024) return error('Too large');

// API bodies — validate with zod
const schema = z.object({ amount: z.number().positive().max(100000) });
const parsed = schema.safeParse(await req.json());
if (!parsed.success) return NextResponse.json({ error: 'Invalid' }, { status: 400 });
```

---

## 7. Sensitive Data in Logs & Error Responses

Stack traces and PII in responses give attackers a map of your system.

```bash
grep -r "console\.log\|console\.error\|print(" src/ lib/ --include="*.ts" --include="*.dart" | grep -i "user\|token\|password\|email\|phone\|card"
grep -r "catch.*error" src/app/api/ --include="*.ts" | grep "json(error\|json(err"
```

```ts
// BROKEN
catch (error) { return NextResponse.json({ error }, { status: 500 }); }

// FIXED
catch (error) {
  console.error('[payment/charge]', error); // server only
  return NextResponse.json({ error: 'Payment failed' }, { status: 500 });
}
```

---

## 8. Firebase Storage Rules

Firestore rules and Storage rules are separate — most projects forget Storage.

Check Firebase Console → Storage → Rules for `allow read, write: if true;`

```js
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read: if request.auth != null;
      allow write: if request.auth != null
        && request.resource.size < 10 * 1024 * 1024
        && request.resource.contentType.matches('image/.*');
    }
    match /public/{allPaths=**} {
      allow read;
      allow write: if false;
    }
  }
}
```

---

## 9. Rate Limiting & Bot Protection

No rate limiting means bots can buy out all tickets in seconds, brute-force passwords, or spam OTP endpoints.

**Detection:**
```bash
# Find auth and transaction endpoints with no rate limiting
grep -rL "rateLimit\|rateLimiter\|upstash\|bottleneck\|express-rate-limit" src/app/api/ --include="*.ts"
```

**Fix — Next.js with Upstash Redis:**
```ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '1 m'), // 10 requests per minute
});

export async function POST(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for') ?? 'anonymous';
  const { success } = await ratelimit.limit(ip);
  if (!success) return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
  // ... handler
}
```

**Endpoints that must have rate limiting:**
| Endpoint | Recommended limit |
|---|---|
| Login / sign up | 5–10 per minute per IP |
| OTP / verification code | 3–5 per minute per user |
| Password reset | 3 per hour per email |
| Ticket checkout / reserve | 5 per minute per user |
| Any payment endpoint | 3 per minute per user |
| Search / public listing | 60 per minute per IP |

**Bot protection for ticketing:**
- Require reCAPTCHA Enterprise or Cloudflare Turnstile on checkout
- Enforce per-user ticket quantity limits server-side (not just UI)
- Add a short server-side reservation TTL so bots can't hold inventory without paying

---

## 10. Authentication Security

Weak auth lets attackers in even when everything else is correct.

**Detection:**
```bash
# Find JWT secret strength
grep -r "jwt\.sign\|sign(" src/ --include="*.ts" --include="*.js" -A2 | grep "secret\|key"

# Find missing token expiry
grep -r "jwt\.sign" src/ --include="*.ts" --include="*.js" -A5 | grep -v "expiresIn"

# Find different error messages for wrong email vs wrong password (account enumeration)
grep -r "User not found\|Invalid email\|No account" src/ --include="*.ts"
```

**JWT checklist:**
- [ ] Secret is at least 32 random characters — not `"secret"` or `"jwt_secret"`
- [ ] `expiresIn` is set (access token: 15m–1h; refresh token: 7–30d)
- [ ] Token is verified on every protected route, not just checked for existence
- [ ] Refresh token rotation: old refresh token is invalidated after use
- [ ] Algorithm is explicitly set to `HS256` or `RS256` — never `none`

```ts
// BROKEN — weak secret, no expiry, no algorithm lock
jwt.sign({ userId }, 'secret');

// FIXED
jwt.sign({ userId }, process.env.JWT_SECRET, {
  expiresIn: '15m',
  algorithm: 'HS256',
});
```

**Account enumeration fix — always return the same error:**
```ts
// BROKEN — reveals which field is wrong
if (!user) return error('Email not found');
if (!valid) return error('Wrong password');

// FIXED — same message always, same timing
await bcrypt.compare(password, user?.passwordHash ?? '$2b$10$placeholder');
return error('Invalid email or password');
```

**Password hashing:**
```ts
// BROKEN — MD5, SHA1, or plain SHA256 for passwords
const hash = crypto.createHash('md5').update(password).digest('hex');

// FIXED — bcrypt or argon2
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12); // cost factor 12+
const valid = await bcrypt.compare(password, storedHash);
```

---

## 11. Business Logic Vulnerabilities

Ticketing platforms are targets for price manipulation, inventory abuse, and race conditions.

**Price manipulation — always verify price server-side:**
```ts
// BROKEN — trusts the price sent by the client
const { ticketId, price } = await req.json();
await charge(price);

// FIXED — look up the real price from the database
const ticket = await db.tickets.findById(ticketId);
await charge(ticket.price); // client-sent price is ignored
```

**Quantity limits — enforce server-side, not just in UI:**
```ts
// BROKEN — UI shows max 4 but API doesn't check
const { quantity } = await req.json();
await reserveTickets(userId, eventId, quantity);

// FIXED
const MAX_PER_USER = 4;
const existing = await db.orders.countByUserAndEvent(userId, eventId);
if (existing + quantity > MAX_PER_USER) {
  return NextResponse.json({ error: 'Ticket limit exceeded' }, { status: 400 });
}
```

**Race conditions / double-booking — use atomic operations:**
```ts
// BROKEN — two requests can both see available=true at the same time
const ticket = await db.tickets.findById(id);
if (ticket.available) await db.tickets.update(id, { available: false });

// FIXED — atomic update with condition
const result = await db.tickets.updateOne(
  { _id: id, available: true },   // condition
  { $set: { available: false, reservedBy: userId } }
);
if (result.modifiedCount === 0) return error('Ticket no longer available');
```

**Discount / promo code abuse:**
```ts
// Check if code was already used by this user
const used = await db.promoUsage.findOne({ code, userId });
if (used) return error('Code already used');

// Apply and mark as used in a transaction
await db.transaction(async (tx) => {
  await tx.promoUsage.insert({ code, userId, usedAt: new Date() });
  await tx.orders.create({ ...orderData, discount: promo.value });
});
```

**Detection — patterns to search for:**
```bash
# Price or amount coming from client body (should come from DB)
grep -r "body\.price\|body\.amount\|req\.body\.total" src/app/api/ --include="*.ts"

# Quantity limits only in UI
grep -r "max.*4\|maxTickets\|quantity.*limit" src/ --include="*.tsx" --include="*.ts"
```

---

## 12. Predictable & Sequential IDs

Sequential IDs (`/orders/1001`, `/orders/1002`) let attackers enumerate every record in your system.

**Detection:**
```bash
# Find auto-increment or sequential ID patterns
grep -r "autoIncrement\|SERIAL\|INTEGER PRIMARY KEY\|id: \d\+" src/ --include="*.ts" --include="*.sql"

# Find routes that expose numeric IDs
grep -r "params\.id\|searchParams\.get.*id" src/app/api/ --include="*.ts"
```

**Fix — use UUIDs or cuid2:**
```ts
import { createId } from '@paralleldrive/cuid2';  // cuid2
import { v4 as uuidv4 } from 'uuid';              // uuid

const orderId = createId();   // cl9...  — unguessable
const ticketId = uuidv4();    // 550e8400-e29b-... — unguessable
```

**Firestore** generates random document IDs by default — use `db.collection('orders').doc()` without passing an ID.

**Rule:** Even with auth and ownership checks, sequential IDs leak the total count of your records to any authenticated user. Always use random IDs.

---

## 13. CI/CD Pipeline Secrets

Secrets committed to repos, printed in CI logs, or baked into build artifacts.

**Detection:**
```bash
# Secrets accidentally committed
git log --all --full-history -- .env .env.local .env.production
git show HEAD:.env 2>/dev/null

# Check GitHub Actions workflows for secrets printed in logs
grep -r "echo\|print\|console.log" .github/workflows/ --include="*.yml" | grep -i "secret\|token\|key\|password"

# Check if .env files are gitignored
cat .gitignore | grep "\.env"
```

**Rules:**
- `.env`, `.env.local`, `.env.production` must be in `.gitignore` — always
- Never `echo $SECRET` in CI — it prints to the log
- Use `${{ secrets.MY_SECRET }}` in GitHub Actions — never hardcode values in workflow files
- Rotate any secret that has ever appeared in a CI log
- Use `git-secrets` or `truffleHog` in pre-commit hooks to block accidental commits

**GitHub Actions secret scanning:**
```bash
# Install trufflehog and scan repo history
trufflehog git file://. --since-commit HEAD~50 --only-verified
```

**Safe workflow pattern:**
```yaml
# BROKEN — secret visible in logs
- run: curl -H "Authorization: $MY_TOKEN" https://api.example.com

# FIXED — masked secret, never echoed
- run: curl -H "Authorization: ${{ secrets.MY_TOKEN }}" https://api.example.com
```

---

## 14. Mobile Certificate Pinning

Without certificate pinning, anyone on the same WiFi can intercept all Flutter/React Native API calls using a proxy (Charles, mitmproxy, Burp Suite) — including auth tokens, payment data, and user PII.

**Detection:**
```bash
# Flutter — check if http_certificate_pinning or dio is configured with pinning
grep -r "SecurityContext\|badCertificateCallback\|HttpClient\|certificate" lib/ --include="*.dart"
grep "http_certificate_pinning\|dio_certificate_pinner" pubspec.yaml

# React Native
grep -r "ssl\|pin\|certificate" . --include="*.js" --include="*.ts" | grep -v node_modules
```

**Fix — Flutter with Dio:**
```dart
import 'package:dio/dio.dart';

final dio = Dio();
(dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => false; // reject bad certs
  return client;
};

// With pinning (check SHA256 fingerprint of your server cert)
client.badCertificateCallback = (X509Certificate cert, String host, int port) {
  const expectedFingerprint = 'AA:BB:CC:...'; // your cert's SHA256
  return cert.sha256.toString() == expectedFingerprint;
};
```

**Minimum without full pinning — at least enforce HTTPS:**
```dart
// Never allow HTTP in production
final dio = Dio(BaseOptions(
  baseUrl: 'https://api.yourapp.com', // https always
));
```

**Priority:** Implement pinning for endpoints that handle auth tokens or payment data. Use a backup pin (second certificate) so a cert rotation doesn't break the app.

---

## 15. Mobile Deep Link Injection

Unvalidated deep links can redirect users mid-flow, steal auth tokens from URL callbacks, or trigger unintended actions.

**Detection:**
```bash
# Flutter — find deep link / URL scheme handlers
grep -r "onGenerateRoute\|GoRouter\|deepLink\|scheme\|host" lib/ --include="*.dart"
grep -r "flutter_deep_link\|uni_links\|app_links" pubspec.yaml

# React Native
grep -r "Linking\|deepLink\|scheme" . --include="*.ts" --include="*.js" | grep -v node_modules

# Android — check intent filters in manifest
grep -A5 "android.intent.action.VIEW" android/app/src/main/AndroidManifest.xml

# iOS — check URL schemes in Info.plist
grep -A2 "CFBundleURLSchemes" ios/Runner/Info.plist
```

**Vulnerable patterns:**
```dart
// BROKEN — redirects to any URL passed in the deep link
final uri = Uri.parse(link);
final redirectUrl = uri.queryParameters['next'];
Navigator.pushNamed(context, redirectUrl!); // attacker controls this

// BROKEN — exposes token in URL (shows in logs, referrer headers)
// yourapp://auth?token=eyJhbG...
final token = uri.queryParameters['token'];
```

**Fix:**
```dart
// Whitelist valid routes
const allowedRoutes = ['/home', '/tickets', '/profile', '/checkout'];
final redirectTo = uri.queryParameters['next'] ?? '/home';
if (!allowedRoutes.contains(redirectTo)) {
  Navigator.pushNamed(context, '/home'); // safe default
  return;
}
Navigator.pushNamed(context, redirectTo);

// Never pass tokens in deep link URLs — use a short-lived code instead
// yourapp://auth?code=abc123  ← code exchanged server-side for token
```

---

## 16. Subresource Integrity (SRI)

If you load scripts or stylesheets from a CDN without an `integrity` attribute, a CDN compromise injects malicious JS into every page of your site.

**Detection:**
```bash
# Find script/link tags loading from external CDNs without integrity
grep -r "src=.*cdn\|src=.*unpkg\|src=.*jsdelivr\|src=.*cloudflare" src/ public/ --include="*.html" --include="*.tsx" --include="*.ts"
grep -r "<script" src/ public/ --include="*.html" | grep -v "integrity="
```

**Vulnerable:**
```html
<script src="https://cdn.jsdelivr.net/npm/some-lib@1.0.0/dist/lib.min.js"></script>
```

**Fixed:**
```html
<script
  src="https://cdn.jsdelivr.net/npm/some-lib@1.0.0/dist/lib.min.js"
  integrity="sha384-abc123..."
  crossorigin="anonymous"
></script>
```

**Generate the hash:**
```bash
curl -s https://cdn.jsdelivr.net/npm/some-lib@1.0.0/dist/lib.min.js | openssl dgst -sha384 -binary | openssl base64 -A
# Output: sha384-abc123...  — use this as the integrity value
```

**Next.js note:** If you self-host all scripts via `next/script` and don't load from external CDNs, SRI is less critical. Audit third-party scripts added directly to `_document.tsx` or `layout.tsx`.

---

## 17. Exposed .git Directory & Debug Endpoints

Accidentally exposed infrastructure that gives attackers source code or system info.

**Detection:**
```bash
# Check if .git is publicly accessible (should return 404, not 200)
curl -s -o /dev/null -w "%{http_code}" https://yourapp.com/.git/config
# Should return 403 or 404 — if 200, your source code is public

# Check for exposed debug/health endpoints
curl https://yourapp.com/api/health
curl https://yourapp.com/__nextjs_original-stack-frame
curl https://yourapp.com/api/debug
```

**Check for sensitive paths:**
```bash
for path in /.git/config /.env /.env.local /api/debug /admin /phpinfo.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://yourapp.com$path")
  echo "$code $path"
done
```

**Fix:**
- Add to `next.config.js` or Vercel config to block `.git` and `.env` paths
- Health check endpoints must not expose version numbers, dependency lists, or environment info
- Remove or password-protect any `/admin`, `/debug`, `/metrics` endpoints

```ts
// Safe health endpoint — no internal info
export async function GET() {
  return NextResponse.json({ status: 'ok' });
}
// Not: { status: 'ok', version: '1.2.3', env: process.env, uptime: ... }
```

---

## 18. SQL & Database Security

SQL injection, over-privileged database users, missing row-level security, and exposed sensitive columns are among the most damaging vulnerabilities in any backend. This section covers SQL (PostgreSQL, MySQL, SQLite) and NoSQL (MongoDB) databases.

### SQL Injection

String interpolation in queries lets attackers run arbitrary SQL. A single vulnerable query can dump your entire database.

**Detection:**
```bash
# Find string interpolation inside SQL queries — highest risk
grep -rn "query\`\|execute\`\|raw\`\|sql\`" src/ --include="*.ts" --include="*.js" | grep '\${'

# Find raw query methods in ORMs
grep -rn "\$queryRaw\|\$executeRaw\|knex\.raw\|sequelize\.query\|db\.prepare" src/ --include="*.ts"

# Find template literals building SQL
grep -rn "SELECT\|INSERT\|UPDATE\|DELETE\|WHERE" src/ --include="*.ts" | grep '\${'
```

```ts
// BROKEN — user input directly in query string
const results = await db.query(`SELECT * FROM tickets WHERE event_id = '${eventId}'`);
// Attacker sends: eventId = "' OR '1'='1"  → dumps all tickets

// FIXED — parameterized query (works for any SQL driver)
const results = await db.query('SELECT * FROM tickets WHERE event_id = $1', [eventId]);

// FIXED — Prisma ORM (parameterized automatically)
const results = await prisma.ticket.findMany({ where: { eventId } });

// FIXED — Prisma raw query, use Prisma.sql tag (not string interpolation)
const results = await prisma.$queryRaw`SELECT * FROM tickets WHERE event_id = ${eventId}`;
// NOT: prisma.$queryRaw(`SELECT * FROM tickets WHERE event_id = '${eventId}'`)
```

**ORM raw query danger — all of these are vulnerable:**
```ts
// Prisma — unsafe
prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${userId}`)

// Drizzle — unsafe
db.execute(sql.raw(`SELECT * FROM users WHERE id = ${userId}`))

// TypeORM — unsafe
repo.query(`SELECT * FROM users WHERE id = ${userId}`)

// All safe alternatives use parameterization:
prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`
db.execute(sql`SELECT * FROM users WHERE id = ${userId}`)
repo.query('SELECT * FROM users WHERE id = $1', [userId])
```

### Least-Privilege Database Users

The application should never connect to the database as `root`, `postgres`, or any superuser. If an attacker gets SQL injection, they should hit a wall immediately.

**Create a restricted app user (PostgreSQL):**
```sql
-- Create user with a strong password
CREATE USER app_user WITH PASSWORD 'strong-random-password';

-- Grant only what the app needs
GRANT CONNECT ON DATABASE mydb TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- Never grant these to the app user:
-- GRANT ALL PRIVILEGES ...
-- GRANT SUPERUSER ...
-- GRANT CREATEDB ...
```

**Create a read-only user for analytics/reporting:**
```sql
CREATE USER readonly_user WITH PASSWORD 'another-strong-password';
GRANT CONNECT ON DATABASE mydb TO readonly_user;
GRANT USAGE ON SCHEMA public TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;
-- No INSERT, UPDATE, DELETE
```

**Detection — check your connection string:**
```bash
# If your DATABASE_URL contains 'postgres:' or 'root:' as the user, it's a superuser
echo $DATABASE_URL | grep -E "postgres:|root:|admin:"
```

### Row-Level Security (PostgreSQL RLS)

RLS is the SQL equivalent of Firebase Security Rules — it enforces data ownership at the database level, so even a buggy query can't leak another user's data.

```sql
-- Step 1: Enable RLS on the table
ALTER TABLE tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tickets FORCE ROW LEVEL SECURITY;  -- applies to table owner too

-- Step 2: Create policies

-- Users can only see their own tickets
CREATE POLICY tickets_select_own ON tickets
  FOR SELECT
  USING (user_id = current_setting('app.current_user_id', true)::uuid);

-- Users can only update their own tickets
CREATE POLICY tickets_update_own ON tickets
  FOR UPDATE
  USING (user_id = current_setting('app.current_user_id', true)::uuid);

-- Admins can see everything
CREATE POLICY tickets_admin ON tickets
  FOR ALL
  USING (current_setting('app.user_role', true) = 'admin');
```

**Set the user context per request in your app:**
```ts
// Set the current user ID before any query in the request
await prisma.$executeRaw`SET LOCAL app.current_user_id = ${userId}`;
await prisma.$executeRaw`SET LOCAL app.user_role = ${userRole}`;
// All subsequent queries in this transaction are scoped to this user
```

**RLS checklist:**
- [ ] RLS enabled on all tables that contain per-user data
- [ ] `FORCE ROW LEVEL SECURITY` set — applies even to the table owner
- [ ] Default-deny: no policy = no access (PostgreSQL default when RLS is enabled)
- [ ] Admin bypass policy is explicit and role-gated

### Data Exposure — SELECT * and Sensitive Columns

Returning more data than needed is a common source of accidental PII exposure.

**Detection:**
```bash
# Find SELECT * in raw queries
grep -rn "SELECT \*\|findMany()\|findAll()" src/ --include="*.ts"

# Find API routes that return full DB objects (may include sensitive fields)
grep -rn "return.*ticket\b\|res\.json(user\b" src/app/api/ --include="*.ts"
```

```ts
// BROKEN — returns password_hash, internal fields, PII to the client
const user = await prisma.user.findUnique({ where: { id } });
return NextResponse.json(user);

// FIXED — explicitly select only what the client needs
const user = await prisma.user.findUnique({
  where: { id },
  select: { id: true, name: true, email: true }, // password_hash excluded
});
return NextResponse.json(user);
```

**Columns that must never be returned to clients:**
- `password`, `password_hash`, `hashed_password`
- `secret_key`, `api_key`, `private_key`
- `ssn`, `tax_id`, `national_id`
- `credit_card_number`, `cvv`
- `reset_token`, `verification_token`, `mfa_secret`
- Internal audit fields: `created_by_admin`, `is_flagged`, `internal_notes`

**Missing LIMIT — full table dump:**
```ts
// BROKEN — attacker requests page=0&limit=999999
const { limit } = await req.json();
const tickets = await db.query(`SELECT * FROM tickets LIMIT ${limit}`);

// FIXED — cap the limit server-side
const MAX_PAGE_SIZE = 100;
const safeLimit = Math.min(Number(limit) || 20, MAX_PAGE_SIZE);
const tickets = await prisma.ticket.findMany({ take: safeLimit });
```

### Connection Security

```bash
# Check if your database port is exposed to the internet (should not be)
nmap -p 5432 your-server-ip    # PostgreSQL default port
nmap -p 3306 your-server-ip    # MySQL default port
nmap -p 27017 your-server-ip   # MongoDB default port
# Any of these returning "open" is a critical misconfiguration
```

**SSL for database connections (PostgreSQL):**
```ts
// Prisma — require SSL in production
// DATABASE_URL="postgresql://user:pass@host:5432/db?sslmode=require"

// pg driver
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});
```

**Rules:**
- Database must not be reachable from the public internet — only from your app servers / VPC
- All connections must use SSL in production (`sslmode=require`)
- Rotate database passwords the same way you rotate API keys — treat them as secrets
- Use a connection pooler (PgBouncer, Prisma Accelerate) — never open a new connection per request

### NoSQL Injection (MongoDB)

MongoDB is vulnerable to operator injection when query objects are built from user input.

**Detection:**
```bash
grep -rn "find(\|findOne(\|aggregate(" src/ --include="*.ts" | grep "req\.\|body\.\|params\."
```

```ts
// BROKEN — attacker sends { "username": { "$gt": "" } } to bypass auth
const user = await User.findOne({ username: req.body.username });

// BROKEN — $where executes arbitrary JS
User.find({ $where: `this.username == '${username}'` });

// FIXED — cast to expected types, never pass objects from client directly
const user = await User.findOne({ username: String(req.body.username) });

// FIXED — validate input shape with zod before using in query
const { username } = z.object({ username: z.string().max(100) }).parse(req.body);
const user = await User.findOne({ username });
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

### 1. Secrets
- [ ] No `NEXT_PUBLIC_` vars contain secrets — check `.next/static/`
- [ ] No hardcoded strings in Flutter `lib/` or RN bundle
- [ ] No secrets in git history — `git log -S "key" --all`
- [ ] All payment credentials are server-side only
- [ ] Firebase: App Check enabled + Firestore Security Rules in place

### 2. Dependencies
- [ ] `npm audit` — zero high/critical findings
- [ ] `flutter pub outdated` — no major-version CVEs
- [ ] Dependencies reviewed after every major update

### 3. Security Headers
- [ ] `X-Frame-Options: DENY`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `Strict-Transport-Security` present
- [ ] `Content-Security-Policy` present
- [ ] `Referrer-Policy` present

### 4. Client Storage
- [ ] Auth tokens in `httpOnly` cookies, not `localStorage`
- [ ] Auth tokens in `flutter_secure_storage` / Keychain / Keystore on mobile
- [ ] Firebase Storage rules require `request.auth != null`

### 5. Access Control
- [ ] Every API route verifies authentication
- [ ] Every resource query filters by `userId` or equivalent
- [ ] Admin routes have role checks
- [ ] Firebase Firestore rules enforce per-document ownership

### 6. Input Validation
- [ ] No `dangerouslySetInnerHTML` without DOMPurify
- [ ] All redirect targets validated against a whitelist
- [ ] File uploads validate type and size server-side
- [ ] API request bodies validated with zod/joi/yup

### 7. Logging
- [ ] No PII in `console.log` / `print`
- [ ] API catch blocks return generic messages to clients
- [ ] Cloud Functions use `HttpsError` with safe messages

### 8. Firebase Storage
- [ ] No `allow read, write: if true` rules
- [ ] Write rules include size and content type limits

### 9. Rate Limiting
- [ ] Login endpoint rate limited (5–10/min per IP)
- [ ] OTP / verification rate limited (3–5/min per user)
- [ ] Checkout / ticket reserve rate limited (5/min per user)
- [ ] Payment endpoints rate limited (3/min per user)
- [ ] reCAPTCHA or Turnstile on checkout flow

### 10. Authentication
- [ ] JWT secret is 32+ random characters
- [ ] JWT has `expiresIn` set (access: 15m–1h)
- [ ] Algorithm explicitly set (`HS256` or `RS256` — never `none`)
- [ ] Refresh token rotation enabled
- [ ] Login returns same error for wrong email and wrong password
- [ ] Passwords hashed with bcrypt (cost 12+) or argon2

### 11. Business Logic
- [ ] Price looked up from DB — never trusted from client
- [ ] Ticket quantity limits enforced server-side
- [ ] Ticket reservation uses atomic DB operations
- [ ] Promo/discount codes checked for previous use before applying

### 12. IDs
- [ ] No sequential integer IDs exposed in URLs or APIs
- [ ] All record IDs are UUIDs or cuid2

### 13. CI/CD
- [ ] `.env` files in `.gitignore`
- [ ] No secrets echoed in CI logs
- [ ] GitHub Actions uses `${{ secrets.X }}` — no hardcoded values
- [ ] No `.env` files in git history

### 14. Mobile Certificate Pinning
- [ ] Certificate pinning on auth and payment endpoints
- [ ] Backup pin configured for cert rotation
- [ ] All API calls use HTTPS only

### 15. Deep Links
- [ ] Deep link route destinations validated against a whitelist
- [ ] Auth tokens never passed in deep link URLs
- [ ] Intent filters (Android) / URL schemes (iOS) scoped to expected hosts

### 16. SRI
- [ ] All external CDN scripts have `integrity` attribute
- [ ] SRI hashes pinned to specific versions

### 17. Exposed Paths
- [ ] `/.git/config` returns 403/404
- [ ] `/.env` returns 403/404
- [ ] Health endpoints expose no version or config info
- [ ] No `/debug` or `/admin` endpoints publicly accessible

### 18. SQL & Database Security
- [ ] No string interpolation in SQL queries — parameterized queries or ORM only
- [ ] No `$queryRawUnsafe` / `knex.raw` / `repo.query` with template literals
- [ ] App connects as a least-privilege user — not `postgres` / `root` / superuser
- [ ] Read-only DB user used for analytics/reporting queries
- [ ] Row-Level Security (RLS) enabled on all per-user tables in PostgreSQL
- [ ] `FORCE ROW LEVEL SECURITY` set on RLS tables
- [ ] API routes use `select` to return only needed fields — no `SELECT *` to client
- [ ] Sensitive columns never returned: `password_hash`, `reset_token`, `mfa_secret`
- [ ] All list endpoints have a server-enforced `LIMIT` / `take` cap
- [ ] Database port not reachable from the public internet
- [ ] Database connections use SSL in production (`sslmode=require`)
- [ ] For MongoDB: user input cast to expected types before use in queries — never pass raw body objects

### Post-fix (after finding any issue)
1. Rotate the exposed credential immediately — assume compromised
2. Remove from client code and env config
3. Add as server-only env var in deployment platform
4. Clean git history with `git filter-repo` if committed
5. Restrict remaining client-facing keys in vendor console
6. Re-run detection commands to confirm clean
