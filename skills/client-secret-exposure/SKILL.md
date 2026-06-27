---
name: client-secret-exposure
description: Use when auditing any project for secrets exposed in client-side code — web JS bundles, mobile app binaries (Flutter, React Native, iOS, Android), or git history. Triggers on leaked API keys, hardcoded credentials, NEXT_PUBLIC_ variables, reverse-engineered APKs, payment credentials in source code, or questions about what is safe to ship in client code.
---

# Client Secret Exposure

## Overview

Any secret embedded in code that runs on a user's device — browser JavaScript, a Flutter app, a React Native bundle, an iOS/Android binary — can be extracted. There is no such thing as a hidden client-side secret. The fix is always one of two things: move it server-side, or confirm it is public by design.

---

## Where Secrets Hide by Platform

### Web (React, Next.js, Vue, Angular)
- `NEXT_PUBLIC_` env vars (Next.js) are statically baked into the JS bundle at build time
- Keys in image URLs (`<img src="...key=XYZ">`) are visible in raw HTML without DevTools
- Any secret in `process.env.NEXT_PUBLIC_*` is readable via F12 → Sources → Search

```bash
# Find all public env vars baked into the Next.js bundle
grep -oh "NEXT_PUBLIC_[A-Z_]*" .next/static/chunks/*.js | sort -u

# Search for a known key value in the bundle
grep -rl "YOUR_KEY_VALUE" .next/static/

# Find keys hardcoded in fetch/image URLs
grep -r "key=" src/ --include="*.tsx" --include="*.ts" --include="*.js"
```

### Flutter / Dart
- Strings hardcoded in `lib/` are compiled into the binary
- `dart-define` values and `.env` files bundled as assets are extractable

```bash
# Extract strings from Flutter APK
unzip app-release.apk -d apk_out
strings apk_out/lib/arm64-v8a/libapp.so | grep -Ei "(key|secret|password|token|api)"

# Search source
grep -r "apiKey\|secretKey\|password\|Bearer\|token" lib/ --include="*.dart"
```

### React Native
- The JS bundle is embedded in the APK/IPA — readable with basic tools
- `.env` values from `react-native-config` are compiled into the JS bundle

```bash
unzip app-release.apk assets/index.android.bundle -d rn_out
grep -o '"[A-Za-z_]*[Kk]ey[^"]*"' rn_out/assets/index.android.bundle | head -20
```

### iOS / Android Native
```bash
strings MyApp.ipa | grep -Ei "(key|secret|token|password)"
```

### Git History (any platform)
Secrets deleted from code are still in git history.

```bash
# Search all history for a specific value
git log -S "YOUR_KEY_VALUE" --all --oneline

# Broad pattern search across all commits
git grep -E "(apiKey|secret|password|Bearer)" $(git rev-list --all)
```

---

## Classification — Safe vs Dangerous

| Key Type | Safe in Client? | Reason |
|---|---|---|
| Stripe `pk_live_` / `pk_test_` | ✅ Yes | Publishable key — designed for client use |
| Google Analytics / GA4 ID | ✅ Yes | Tracking identifier, cannot access data |
| Google Tag Manager ID | ✅ Yes | Container ID, public by design |
| reCAPTCHA site key | ✅ Yes | Required client-side; secret key stays server |
| Intercom / Crisp App ID | ✅ Yes | Widget identifier only |
| Sentry DSN | ✅ Yes | Error reporting only; auth token is separate |
| Adjust / AppsFlyer / attribution tokens | ✅ Yes | Write-only attribution identifier |
| Firebase API key | ⚠️ Partial | Public by design; security requires App Check + Security Rules |
| Google Maps API key | ⚠️ Needs restriction | Restrict in Cloud Console AND proxy server-side |
| Analytics write keys (Customer.io, Segment) | ⚠️ Medium | Attacker can inject fake events |
| Payment gateway credentials (username/password/secret) | ❌ Never | Server-side only |
| OAuth client secrets | ❌ Never | Only OAuth Client IDs are safe client-side |
| Database connection strings | ❌ Never | Direct DB access from client is always wrong |
| Private API keys / service account keys | ❌ Never | Any key with write or admin scope |
| Anything named "secret" or "password" | ❌ Never | Self-explanatory |

---

## Fix Patterns

### Pattern 1 — Backend-for-Frontend (BFF) proxy
Your client calls **your own backend**, which calls the third-party API with the secret. Works for every platform.

**Web — Next.js API route:**
```ts
// src/app/api/payment/route.ts
export async function POST(request: NextRequest) {
  const key = process.env.PAYMENT_SECRET_KEY; // server-only, no NEXT_PUBLIC_
  const body = await request.json();
  const response = await fetch('https://api.payment-gateway.com/charge', {
    method: 'POST',
    headers: { Authorization: `Basic ${key}` },
    body: JSON.stringify(body),
  });
  return NextResponse.json(await response.json());
}
```

**Flutter / Mobile — call your own backend:**
```dart
// Client calls YOUR backend, not the third-party API directly
final response = await http.post(
  Uri.parse('https://api.yourapp.com/payment/charge'),
  headers: {'Authorization': 'Bearer $userToken'},
  body: jsonEncode({'amount': amount}),
);
// Your backend holds the payment secret and calls the gateway server-side
```

**Node.js / Express backend:**
```js
app.post('/api/payment/charge', authenticate, async (req, res) => {
  const secret = process.env.PAYMENT_SECRET_KEY; // from environment
  const result = await paymentGateway.charge({ ...req.body, apiKey: secret });
  res.json(result);
});
```

### Pattern 2 — Static image/asset URL with API key
Keys embedded in image src URLs are visible in raw HTML without DevTools. Proxy them:

```ts
// Next.js — same BFF pattern applies for Express/Fastify/any backend
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const lat = parseFloat(searchParams.get('lat') ?? '');
  const lng = parseFloat(searchParams.get('lng') ?? '');

  if (isNaN(lat) || isNaN(lng)) return NextResponse.json({ error: 'Bad coords' }, { status: 400 });

  const key = process.env.GOOGLE_API_KEY; // server-only
  const url = `https://maps.googleapis.com/maps/api/staticmap?center=${lat},${lng}&zoom=18&size=600x400&key=${key}`;
  const img = await fetch(url);
  return new NextResponse(await img.arrayBuffer(), {
    headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' },
  });
}
// Component/app uses: /api/maps/static?lat=...&lng=...
```

### Pattern 3 — Environment variables (never hardcode)

| Platform | Correct approach |
|---|---|
| Next.js / Node | Server-only `.env` vars — no `NEXT_PUBLIC_` prefix |
| Flutter | Fetch config from your own backend at app start — not `dart-define` or bundled `.env` |
| React Native | Server-fetched config on launch — not `.env` files or `react-native-config` for secrets |
| Backend | OS environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler) |
| CI/CD | Repository secrets (GitHub Actions Secrets, Vercel Env Vars) — never committed to code |

### Pattern 4 — Firebase (cannot be hidden — secure differently)
Firebase config must be client-side for the SDK. Two required layers:

1. **Firebase App Check** — Firebase servers reject all requests without a valid cryptographic token
   - Web: reCAPTCHA Enterprise | Android: Play Integrity | iOS: DeviceCheck
   - Firebase Console → App Check → Register → **monitoring mode first**, then **Enforce**

2. **Security Rules** minimum:
   ```js
   allow read, write: if request.auth != null;
   ```

3. Restrict the Firebase API key in Google Cloud Console to only the needed APIs.

---

## CORS vs Real Server Enforcement

`Access-Control-Allow-Origin: yourapp.com` does **not** protect your API.

| | CORS | App Check / Server Auth |
|---|---|---|
| Enforced by | **Browser** | **Your server** |
| Bypassed by curl / Postman / scripts | **Yes** | No |
| Protects APIs from automation | No | Yes |

CORS only prevents a browser tab on site A from reading a response from site B. Any server-to-server request ignores it completely.

---

## Base64 is Not Encryption

`atob("dXNlcjpwYXNz")` decodes to `"user:pass"` in 2 seconds in any browser console. Rotate and proxy any Base64-encoded credentials found in client code.

---

## Post-fix Checklist

1. **Rotate** the exposed key with the vendor — assume it is already compromised
2. **Remove** it from client code and environment config
3. **Add** as a server-only environment variable in your deployment platform
4. **Deploy** and verify:
   - Web: `grep -r "YOUR_OLD_KEY" .next/static/` → nothing
   - Mobile: re-run the `strings` / APK extraction commands above
5. **Clean git history** if the key was committed — use `git filter-repo` or BFG Repo Cleaner
6. **Restrict** any remaining client-facing keys in the vendor console (domain, app, IP, API scope)
