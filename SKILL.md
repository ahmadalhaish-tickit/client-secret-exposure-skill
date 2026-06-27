---
name: nextjs-secret-exposure
description: Use when auditing a Next.js app for secrets exposed in the client bundle, reviewing leaked API keys, deciding whether a credential needs a server-side proxy, or assessing what is safe to expose in a browser. Triggers on NEXT_PUBLIC_ variables, security reviews, leaked key reports, or questions about client-side secret exposure.
---

# Next.js Secret Exposure

## Overview

In Next.js, any env var prefixed `NEXT_PUBLIC_` is **statically inlined into the client JS bundle at build time**. Every visitor can read these values in browser DevTools — no hacking required. The fix is never "hide it better" — it is either moving the secret server-side or confirming it is public by design.

## Detection

**Search the built bundle:**
```bash
# List all NEXT_PUBLIC_ vars baked into the bundle
grep -oh "NEXT_PUBLIC_[A-Z_]*" .next/static/chunks/*.js | sort -u

# Search for a known key value
grep -rl "YOUR_KEY_VALUE" .next/static/
```

**In the browser (no tools needed):**
F12 → Sources → Search (Ctrl+Shift+F) → type any key value

**Find keys hardcoded in `<img src>` or fetch URLs (visible in raw HTML):**
```bash
grep -r "api/staticmap\|googleapis.com.*key=" src/
```

## Classification

| Key Type | Safe in Bundle? | Reason |
|---|---|---|
| Stripe `pk_live_` / `pk_test_` | ✅ Yes | Publishable key — Stripe designed it for client use |
| Google Analytics / GA4 ID | ✅ Yes | Tracking identifier, cannot access private data |
| Google Tag Manager ID | ✅ Yes | Container identifier, public by design |
| reCAPTCHA site key | ✅ Yes | Required client-side; secret key stays server |
| Intercom App ID | ✅ Yes | Widget identifier only |
| Sentry DSN | ✅ Yes | Error reporting only; auth token is separate |
| Adjust / attribution tokens | ✅ Yes | Attribution identifiers, write-only |
| Firebase API key | ⚠️ Partial | Key is public by design; security comes from App Check + Security Rules |
| Google Maps API key | ⚠️ Needs restriction | Must be restricted in Cloud Console AND proxied server-side |
| Analytics write keys (Customer.io) | ⚠️ Medium | Can inject fake events; move server-side if automations are critical |
| Payment gateway credentials (username / password) | ❌ Never | Must be server-side only |
| OAuth client secrets | ❌ Never | Only OAuth Client IDs are safe client-side |
| Any key named "secret" or "password" | ❌ Never | Self-explanatory |

## Fix Patterns

### Pattern 1 — Server-side proxy for any secret key

Remove `NEXT_PUBLIC_` from the env var name, create an API route:

```ts
// src/app/api/payment/route.ts
import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const key = process.env.WHISH_API_KEY; // server-only — no NEXT_PUBLIC_
  const body = await request.json();
  const response = await fetch('https://api.whish.money/...', {
    method: 'POST',
    headers: { Authorization: `Basic ${key}` },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  return NextResponse.json(data);
}
```

Browser calls `/api/payment` — credential never leaves the server.

### Pattern 2 — Static image URL with API key (visible in raw HTML)

Keys embedded directly in `<img src="...key=XYZ">` are exposed without DevTools — readable in the page source. Use a proxy route:

```ts
// src/app/api/maps/static/route.ts
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const lat = parseFloat(searchParams.get('lat') ?? '');
  const lng = parseFloat(searchParams.get('lng') ?? '');

  if (isNaN(lat) || isNaN(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
    return NextResponse.json({ error: 'Invalid coordinates' }, { status: 400 });
  }

  const key = process.env.GOOGLE_API_KEY; // server-only
  const url = `https://maps.googleapis.com/maps/api/staticmap?center=${lat},${lng}&zoom=18&size=600x400&maptype=roadmap&markers=color:red%7C${lat},${lng}&key=${key}`;
  const response = await fetch(url);
  const buffer = await response.arrayBuffer();

  return new NextResponse(buffer, {
    headers: {
      'Content-Type': response.headers.get('Content-Type') || 'image/png',
      'Cache-Control': 'public, max-age=86400',
    },
  });
}
```

Component uses `src="/api/maps/static?lat=...&lng=..."` — key never reaches client.

**If you used `useJsApiLoader` only to check if maps loaded, but only render a static image:** remove `useJsApiLoader` entirely. The JS Maps SDK is not needed for static image URLs.

### Pattern 3 — Firebase API key (cannot be hidden)

Firebase config must be client-side for the SDK to work. Security comes from two independent layers:

1. **Firebase App Check** — enforced by Firebase servers, blocks all SDK usage from off-domain origins
   - Firebase Console → App Check → Register web app → reCAPTCHA Enterprise
   - Enable **monitoring mode** for 1–2 days first, then switch to **Enforce**
   - Even Postman/curl cannot generate a valid App Check token without running real reCAPTCHA

2. **Firestore Security Rules** — minimum required:
   ```js
   allow read, write: if request.auth != null;
   ```

3. **Google Cloud Console** — restrict the Firebase API key to only the APIs it needs

## CORS vs App Check

A common confusion: many Firebase Cloud Functions return `Access-Control-Allow-Origin: tickit.co` headers. This does NOT secure the API.

| | CORS | App Check |
|---|---|---|
| Enforced by | **Browser** | **Firebase servers** |
| Can bypass with curl / Postman | **Yes** — completely | **No** |
| Prevents off-domain SDK use | No | Yes |
| Is the real protection | No | Yes |

CORS only stops one website from reading another website's response in a shared browser tab. A script running outside a browser (curl, Postman, Python `requests`) ignores CORS entirely.

## Base64 is not encryption

Credentials stored as Base64 (`atob(value)` in the browser console) are decoded in 2 seconds. It is obfuscation, not security. Rotate and proxy any Base64-encoded credentials found in client bundles.

## Common Mistakes

- **Rotating keys without fixing the code** — the new key gets inlined in the next build
- **Moving to `.env.local` without removing `NEXT_PUBLIC_`** — the value is still in the bundle
- **Assuming referer-lock solves Google API key exposure** — referer headers are spoofable by server-side requests
- **Using `useJsApiLoader` when only rendering a static map image** — loads the full JS Maps SDK unnecessarily

## Checklist After Fixing

1. Remove old env var from Vercel dashboard (Settings → Environment Variables)
2. Add new server-only var (no `NEXT_PUBLIC_` prefix) to Vercel
3. Trigger a new Vercel deployment
4. Verify key is gone from bundle:
   ```bash
   grep -r "YOUR_OLD_KEY_VALUE" .next/static/
   # should return nothing
   ```
5. Open F12 → Network → reload page → confirm the route returns the proxied response
