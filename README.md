# nextjs-secret-exposure — Claude Skill

A Claude Code skill that audits Next.js apps for secrets exposed in the client-side JavaScript bundle.

## Install

```bash
/plugin marketplace add ahmadalhaish-tickit/tickit-claude-marketplace
/plugin install nextjs-secret-exposure@tickit-claude-marketplace
```

That's it. Claude Code loads the skill automatically from that point on.

## What it does

When you ask Claude to audit your Next.js project for leaked secrets, this skill teaches it:

- How to detect `NEXT_PUBLIC_` variables baked into the JS bundle
- Which credentials are **dangerous** (payment credentials, API secrets) vs **public by design** (Stripe publishable key, GTM ID, reCAPTCHA site key)
- How to implement a **server-side proxy route** for secrets that must never reach the browser
- The difference between **CORS** (browser-enforced, bypassable) and **Firebase App Check** (server-enforced, cannot be faked)
- A post-fix verification checklist for Vercel deployments

## What the skill covers

| Topic | Detail |
|---|---|
| Detection | `grep` commands for bundle and raw HTML |
| Classification | Table of 12+ key types — dangerous vs safe |
| Fix Pattern 1 | Server-side proxy for payment/API credentials |
| Fix Pattern 2 | Image URL proxy for Google Maps static API |
| Fix Pattern 3 | Firebase App Check + Firestore Security Rules |
| CORS vs App Check | Why CORS does not protect Firebase APIs |
| Base64 warning | Not encryption — decoded in 2 seconds |
| Verification | Post-fix checklist for Vercel deployment |

## Usage

After installing, just ask Claude:

```
audit this Next.js project for exposed secrets
```

or

```
check if any NEXT_PUBLIC_ variables contain secrets
```

## License

MIT
