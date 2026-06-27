# client-secret-exposure — Claude Skill

A Claude Code skill for auditing **any** project — web, Flutter, React Native, iOS, Android, backend — for secrets exposed in client-side code.

## Install

```bash
/plugin marketplace add ahmadalhaish-tickit/tickit-claude-marketplace
/plugin install client-secret-exposure@tickit-claude-marketplace
```

## What it covers

| Platform | What it detects |
|---|---|
| Web (Next.js, React, Vue) | `NEXT_PUBLIC_` vars baked into JS bundle, keys in image URLs |
| Flutter / Dart | Hardcoded strings in `lib/`, `dart-define` values in APK binary |
| React Native | Secrets in embedded JS bundle inside APK/IPA |
| iOS / Android native | Strings in compiled binary |
| Any platform | Secrets in git history |

## Skill topics

| Topic | Detail |
|---|---|
| Detection | grep commands per platform — bundle, binary, git history |
| Classification | 15+ key types — safe vs dangerous vs partial |
| BFF proxy pattern | Client calls your backend, your backend calls the API |
| Image URL proxy | For keys embedded in `<img src>` or static asset URLs |
| Environment variables | Correct approach per platform (Next.js, Flutter, RN, backend) |
| Firebase | App Check + Security Rules — the right way to secure Firebase |
| CORS vs server auth | Why `Access-Control-Allow-Origin` does not protect APIs |
| Base64 warning | Not encryption — decoded in 2 seconds |
| Post-fix checklist | Rotate, remove, deploy, verify, clean history, restrict |

## Usage

After installing, ask Claude:

```
audit this project for exposed secrets
```
```
check our Flutter app for hardcoded API keys
```
```
is this key safe to put in the client bundle?
```

## License

MIT
