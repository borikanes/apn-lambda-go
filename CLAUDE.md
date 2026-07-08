# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A single Go AWS Lambda that sends APN (Apple Push Notification) pushes for the "Song Updater" iOS app. It is invoked over API Gateway (`ho7won2i0j`, path `/send-notifications`) by the `fetch-new-song` lambda in the `spotify-lambdas` repo (`/Users/borikanes/Code/spotify-lambdas`).

The same code is deployed to **two** lambda functions, selected by an API Gateway stage variable (`lambdaFunctionName`):

| Function | Stage | APNs endpoint | App |
|---|---|---|---|
| `APNProd` | prod | `api.push.apple.com` | `me.borikanes.SongUpdater` |
| `APNTester` | QA | `api.development.push.apple.com` (sandbox) | `me.borikanes.SongUpdaterQA` |

The endpoint is chosen **by bundle ID** in `formRequestObject` (main.go): `me.borikanes.SongUpdaterQA` → sandbox, anything else → production.

## Build & Deploy

Runtime is `provided.al2023` (migrated from the deprecated `go1.x` in July 2026). The handler is a custom-runtime binary that must be named `bootstrap`:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags lambda.norpc -o bootstrap main.go
zip -j apn-lambda.zip bootstrap AuthKey_<KEY_ID>.p8
aws lambda update-function-code --function-name APNProd --zip-file fileb://apn-lambda.zip
```

The `.p8` signing key **must be inside the zip** — the lambda reads it from the package at the path in `PRIVATE_KEY_FILE_NAME`.

## Environment Variables (set on each lambda)

- `TEAM_ID` — Apple Developer Team ID (`7B6H8LADVH`)
- `KEY_ID` — APNs auth key ID (as of July 2026: `4BARAYGJD2`, scoped Sandbox & Production, shared by both lambdas)
- `PRIVATE_KEY_FILE_NAME` — filename of the bundled `.p8` (e.g. `AuthKey_4BARAYGJD2.p8`)

## Event Payload

```json
{ "message": "...", "deviceToken": "<hex>", "bundleID": "me.borikanes.SongUpdater" }
```

## APNs Facts That Have Bitten Us Before

- **`403 {"reason":"InvalidProviderToken"}`** means the signing key/JWT is bad — check that the `.p8` content actually matches the KEY_ID at Apple and that TEAM_ID is right. In July 2026 both old keys (`295Z45J4K2`, `G97YVCGY52`) were rejected this way and had to be replaced with a fresh key; `.p8` files can only be downloaded from Apple **once**, and the team is limited to 2 active APNs keys.
- **Provider JWTs expire after 1 hour** but must not be regenerated more than once per ~20 minutes (`TooManyProviderTokenUpdates`). `ensureFreshToken` regenerates at 50 minutes; warm lambda containers outlive the token, so age-based refresh is required (init-only generation is not enough).
- **An `*http.Request` is single-use.** Re-sending one after its body was consumed causes an HTTP/2 `PROTOCOL_ERROR` — always rebuild via `formRequestObject` before a retry.
- **Xcode-installed builds register sandbox device tokens** (even with the prod bundle ID); only TestFlight/App Store installs get production tokens. Sending a sandbox token to the production endpoint returns `400 {"reason":"BadDeviceToken"}` — that's an environment mismatch, not a corrupt token.
- Always log the APNs **response body**; the `{"reason":...}` inside is the only way to tell 403/400/404 causes apart.
- Never log the JWT or the Authorization header.
