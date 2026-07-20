# LucidCode GitHub App

Posts LucidCode confessions as PR reviews on any repo where the app is installed.

## What it does

On every `pull_request` (opened / synchronize / reopened):

1. Shallow-clones the PR head into a temp dir.
2. Runs `python -m lucidcode.cli analyze . --json --min-verdict LIKELY`.
3. Groups findings per file and posts a single collapsible PR review.
4. Reports a `LucidCode` check-run so branch protection can gate on it.

If any `TRUTH`-verdict confession is present, the review is filed as
`REQUEST_CHANGES` (configurable).

## Per-repo config

Create `.github/lucidcode.yml` in the target repo:

```yaml
min_verdict: LIKELY          # TRUTH | LIKELY | DISPUTED
request_changes_on: TRUTH    # TRUTH | LIKELY | never
fail_check_on: TRUTH         # controls the "LucidCode" check-run conclusion
```

## Deploy

### Local (Probot dev mode)

```bash
cd extensions/github-app
npm install
export APP_ID=...
export PRIVATE_KEY="$(cat private-key.pem)"
export WEBHOOK_SECRET=...
export LUCID_PYTHON=$(which python)
npm run dev
```

### Docker

From the repo root:

```bash
docker build -f extensions/github-app/Dockerfile -t lucidcode-app .
docker run --rm -p 3000:3000 \
  -e APP_ID=... \
  -e PRIVATE_KEY="$(cat private-key.pem)" \
  -e WEBHOOK_SECRET=... \
  lucidcode-app
```

## Permissions the app needs on install

- `contents`: **read** (to clone)
- `pull_requests`: **write** (to post reviews)
- `checks`: **write** (to publish the check-run)

## Events subscribed

- `pull_request` (opened, synchronize, reopened)

## Publishing to the GitHub Marketplace

1. Create a new GitHub App under your org.
2. Set the webhook URL to your deployed instance.
3. Fill out the manifest at https://github.com/settings/apps/new.
4. Once live, submit for Marketplace listing (requires org verification).
