# Release Checklist

Use this checklist for every Mini-SIEM release. A release commit is eligible for tagging only when the GitHub Actions `release-gate` job is green.

## Prepare the release commit

- [ ] Choose the semantic version and release date.
- [ ] Add a dated `## [x.y.z] - YYYY-MM-DD` entry to `CHANGELOG.md`.
- [ ] Synchronize the version and release links in `README.md`.
- [ ] Update `.env.example` and operational documentation for changed configuration.
- [ ] Document migrations, upgrade notes, and known limitations.
- [ ] Confirm `.env`, `data/**`, and `logs/**` are not tracked.
- [ ] Review every active `.gitleaksignore` fingerprint and record why it remains necessary.

## Verify from a clean clone

```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git mini-siem-release-check
cd mini-siem-release-check
cp .env.example .env
docker compose --profile train config --quiet
```

- [ ] `baseline` passes syntax, Compose, and regression checks.
- [ ] `docker-smoke` builds the image and verifies `/health`, dashboard startup, and SQLite.
- [ ] `security` passes Gitleaks, dependency audit, and runtime-file tracking checks.
- [ ] `release-gate` passes release-artifact and clean-clone checks.
- [ ] No real Ollama key, webhook, collector secret, or response action is used by CI.

## Tag and publish

Run these commands only from the verified release commit:

```bash
git status --short
git tag -a vX.Y.Z -m "Mini-SIEM vX.Y.Z"
git push origin <release-branch>
git push origin vX.Y.Z
```

- [ ] Working tree is clean before tagging.
- [ ] The annotated tag points to the green release commit.
- [ ] The pushed tag's GitHub Actions run is green.
- [ ] The published changelog and release notes match the tag.

Tag creation and push remain explicit repository-owner actions; CI validates readiness but does not publish a release automatically.
