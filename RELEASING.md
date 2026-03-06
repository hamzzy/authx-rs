# Releasing `authx-rs`

This document describes the release flow for both the Rust crates and the TypeScript SDK packages.

## Automation Overview

There are now two version-preparation workflows:

- `Rust Versioning` in `.github/workflows/rust-versioning.yml`
- `JS Versioning` in `.github/workflows/js-versioning.yml`

And one publish workflow:

- `Release` in `.github/workflows/release.yml`

The intended process is:

1. Merge normal feature/fix PRs into `main`.
2. Let the versioning workflows open/update release PRs.
3. Merge the release PRs.
4. Push a `vX.Y.Z` tag.
5. Let `Release` publish crates, npm packages, and create the GitHub release.

## Rust Crates

Rust versioning and changelog updates are prepared automatically with `release-plz`.

### What `Rust Versioning` does

On pushes to `main`, `release-plz`:

- computes the next crate versions
- updates `Cargo.toml` / `Cargo.lock`
- updates the root `CHANGELOG.md`
- opens or updates a release PR

The Rust changelog is configured in `release-plz.toml` and is written to the repository root `CHANGELOG.md`.

### Rust maintainer flow

1. Merge code changes into `main`.
2. Wait for the `Rust Versioning` workflow to open or refresh its PR.
3. Review the version bumps and changelog entries.
4. Merge that PR.
5. Tag the merged commit:

```bash
git checkout main
git pull --ff-only
git tag v0.X.Y
git push origin v0.X.Y
```

## TypeScript SDK Packages

TypeScript package versioning is prepared with Changesets.

See:

- `docs/src/content/docs/guides/publish-typescript-sdk.md`
- `.changeset/config.json`

## Publish Prerequisites

Before tagging a release, confirm:

- `CRATES_IO_TOKEN` is configured in GitHub repository secrets
- `NPM_TOKEN` is configured in GitHub repository secrets
- GitHub Actions has permission to create and update pull requests
- the release PRs for Rust and JS have already been merged

## Publish Step

Push a version tag:

```bash
git tag v0.X.Y
git push origin v0.X.Y
```

## What `Release` does

The tag-driven release workflow:

1. runs the JS SDK release gates
2. runs the Rust release gates
3. publishes the Rust crates to crates.io
4. publishes the npm packages
5. creates the GitHub release

## Notes

- The Rust GitHub release no longer depends on manually parsing `CHANGELOG.md`; it uses generated GitHub release notes.
- The root `CHANGELOG.md` is still maintained for the Rust workspace by `release-plz`.
- If a crates.io publish fails midway, the workflow is idempotent and can be re-run safely for already-published versions.
