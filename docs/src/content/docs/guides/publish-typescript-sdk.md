---
title: Publish TypeScript SDK
description: Maintainer guide for versioning and publishing the authx TypeScript SDK packages.
---

This guide documents the exact maintainer flow for the TypeScript SDK line:

- `@authx/sdk`
- `@authx/sdk-web`
- `@authx/sdk-react`
- `@authx/sdk-vue`

The repository now uses a two-stage process:

1. Changesets creates a version PR for the JavaScript packages.
2. A release tag triggers the existing release workflow, which publishes the npm packages.

## Prerequisites

Before the first publish, confirm:

- the npm organization/package names are available
- `NPM_TOKEN` is configured in GitHub repository secrets
- the release workflow on `main` has permission to publish with provenance
- package metadata is correct in each `packages/authx-sdk-*/package.json`

## Day-to-day release flow

### 1. Create a changeset

From the repository root:

```bash
npm install
npx changeset
```

Choose the four TypeScript packages when the public SDK line changes. They are linked and should version together.

Commit the generated file in `.changeset/`.

### 2. Merge the version PR

The `JS Versioning` GitHub workflow opens or updates a PR on `main` that:

- bumps package versions
- updates internal dependency ranges
- prepares the package metadata for release

Merge that PR once CI is green.

### 3. Verify release readiness on `main`

Optional local verification:

```bash
cd packages/authx-sdk-ts && npm run pack:check
cd ../authx-sdk-web && npm run pack:check
cd ../authx-sdk-react && npm run pack:check
cd ../authx-sdk-vue && npm run pack:check
cd ../../docs && npm run build
```

### 4. Create the release tag

Use the shared linked package version from the merged version PR:

```bash
git checkout main
git pull --ff-only
git tag v0.1.0
git push origin v0.1.0
```

Replace `0.1.0` with the version prepared by Changesets.

### 5. Watch the release workflow

`Release` now does all of the following:

- runs the Rust release gates
- runs JS package tests and `npm pack --dry-run`
- verifies generated TypeScript API docs
- publishes each npm package if that exact version is not already on npm
- publishes the Rust crates
- creates the GitHub release

## First npm publish checklist

For the first publish specifically:

1. Confirm the four package names on npm.
2. Confirm `publishConfig.access` is `public` for scoped packages.
3. Confirm `repository`, `homepage`, and `bugs` fields point at this repo.
4. Confirm `npm view @authx/sdk version` and the other three names do not already contain the target version.
5. Merge the Changesets version PR.
6. Push the matching `vX.Y.Z` tag.
7. Confirm the workflow publishes:
   - `@authx/sdk`
   - `@authx/sdk-web`
   - `@authx/sdk-react`
   - `@authx/sdk-vue`

## Notes

- The docs API reference is generated from emitted `.d.ts` files via `scripts/generate-ts-api-docs.mjs`.
- `docs/package.json` runs that generator as part of `npm run build`.
- The npm release remains tag-driven on purpose so JS package publication stays aligned with the repo-wide release event.
