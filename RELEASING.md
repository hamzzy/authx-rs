# Releasing `authx-rs`

This document describes the process for releasing new versions of the crates in this workspace.

## Prerequisites
- All PRs merged into `main`.
- `CRATES_IO_TOKEN` configured in GitHub Repository Secrets.

## Release Process

### 1. Update Versions
Bump the version in the root `Cargo.toml`. Since we use workspace inheritance, this will update all member crates.

```toml
[workspace.package]
version = "0.X.Y"
```

### 2. Update Documentation
Ensure the `CHANGELOG.md` (if any) or `README.md` is updated with the new version's highlights.

### 3. Create a Tag
Following semantic versioning, create a tag prefixed with `v`.

```bash
git tag -a v0.X.Y -m "Release v0.X.Y"
```

### 4. Push the Tag
Push the tag to the remote repository.

```bash
git push origin v0.X.Y
```

## Automation
Pushing a `v*` tag triggers the `release.yml` GitHub Action, which:
1. Builds and tests the workspace.
2. Publishes all crates to crates.io in the correct dependency order.
3. Automatically waits for the index to update between publishes.

> [!IMPORTANT]
> If a publish fail midway, you can resume by manually running the remaining `cargo publish -p <crate>` commands or re-triggering the action if you delete and re-push the tag.
