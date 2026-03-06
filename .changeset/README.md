This directory stores pending changesets for the TypeScript SDK packages.

Typical maintainer flow:

1. Run `npm install` at the repository root.
2. Run `npx changeset`.
3. Commit the generated markdown file in this directory.
4. Let the `JS Versioning` workflow open or update the version PR.
5. Merge the version PR, then push the matching `vX.Y.Z` tag to trigger publication.
