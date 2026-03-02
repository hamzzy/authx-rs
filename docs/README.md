# authx-rs Documentation

This directory contains the authx-rs documentation site, built with [Starlight](https://starlight.astro.build) (Astro).

## Local development

```bash
cd docs
pnpm install
pnpm dev        # http://localhost:4321
```

## Build

```bash
pnpm build      # output in docs/dist/
pnpm preview    # preview the production build
```

## Structure

```
docs/
  src/
    content/docs/     # all .md / .mdx pages
    assets/           # logos and images
    styles/           # custom CSS (accent colours)
  astro.config.mjs    # sidebar, site metadata
  package.json
```

## Adding a page

1. Create a `.md` file under `src/content/docs/<section>/`.
2. Add a frontmatter `title:` and optionally `description:`.
3. Add it to the `sidebar` array in `astro.config.mjs`.

Pages are automatically available at the corresponding URL path.
