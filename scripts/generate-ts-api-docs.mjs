import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const outputDir = path.join(
  repoRoot,
  "docs",
  "src",
  "content",
  "docs",
  "reference",
  "typescript",
);

const packages = [
  {
    name: "@authx-rs/sdk",
    slug: "sdk",
    packageDir: path.join(repoRoot, "packages", "authx-sdk-ts"),
    summary: "Low-level OIDC, JWKS, PKCE, device, and browser-session helpers.",
  },
  {
    name: "@authx-rs/sdk-web",
    slug: "sdk-web",
    packageDir: path.join(repoRoot, "packages", "authx-sdk-web"),
    summary: "Browser token storage, authenticated fetch, and refresh orchestration.",
  },
  {
    name: "@authx-rs/sdk-react",
    slug: "sdk-react",
    packageDir: path.join(repoRoot, "packages", "authx-sdk-react"),
    summary: "React provider and hooks for authx token clients.",
  },
  {
    name: "@authx-rs/sdk-vue",
    slug: "sdk-vue",
    packageDir: path.join(repoRoot, "packages", "authx-sdk-vue"),
    summary: "Vue plugin and composable for authx token clients.",
  },
];

await rm(outputDir, { recursive: true, force: true });
await mkdir(outputDir, { recursive: true });

for (const pkg of packages) {
  const sections = await readPublicDeclarations(pkg.packageDir);
  await writeFile(
    path.join(outputDir, `${pkg.slug}.md`),
    renderPackagePage(pkg, sections),
    "utf8",
  );
}

await writeFile(path.join(outputDir, "index.md"), renderIndexPage(packages), "utf8");

async function readPublicDeclarations(packageDir) {
  const typesDir = path.join(packageDir, "dist", "types");
  const indexFile = path.join(typesDir, "index.d.ts");
  const indexContents = await readFile(indexFile, "utf8");

  const moduleNames = extractExportedModules(indexContents);
  if (moduleNames.length === 0) {
    return [
      {
        moduleName: "index",
        declarations: extractDeclarations(indexContents),
      },
    ];
  }

  const sections = [];
  for (const moduleName of moduleNames) {
    const moduleFile = path.join(typesDir, `${moduleName}.d.ts`);
    const contents = await readFile(moduleFile, "utf8");
    sections.push({
      moduleName,
      declarations: extractDeclarations(contents),
    });
  }
  return sections;
}

function extractExportedModules(contents) {
  return Array.from(
    contents.matchAll(/^export \* from "\.\/([^"]+)\.js";$/gm),
    (match) => match[1],
  );
}

function extractDeclarations(contents) {
  const declarations = [];
  const lines = contents.split("\n");
  let buffer = [];
  let depth = 0;
  let inExport = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!inExport) {
      if (!trimmed.startsWith("export ") || trimmed === "export {};") {
        continue;
      }
      inExport = true;
      buffer = [line];
      depth += countBraces(line);
      if (isTerminalDeclaration(trimmed, depth)) {
        declarations.push(toDeclaration(buffer));
        buffer = [];
        depth = 0;
        inExport = false;
      }
      continue;
    }

    buffer.push(line);
    depth += countBraces(line);
    if (isTerminalDeclaration(trimmed, depth)) {
      declarations.push(toDeclaration(buffer));
      buffer = [];
      depth = 0;
      inExport = false;
    }
  }

  return declarations;
}

function toDeclaration(lines) {
  const signature = lines[0].trim();
  const kind = detectKind(signature);
  const name = detectName(signature, kind);
  const rendered = renderDeclaration(lines, kind);
  return { name, kind, rendered };
}

function detectKind(signature) {
  if (signature.startsWith("export interface ")) {
    return "interface";
  }
  if (signature.startsWith("export declare class ")) {
    return "class";
  }
  if (signature.startsWith("export declare function ")) {
    return "function";
  }
  if (signature.startsWith("export declare const ")) {
    return "const";
  }
  if (signature.startsWith("export type ")) {
    return "type";
  }
  return "export";
}

function detectName(signature, kind) {
  const patterns = {
    interface: /^export interface ([A-Za-z0-9_]+)/,
    class: /^export declare class ([A-Za-z0-9_]+)/,
    function: /^export declare function ([A-Za-z0-9_]+)/,
    const: /^export declare const ([A-Za-z0-9_]+)/,
    type: /^export type ([A-Za-z0-9_]+)/,
    export: /^export ([A-Za-z0-9_]+)/,
  };

  return signature.match(patterns[kind])?.[1] ?? signature;
}

function renderDeclaration(lines, kind) {
  const filtered =
    kind === "class"
      ? lines.filter((line) => !line.trim().startsWith("private "))
      : lines;

  return filtered.join("\n").trim();
}

function isTerminalDeclaration(trimmed, depth) {
  if (depth > 0) {
    return false;
  }

  return (
    trimmed.endsWith(";") ||
    trimmed === "}" ||
    trimmed === "};" ||
    trimmed.endsWith("}")
  );
}

function countBraces(line) {
  let count = 0;
  for (const char of line) {
    if (char === "{") {
      count += 1;
    } else if (char === "}") {
      count -= 1;
    }
  }
  return count;
}

function renderIndexPage(packages) {
  return `---
title: "TypeScript API"
description: "Generated API reference for the authx TypeScript SDK packages."
---

This section is generated from the emitted \`.d.ts\` files for the TypeScript SDK packages.

## Packages

${packages
  .map((pkg) => `- [\`${pkg.name}\`](./${pkg.slug}/) — ${pkg.summary}`)
  .join("\n")}
`;
}

function renderPackagePage(pkg, sections) {
  const moduleText = sections
    .map((section) => renderModuleSection(section))
    .join("\n\n");

  return `---
title: "${pkg.name}"
description: "Generated API reference for ${pkg.name}."
---

Generated from \`${path.relative(repoRoot, pkg.packageDir)}/dist/types\`.

${pkg.summary}

## Modules

${sections.map((section) => `- [\`${section.moduleName}\`](#${slugify(section.moduleName)})`).join("\n")}

${moduleText}
`;
}

function renderModuleSection(section) {
  const declarations = section.declarations
    .map(
      (declaration) => `#### \`${declaration.name}\`

\`\`\`ts
${declaration.rendered}
\`\`\``,
    )
    .join("\n\n");

  return `### ${section.moduleName}

${declarations || "No exported declarations found."}`;
}

function slugify(value) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
