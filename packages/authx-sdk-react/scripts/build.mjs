import { spawnSync } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const distDir = path.join(packageRoot, "dist");
const tscBinary = resolveTscBinary();

await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });

runTsc("tsconfig.esm.json");
runTsc("tsconfig.types.json");

function runTsc(projectFile) {
  const result = spawnSync(tscBinary, ["-p", projectFile], {
    cwd: packageRoot,
    stdio: "inherit",
  });

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function resolveTscBinary() {
  const binaryName = process.platform === "win32" ? "tsc.cmd" : "tsc";
  const candidates = [
    path.join(packageRoot, "node_modules", ".bin", binaryName),
    path.join(packageRoot, "..", "authx-sdk-ts", "node_modules", ".bin", binaryName),
  ];

  for (const candidate of candidates) {
    const result = spawnSync(candidate, ["--version"], {
      cwd: packageRoot,
      stdio: "ignore",
    });

    if (result.status === 0) {
      return candidate;
    }
  }

  throw new Error("TypeScript compiler was not found in local package dependencies");
}
