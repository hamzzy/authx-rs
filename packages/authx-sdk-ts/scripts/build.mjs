import { spawnSync } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const distDir = path.join(packageRoot, "dist");
const tscBinary = path.join(
  packageRoot,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "tsc.cmd" : "tsc",
);

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
