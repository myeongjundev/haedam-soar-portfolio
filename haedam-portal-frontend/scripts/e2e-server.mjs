import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
const frontend = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const backend = path.resolve(frontend, "../haedam-portal-backend");
const python = path.join(
  backend,
  process.platform === "win32"
    ? ".venv/Scripts/python.exe"
    : ".venv/bin/python",
);
const child = spawn(python, [path.join(backend, "tools/e2e_server.py")], {
  cwd: backend,
  stdio: "inherit",
});
child.on("exit", (code) => process.exit(code ?? 1));
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => child.kill(signal));
