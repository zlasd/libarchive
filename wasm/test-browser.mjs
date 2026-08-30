import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { constants } from "node:fs";
import { extname, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const sourceRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const chromeCandidates = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
];

let chrome = null;
for (const candidate of chromeCandidates) {
  try {
    await access(candidate, constants.X_OK);
    chrome = candidate;
    break;
  } catch {
    // Try the next known browser location.
  }
}

if (chrome === null) {
  console.log("Browser validation skipped: Chrome or Chromium was not found");
  process.exit(0);
}

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".wasm", "application/wasm"],
]);

const server = createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(
      new URL(request.url ?? "/", "http://127.0.0.1").pathname,
    );
    const path = resolve(sourceRoot, `.${pathname}`);
    if (path !== sourceRoot && !path.startsWith(`${sourceRoot}${sep}`)) {
      response.writeHead(403).end();
      return;
    }
    const data = await readFile(path);
    response.writeHead(200, {
      "Content-Type": contentTypes.get(extname(path)) ?? "application/octet-stream",
    });
    response.end(data);
  } catch {
    response.writeHead(404).end();
  }
});

await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
const address = server.address();
if (address === null || typeof address === "string") {
  server.close();
  throw new Error("Could not determine browser test server port");
}

const url = `http://127.0.0.1:${address.port}/wasm/test-browser.html`;
const profile = await mkdtemp(`${tmpdir()}${sep}libarchive-wasm-chrome-`);
const browser = spawn(chrome, [
  "--headless=new",
  "--disable-gpu",
  "--disable-background-networking",
  "--no-first-run",
  `--user-data-dir=${profile}`,
  "--remote-debugging-port=0",
  "about:blank",
]);

let errors = "";
const devtoolsUrl = await new Promise((resolveUrl, rejectUrl) => {
  const timeout = setTimeout(() => {
    rejectUrl(new Error(`Chrome did not expose DevTools\n${errors}`));
  }, 10000);
  browser.stderr.on("data", (chunk) => {
    errors += chunk;
    const match = errors.match(/DevTools listening on (ws:\/\/[^\s]+)/);
    if (match) {
      clearTimeout(timeout);
      resolveUrl(match[1]);
    }
  });
});

const socket = new WebSocket(devtoolsUrl);
await new Promise((resolveOpen, rejectOpen) => {
  socket.addEventListener("open", resolveOpen, { once: true });
  socket.addEventListener("error", rejectOpen, { once: true });
});

let nextId = 1;
const pending = new Map();
socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  const handler = pending.get(message.id);
  if (handler) {
    pending.delete(message.id);
    if (message.error) handler.reject(new Error(message.error.message));
    else handler.resolve(message.result);
  }
});

function command(method, params = {}, sessionId = undefined) {
  const id = nextId++;
  socket.send(JSON.stringify({ id, method, params, sessionId }));
  return new Promise((resolveCommand, rejectCommand) => {
    pending.set(id, { resolve: resolveCommand, reject: rejectCommand });
  });
}

let browserResult;
try {
  const { targetId } = await command("Target.createTarget", { url });
  const { sessionId } = await command("Target.attachToTarget", {
    targetId,
    flatten: true,
  });
  await command("Runtime.enable", {}, sessionId);

  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const evaluation = await command(
      "Runtime.evaluate",
      {
        expression:
          "({ result: document.body?.dataset.result, text: document.body?.textContent })",
        returnByValue: true,
      },
      sessionId,
    );
    browserResult = evaluation.result?.value;
    if (browserResult?.result === "passed") break;
    if (browserResult?.result === "failed") {
      throw new Error(`Browser validation failed: ${browserResult.text}`);
    }
    await new Promise((resolvePoll) => setTimeout(resolvePoll, 100));
  }
  if (browserResult?.result !== "passed") {
    throw new Error(
      `Browser validation timed out: ${browserResult?.text ?? "no page state"}`,
    );
  }
} finally {
  try {
    await command("Browser.close");
  } catch {
    browser.kill("SIGKILL");
  }
  socket.close();
  await new Promise((resolveClose) => server.close(resolveClose));
  await rm(profile, { recursive: true, force: true });
}

console.log("Browser WorkerFS validation passed in headless Chrome");
