import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("uses the AWS Amplify compatible Next.js build", async () => {
  const packageJson = JSON.parse(await read("package.json"));
  assert.equal(packageJson.scripts.dev, "next dev");
  assert.equal(packageJson.scripts.build, "next build");
  assert.match(packageJson.dependencies.next, /^15\./);
  assert.ok(packageJson.dependencies["aws-amplify"]);
  assert.ok(packageJson.dependencies["@aws-amplify/ui-react"]);
});

test("defines email authentication and owner-private scan storage", async () => {
  const [auth, storage, backend] = await Promise.all([
    read("amplify/auth/resource.ts"),
    read("amplify/storage/resource.ts"),
    read("amplify/backend.ts"),
  ]);
  assert.match(auth, /email:\s*true/);
  assert.match(storage, /scans\/\{entity_id\}\/\*/);
  assert.match(storage, /allow\.entity\("identity"\)/);
  assert.match(backend, /defineBackend\(\{[\s\S]*auth,[\s\S]*storage/);
});

test("restores and replaces one current snapshot per scanner", async () => {
  const page = await read("app/page.tsx");
  assert.match(page, /<Authenticator/);
  assert.match(page, /downloadData\(\{ path: snapshotPath\(scanner\) \}\)/);
  assert.match(page, /uploadData\(\{/);
  assert.match(page, /\$\{scanner\}\/current\.json/);
  assert.match(page, /Amplify\.configure/);
});
