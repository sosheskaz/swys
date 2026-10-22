const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

const { classify } = require("../scripts/pr-labels.cjs");

// A miniature module shaped like the real one: two families that share one
// package, one family-exclusive package, and shared CLI plumbing.
const tree = {
  "go.mod": "module example.com/swys\n\ngo 1.27\n",
  "release-please-config.json": fs.readFileSync("release-please-config.json"),
  "main.go": 'package main\n\nimport "example.com/swys/cmd"\n',
  "cmd/root.go":
    'package cmd\n\nimport (\n\t"example.com/swys/cmd/internal/commands/cert"\n\t"example.com/swys/cmd/internal/commands/net"\n)\n',
  "cmd/net_shared_test.go": "package cmd_test\n",
  "cmd/root_test.go": "package cmd_test\n",
  "cmd/internal/cli/io.go": "package cli\n",
  "cmd/internal/commands/cert/cert.go":
    'package cert\n\nimport (\n\t"example.com/swys/cmd/internal/cli"\n\tpem "example.com/swys/internal/pemstrict"\n)\n',
  "cmd/internal/commands/cert/guides/connect.md": "# connect\n",
  "cmd/internal/commands/net/net.go":
    'package net\n\nimport "example.com/swys/internal/netconn"\n',
  "internal/netconn/conn.go":
    'package netconn\n\nimport _ "example.com/swys/internal/pemstrict"\n',
  "internal/netconn/conn_test.go":
    'package netconn\n\nimport "example.com/swys/cmd/internal/commands/cert"\n',
  "internal/netconn/testdata/fixture.txt": "data\n",
  "internal/pemstrict/pem.go": "package pemstrict\n",
};
const root = fs.mkdtempSync(path.join(os.tmpdir(), "pr-labels-"));
for (const [file, content] of Object.entries(tree)) {
  fs.mkdirSync(path.join(root, path.dirname(file)), { recursive: true });
  fs.writeFileSync(path.join(root, file), content);
}
test.after(() => fs.rmSync(root, { recursive: true, force: true }));

function labels(title, files = [], extra = {}) {
  const result = classify({ root, title, files, ...extra });
  assert.equal(result.error, undefined);
  return result.labels;
}

test("labels the commit type, including deps", () => {
  assert.deepEqual(labels("deps(go): update module x"), ["type: deps"]);
  assert.deepEqual(labels("revert: undo a change"), ["type: revert"]);
});

test("rejects unknown types and malformed titles", () => {
  for (const title of ["feet: x", "feat x", "Feat: x", "feat(Cert): x", "feat:x"]) {
    const result = classify({ root, title, files: [] });
    assert.match(result.error, /allowed types: .*\bdeps\b/, title);
    assert.equal(result.labels, undefined, title);
  }
});

test("flags breaking changes from the bang or a body footer", () => {
  assert.ok(labels("fix(cert)!: remove flags").includes("breaking change"));
  assert.ok(labels("feat!: drop v1").includes("breaking change"));
  assert.ok(
    labels("feat: x", [], { body: "Details.\n\nBREAKING CHANGE: removed y" })
      .includes("breaking change"),
  );
  assert.ok(
    !labels("feat: x", [], { body: "mentions BREAKING CHANGE: inline" })
      .includes("breaking change"),
  );
});

test("labels the family that owns a changed path", () => {
  assert.deepEqual(
    labels("docs: x", ["cmd/internal/commands/cert/guides/connect.md"]),
    ["type: docs", "area: cert"],
  );
  assert.deepEqual(labels("test: x", ["cmd/net_shared_test.go"]), [
    "type: test",
    "area: net",
  ]);
});

test("labels every family that transitively imports a changed package", () => {
  assert.deepEqual(labels("fix: x", ["internal/pemstrict/pem.go"]), [
    "type: fix",
    "area: cert",
    "area: core",
    "area: net",
  ]);
  // Test-only imports do not make netconn a cert dependency.
  assert.deepEqual(labels("fix: x", ["internal/netconn/conn.go"]), [
    "type: fix",
    "area: core",
    "area: net",
  ]);
});

test("keeps test-only shared changes out of consuming families", () => {
  // Regression: a help golden fixture (#83, #84) labeled every family.
  for (const file of [
    "internal/netconn/conn_test.go",
    "internal/netconn/testdata/fixture.txt",
    "cmd/internal/cli/testdata/leaf.plain.golden",
  ]) {
    assert.deepEqual(labels("test: x", [file]), ["type: test", "area: core"], file);
  }
  assert.deepEqual(
    labels("test: x", ["cmd/internal/commands/cert/testdata/leaf.pem"]),
    ["type: test", "area: cert"],
  );
});

test("labels shared CLI plumbing as core plus its consumers", () => {
  assert.deepEqual(labels("feat(cli): x", ["cmd/internal/cli/io.go"]), [
    "type: feat",
    "area: cert",
    "area: core",
  ]);
  assert.deepEqual(labels("fix(help): x", ["cmd/root.go", "main.go"]), [
    "type: fix",
    "area: core",
  ]);
});

test("adds a family named by the scope and ignores other scopes", () => {
  assert.deepEqual(labels("docs(cert): x", ["docs/cert.md"]), [
    "type: docs",
    "area: cert",
  ]);
  assert.deepEqual(labels("ci(mise): x", [".config/mise/config.toml"]), [
    "type: ci",
  ]);
});

test("skips areas on release-please PRs", () => {
  assert.deepEqual(
    labels("chore(main): release 1.0.0", ["skills/swys/SKILL.md", "cmd/root.go"], {
      headRef: "release-please--branches--main",
    }),
    ["type: chore"],
  );
});

// Execute the actual no-checkout label step, with only its API consumers mocked.
const workflow = fs.readFileSync(".github/workflows/pr-labels.yml", "utf8");
const step = workflow.match(
  /^      - name: Reconcile managed labels\n(?: {8}.*\n|\n)*/m,
)?.[0];
assert.ok(step, "workflow must provide the named label step");
const script = step
  .split("          script: |\n")[1]
  .split("\n")
  .filter((line) => line.startsWith("            "))
  .map((line) => line.slice(12))
  .join("\n");

async function reconcile(desired, { current = [], defined = [] } = {}) {
  const calls = [];
  const notices = [];
  const record = (method) => async (data) => calls.push({ method, ...data });
  const issues = {
    removeLabel: record("remove"),
    addLabels: record("add"),
    listLabelsForRepo() {},
    listLabelsOnIssue() {},
  };
  const github = {
    rest: { issues },
    paginate: async (method) =>
      (method === issues.listLabelsForRepo ? defined : current).map((name) => ({ name })),
  };
  const context = {
    repo: { owner: "owner", repo: "project" },
    payload: { pull_request: { number: 7 } },
  };
  const core = { notice: (message) => notices.push(message) };
  const process = { env: { PR_LABELS: JSON.stringify(desired) } };
  await vm.runInNewContext(`(async () => {\n${script}\n})()`, {
    github,
    context,
    core,
    process,
  });
  // Normalize objects created in the VM realm for deepStrictEqual.
  return JSON.parse(
    JSON.stringify({
      calls: calls.map(({ owner, repo, ...call }) => call),
      notices,
    }),
  );
}

test("applies defined labels and skips undefined ones without creating them", async () => {
  const result = await reconcile(["type: feat", "area: cert", "breaking change"], {
    defined: ["type: feat", "breaking change", "bug"],
  });
  assert.deepEqual(result, {
    calls: [
      { method: "add", issue_number: 7, labels: ["type: feat", "breaking change"] },
    ],
    notices: ["Skipping labels not defined in this repository: area: cert"],
  });
});

test("removes stale managed labels and preserves bot-owned labels", async () => {
  const { calls } = await reconcile(["type: feat", "area: cert"], {
    current: ["type: fix", "area: net", "breaking change", "automerge", "ci", "type: feat"],
    defined: ["type: feat", "type: fix", "area: cert", "area: net", "breaking change"],
  });
  assert.deepEqual(calls, [
    { method: "remove", issue_number: 7, name: "type: fix" },
    { method: "remove", issue_number: 7, name: "area: net" },
    { method: "remove", issue_number: 7, name: "breaking change" },
    { method: "add", issue_number: 7, labels: ["area: cert"] },
  ]);
});

test("removes a stale managed label even when the replacement is undefined", async () => {
  const { calls } = await reconcile(["type: feat"], {
    current: ["type: fix"],
    defined: ["type: fix"],
  });
  assert.deepEqual(calls, [{ method: "remove", issue_number: 7, name: "type: fix" }]);
});

test("refuses labels outside the managed namespace", async () => {
  for (const desired of [["automerge"], ["type: Feat"], [{ name: "type: feat" }], "type: feat"]) {
    await assert.rejects(reconcile(desired), /unmanaged or malformed/);
  }
});
