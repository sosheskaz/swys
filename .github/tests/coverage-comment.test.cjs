const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const test = require("node:test");

// Execute the actual no-checkout publisher, with only its data and API consumers mocked.
const workflow = fs.readFileSync(".github/workflows/ci.yml", "utf8");
const step = workflow.match(
  /^      - name: Update coverage comment\n(?: {8}.*\n|\n)*/m,
)?.[0];
assert.ok(step, "CI must provide the named coverage publisher step");
const block = step.split("          script: |\n")[1];
assert.ok(block, "CI must provide the coverage publisher script");
const script = block
  .split("\n\n")[0]
  .split("\n")
  .filter((line) => line.startsWith("            "))
  .map((line) => line.slice(12))
  .join("\n");
const marker = "<!-- npc-coverage-bot:v1 -->";
const provenance =
  "<sub>checkout: `merge`; PR head: `head`; recorded base: `base`; PR run: `200` attempt `2`; baseline run: `100`; baseline artifact: `101`</sub>";
const report = `${marker}\n<!-- npc-coverage-run:200:2 -->\n## Coverage\n\n**Total: 75.0%**\n${provenance}\n`;

async function publish(options = {}) {
  const writes = [];
  const reads = [];
  const body = options.body ?? report;
  const repo = { owner: "owner", repo: "project" };
  const context = {
    repo,
    sha: "merge",
    payload: {
      pull_request: {
        number: 123,
        head: {
          sha: "head",
          repo: { full_name: options.repository ?? "owner/project" },
        },
        base: { sha: "base" },
      },
    },
  };
  const github = {
    rest: {
      pulls: {
        get: async () => {
          reads.push("head");
          return { data: { head: { sha: options.currentHead ?? "head" } } };
        },
      },
      issues: {
        listComments() {},
        createComment: async (data) =>
          writes.push({ method: "create", ...data }),
        updateComment: async (data) =>
          writes.push({ method: "update", ...data }),
      },
    },
    paginate: async () => {
      reads.push("comments");
      return options.comments ?? [];
    },
  };
  const environment = {
    COVERAGE_REPORT_PATH: "/report/coverage-report.md",
    GITHUB_RUN_ID: "200",
    GITHUB_RUN_ATTEMPT: options.publisherAttempt ?? "2",
    COVERAGE_PRODUCER_ATTEMPT: options.producerAttempt ?? "2",
    COVERAGE_BASE_RUN_ID: "100",
    COVERAGE_BASE_ARTIFACT_ID: "101",
  };
  const sandbox = {
    context,
    github,
    core: { info() {} },
    TextDecoder,
    process: { env: environment },
    require: (name) => {
      assert.equal(name, "node:fs");
      return {
        lstatSync: () => ({
          isFile: () => options.regular ?? true,
          size: options.size ?? Buffer.byteLength(body),
        }),
        readFileSync: () => Buffer.from(body),
      };
    },
  };
  await vm.runInNewContext(`(async () => {\n${script}\n})()`, sandbox);
  return { writes, reads };
}

const comment = (body, login = "github-actions[bot]") => ({
  id: 42,
  body,
  user: { login },
});

test("publishes coverage as serialized comment data and updates its bot comment", async () => {
  const created = await publish({ comments: [comment(report, "contributor")] });
  assert.equal(created.writes.length, 1);
  assert.equal(created.writes[0].method, "create");
  assert.equal(created.writes[0].body, report);
  assert.equal(created.writes[0].issue_number, 123);
  const updated = await publish({
    comments: [comment(`${marker}\n<!-- npc-coverage-run:199:9 -->`)],
  });
  assert.equal(updated.writes.length, 1);
  assert.equal(updated.writes[0].method, "update");
  assert.equal(updated.writes[0].comment_id, 42);
  assert.equal(updated.writes[0].body, report);
});

test("a publisher-only rerun preserves the original report attempt", async () => {
  const result = await publish({ producerAttempt: "2", publisherAttempt: "3" });
  assert.equal(result.writes.length, 1);
  assert.equal(result.writes[0].body, report);
});

test("stale heads and older run attempts cannot replace newer coverage", async () => {
  const stale = await publish({ currentHead: "new-head" });
  assert.deepEqual(stale.reads, ["head"]);
  assert.deepEqual(stale.writes, []);
  for (const order of ["201:1", "200:3"]) {
    const result = await publish({
      comments: [comment(`${marker}\n<!-- npc-coverage-run:${order} -->`)],
    });
    assert.deepEqual(result.writes, []);
  }
});

test("refuses reports from other revisions, oversized files, and fork repositories", async () => {
  for (const options of [
    { body: report.replace("PR head: `head`", "PR head: `other`") },
    { size: 60 * 1024 + 1 },
    { regular: false },
    { repository: "fork/project" },
  ]) {
    await assert.rejects(publish(options));
  }
});
