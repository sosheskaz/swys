const readline = require("node:readline");

const mode = process.argv[2];
if (!["extract", "lookup"].includes(mode))
  throw new Error("expected extract or lookup");
const managers = ["cargo", "github-actions", "gomod", "mise", "dockerfile"];
let discovered = false;
let extracted = false;
let lookedUp = false;
let failed = false;

const representatives = [
  ["cargo", "tests/interop/openpgp/Cargo.toml", "sequoia-openpgp"],
  [
    "github-actions",
    ".github/workflows/renovate.yml",
    "actions/create-github-app-token",
  ],
  ["gomod", "go.mod", "go"],
  // Recommended policy disables indirect module updates; retain extraction proof.
  ["gomod", "go.mod", "google.golang.org/genproto/googleapis/rpc", false],
  ["mise", ".config/mise/config.toml", "go"],
  ["mise", ".config/mise/config.toml", "node"],
  ["mise", ".config/mise/config.toml", "go:golang.org/x/vuln/cmd/govulncheck"],
  ["dockerfile", ".github/renovate.Dockerfile", "docker.io/renovate/renovate"],
];

function inspect(config, lookup) {
  const counts = {};
  for (const manager of managers) {
    const files = config[manager] ?? [];
    const deps = files.flatMap((file) => file.deps ?? []);
    counts[manager] = deps.length;
    if (
      !deps.length ||
      (lookup &&
        !deps.some(
          (dep) =>
            dep.currentVersion && !dep.skipReason && !dep.warnings?.length,
        ))
    )
      failed = true;
  }
  for (const [
    manager,
    packageFile,
    depName,
    requireLookup = true,
  ] of representatives) {
    const dep = config[manager]
      ?.find((file) => file.packageFile === packageFile)
      ?.deps?.find((dep) => dep.depName === depName);
    if (
      !dep?.datasource ||
      !dep.currentValue ||
      (lookup &&
        requireLookup &&
        (!dep.currentVersion || dep.skipReason || dep.warnings?.length))
    )
      failed = true;
    if (lookup && manager === "dockerfile") {
      const timestamps = [
        dep?.currentVersionTimestamp,
        ...(dep?.updates ?? []).map((update) => update.releaseTimestamp),
      ];
      if (
        !timestamps.some(
          (timestamp) =>
            typeof timestamp === "string" &&
            Number.isFinite(Date.parse(timestamp)),
        )
      ) {
        failed = true;
        console.error(
          JSON.stringify({
            stage: "lookup",
            error: "Renovate image lookup lacks release timestamps",
          }),
        );
      }
    }
  }
  console.log(
    JSON.stringify({
      stage: lookup ? "lookup" : "extract",
      dependencies: counts,
    }),
  );
}

const lines = readline.createInterface({ input: process.stdin });
lines.on("line", (line) => {
  // Raw trace records can contain credential-bearing configuration. Publish only
  // known stage metadata and counts, never the record or arbitrary log text.
  if (line.length > 16 * 1024 * 1024) {
    failed = true;
    return;
  }
  let record;
  try {
    record = JSON.parse(line);
  } catch {
    failed = true;
    return;
  }
  if (record.msg === "Found .github/renovate.json config file") discovered = true;
  if (record.msg === "packageFiles") {
    inspect(record.config, false);
    extracted = true;
  }
  if (record.msg === "packageFiles with updates") {
    inspect(record.config, true);
    lookedUp = true;
  }
  if (
    record.level >= 40 &&
    !(
      mode === "extract" &&
      record.msg === "GitHub token is required for some dependencies"
    )
  ) {
    failed = true;
    console.error(
      JSON.stringify({
        stage: mode,
        error: "Renovate reported a warning or error",
        level: record.level,
      }),
    );
  }
});
lines.on("close", () => {
  if (!discovered || !extracted || (mode === "lookup" && !lookedUp) || failed) {
    console.error(
      JSON.stringify({ stage: mode, discovered, extracted, lookedUp, failed }),
    );
    process.exitCode = 1;
  }
});
