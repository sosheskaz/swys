// Classifies a pull request from its title, body, and changed files into the
// managed `type:`, `breaking change`, and `area:` labels. The squash commit
// takes the PR title as its subject and the PR body as its message, so these
// are exactly what release-please will read on main.
const fs = require("node:fs");
const path = require("node:path");

const TITLE = /^(?<type>[a-z]+)(?:\((?<scope>[a-z0-9-]+)\))?(?<bang>!)?: \S/;
const BREAKING_FOOTER = /^BREAKING[ -]CHANGE: \S/m;
const FAMILY_ROOT = "cmd/internal/commands";
const RELEASE_BRANCH = "release-please--";

const TYPE_COLOR = "c5def5";
const BREAKING = {
  name: "breaking change",
  color: "b60205",
  description: "Breaking change: requires a major (or pre-1.0 minor) release",
};
// Hues 36° apart starting at 18°, so the breaking label stays the only red.
const AREA_COLORS = {
  aes: "e2835a",
  cert: "e2d45a",
  crpc: "9ee25a",
  dns: "5ae268",
  grpc: "5ae2b9",
  hash: "5ab9e2",
  http: "5a68e2",
  net: "9e5ae2",
  skill: "e25ad4",
  core: "e25a83",
};
const CORE_SCOPES = new Set(["cli", "help"]);
// Non-Go paths owned by one family.
const PATH_AREAS = [
  ["tests/interop/openpgp/", "aes"],
  ["skills/", "skill"],
];

function commitTypes(root) {
  const config = JSON.parse(
    fs.readFileSync(path.join(root, "release-please-config.json"), "utf8"),
  );
  return new Map(
    config["changelog-sections"].map(({ type, section }) => [type, section]),
  );
}

function walkGoFiles(root, dir = "", out = []) {
  for (const entry of fs.readdirSync(path.join(root, dir), {
    withFileTypes: true,
  })) {
    const rel = dir ? `${dir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (!entry.name.startsWith(".") && entry.name !== "testdata") {
        walkGoFiles(root, rel, out);
      }
    } else if (entry.name.endsWith(".go") && !entry.name.endsWith("_test.go")) {
      out.push(rel);
    }
  }
  return out;
}

function goImports(source) {
  const specs = [];
  for (const [, block] of source.matchAll(/^import\s*\(([\s\S]*?)^\)/gm)) {
    specs.push(...block.matchAll(/"([^"]+)"/g));
  }
  specs.push(...source.matchAll(/^import\s+(?:[\w.]+\s+)?"([^"]+)"/gm));
  return specs.map((match) => match[1]);
}

// Maps each in-module package directory to the in-module directories it
// imports. Build constraints are ignored, which only over-approximates.
function importGraph(root) {
  const module = fs
    .readFileSync(path.join(root, "go.mod"), "utf8")
    .match(/^module\s+(\S+)/m)[1];
  const graph = new Map();
  for (const file of walkGoFiles(root)) {
    const dir = path.posix.dirname(file);
    const deps = graph.get(dir) ?? new Set();
    graph.set(dir, deps);
    for (const spec of goImports(fs.readFileSync(path.join(root, file), "utf8"))) {
      if (spec.startsWith(`${module}/`)) {
        deps.add(spec.slice(module.length + 1));
      }
    }
  }
  return graph;
}

function familyOf(dir) {
  const parts = dir.split("/");
  return dir.startsWith(`${FAMILY_ROOT}/`) ? parts[3] : undefined;
}

// Maps each package directory to the set of families that contain or
// transitively import it.
function consumers(graph) {
  const result = new Map();
  for (const start of graph.keys()) {
    const family = familyOf(start);
    if (!family) continue;
    const stack = [start];
    const seen = new Set();
    while (stack.length) {
      const dir = stack.pop();
      if (seen.has(dir)) continue;
      seen.add(dir);
      if (!result.has(dir)) result.set(dir, new Set());
      result.get(dir).add(family);
      stack.push(...(graph.get(dir) ?? []));
    }
  }
  return result;
}

function isGoSourcePath(file) {
  return (
    file.startsWith("cmd/") ||
    file.startsWith("internal/") ||
    (!file.includes("/") && file.endsWith(".go"))
  );
}

function fileAreas(file, graph, users, families) {
  const pathArea = PATH_AREAS.find(([prefix]) => file.startsWith(prefix));
  if (pathArea) return [pathArea[1]];
  if (!isGoSourcePath(file)) return [];

  const base = path.posix.basename(file);
  const dir = path.posix.dirname(file);
  if (dir === "cmd") {
    const prefix = base.split("_")[0];
    if (base.endsWith("_test.go") && families.has(prefix)) return [prefix];
  }
  const family = familyOf(dir);
  if (family) return [family];
  // Tests and their fixtures cannot change what importing families do.
  if (base.endsWith("_test.go") || `/${dir}/`.includes("/testdata/")) {
    return ["core"];
  }

  // Other non-Go files, such as embedded templates, belong to their nearest
  // enclosing package.
  let pkg = dir;
  while (!graph.has(pkg) && pkg !== ".") pkg = path.posix.dirname(pkg);
  return ["core", ...(users.get(pkg) ?? [])];
}

function familyNames(root) {
  return new Set(
    fs
      .readdirSync(path.join(root, FAMILY_ROOT), { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name),
  );
}

function classify({ root, title, body, files, headRef }) {
  const types = commitTypes(root);
  const allowed = [...types.keys()].join(", ");
  const match = title.match(TITLE);
  if (!match) {
    return {
      error: `PR title must be a conventional commit, "type(scope)!: subject"; allowed types: ${allowed}`,
    };
  }
  const { type, scope, bang } = match.groups;
  if (!types.has(type)) {
    return { error: `Unknown commit type "${type}"; allowed types: ${allowed}` };
  }

  const breaking = Boolean(bang) || BREAKING_FOOTER.test(body ?? "");
  const areas = new Set();
  if (!headRef?.startsWith(RELEASE_BRANCH)) {
    const families = familyNames(root);
    const graph = importGraph(root);
    const users = consumers(graph);
    for (const file of files) {
      for (const area of fileAreas(file, graph, users, families)) areas.add(area);
    }
    if (families.has(scope)) areas.add(scope);
    if (CORE_SCOPES.has(scope)) areas.add("core");
  }

  const labels = [
    {
      name: `type: ${type}`,
      color: TYPE_COLOR,
      description: `Conventional commit type: ${types.get(type)}`,
    },
  ];
  if (breaking) labels.push(BREAKING);
  for (const area of [...areas].sort()) {
    labels.push({
      name: `area: ${area}`,
      color: AREA_COLORS[area] ?? AREA_COLORS.core,
      description:
        area === "core"
          ? "Shared CLI support and internal packages"
          : `The ${area} command family`,
    });
  }
  return { type, scope, breaking, labels };
}

module.exports = { classify, importGraph, consumers, AREA_COLORS };
