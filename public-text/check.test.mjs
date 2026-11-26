// The tests of check.mjs: node --test public-text/
//
// Every text that a class hits is built by joining its parts at run time, so this file holds none of
// them as written. The tests that run gitleaks itself take its path from GITLEAKS, and fail rather
// than pass quietly when CI is set and GITLEAKS is not.
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { load, run, scan, scanDiff, unquote } from "./check.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const patterns = join(here, "patterns.json");
const classes = load(readFileSync(patterns, "utf8"));
const j = (...parts) => parts.join("");
const classesOf = (text) => scan(classes, text).map((h) => h.cls.name);

// The texts each class hits, and the near misses it lets through.
const cases = {
  home: {
    hit: [
      j("/Use", "rs/fixture/x"),
      j("cd /ho", "me/fixture/src"),
      j("C:", "\\Users\\fixture\\x"),
      j("C:", "\\\\Users\\\\fixture\\\\x"),
      j("c:/", "users/fixture/x"),
      j("file:///Use", "rs/fixture/x"),
      j('"/ho', 'me/fixture/"'),
    ],
    miss: [
      j("/Use", "rs/a/x"),
      j("/ho", "me/u/x"),
      j("C:", "\\Users\\<user>\\x"),
      j("/ho", "me/someone/x"),
      j("C:", "\\Users\\..\\x"),
      j("https://github.com/use", "rs/fixture/x"),
      j("/tmp/ho", "me/fixture/x"),
      j("/ho", "me/fixture"),
    ],
  },
  email: {
    hit: [j("someone", "@", "birdtable.fixture"), j("a.b+c", "@", "mail.fixture.org")],
    miss: [
      j("12345+someone", "@", "users.noreply.github.com"),
      j("noreply", "@", "github.com"),
      j("noreply", "@", "anthropic.com"),
      j("someone", "@", "example.com"),
      j("someone", "@", "mail.example.org"),
      j("someone", "@", "example.net"),
      j("someone", "@", "host.example"),
      j("someone", "@", "host.invalid"),
      j("someone", "@", "host.test"),
      j("someone", "@", "localhost"),
      j("golang.org/toolchain", "@", "v0.0.1-go1.27.4.darwin"),
    ],
  },
  decision: {
    hit: [j("P", "D-1"), j("as G", "D-43 says"), j("X", "D-9"), j("D", "L-886"), j("AB", "C", "D-12")],
    miss: [j("BS", "D-3"), j("BS", "D-2-Clause"), j("P", "D-"), j("p", "d-1"), j("ABC", "D", "D-1")],
  },
  session: {
    hit: [j("https://claude.ai/code/", "session_", "01R3"), j("session_", "014a3uhWBYey8jPfkQ93")],
    miss: [j("session_", "id"), j("new_", "session_state"), j("session_", "short")],
  },
  agent: {
    hit: [
      j("platform", "-hub"),
      j("review", "-fable"),
      j("fable", "-process"),
      j("files", "-review-2"),
      j("process", "-1"),
      j("files", "-lead"),
      j("console", "-lander"),
      j("process", "-review"),
      j("to console", "-7."),
      j("tmp/process", "-1"),
      j("x.files", "-lead"),
    ],
    miss: [
      j("utf", "-8"),
      j("go-files", "-3"),
      j("tmp/testkit", "-1"),
      j("second", "-review"),
      j("socket", "-4"),
      j("n", "-1"),
      j("processes", "-1"),
    ],
  },
};

for (const [name, { hit, miss }] of Object.entries(cases)) {
  test(`${name}: each hit is found, and in that class only`, () => {
    for (const t of hit) assert.deepEqual(classesOf(t), [name], `hit ${JSON.stringify(t)}`);
  });
  test(`${name}: each near miss is let through`, () => {
    for (const t of miss) assert.deepEqual(classesOf(t).filter((c) => c === name), [], `miss ${JSON.stringify(t)}`);
  });
}

test("scan: one hit per match, at its line, with a CR at a line's end ignored", () => {
  const text = ["clean", j("P", "D-1 and P", "D-2\r"), j("process", "-1")].join("\n");
  assert.deepEqual(
    scan(classes, text).map((h) => [h.line, h.cls.name]),
    [
      [2, "decision"],
      [2, "decision"],
      [3, "agent"],
    ],
  );
  assert.deepEqual(scan(classes, undefined), []);
});

test("load: refuses a file it cannot read whole", () => {
  const good = { version: 1, classes: [{ name: "x", what: "x", pattern: "x" }] };
  const bad = [
    { ...good, version: 2 },
    { version: 1, classes: [] },
    { version: 1, classes: [{ name: "X", what: "x", pattern: "x" }] },
    { version: 1, classes: [{ name: "x", what: "x", pattern: "x" }, { name: "x", what: "x", pattern: "y" }] },
    { version: 1, classes: [{ name: "x", what: "x", pattern: "x", flags: "g" }] },
    { version: 1, classes: [{ name: "x", what: "x", pattern: "x", flags: "y" }] },
    { version: 1, classes: [{ name: "x", what: "x", pattern: "(" }] },
    { version: 1, classes: [{ name: "x", what: "x", pattern: "x", allow: "x" }] },
    { version: 1, classes: [{ name: "x", what: "x", pattern: "x", allowGroup: -1 }] },
    { version: 1, classes: [{ name: "x", pattern: "x" }] },
  ];
  assert.equal(load(JSON.stringify(good)).length, 1);
  for (const b of bad) assert.throws(() => load(JSON.stringify(b)), undefined, JSON.stringify(b));
});

test("unquote: reads git's quoted paths", () => {
  assert.equal(unquote("b/plain.txt"), "b/plain.txt");
  assert.equal(unquote('"b/a \\"b\\".txt"'), 'b/a "b".txt');
  assert.equal(unquote('"b/caf\\303\\251\\t.txt"'), "b/caf\u00e9\t.txt");
});

test("scanDiff: added lines at their new lines, paths, renames, and no header read inside a hunk", () => {
  const diff = [
    "diff --git a/a.txt b/a.txt",
    "index 1..2 100644",
    "--- a/a.txt",
    "+++ b/a.txt",
    "@@ -3 +3,2 @@",
    j("-old P", "D-1"),
    "+clean",
    j("++++ ", "process", "-1"),
    "@@ -10,0 +12 @@",
    j("+P", "D-2"),
    "\\ No newline at end of file",
    "diff --git a/old.txt b/new.txt",
    "similarity index 90%",
    "rename from old.txt",
    j("rename to ", "fable", "-x.txt"),
    j("--- a/", "old.txt"),
    j("+++ b/", "fable", "-x.txt"),
    "@@ -1 +1 @@",
    "-a",
    j("+P", "D-3"),
    "diff --git a/gone.txt b/gone.txt",
    "deleted file mode 100644",
    "--- a/gone.txt",
    "+++ /dev/null",
    "@@ -1 +0,0 @@",
    j("-P", "D-4"),
    "",
  ].join("\n");
  const { files, hits, added } = scanDiff(classes, diff);
  assert.deepEqual(files, ["a.txt", j("fable", "-x.txt")]);
  assert.deepEqual(
    hits.map((h) => [h.file, h.line, h.cls.name]),
    [
      [0, 4, "agent"],
      [0, 12, "decision"],
      [1, 0, "agent"],
      [1, 1, "decision"],
    ],
  );
  assert.deepEqual(
    added.map((a) => [a.file, a.line]),
    [
      [0, 0],
      [0, 3],
      [0, 4],
      [0, 12],
      [1, 0],
      [1, 1],
    ],
  );
  assert.throws(() => scanDiff(classes, "+++ b/a\n@@ -1 +1,2 @@\n+one\ndiff --git a/b b/b\n"));
});

// repo makes a clone with a base commit and a head commit on top of it, and returns their shas.
function repo(files, message) {
  const dir = mkdtempSync(join(tmpdir(), "public-text-test-"));
  const git = (...a) =>
    execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...a], {
      encoding: "utf8",
    });
  git("init", "-q");
  writeFileSync(join(dir, "README"), "base\n");
  git("add", "README");
  git("commit", "-q", "-m", "base");
  const base = git("rev-parse", "HEAD").trim();
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), text);
    git("add", p);
  }
  git("commit", "-q", "--allow-empty", "-m", message);
  return { dir, base, head: git("rev-parse", "HEAD").trim() };
}

function check(r, env, extra = []) {
  const lines = [];
  const code = run(["--patterns", patterns, "--repo", r.dir, ...extra], { BASE_SHA: r.base, HEAD_SHA: r.head, ...env }, (l) => lines.push(l));
  return { code, out: lines.join("\n") };
}

test("run: a clean pull request is 0", () => {
  const r = repo({ "a.txt": "nothing here\n" }, "add a.txt");
  const { code, out } = check(r, { PR_TITLE: "Add a.txt", PR_BODY: "Adds it.", GITHUB_EVENT_NAME: "pull_request" });
  assert.equal(code, 0, out);
  assert.match(out, /public-text: no hits over 1 files, the title, the body and 1 commit messages, without gitleaks/);
});

test("run: hits in a file, the title, the body and a message are 1, each named by place and class, never by text", () => {
  const home = j("/ho", "me/fixture/");
  const mail = j("someone", "@", "birdtable.fixture");
  const dec = j("X", "D-9");
  const sess = j("session_", "014a3uhWBYey8jPfkQ93");
  const agent = j("console", "-99");
  const r = repo({ "dir/a.txt": `one\n${home}\n`, [j("dir/", agent, ".txt")]: "x\n" }, `fix\n\nas ${dec} says`);
  const { code, out } = check(r, { PR_TITLE: `mail ${mail}`, PR_BODY: `line one\r\n${sess}` });
  assert.equal(code, 1, out);
  const want = [
    /::error file=dir\/a\.txt,line=2,title=public-text home::dir\/a\.txt, line 2: a home folder path/,
    /::error title=public-text agent::the path of file \d of the diff: an agent name/,
    /::error title=public-text email::the pull request's title: an email address/,
    /::error title=public-text session::the pull request's body, line 2: a session link or id/,
    new RegExp(`::error title=public-text decision::commit ${r.head}, message line 3: a decision id`),
    /public-text: 5 hits \(home 1, agent 1, email 1, session 1, decision 1\) over 2 files/,
  ];
  for (const w of want) assert.match(out, w);
  for (const t of [home, mail, dec, sess, agent]) assert.ok(!out.includes(t), `the log holds ${t}`);
});

test("run: anything but a pull_request event, a bad sha, a bad patterns file or bad arguments are 2", () => {
  const r = repo({ "a.txt": "x\n" }, "m");
  assert.equal(check(r, { GITHUB_EVENT_NAME: "pull_request_target" }).code, 2);
  assert.equal(check(r, { GITHUB_EVENT_NAME: "push" }).code, 2);
  assert.equal(check({ ...r, head: "HEAD" }, {}).code, 2);
  assert.equal(check({ ...r, base: r.base.slice(0, 12) }, {}).code, 2);
  assert.equal(check({ ...r, base: "0".repeat(40) }, {}).code, 2);
  const bad = join(mkdtempSync(join(tmpdir(), "public-text-test-")), "p.json");
  writeFileSync(bad, "{");
  assert.equal(run(["--patterns", bad, "--repo", r.dir], { BASE_SHA: r.base, HEAD_SHA: r.head }, () => {}), 2);
  assert.equal(run(["--patterns", patterns], { BASE_SHA: r.base, HEAD_SHA: r.head }, () => {}), 2);
  assert.equal(run(["--patterns", patterns, "--repo", r.dir, "--other", "x"], { BASE_SHA: r.base, HEAD_SHA: r.head }, () => {}), 2);
});

// fake writes a stand-in for gitleaks that checks how it was called, and reports each line of its
// input that holds FAKE-SECRET, or exits 3 when its input holds FAIL.
function fake() {
  const dir = mkdtempSync(join(tmpdir(), "public-text-fake-"));
  const bin = join(dir, "gitleaks");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("node:fs");
const a = process.argv.slice(2);
const at = (f) => a[a.indexOf(f) + 1];
const want = ["stdin", "--config", "--gitleaks-ignore-path", "--ignore-gitleaks-allow", "--redact", "--exit-code", "--report-path"];
for (const w of want) if (!a.includes(w)) { console.error("missing " + w); process.exit(4); }
if (at("--config") !== ${JSON.stringify(join(here, "gitleaks.toml"))}) { console.error("config"); process.exit(4); }
if (fs.realpathSync(at("--gitleaks-ignore-path")) !== fs.realpathSync(process.cwd()) || fs.readdirSync(process.cwd()).length !== 0) { console.error("cwd"); process.exit(4); }
if (Object.keys(process.env).some((k) => k.startsWith("GITLEAKS"))) { console.error("env"); process.exit(4); }
const input = fs.readFileSync(0, "utf8");
if (input.includes("FAIL")) { console.error("it failed"); process.exit(3); }
const found = [];
input.split("\\n").forEach((l, i) => { if (l.includes("FAKE-SECRET")) found.push({ RuleID: "fake-rule", StartLine: i + 1, Secret: "REDACTED" }); });
fs.writeFileSync(at("--report-path"), JSON.stringify(found));
`,
  );
  chmodSync(bin, 0o755);
  return bin;
}

test("run: gitleaks's findings in the diff, the title, the body and a message are named by place, and its failure is 2", () => {
  const bin = fake();
  const r = repo({ "a.txt": "one\ntwo FAKE-SECRET\n", "b.txt": "clean\n" }, "m\n\nFAKE-SECRET");
  const { code, out } = check(r, { PR_TITLE: "FAKE-SECRET", PR_BODY: "x\nFAKE-SECRET", GITLEAKS_CONFIG: "/nowhere" }, ["--gitleaks", bin]);
  assert.equal(code, 1, out);
  for (const w of [
    /::error file=a\.txt,line=2,title=public-text secret::a\.txt, line 2: a secret \(gitleaks rule fake-rule\)/,
    /::error title=public-text secret::the pull request's title: a secret/,
    /::error title=public-text secret::the pull request's body, line 2: a secret/,
    new RegExp(`::error title=public-text secret::commit ${r.head}, message line 3: a secret`),
    /public-text: 4 hits \(secret 4\) over 2 files, the title, the body and 1 commit messages, with gitleaks/,
  ]) {
    assert.match(out, w);
  }
  assert.equal(check(r, { PR_TITLE: "FAIL" }, ["--gitleaks", bin]).code, 2);
  assert.equal(check(r, {}, ["--gitleaks", join(dirname(bin), "missing")]).code, 2);
});

test("run: the real gitleaks finds a secret that the pull request tries to hide from it", (t) => {
  const bin = process.env.GITLEAKS;
  if (!bin) {
    assert.ok(!process.env.CI, "CI is set and GITLEAKS is not, so this test cannot run");
    t.diagnostic("GITLEAKS is not set, so the real gitleaks was not run");
    return;
  }
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let key = "";
  for (let i = 0; i < 40; i++) key += chars[Math.floor(Math.random() * chars.length)];
  const line = j("aws_", "secret = ", JSON.stringify(key));
  const first = repo({ "a.txt": `${line}\n` }, "m");
  const found = check(first, {}, ["--gitleaks", bin]);
  assert.equal(found.code, 1, found.out);
  assert.match(found.out, /a\.txt, line 1: a secret \(gitleaks rule /);
  assert.ok(!found.out.includes(key), "the log holds the secret");
  // The same line with an inline allow, beside an ignore file and a config that allows every path.
  const r = repo(
    {
      "a.txt": `${line} # ${j("gitleaks", ":allow")}\n`,
      ".gitleaksignore": "a.txt:generic-api-key:1\n",
      ".gitleaks.toml": "[allowlist]\npaths = ['''.*''']\n",
    },
    "m",
  );
  const hidden = check(r, {}, ["--gitleaks", bin]);
  assert.equal(hidden.code, 1, hidden.out);
  assert.match(hidden.out, /a\.txt, line 1: a secret \(gitleaks rule /);
});

test("the workflow and its test fetch the same gitleaks", () => {
  const pin = (f) =>
    readFileSync(join(here, "..", ".github", "workflows", f), "utf8")
      .split("\n")
      .filter((l) => /GITLEAKS_(VERSION|SHA256):/.test(l))
      .map((l) => l.trim());
  const used = pin("public-text.yml");
  assert.equal(used.length, 2);
  assert.deepEqual(pin("public-text-test.yml"), used);
});
