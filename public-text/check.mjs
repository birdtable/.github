// check.mjs: the public-text check, run by .github/workflows/public-text.yml on a pull request of a
// public repository. It reads the text the pull request would publish:
//
//   - the lines its diff adds, and the paths of the files it adds, changes or renames;
//   - its title and its body;
//   - the message of every commit from the merge base to the head;
//
// and matches each line against the classes of patterns.json, and, when given gitleaks, has gitleaks
// look for secrets in the same text. A hit is printed as its place (a file and line, the title, a line
// of the body, or a commit and line) and its class, never as the text it matched, so the log doesn't
// publish that text a second time. Exit 0 when nothing is hit, 1 when something is, and 2 when the
// check could not run, in which case nothing was checked.
//
//   node check.mjs --patterns <patterns.json> --repo <clone> [--gitleaks <gitleaks binary>]
//
// In Actions it reads the pull request from the event's file, GITHUB_EVENT_PATH; anywhere else, from
// BASE_SHA and HEAD_SHA (full shas), PR_TITLE and PR_BODY. GITHUB_EVENT_NAME, when set, must be
// pull_request. It runs no code from the pull request: git reads the clone, and nothing in it is
// executed.
import { execFileSync, spawnSync } from "node:child_process";
import { appendFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// load reads patterns.json's text into its classes, and refuses a file it cannot read whole.
export function load(text) {
  const doc = JSON.parse(text);
  if (doc.version !== 1 || !Array.isArray(doc.classes) || doc.classes.length === 0) {
    throw new Error("patterns: want version 1 and at least one class");
  }
  const names = new Set();
  return doc.classes.map((c) => {
    if (typeof c.name !== "string" || !/^[a-z][a-z-]*$/.test(c.name) || names.has(c.name)) {
      throw new Error("patterns: every class has a distinct name of lower-case letters and -");
    }
    names.add(c.name);
    if (typeof c.what !== "string" || typeof c.pattern !== "string") {
      throw new Error(`patterns: class ${c.name} wants what and pattern`);
    }
    const flags = c.flags ?? "";
    if (!/^[imsu]*$/.test(flags)) throw new Error(`patterns: class ${c.name}: flags may hold only i, m, s and u`);
    const allow = c.allow ?? [];
    if (!Array.isArray(allow) || allow.some((a) => typeof a !== "string")) {
      throw new Error(`patterns: class ${c.name}: allow is a list of expressions`);
    }
    const group = c.allowGroup ?? 0;
    if (!Number.isInteger(group) || group < 0) throw new Error(`patterns: class ${c.name}: allowGroup is a group number`);
    return {
      name: c.name,
      what: c.what,
      re: new RegExp(c.pattern, flags + "g"),
      allow: allow.map((a) => new RegExp(a, "i")),
      group,
    };
  });
}

// scan is the hits in text, one per match: its 1-based line and its class.
export function scan(classes, text) {
  const out = [];
  (text ?? "").split("\n").forEach((raw, i) => {
    const line = raw.replace(/\r$/, "");
    for (const c of classes) {
      for (const m of line.matchAll(c.re)) {
        const part = m[c.group] ?? "";
        if (c.allow.some((a) => a.test(part))) continue;
        out.push({ line: i + 1, cls: c });
      }
    }
  });
  return out;
}

// unquote reads a path as git writes it in a diff header: bare, or in double quotes with C escapes.
export function unquote(p) {
  if (!p.startsWith('"')) return p;
  const bytes = [];
  const body = p.slice(1, -1);
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch !== "\\") {
      bytes.push(...Buffer.from(ch, "utf8"));
      continue;
    }
    const next = body[++i];
    if (/[0-7]/.test(next)) {
      bytes.push(parseInt(body.slice(i, i + 3), 8));
      i += 2;
    } else {
      bytes.push({ n: 10, t: 9, r: 13, a: 7, b: 8, f: 12, v: 11 }[next] ?? next.charCodeAt(0));
    }
  }
  return Buffer.from(bytes).toString("utf8");
}

// scanDiff is the hits in a diff written with --unified=0: in the lines it adds, each at its line in
// the new file, and in the paths it adds, changes or renames to.
export function scanDiff(classes, diff) {
  const files = []; // the paths, in the diff's order
  const hits = []; // {file, line, cls}, line 0 for the path itself
  const added = []; // {file, line, text}: each path and added line, in order, for gitleaks
  let file = -1;
  let next = 0; // the new file's line the next added line is at
  let olds = 0; // the removed lines still to come in this hunk
  let news = 0; // the added lines still to come in this hunk
  const begin = (path) => {
    if (file !== -1 && files[file] === path) return;
    files.push(path);
    file = files.length - 1;
    added.push({ file, line: 0, text: path });
    for (const h of scan(classes, path)) hits.push({ file, line: 0, cls: h.cls });
  };
  for (const raw of diff.split("\n")) {
    // Inside a hunk, a line is read by its first character alone, so an added line that starts
    // with ++ or a removed one that starts with -- is never read as a header.
    if (olds + news > 0) {
      if (raw.startsWith("+") && news > 0) {
        added.push({ file, line: next, text: raw.slice(1) });
        for (const h of scan(classes, raw.slice(1))) hits.push({ file, line: next, cls: h.cls });
        next++;
        news--;
      } else if (raw.startsWith("-") && olds > 0) {
        olds--;
      } else if (!raw.startsWith("\\")) {
        throw new Error("the diff has a hunk shorter than its header says");
      }
      continue;
    }
    if (raw.startsWith("diff --git ")) {
      file = -1;
    } else if (raw.startsWith("rename to ")) {
      begin(unquote(raw.slice("rename to ".length)));
    } else if (raw.startsWith("+++ ")) {
      const p = unquote(raw.slice(4));
      if (p !== "/dev/null") begin(p.replace(/^b\//, ""));
    } else if (raw.startsWith("@@ ")) {
      const m = raw.match(/^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
      if (!m) throw new Error("the diff has a hunk header this check cannot read");
      olds = m[1] === undefined ? 1 : Number(m[1]);
      next = Number(m[2]);
      news = m[3] === undefined ? 1 : Number(m[3]);
    }
  }
  return { files, hits, added };
}

// escape writes a value into a workflow command, as GitHub reads one.
const escape = (s, prop) => {
  let out = String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
  if (prop) out = out.replace(/:/g, "%3A").replace(/,/g, "%2C");
  return out;
};

// The gitleaks config beside this file: gitleaks's own rules.
const gitleaksConfig = join(dirname(fileURLToPath(import.meta.url)), "gitleaks.toml");

// gitleaks has the gitleaks binary scan input, given on its stdin, and returns the findings of its
// JSON report. Text is given on stdin, never as a clone to scan, because gitleaks honours a
// .gitleaksignore inside a clone it scans, which the pull request could add. It runs in an empty
// folder of its own, with this check's config and with inline gitleaks:allow comments ignored, so
// nothing the pull request holds can tell it to look away. Any failure of gitleaks itself throws, so
// a scan that did not run is never read as a clean one.
function gitleaks(bin, input) {
  const dir = mkdtempSync(join(tmpdir(), "public-text-"));
  const report = join(dir, "report.json");
  const r = spawnSync(
    bin,
    [
      "stdin",
      "--config", gitleaksConfig,
      "--gitleaks-ignore-path", dir,
      "--ignore-gitleaks-allow",
      "--redact",
      "--no-banner",
      "--no-color",
      "--log-level", "error",
      "--exit-code", "0",
      "--report-format", "json",
      "--report-path", report,
    ],
    { cwd: dir, env: { PATH: process.env.PATH ?? "" }, input: input ?? "", encoding: "utf8", maxBuffer: 1 << 28 },
  );
  if (r.error || r.status !== 0) {
    throw new Error(`gitleaks failed (${r.error ? r.error.code : `exit ${r.status}`}): ${(r.stderr ?? "").trim().split("\n").pop()}`);
  }
  const findings = JSON.parse(readFileSync(report, "utf8"));
  if (!Array.isArray(findings)) throw new Error("gitleaks wrote a report that is not a list");
  return findings;
}

// pullRequest reads the pull request's base and head shas, title and body. In Actions it reads them
// from the event's own file, GITHUB_EVENT_PATH, and never from the environment: the runner prints a
// step's env block in the log, which would publish the title and body there a second time. Anywhere
// else, it reads BASE_SHA, HEAD_SHA, PR_TITLE and PR_BODY.
export function pullRequest(env) {
  if (env.GITHUB_ACTIONS === "true" && !env.GITHUB_EVENT_PATH) throw new Error("GITHUB_EVENT_PATH is not set");
  if (!env.GITHUB_EVENT_PATH) {
    return { base: env.BASE_SHA ?? "", head: env.HEAD_SHA ?? "", title: env.PR_TITLE ?? "", body: env.PR_BODY ?? "" };
  }
  const p = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8")).pull_request;
  if (p === null || typeof p !== "object") throw new Error("the event holds no pull request");
  const text = (v, what) => {
    if (v === null || v === undefined) return "";
    if (typeof v !== "string") throw new Error(`the pull request's ${what} is not text`);
    return v;
  };
  const sha = (v) => (typeof v === "string" ? v : "");
  return { base: sha(p.base?.sha), head: sha(p.head?.sha), title: text(p.title, "title"), body: text(p.body, "body") };
}

// run is the check: it prints each hit and a summary, and returns the exit status.
export function run(argv, env, out = console.log) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!["--patterns", "--repo", "--gitleaks"].includes(argv[i]) || argv[i + 1] === undefined) {
      out(`::error title=public-text::usage: check.mjs --patterns <file> --repo <clone> [--gitleaks <binary>]`);
      return 2;
    }
    args[argv[i].slice(2)] = argv[i + 1];
  }
  // gitleaks runs in a folder of its own, so a path to it is made absolute here; a bare name is
  // still looked up on PATH.
  if (args.gitleaks && args.gitleaks.includes("/")) args.gitleaks = resolve(args.gitleaks);
  if (!args.patterns || !args.repo) {
    out(`::error title=public-text::usage: check.mjs --patterns <file> --repo <clone> [--gitleaks <binary>]`);
    return 2;
  }
  if (env.GITHUB_EVENT_NAME !== undefined && env.GITHUB_EVENT_NAME !== "pull_request") {
    out(`::error title=public-text::public-text runs on pull_request only, and this run is ${escape(env.GITHUB_EVENT_NAME)}`);
    return 2;
  }
  let pr;
  try {
    pr = pullRequest(env);
  } catch (e) {
    out(`::error title=public-text::the check could not run, so nothing was checked: ${escape(e.message.split("\n")[0])}`);
    return 2;
  }
  for (const k of ["base", "head"]) {
    if (!/^[0-9a-f]{40}$/.test(pr[k])) {
      out(`::error title=public-text::the pull request's ${k} is not a full commit sha`);
      return 2;
    }
  }

  const hits = []; // {place, file?, line?, what, cls}
  let files;
  let commits;
  try {
    const classes = load(readFileSync(args.patterns, "utf8"));
    const git = (...a) =>
      execFileSync("git", ["-C", args.repo, "-c", "core.quotePath=false", ...a], { encoding: "utf8", maxBuffer: 1 << 30 });
    const base = git("merge-base", pr.base, pr.head).trim();
    const range = `${base}..${pr.head}`;

    const diff = scanDiff(classes, git("diff", "--no-color", "--no-ext-diff", "--unified=0", "-M", base, pr.head));
    files = diff.files;
    // A file whose path is hit is named by its number in the diff, never by its path.
    const named = new Set(diff.hits.filter((h) => h.line === 0).map((h) => h.file));
    const fileName = (i) => (named.has(i) ? `file ${i + 1} of the diff` : files[i]);
    for (const h of diff.hits) {
      if (h.line === 0) hits.push({ place: `the path of file ${h.file + 1} of the diff`, cls: h.cls.name, what: h.cls.what });
      else if (named.has(h.file)) hits.push({ place: `${fileName(h.file)}, line ${h.line}`, cls: h.cls.name, what: h.cls.what });
      else hits.push({ place: `${files[h.file]}, line ${h.line}`, file: files[h.file], line: h.line, cls: h.cls.name, what: h.cls.what });
    }

    for (const h of scan(classes, pr.title)) hits.push({ place: "the pull request's title", cls: h.cls.name, what: h.cls.what });
    for (const h of scan(classes, pr.body)) hits.push({ place: `the pull request's body, line ${h.line}`, cls: h.cls.name, what: h.cls.what });

    commits = git("log", "--format=%H%x00%B%x1e", range)
      .split("\x1e")
      .map((r) => r.replace(/^\n/, ""))
      .filter((r) => r.includes("\x00"))
      .map((r) => {
        const [sha, msg] = r.split("\x00");
        return { sha, msg };
      });
    for (const c of commits) {
      for (const h of scan(classes, c.msg)) hits.push({ place: `commit ${c.sha}, message line ${h.line}`, cls: h.cls.name, what: h.cls.what });
    }

    if (args.gitleaks) {
      const secret = (f) => `a secret (gitleaks rule ${f.RuleID})`;
      // The diff's paths and added lines go to gitleaks one to a line, so a finding's line is the
      // index of what it found in.
      for (const f of gitleaks(args.gitleaks, diff.added.map((a) => a.text).join("\n"))) {
        const a = diff.added[f.StartLine - 1];
        if (!a) throw new Error("gitleaks reported a line past the end of the diff");
        if (a.line === 0) hits.push({ place: `the path of file ${a.file + 1} of the diff`, cls: "secret", what: secret(f) });
        else if (named.has(a.file)) hits.push({ place: `${fileName(a.file)}, line ${a.line}`, cls: "secret", what: secret(f) });
        else hits.push({ place: `${files[a.file]}, line ${a.line}`, file: files[a.file], line: a.line, cls: "secret", what: secret(f) });
      }
      for (const f of gitleaks(args.gitleaks, pr.title)) hits.push({ place: "the pull request's title", cls: "secret", what: secret(f) });
      for (const f of gitleaks(args.gitleaks, pr.body)) {
        hits.push({ place: `the pull request's body, line ${f.StartLine}`, cls: "secret", what: secret(f) });
      }
      for (const c of commits) {
        for (const f of gitleaks(args.gitleaks, c.msg)) {
          hits.push({ place: `commit ${c.sha}, message line ${f.StartLine}`, cls: "secret", what: secret(f) });
        }
      }
    }
  } catch (e) {
    out(`::error title=public-text::the check could not run, so nothing was checked: ${escape(e.message.split("\n")[0])}`);
    return 2;
  }

  for (const h of hits) {
    const at = h.file ? ` file=${escape(h.file, true)},line=${h.line},` : " ";
    out(`::error${at}title=public-text ${h.cls}::${escape(h.place)}: ${escape(h.what)}`);
  }
  const scope = `${files.length} files, the title, the body and ${commits.length} commit messages${args.gitleaks ? ", with gitleaks" : ", without gitleaks"}`;
  const counts = {};
  for (const h of hits) counts[h.cls] = (counts[h.cls] ?? 0) + 1;
  const tally = Object.entries(counts)
    .map(([k, n]) => `${k} ${n}`)
    .join(", ");
  const line = hits.length ? `public-text: ${hits.length} hits (${tally}) over ${scope}` : `public-text: no hits over ${scope}`;
  out(line);
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `${line}\n`);
  return hits.length ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = run(process.argv.slice(2), process.env);
}
