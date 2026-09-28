/* i18n dictionary integrity - load docs/assets/i18n.js and check the RESULT.
 *
 * Why this exists, and why it is not part of i18n_render_check.js: that harness
 * slices out the renderer and feeds it hostile strings, so it answers "can
 * this string become live markup". It never looks at the dictionaries, so it
 * cannot tell you a key is missing, empty, or that a bad splice left one
 * language holding a value which is really two values run together.
 *
 * Both of those happened while adding the v1.15.1 changelog entry. An edit
 * anchored on `{ "chg.v1151": ` appended AFTER the key's colon, so the new
 * block landed inside the existing value and the whole file became
 *     { "chg.v1151": "chg.v1151e_lead": "..." }
 * `node --check` caught that one. A second attempt, aimed at a semantic rather
 * than a syntax fault, did not.
 *
 * So this evaluates the file and inspects the object a browser would get, and
 * it checks the invariant the house style actually promises: every key any
 * page references must resolve in ALL FOUR languages.
 *
 * Usage: node i18n_dict_check.js [path-to-i18n.js] [docs-dir]
 * Exit: 0 clean, 1 on any problem.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SRC = process.argv[2] || path.join(__dirname, "docs", "assets", "i18n.js");
const DOCS = process.argv[3] || path.join(__dirname, "docs");
const LANGS = ["en", "fa", "zh", "ru"];

const problems = [];
const note = (m) => problems.push(m);

// ---- which attributes does the code ACTUALLY translate? --------------------
// Derived from applyI18n rather than restated here. A hardcoded list was
// written first and immediately produced a false positive on data-i18n-alt,
// which applyI18n does handle - the same mistake as a test that hardcodes the
// value it is checking. Read the shipped code instead.
const RAW = fs.readFileSync(SRC, "utf8");
const applyAt = RAW.indexOf("function applyI18n");
const HANDLED = new Set(
  (applyAt === -1 ? [] : RAW.slice(applyAt, applyAt + 2000).match(/data-i18n[a-z-]*/g) || [])
    .concat(["data-i18n"]));
console.log("i18n_dict_check: applyI18n handles " +
            [...HANDLED].sort().join(", "));

// ---- load it the way a browser would ---------------------------------------
// `const Z_STRINGS` at top level of a strict-mode script is not a property of
// the vm context, so ask for it explicitly instead of guessing.
const ctx = { window: {}, document: { documentElement: {}, querySelectorAll: () => [] } };
ctx.globalThis = ctx;
vm.createContext(ctx);
try {
  vm.runInContext(fs.readFileSync(SRC, "utf8") + "\n;globalThis.__Z = Z_STRINGS;", ctx);
} catch (e) {
  console.log("i18n_dict_check: " + SRC + " does not evaluate: " + e.message);
  process.exit(1);
}
const S = ctx.__Z;
if (!S) {
  console.log("i18n_dict_check: the file did not define Z_STRINGS");
  process.exit(1);
}

// ---- every key every page references ---------------------------------------
const pages = fs.readdirSync(DOCS).filter((f) => f.endsWith(".html")).sort();
const referenced = new Map();   // key -> Set(pages)
for (const f of pages) {
  const html = fs.readFileSync(path.join(DOCS, f), "utf8");
  for (const m of html.matchAll(/data-i18n(?:-ph|-title|-aria)?="([^"]+)"/g)) {
    if (!referenced.has(m[1])) referenced.set(m[1], new Set());
    referenced.get(m[1]).add(f);
  }
  // A misspelled attribute is invisible: the key exists in all four languages,
  // so the page still shows its English fallback and nothing looks broken. Four
  // `data-i14n` typos sat in the changelog that way, permanently untranslated.
  for (const m of html.matchAll(/data-(i[a-z0-9-]*n[a-z0-9-]*)="([^"]+)"/g)) {
    if (!HANDLED.has("data-" + m[1])) {
      note(`${f}: attribute data-${m[1]} looks like a typo of data-i18n ` +
           `(key "${m[2]}") - applyI18n does not read it, so it will never ` +
           `be translated`);
    }
  }
  // A key referenced by a page but present in NO language renders as a silent
  // English fallback too, so check the union as well as each language.
  for (const m of html.matchAll(/(data-i18n[a-z-]*)="([^"]+)"/g)) {
    if (!HANDLED.has(m[1])) continue;
    if (!LANGS.some((l) => S[l] && typeof S[l][m[2]] === "string")) {
      note(`${f}: "${m[2]}" is referenced but exists in NO language`);
    }
  }
}

let checked = 0;
for (const [key, where] of referenced) {
  for (const l of LANGS) {
    if (!S[l]) { note("no dictionary at all for " + l); continue; }
    const v = S[l][key];
    if (typeof v !== "string") {
      note(`${l}: "${key}" is missing (used by ${[...where].join(", ")})`);
    } else if (!v.trim()) {
      note(`${l}: "${key}" is empty (used by ${[...where].join(", ")})`);
    } else {
      checked++;
      if (v.indexOf("\ufffd") !== -1) note(`${l}: "${key}" contains U+FFFD (mojibake)`);
      // The signature of a splice that ran two entries together.
      if (/^"[A-Za-z0-9_.-]+":/.test(v)) {
        note(`${l}: "${key}" holds what looks like two entries run together`);
      }
    }
  }
}

// ---- the four languages must actually differ ------------------------------
// A copy-paste that leaves `fa` holding the English string is invisible in a
// screenshot of the source. But this CANNOT be a hard failure, and the reason
// is worth stating rather than discovering later: some values are correct
// untranslated. "GitHub Security Advisories" is GitHub's own feature name, and
// the Russian changelog line for v1.6.0 is a list of Latin protocol names whose
// correct Russian spelling is identical to the English. Demanding a difference
// would push someone to "translate" a product name.
//
// So: report them, do not fail on them. An empty value, by contrast, is never
// a judgement call - the page renders a blank - so that stays a hard failure.
const advisory = [];
for (const [key] of referenced) {
  const vals = LANGS.map((l) => (S[l] ? S[l][key] : null));
  if (vals.some((v) => typeof v !== "string" || !v)) continue;
  for (let i = 1; i < vals.length; i++) {
    if (vals[i] === vals[0] && vals[0].length > 24) {
      advisory.push(`${LANGS[i]}: "${key}" is byte-identical to en ` +
                    `(${vals[0].slice(0, 44)}...) - correct if it is a product ` +
                    `or protocol name, a gap if it is prose`);
      break;
    }
  }
}

console.log(`i18n_dict_check: ${pages.length} pages, ${referenced.size} distinct keys, ` +
            `${LANGS.length} languages, ${checked} values inspected`);
if (problems.length) {
  for (const p of problems.slice(0, 40)) console.log("  [FAIL] " + p);
  if (problems.length > 40) console.log("  ... and " + (problems.length - 40) + " more");
  console.log("i18n_dict_check: " + problems.length + " problem(s)");
  process.exit(1);
}
if (advisory.length) {
  console.log("  [note] " + advisory.length + " value(s) identical to English, " +
              "each needing a human call:");
  for (const a of advisory.slice(0, 8)) console.log("         " + a);
}
console.log("i18n_dict_check: ALL OK");
