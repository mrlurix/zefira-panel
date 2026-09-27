/* Run the REAL zDecodeEntities / zRenderI18n from docs/assets/i18n.js over a
 * set of hostile inputs, in Node, and report anything that could become live
 * markup.
 *
 * Why this is a shipped helper rather than a one-off: the renderer's safety
 * rests on a chain of invariants (escape order, then an allowlist pattern with
 * no attribute slot). Reading that by eye is how it stays safe for a year and
 * then is not. This executes the shipped code instead.
 *
 * Usage: node i18n_render_check.js [path-to-i18n.js]
 * Exit: 0 clean, 1 on any leak.
 */
"use strict";
const fs = require("fs");
const path = require("path");

const SRC = process.argv[2] || path.join(__dirname, "docs", "assets", "i18n.js");
const src = fs.readFileSync(SRC, "utf8");

// Slice out just the two functions plus the tag allowlist.
const start = src.indexOf("var Z_INLINE_TAGS");
const end = src.indexOf("function applyI18n");
if (start === -1 || end === -1 || end <= start) {
  console.log("i18n_render_check: could not locate the renderer in " + SRC);
  process.exit(1);
}
// Evaluate the slice in a scope and hand back the two functions it defines.
const scope = {};
const factory = new Function(
  "scope",
  src.slice(start, end) + "\nscope.zDecodeEntities = zDecodeEntities;"
  + "\nscope.zRenderI18n = zRenderI18n;"
);
factory(scope);
if (typeof scope.zRenderI18n !== "function") {
  console.log("i18n_render_check: zRenderI18n was not defined in the slice");
  process.exit(1);
}
const render = scope.zRenderI18n;

const CASES = [
  // Raw tags.
  "<img src=x onerror=alert(1)>",
  "<script>alert(1)</script>",
  "<IMG SRC=x ONERROR=alert(1)>",
  "< img src=x >",
  "<img\nsrc=x onerror=alert(1)>",
  "<svg/onload=alert(1)>",
  // Attribute on an ALLOWLISTED tag - the case the bare-tag pattern exists for.
  '<b onmouseover="alert(1)">x</b>',
  "<i\tonmouseover=alert(1)>x</i>",
  '<a href="javascript:alert(1)">x</a>',
  // Encoded once.
  "&lt;script&gt;alert(1)&lt;/script&gt;",
  "&lt;img src=x onerror=1&gt;",
  "&#60;script&#62;alert(1)&#60;/script&#62;",
  "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
  // Encoded TWICE - the decode is a single pass, so this must stay text.
  "&amp;lt;img src=x onerror=1&amp;gt;",
  "&amp;#60;img src=x onerror=1&amp;#62;",
  "&amp;amp;lt;script&amp;amp;gt;",
  // Legitimate markup that MUST keep working.
  "<i>emphasis</i> and <code>x</code>",
  "<b>bold</b><br>",
  // A BARE tag that is not on the allowlist. Harmless on its own, but it is
  // the only shape that survives the bare-tag pattern, so it is what proves
  // the allowlist is doing the work rather than the escaping.
  "<img>",
  "<span>",
  // Entities that must decode.
  "&#8212; an em dash",
  "a &amp; b",
  "&lt;script&gt; shown as text",
  "",
  null,
];

const ALLOWED = /^(?:<\/?(?:i|b|em|strong|code|br)>)+$/;
let leaks = 0;

for (const input of CASES) {
  const r = render(input);
  const html = r.html || "";
  // 1. Every tag-shaped run must be an allowlisted bare tag.
  const tags = html.match(/<[^>]*>/g) || [];
  for (const tag of tags) {
    if (!/^<\/?(?:i|b|em|strong|code|br)>$/.test(tag)) {
      leaks++;
      console.log("  LEAK un-allowlisted tag " + JSON.stringify(tag)
        + " from input " + JSON.stringify(input));
    }
  }
  // 2. No attribute can survive inside a REAL tag.
  //
  //    Scoped to the matched tags on purpose. A first version searched the
  //    whole string for `on...=` and flagged every correctly-escaped input -
  //    "&lt;img src=x onerror=1&gt;" is literal TEXT, not markup, so that
  //    check was reporting the escaping working.
  for (const tag of tags) {
    if (/=/.test(tag) || /\son[a-z]+\b/i.test(tag)) {
      leaks++;
      console.log("  LEAK attribute inside a live tag " + JSON.stringify(tag)
        + " from " + JSON.stringify(input));
    }
  }
  // 3. An escaped angle bracket must never have been re-decoded back into a
  //    bare one. Any "<" or ">" left in the output has to belong to an
  //    allowlisted tag.
  const bareAngles = html.replace(/<\/?(?:i|b|em|strong|code|br)>/g, "");
  if (bareAngles.indexOf("<") !== -1 || bareAngles.indexOf(">") !== -1) {
    leaks++;
    console.log("  LEAK unescaped angle bracket from " + JSON.stringify(input)
      + " -> " + html.slice(0, 80));
  }
  // 4. When nothing is allowlisted, the renderer must take the textContent
  //    branch - i.e. it must have declined to produce markup at all.
  if (tags.length === 0 && !r.escaped) {
    leaks++;
    console.log("  LEAK produced markup it should have escaped: " + JSON.stringify(input));
  }
  if (tags.length && r.escaped) {
    leaks++;
    console.log("  INCONSISTENT has tags but claims escaped: " + JSON.stringify(input));
  }
}

// The legitimate cases must still work, or the hardening broke the feature.
const mustRender = [
  ["<i>emphasis</i> and <code>x</code>", (h) => h.indexOf("<i>") !== -1 && h.indexOf("<code>") !== -1],
  ["&#8212; dash", (h) => h.indexOf("&#8212;") === -1 && h.indexOf("mdash") === -1],
];
for (const [input, ok] of mustRender) {
  const r = render(input);
  if (!ok(r.html)) {
    leaks++;
    console.log("  REGRESSION legitimate markup no longer renders: "
      + JSON.stringify(input) + " -> " + r.html.slice(0, 70));
  }
}

console.log(leaks === 0
  ? "i18n_render_check: " + CASES.length + " inputs clean"
  : "i18n_render_check: " + leaks + " problem(s)");
process.exit(leaks === 0 ? 0 : 1);
