/**
 * Extract and exercise the panel's CSV cell sanitizer (static/app.js).
 * Run: node csv_guard_check.js
 * Exits non-zero when a dangerous cell is not neutralised.
 */
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "static", "app.js"), "utf8");
const start = src.indexOf("const safeCell = (v) => {");
if (start < 0) {
  console.error("FAIL: safeCell not found in static/app.js");
  process.exit(1);
}
// Take the arrow function source verbatim: from the first "(" after the
// marker to the matching "};" that closes it.
const fnStart = src.indexOf("(", start);
const fnEnd = src.indexOf("};", fnStart) + 1;   // keep the closing brace
const fnSrc = src.slice(fnStart, fnEnd);
// eslint-disable-next-line no-eval
const safeCell = eval("(" + fnSrc + ")");

const DANGEROUS = [
  "=cmd|'/c calc'!A1",
  "+1+1",
  "-2+3",
  "@SUM(A1:A2)",
  "\t=1+1",
  "\r=1+1",
  "＝cmd",              // fullwidth equals (NFKC -> =)
  "‮=1+1",         // RTL override before the formula
  "⁦=cmd",         // isolate + formula
];
const SAFE = ["normaluser", "user_2024", "۱۲۳", "note with spaces", ""];

let bad = 0;
for (const cell of DANGEROUS) {
  const out = safeCell(cell);
  const dangerous = /^[=+\-@\t\r]/.test(out);
  if (dangerous) {
    console.error("FAIL: not neutralised:", JSON.stringify(cell), "->", JSON.stringify(out));
    bad++;
  }
}
for (const cell of SAFE) {
  const out = safeCell(cell);
  if (out !== cell) {
    console.error("FAIL: safe value altered:", JSON.stringify(cell), "->", JSON.stringify(out));
    bad++;
  }
}
console.log(bad === 0
  ? `csv guard: ${DANGEROUS.length} dangerous + ${SAFE.length} safe cells OK`
  : `csv guard: ${bad} failures`);
process.exit(bad === 0 ? 0 : 1);
