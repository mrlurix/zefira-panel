/* Run the REAL applyMenuLayout() from static/app.js against a fake nav, with a
 * layout that was saved BEFORE the api section existed, and print the order it
 * produces.
 *
 * Why this exists: a Python port of the same logic proved nothing, because it
 * tested the port rather than the shipped code. Two guards "MISSED" a
 * re-introduced regression for exactly that reason. This executes the function
 * that actually ships.
 *
 * Usage: node menu_order_check.js <path-to-app.js>
 * Output: one line per section, "<id> <index>", plus a summary line.
 */
"use strict";
const fs = require("fs");
const path = require("path");

const APP = process.argv[2] || path.join(__dirname, "static", "app.js");
const src = fs.readFileSync(APP, "utf8");

// Pull the function out of the source. Brace-counted rather than regex-matched,
// so a nested block or a string containing "}" cannot end it early.
function extract(name) {
  const start = src.indexOf("function " + name + "(");
  if (start === -1) throw new Error(name + " not found in " + APP);
  let i = src.indexOf("{", start);
  let depth = 0;
  let quote = null;
  for (; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === "\\") { i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") { quote = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return src.slice(start, i + 1);
    }
  }
  throw new Error("unbalanced braces in " + name);
}

const code = extract("applyMenuLayout");

// TEMPLATE order, read from panel.html so it cannot drift from the markup.
const panel = fs.readFileSync(path.join(__dirname, "templates", "panel.html"), "utf8");
const template = [];
const re = /class="nav-btn[^"]*"[^>]*data-section="([a-z]+)"/g;
let m;
while ((m = re.exec(panel)) !== null) template.push(m[1]);

// What Personalize stored on an install that predates the api section, with the
// operator having dragged Nodes above Inbounds.
//
// The drag is deliberately between two sections that are NOT neighbours of
// `api`: if it moved one of those, the test could not tell "api kept its
// template slot" apart from "api is simply next to whatever moved".
function fullLayout() {
  const saved = template.filter((id) => id !== "api").map((id) => ({ id }));
  const iIn = saved.findIndex((x) => x.id === "inbounds");
  const iNo = saved.findIndex((x) => x.id === "nodes");
  if (iIn !== -1 && iNo !== -1) {
    const [moved] = saved.splice(iNo, 1);
    saved.splice(iIn, 0, moved);
  }
  return saved;
}

// A SPARSE layout - the case both normalizers happen to prevent today, which
// is exactly why it needed a test. With no earlier section in the saved list,
// the old "splice at 0" fallback inverted the whole menu. Run it too.
function sparseLayout() {
  return [{ id: "settings" }];
}

function run(layout) {
  const navOrder = [];
  const buttons = template.map((id) => {
    const classes = new Set();
    return {
      dataset: { section: id },
      parentElement: null,
      classList: {
        add: (c) => classes.add(c),
        remove: (c) => classes.delete(c),
        toggle: (c, on) => { if (on) classes.add(c); else classes.delete(c); },
        contains: (c) => classes.has(c),
      },
      _classes: classes,
    };
  });
  const sections = {};
  template.forEach((id) => { sections[id] = { classList: { toggle() {}, add() {}, remove() {} } }; });
  const nav = {
    querySelectorAll: (sel) => (sel === ".nav-btn" ? buttons : []),
    appendChild(child) { navOrder.push(child.dataset.section); },
  };
  buttons.forEach((b) => { b.parentElement = nav; });
  const first = buttons[0];
  const fn = new Function("document", code + "\nreturn applyMenuLayout;");
  const apply = fn({ querySelector: () => first, getElementById: (i) => sections[i] || null });
  apply(layout);
  return { navOrder, buttons };
}

// A minimal DOM: just enough for the function under test.
const full = run(fullLayout());
const sparse = run(sparseLayout());

full.navOrder.forEach((id) => {
  process.stdout.write(id + " " + full.navOrder.indexOf(id) + "\n");
});
process.stdout.write("count " + full.navOrder.length + "\n");
process.stdout.write("all_present " + (full.navOrder.length === template.length) + "\n");
process.stdout.write("api_visible "
  + !full.buttons[template.indexOf("api")]._classes.has("hidden") + "\n");
process.stdout.write("sparse_count " + sparse.navOrder.length + "\n");
process.stdout.write("sparse_all_present "
  + (sparse.navOrder.length === template.length) + "\n");
// A sparse layout must not INVERT the menu: the known section keeps its slot
// and the unknown ones land at their template positions, not reversed at the
// top.
process.stdout.write("sparse_order " + sparse.navOrder.join(",") + "\n");
process.stdout.write("sparse_settings_at " + sparse.navOrder.indexOf("settings") + "\n");
process.stdout.write("sparse_dashboard_at " + sparse.navOrder.indexOf("dashboard") + "\n");
