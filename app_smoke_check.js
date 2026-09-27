/* Does static/app.js actually LOAD?
 *
 * `node --check` only parses; it cannot see `document.bind(...)` - a typo that
 * is perfectly valid JavaScript and throws the moment the script runs, which
 * aborts every LATER top-level statement. That is not hypothetical: a scripted
 * refactor left exactly that behind, and because every suite in this repo is
 * HTTP-level (it never clicks a nav button), all 902 checks stayed green while
 * the panel's entire lower half was dead. Only a browser found it.
 *
 * So: evaluate the WHOLE file against a minimal DOM stub and fail on any
 * throw. A stub is not a browser, but it is enough to run module-scope code,
 * and module-scope code is where this class of bug lives.
 *
 * Usage: node app_smoke_check.js [path-to-app.js]
 * Exit: 0 the module evaluated, 1 it threw.
 */
"use strict";
const fs = require("fs");
const path = require("path");

const APP = process.argv[2] || path.join(__dirname, "static", "app.js");
const src = fs.readFileSync(APP, "utf8");

// ---- a DOM stub big enough for module-scope code ----------------------
const bound = [];          // [selector, event] for every bind() that resolved
const missing = [];        // selectors bind() could not find
const timerIds = [];
const askedButNull = [];   // every "#id" the file asked for and did not get

function makeClassList(el) {
  const set = new Set();
  return {
    add: (c) => set.add(c),
    remove: (c) => set.delete(c),
    toggle: (c, on) => { if (on === undefined) { set.has(c) ? set.delete(c) : set.add(c); } else if (on) set.add(c); else set.delete(c); },
    contains: (c) => set.has(c),
    _set: set,
  };
}

function makeEl(tag, id) {
  const el = {
    tagName: (tag || "div").toUpperCase(),
    id: id || "",
    dataset: {},
    style: { setProperty() {} },
    classList: makeClassList(),
    children: [],
    value: "",
    checked: false,
    textContent: "",
    innerHTML: "",
    innerText: "",
    href: "",
    src: "",
    disabled: false,
    hidden: false,
    parentElement: null,
    options: [],
    files: [],
    addEventListener(ev, fn) { bound.push([id || el.className || "?", ev]); },
    removeEventListener() {},
    setAttribute() {},
    getAttribute() { return null; },
    removeAttribute() {},
    hasAttribute() { return false; },
    appendChild(c) { el.children.push(c); return c; },
    removeChild(c) { return c; },
    insertBefore(c) { el.children.push(c); return c; },
    replaceChildren() { el.children = []; },
    remove() {},
    cloneNode() { return makeEl(tag, id); },
    closest() { return null; },
    querySelector() { return makeEl("div"); },
    querySelectorAll() { return []; },
    getElementsByClassName() { return []; },
    getBoundingClientRect() { return { top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }; },
    focus() {},
    blur() {},
    click() {},
    dispatchEvent() {},
    scrollIntoView() {},
    getContext() { return null; },
  };
  return el;
}

// The nav and section elements app.js queries at module scope.
const NAV_SECTIONS = ["dashboard", "users", "inbounds", "tunnels", "nodes",
  "reality", "blocker", "update", "customize", "api", "settings"];
const cache = new Map();
for (const s of NAV_SECTIONS) {
  cache.set("#section-" + s, makeEl("section", "section-" + s));
  cache.set(`#${s}-badge`, makeEl("span", s + "-badge"));
}

// Build the element cache from the TEMPLATE, not from a list typed out here.
// A hand-written list is a snapshot: the first time the panel gained a new
// button, this harness reported it as a product bug (the element was right
// there in panel.html) - which is worse than no harness, because it teaches
// you to distrust it. Reading the ids makes "the script asked for an id the
// template does not have" the only thing it can ever report.
const PANEL = path.join(__dirname, "templates", "panel.html");
let templateIds = [];
try {
  const html = fs.readFileSync(PANEL, "utf8");
  templateIds = [...new Set((html.match(/\bid="([^"]+)"/g) || [])
    .map((m) => m.replace(/\bid="([^"]+)"/, "$1")))];
} catch (e) {
  console.log("app_smoke_check: could not read " + PANEL);
  process.exit(1);
}
for (const id of templateIds) {
  if (!cache.has("#" + id)) cache.set("#" + id, makeEl("div", id));
}

const documentStub = {
  documentElement: makeEl("html"),
  body: makeEl("body"),
  head: makeEl("head"),
  cookie: "zefira_session=test-session",
  readyState: "complete",
  hidden: false,
  visibilityState: "visible",
  title: "Zefira",
  addEventListener() {},
  removeEventListener() {},
  querySelector(sel) {
    if (cache.has(sel)) return cache.get(sel);
    // Anything unknown resolves to null, exactly like the real thing: a missing
    // id is the case that must not take the page down. Record it, because the
    // id is the actionable part of any report from this harness.
    if (typeof sel === "string" && sel.startsWith("#")) {
      askedButNull.push(sel);
      return null;
    }
    return makeEl("div");
  },
  querySelectorAll(sel) {
    if (sel === ".nav-btn") return NAV_SECTIONS.map((s) => makeEl("button", s));
    if (sel === ".section") return NAV_SECTIONS.map((s) => makeEl("section", s));
    if (sel === "form") return [];
    return [];
  },
  getElementById(id) { return cache.get("#" + id) || null; },
  createElement: (t) => makeEl(t),
  createTextNode: (t) => ({ nodeValue: t }),
  createDocumentFragment: () => makeEl("fragment"),
  createEvent: () => ({ initEvent() {} }),
  dispatchEvent() {},
  addRange() {},
  execCommand() { return true; },
};

const windowStub = {
  document: documentStub,
  location: { origin: "http://127.0.0.1:8000", href: "http://127.0.0.1:8000/panel",
              pathname: "/panel", search: "", hash: "", reload() {} },
  navigator: { clipboard: null, userAgent: "node", language: "en" },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
  sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
  history: { replaceState() {}, pushState() {} },
  matchMedia: () => ({ matches: false, addEventListener() {}, addListener() {} }),
  getComputedStyle: () => ({ getPropertyValue: () => "" }),
  requestAnimationFrame: (fn) => { try { fn(0); } catch (_) {} return 0; },
  cancelAnimationFrame() {},
  setTimeout: () => 0,
  clearTimeout() {},
  setInterval: () => { const id = timerIds.length; timerIds.push(1); return id; },
  clearInterval() {},
  addEventListener() {},
  removeEventListener() {},
  fetch: () => Promise.reject(new Error("no network in the smoke test")),
  FormData: function () { this.append = () => {}; },
  URL: { createObjectURL: () => "blob:x", revokeObjectURL() {} },
  Intl,
  Date,
  Math,
  JSON,
  Promise,
  console: { log() {}, warn() {}, error() {}, info() {}, debug() {} },
  alert() {},
  confirm: () => true,
  prompt: () => "x",
  scrollTo() {},
  innerWidth: 1280,
  innerHeight: 800,
  devicePixelRatio: 1,
  screen: { width: 1280, height: 800 },
  getSelection: () => ({ rangeCount: 0, addRange() {}, removeAllRanges() {} }),
};
windowStub.window = windowStub;
windowStub.self = windowStub;
windowStub.top = windowStub;
windowStub.globalThis = windowStub;

const sandboxGlobals = Object.assign({}, windowStub, {
  document: documentStub,
  window: windowStub,
  globalThis: windowStub,
  self: windowStub,
  __dirname: __dirname,
  __filename: APP,
  module: undefined,
  exports: undefined,
  require: undefined,
});

// Track which selectors bind() could not find, by wrapping it after load is
// impossible - so instead we re-run just the helper to confirm its contract.
let thrown = null;
try {
  const fn = new Function(
    ...Object.keys(sandboxGlobals),
    // The sourceURL comment is what makes V8 map a stack line back to the real
    // file. Without it every frame says <anonymous>:NNN and the report is not
    // actionable - which is the whole point of running this.
    src + "\n;return { bind: typeof bind !== 'undefined' ? bind : null };\n//# sourceURL=" + APP
  );
  const out = fn(...Object.values(sandboxGlobals));
  process.stdout.write("loaded bind=" + (out && out.bind ? "yes" : "no") + "\n");
} catch (e) {
  thrown = e;
}

if (thrown) {
  console.log("app_smoke_check: app.js THREW while loading");
  console.log("  " + String(thrown.message || thrown));
  // Map the reported line back to the source, so the report is actionable
  // rather than a bare "something at <anonymous>:NNN".
  const stackLines = (thrown.stack || "").split("\n");
  for (let i = 0; i < Math.min(3, stackLines.length); i++) {
    console.log("  " + stackLines[i].trim().slice(0, 130));
  }
  const m = (thrown.stack || "").match(/<anonymous>:(\d+):(\d+)/);
  if (m) {
    const srcLines = src.split("\n");
    const ln = parseInt(m[1], 10);
    for (let d = 0; d <= 2; d++) {
      const i = ln - 1 + d;
      if (srcLines[i] !== undefined) {
        console.log("  src " + (i + 1) + ": " + srcLines[i].trim().slice(0, 110));
      }
    }
  }
  if (askedButNull.length) {
    const uniq = [...new Set(askedButNull)];
    console.log("  #ids the page asked for and did not get (the last one is the "
      + "likely culprit):");
    for (const s of uniq.slice(-8)) console.log("    " + s);
  }
  process.exit(1);
}
console.log("app_smoke_check: app.js evaluated without throwing");
process.exit(0);
