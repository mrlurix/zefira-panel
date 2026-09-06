"use strict";
// Active nav link
(function () {
  var path = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".sidebar a").forEach(function (a) {
    if (a.getAttribute("href") === path) a.classList.add("active");
  });
})();

// Mobile sidebar
document.getElementById("nav-toggle").addEventListener("click", function () {
  document.getElementById("sidebar").classList.toggle("open");
});
document.querySelectorAll(".sidebar a").forEach(function (a) {
  a.addEventListener("click", function () {
    document.getElementById("sidebar").classList.remove("open");
  });
});

// Sidebar search filter
document.getElementById("nav-search").addEventListener("input", function (e) {
  var q = e.target.value.toLowerCase();
  document.querySelectorAll(".sidebar a").forEach(function (a) {
    a.style.display = a.textContent.toLowerCase().includes(q) ? "" : "none";
  });
  document.querySelectorAll(".sidebar .nav-group").forEach(function (g) {
    var next = g.nextElementSibling, visible = false;
    while (next && next.tagName === "A") {
      if (next.style.display !== "none") { visible = true; break; }
      next = next.nextElementSibling;
    }
    g.style.display = visible || !q ? "" : "none";
  });
});

// Copy buttons for code blocks
document.querySelectorAll("pre").forEach(function (pre) {
  var btn = document.createElement("button");
  btn.className = "copy-btn";
  btn.textContent = "Copy";
  btn.addEventListener("click", function () {
    navigator.clipboard.writeText(pre.innerText.replace(/^Copy\n/, "")).then(function () {
      btn.textContent = "Copied ✓";
      setTimeout(function () { btn.textContent = "Copy"; }, 1500);
    });
  });
  pre.appendChild(btn);
});
