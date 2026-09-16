"use strict";

const form = document.getElementById("login-form");const errBox = document.getElementById("login-error");

function showError(msg) {
  errBox.textContent = msg;
  errBox.classList.add("show");
  const card = document.querySelector(".login-card");
  card.classList.remove("shake");
  void card.offsetWidth;
  card.classList.add("shake");
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errBox.textContent = "";
  errBox.classList.remove("show");
  const btn = document.getElementById("login-btn");
  btn.disabled = true;
  const body = {
    username: form.username.value.trim(),
    password: form.password.value
  };
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
      },
      body: JSON.stringify(body)
    });
    if (res.ok) {
      location.href = "/panel";
      return;
    }
    let data = null;
    try { data = await res.json(); } catch (_) {}
    showError((data && typeof data.detail === "string" && data.detail) || "Could not reach the server");
  } catch (_) {
    showError("Could not reach the server");
  } finally {
    btn.disabled = false;
  }
});

// Public brand for the login page (no session needed).
fetch("/api/appearance").then((r) => r.json()).then((a) => {
  const b = ((a && a.brand_name) || "").trim() || "ZEFIRA";
  document.querySelectorAll("[data-brand]").forEach((el) => { el.textContent = b; });
  document.title = "Sign in | " + b;
}).catch(() => {});
