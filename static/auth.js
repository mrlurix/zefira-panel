"use strict";

const form = document.getElementById("login-form");
const errBox = document.getElementById("login-error");
const codeField = document.getElementById("code-field");

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
  if (!codeField.classList.contains("hidden") && form.code.value.trim()) {
    body.code = form.code.value.trim();
  }
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
    if (res.status === 401 && data && data.detail && typeof data.detail === "object") {
      if (data.detail.code === "totp_required") {
        codeField.classList.remove("hidden");
        form.code.focus();
      }
      showError(data.detail.message || "Sign-in failed");
      return;
    }
    showError((data && typeof data.detail === "string" && data.detail) || "Could not reach the server");
  } catch (_) {
    showError("Could not reach the server");
  } finally {
    btn.disabled = false;
  }
});
