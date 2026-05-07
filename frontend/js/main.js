/* js/main.js – shared utilities */

// ── Toast ────────────────────────────────────────────────
function toast(msg, type = "info", duration = 3500) {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), duration);
}

// ── Auth helpers ─────────────────────────────────────────
async function getMe() {
  try {
    const r = await fetch(`${API_BASE}/api/auth/me`, { credentials: "include" });
    return r.ok ? r.json() : null;
  } catch { return null; }
}

async function logout() {
  await fetch(`${API_BASE}/api/auth/logout`, { method: "POST", credentials: "include" });
  window.location.href = "login.html";
}

// ── Navbar active link ────────────────────────────────────
function markActiveNav() {
  const path = window.location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav-links a").forEach(a => {
    const href = a.getAttribute("href");
    if (href === path) a.classList.add("active");
  });
}

// ── Mobile hamburger ──────────────────────────────────────
function initHamburger() {
  const btn = document.getElementById("hamburger-btn");
  const links = document.getElementById("nav-links");
  if (!btn || !links) return;
  btn.addEventListener("click", () => {
    const open = links.classList.toggle("open");
    btn.setAttribute("aria-expanded", open);
  });
}

// ── Render user chip in nav ───────────────────────────────
async function renderUserNav() {
  const user = await getMe();
  const el = document.getElementById("user-nav");
  if (!el) return;
  if (user) {
    el.innerHTML = `
      <span class="text-small" style="color:rgba(255,255,255,.7)">${user.username}</span>
      <button class="btn btn-outline btn-sm" onclick="logout()"
        style="border-color:rgba(255,255,255,.4);color:#fff;padding:.3rem .7rem">
        Sign out
      </button>`;
  } else {
    el.innerHTML = `<a href="login.html" class="btn btn-gold btn-sm">Sign in</a>`;
  }
}

// ── Sanitise HTML (prevent XSS in rendered results) ───────
function esc(str) {
  const d = document.createElement("div");
  d.textContent = String(str ?? "");
  return d.innerHTML;
}

// ── Book card template ────────────────────────────────────
function bookCardHTML(book) {
  const avail = book.available
    ? `<span class="badge badge-green">Available</span>`
    : `<span class="badge badge-red">Checked Out</span>`;
  const cat = book.category
    ? `<span class="badge badge-navy">${esc(book.category)}</span>`
    : "";
  return `
    <div class="card book-card" onclick="openBook('${esc(book.id)}')">
      <div class="book-cover" aria-hidden="true">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
            d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" />
        </svg>
      </div>
      <div class="card-body">
        <div class="book-title">${esc(book.title)}</div>
        <div class="book-author">${esc(book.author)}</div>
        <div class="book-meta">${avail}${cat}</div>
      </div>
    </div>`;
}

// ── Init on page load ─────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  markActiveNav();
  initHamburger();
  renderUserNav();
});
