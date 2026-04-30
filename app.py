"""
Team Task Manager
=================

A dependency-free full-stack web app for managing projects, teams, tasks, and
progress with Admin/Member role-based access control.

Run:
    python3 app.py

Then open:
    http://127.0.0.1:8000
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from datetime import UTC, date, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "team_task_manager.db"
HOST = "127.0.0.1"
PORT = int(os.getenv("PORT", "8000"))
SESSION_TTL_HOURS = 12
TOKEN_BYTES = 32
PBKDF2_ITERATIONS = 260_000
STATUSES = {"todo", "in_progress", "done"}
ROLES = {"admin", "member"}
db_lock = threading.Lock()


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def parse_json_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}$"
        f"{base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def make_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def init_db() -> None:
    with db_lock, get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                owner_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS project_members (
                project_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
                joined_at TEXT NOT NULL,
                PRIMARY KEY (project_id, user_id),
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL CHECK (status IN ('todo', 'in_progress', 'done')),
                assignee_id INTEGER,
                created_by INTEGER NOT NULL,
                due_date TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )


def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    token = make_token()
    expires_at = (utc_now() + timedelta(hours=SESSION_TTL_HOURS)).isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (token, user_id, expires_at, iso_now()),
    )
    return token


def get_current_user(headers: Any) -> dict[str, Any] | None:
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None

    token = auth.removeprefix("Bearer ").strip()
    if not token:
        return None

    with db_lock, get_db() as conn:
        row = conn.execute(
            """
            SELECT users.id, users.name, users.email, sessions.expires_at
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
            """,
            (token,),
        ).fetchone()

        if row is None:
            return None

        if datetime.fromisoformat(row["expires_at"]) < utc_now():
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            return None

        return {"id": row["id"], "name": row["name"], "email": row["email"], "token": token}


def get_project_role(conn: sqlite3.Connection, project_id: int, user_id: int) -> str | None:
    row = conn.execute(
        "SELECT role FROM project_members WHERE project_id = ? AND user_id = ?",
        (project_id, user_id),
    ).fetchone()
    return row["role"] if row else None


def get_task_role(conn: sqlite3.Connection, task_id: int, user_id: int) -> tuple[sqlite3.Row | None, str | None]:
    task = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if task is None:
        return None, None
    return task, get_project_role(conn, task["project_id"], user_id)


def require_text(data: dict[str, Any], field: str, max_len: int) -> tuple[str | None, str | None]:
    value = str(data.get(field, "")).strip()
    if not value:
        return None, f"{field.replace('_', ' ').title()} is required."
    if len(value) > max_len:
        return None, f"{field.replace('_', ' ').title()} must be {max_len} characters or less."
    return value, None


def public_user(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "name": row["name"], "email": row["email"]}


def task_payload(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["assignee"] = (
        {"id": row["assignee_id"], "name": row["assignee_name"], "email": row["assignee_email"]}
        if row["assignee_id"]
        else None
    )
    return item


INDEX_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Team Task Manager</title>
  <style>
    :root {
      --ink: #16202a;
      --muted: #64717f;
      --line: #d9e0e7;
      --paper: #ffffff;
      --bg: #f5f7fa;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --warn: #b45309;
      --danger: #b91c1c;
      --ok: #15803d;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background: var(--bg);
    }

    button, input, textarea, select { font: inherit; }
    button {
      border: 1px solid var(--accent);
      background: var(--accent);
      color: white;
      padding: 0.6rem 0.8rem;
      border-radius: 7px;
      cursor: pointer;
      font-weight: 700;
    }
    button.secondary {
      background: white;
      color: var(--accent-strong);
      border-color: var(--line);
    }
    button.danger {
      background: var(--danger);
      border-color: var(--danger);
    }
    button:disabled { opacity: 0.55; cursor: not-allowed; }

    input, textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 0.58rem 0.68rem;
      background: white;
      color: var(--ink);
    }
    textarea { min-height: 86px; resize: vertical; }
    label { display: grid; gap: 0.35rem; font-size: 0.86rem; font-weight: 700; color: #344151; }

    .app-shell { min-height: 100vh; display: grid; grid-template-rows: auto 1fr; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      padding: 1rem clamp(1rem, 4vw, 2rem);
      background: white;
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .brand { display: flex; align-items: center; gap: 0.7rem; font-weight: 850; }
    .brand-mark {
      display: grid;
      place-items: center;
      width: 34px;
      height: 34px;
      border-radius: 7px;
      background: var(--accent);
      color: white;
    }
    .userbar { display: flex; align-items: center; gap: 0.75rem; color: var(--muted); }

    main {
      width: min(1320px, 100%);
      margin: 0 auto;
      padding: 1.25rem clamp(1rem, 4vw, 2rem) 2rem;
    }
    .auth-grid {
      display: grid;
      grid-template-columns: minmax(280px, 420px);
      justify-content: center;
      gap: 1rem;
      align-items: start;
      max-width: 520px;
      margin: 8vh auto 0;
    }
    .layout {
      display: grid;
      grid-template-columns: 310px 1fr;
      gap: 1rem;
      align-items: start;
    }
    .panel, .card {
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .panel { padding: 1rem; }
    .panel + .panel { margin-top: 1rem; }
    .section-title {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.8rem;
    }
    h1, h2, h3 { margin: 0; letter-spacing: 0; }
    h1 { font-size: 1.45rem; }
    h2 { font-size: 1.05rem; }
    h3 { font-size: 0.96rem; }
    p { color: var(--muted); margin: 0.35rem 0 0; line-height: 1.45; }
    .muted { color: var(--muted); }
    .stack { display: grid; gap: 0.75rem; }
    .row { display: flex; gap: 0.65rem; align-items: end; }
    .row > * { flex: 1; }
    .message { margin-top: 0.75rem; font-weight: 700; }
    .message.error { color: var(--danger); }
    .message.ok { color: var(--ok); }
    .auth-switch {
      text-align: center;
      color: var(--muted);
      font-size: 0.9rem;
      line-height: 1.4;
    }
    .link-button {
      border: 0;
      background: transparent;
      color: var(--accent-strong);
      padding: 0;
      border-radius: 0;
      font-weight: 800;
      text-decoration: underline;
      text-underline-offset: 3px;
    }

    .project-list { display: grid; gap: 0.5rem; }
    .project-button {
      width: 100%;
      background: white;
      color: var(--ink);
      border: 1px solid var(--line);
      text-align: left;
      display: grid;
      gap: 0.25rem;
    }
    .project-button.active { border-color: var(--accent); box-shadow: inset 3px 0 0 var(--accent); }
    .pill {
      display: inline-flex;
      align-items: center;
      width: fit-content;
      gap: 0.25rem;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 0.18rem 0.5rem;
      color: var(--muted);
      font-size: 0.75rem;
      font-weight: 800;
      text-transform: uppercase;
    }
    .pill.admin { color: var(--accent-strong); border-color: #99d3cc; background: #effaf8; }
    .pill.todo { color: #334155; }
    .pill.in_progress { color: #1d4ed8; border-color: #bfdbfe; background: #eff6ff; }
    .pill.done { color: var(--ok); border-color: #bbf7d0; background: #f0fdf4; }
    .pill.overdue { color: var(--warn); border-color: #fed7aa; background: #fff7ed; }

    .dashboard {
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1rem;
    }
    .metric { padding: 0.9rem; }
    .metric strong { display: block; font-size: 1.6rem; line-height: 1.1; }

    .toolbar {
      display: grid;
      grid-template-columns: 1fr 160px 180px;
      gap: 0.65rem;
      margin-bottom: 0.8rem;
    }
    .task-grid { display: grid; gap: 0.7rem; }
    .task-card { padding: 0.9rem; display: grid; gap: 0.75rem; }
    .task-top, .task-actions {
      display: flex;
      justify-content: space-between;
      align-items: start;
      gap: 0.75rem;
    }
    .task-actions { align-items: end; }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
      color: var(--muted);
      font-size: 0.84rem;
    }
    .team-list { display: grid; gap: 0.5rem; }
    .member-item {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 0.5rem;
      align-items: center;
      padding: 0.55rem 0;
      border-top: 1px solid var(--line);
    }
    .hidden { display: none !important; }

    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
      .dashboard, .toolbar { grid-template-columns: repeat(2, 1fr); }
      .toolbar input { grid-column: 1 / -1; }
    }
    @media (max-width: 560px) {
      header, .userbar, .task-top, .task-actions, .row { align-items: stretch; flex-direction: column; }
      .dashboard, .toolbar { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app-shell">
    <header>
      <div class="brand"><span class="brand-mark">✓</span><span>Team Task Manager</span></div>
      <div id="userbar" class="userbar hidden">
        <span id="currentUser"></span>
        <button class="secondary" id="logoutBtn">Logout</button>
      </div>
    </header>

    <main>
      <section id="authView" class="auth-grid">
        <form id="loginForm" class="panel stack">
          <div>
            <h1>Login</h1>
            <p>Use your existing account to continue work.</p>
          </div>
          <label>Email <input name="email" type="email" required autocomplete="email"></label>
          <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
          <button type="submit">Login</button>
          <p class="auth-switch">New account? <button class="link-button" id="showSignupBtn" type="button">Sign up</button></p>
          <div id="loginMessage" class="message"></div>
        </form>

        <form id="signupForm" class="panel stack hidden">
          <div>
            <h1>Create Account</h1>
            <p>Sign up to create projects and invite team members.</p>
          </div>
          <label>Name <input name="name" required maxlength="80" autocomplete="name"></label>
          <label>Email <input name="email" type="email" required maxlength="120" autocomplete="email"></label>
          <label>Password <input name="password" type="password" required minlength="8" autocomplete="new-password"></label>
          <button type="submit">Sign Up</button>
          <p class="auth-switch">Already have an account? <button class="link-button" id="showLoginBtn" type="button">Login</button></p>
          <div id="signupMessage" class="message"></div>
        </form>
      </section>

      <section id="appView" class="layout hidden">
        <aside>
          <div class="panel">
            <div class="section-title">
              <h2>Projects</h2>
              <span id="projectCount" class="pill">0</span>
            </div>
            <div id="projectList" class="project-list"></div>
          </div>

          <form id="projectForm" class="panel stack">
            <h2>New Project</h2>
            <label>Name <input name="name" required maxlength="120"></label>
            <label>Description <textarea name="description" maxlength="500"></textarea></label>
            <button type="submit">Create Project</button>
            <div id="projectMessage" class="message"></div>
          </form>

          <form id="memberForm" class="panel stack hidden">
            <h2>Add Team Member</h2>
            <label>User Email <input name="email" type="email" required></label>
            <label>Role
              <select name="role">
                <option value="member">Member</option>
                <option value="admin">Admin</option>
              </select>
            </label>
            <button type="submit">Add Member</button>
            <div id="memberMessage" class="message"></div>
          </form>
        </aside>

        <section>
          <div id="emptyState" class="panel">
            <h1>No Project Selected</h1>
            <p>Create or select a project to manage tasks, assignments, and progress.</p>
          </div>

          <div id="projectWorkspace" class="hidden">
            <div class="panel">
              <div class="section-title">
                <div>
                  <h1 id="projectName"></h1>
                  <p id="projectDescription"></p>
                </div>
                <span id="myRole" class="pill"></span>
              </div>
              <div id="dashboard" class="dashboard"></div>
            </div>

            <form id="taskForm" class="panel stack">
              <h2>New Task</h2>
              <div class="row">
                <label>Title <input name="title" required maxlength="140"></label>
                <label>Assignee <select name="assignee_id"></select></label>
                <label>Due Date <input name="due_date" type="date"></label>
              </div>
              <label>Description <textarea name="description" maxlength="800"></textarea></label>
              <button type="submit">Create Task</button>
              <div id="taskMessage" class="message"></div>
            </form>

            <div class="panel">
              <div class="section-title">
                <h2>Tasks</h2>
              </div>
              <div class="toolbar">
                <input id="searchInput" placeholder="Search tasks">
                <select id="statusFilter">
                  <option value="">All statuses</option>
                  <option value="todo">To do</option>
                  <option value="in_progress">In progress</option>
                  <option value="done">Done</option>
                </select>
                <select id="assigneeFilter">
                  <option value="">All assignees</option>
                </select>
              </div>
              <div id="taskList" class="task-grid"></div>
            </div>

            <div class="panel">
              <div class="section-title"><h2>Team</h2></div>
              <div id="teamList" class="team-list"></div>
            </div>
          </div>
        </section>
      </section>
    </main>
  </div>

  <script>
    const state = {
      token: localStorage.getItem("ttm_token"),
      user: null,
      projects: [],
      selectedProjectId: null,
      projectDetail: null
    };

    const $ = (id) => document.getElementById(id);
    const statusLabels = { todo: "To do", in_progress: "In progress", done: "Done" };

    function setMessage(id, text, ok = false) {
      const el = $(id);
      el.textContent = text || "";
      el.className = text ? `message ${ok ? "ok" : "error"}` : "message";
    }

    async function api(path, options = {}) {
      const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
      if (state.token) headers.Authorization = `Bearer ${state.token}`;
      const response = await fetch(path, { ...options, headers });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || "Request failed.");
      return payload;
    }

    function formData(form) {
      return Object.fromEntries(new FormData(form).entries());
    }

    function requireProject() {
      if (!state.selectedProjectId) throw new Error("Select a project first.");
      return state.selectedProjectId;
    }

    async function boot() {
      if (!state.token) {
        showAuth();
        return;
      }
      try {
        const payload = await api("/api/me");
        state.user = payload.user;
        showApp();
        await loadProjects();
      } catch {
        logout();
      }
    }

    function showAuth() {
      $("authView").classList.remove("hidden");
      $("appView").classList.add("hidden");
      $("userbar").classList.add("hidden");
      showLogin();
    }

    function showLogin() {
      $("loginForm").classList.remove("hidden");
      $("signupForm").classList.add("hidden");
      setMessage("signupMessage", "");
    }

    function showSignup() {
      $("signupForm").classList.remove("hidden");
      $("loginForm").classList.add("hidden");
      setMessage("loginMessage", "");
    }

    function showApp() {
      $("authView").classList.add("hidden");
      $("appView").classList.remove("hidden");
      $("userbar").classList.remove("hidden");
      $("currentUser").textContent = `${state.user.name} (${state.user.email})`;
    }

    function logout() {
      state.token = null;
      state.user = null;
      state.projects = [];
      state.selectedProjectId = null;
      state.projectDetail = null;
      localStorage.removeItem("ttm_token");
      showAuth();
    }

    async function loadProjects() {
      const payload = await api("/api/projects");
      state.projects = payload.projects;
      if (!state.selectedProjectId && state.projects.length) state.selectedProjectId = state.projects[0].id;
      renderProjects();
      if (state.selectedProjectId) await loadProjectDetail(state.selectedProjectId);
      else renderWorkspace();
    }

    async function loadProjectDetail(id) {
      state.selectedProjectId = Number(id);
      state.projectDetail = await api(`/api/projects/${id}`);
      renderProjects();
      renderWorkspace();
    }

    function renderProjects() {
      $("projectCount").textContent = state.projects.length;
      $("projectList").innerHTML = state.projects.map(project => `
        <button class="project-button ${project.id === state.selectedProjectId ? "active" : ""}" data-project="${project.id}">
          <strong>${escapeHtml(project.name)}</strong>
          <span class="muted">${project.task_count} tasks</span>
          <span class="pill ${project.role}">${project.role}</span>
        </button>
      `).join("") || `<p>No projects yet.</p>`;
      document.querySelectorAll("[data-project]").forEach(btn => {
        btn.addEventListener("click", () => loadProjectDetail(btn.dataset.project));
      });
    }

    function renderWorkspace() {
      const detail = state.projectDetail;
      $("emptyState").classList.toggle("hidden", Boolean(detail));
      $("projectWorkspace").classList.toggle("hidden", !detail);
      $("memberForm").classList.toggle("hidden", !detail || detail.role !== "admin");
      $("taskForm").classList.toggle("hidden", !detail);
      if (!detail) return;

      $("projectName").textContent = detail.project.name;
      $("projectDescription").textContent = detail.project.description || "No description provided.";
      $("myRole").textContent = detail.role;
      $("myRole").className = `pill ${detail.role}`;
      renderDashboard(detail.dashboard);
      renderTeam(detail.members);
      renderAssigneeOptions(detail.members);
      renderTasks();
    }

    function renderDashboard(dashboard) {
      const entries = [
        ["Total", dashboard.total],
        ["To do", dashboard.todo],
        ["In progress", dashboard.in_progress],
        ["Overdue", dashboard.overdue]
      ];
      $("dashboard").innerHTML = entries.map(([label, value]) => `
        <div class="card metric"><strong>${value}</strong><span class="muted">${label}</span></div>
      `).join("");
    }

    function renderTeam(members) {
      $("teamList").innerHTML = members.map(member => `
        <div class="member-item">
          <div>
            <strong>${escapeHtml(member.name)}</strong>
            <p>${escapeHtml(member.email)}</p>
          </div>
          <span class="pill ${member.role}">${member.role}</span>
        </div>
      `).join("");
    }

    function renderAssigneeOptions(members) {
      const options = `<option value="">Unassigned</option>` + members.map(member =>
        `<option value="${member.id}">${escapeHtml(member.name)}</option>`
      ).join("");
      $("taskForm").elements.assignee_id.innerHTML = options;
      $("assigneeFilter").innerHTML = `<option value="">All assignees</option><option value="unassigned">Unassigned</option>` +
        members.map(member => `<option value="${member.id}">${escapeHtml(member.name)}</option>`).join("");
    }

    function renderTasks() {
      const detail = state.projectDetail;
      const search = $("searchInput").value.trim().toLowerCase();
      const status = $("statusFilter").value;
      const assignee = $("assigneeFilter").value;
      let tasks = detail.tasks;

      if (search) {
        tasks = tasks.filter(task =>
          task.title.toLowerCase().includes(search) ||
          (task.description || "").toLowerCase().includes(search)
        );
      }
      if (status) tasks = tasks.filter(task => task.status === status);
      if (assignee === "unassigned") tasks = tasks.filter(task => !task.assignee_id);
      else if (assignee) tasks = tasks.filter(task => String(task.assignee_id) === assignee);

      $("taskList").innerHTML = tasks.map(task => {
        const overdue = task.due_date && task.status !== "done" && task.due_date < new Date().toISOString().slice(0, 10);
        return `
          <article class="card task-card">
            <div class="task-top">
              <div>
                <h3>${escapeHtml(task.title)}</h3>
                <p>${escapeHtml(task.description || "No description.")}</p>
              </div>
              <span class="pill ${task.status}">${statusLabels[task.status]}</span>
            </div>
            <div class="meta">
              <span>Assignee: ${task.assignee ? escapeHtml(task.assignee.name) : "Unassigned"}</span>
              <span>Due: ${task.due_date || "None"}</span>
              ${overdue ? `<span class="pill overdue">Overdue</span>` : ""}
            </div>
            <div class="task-actions">
              <label>Status
                <select data-status-task="${task.id}">
                  ${Object.entries(statusLabels).map(([value, label]) =>
                    `<option value="${value}" ${task.status === value ? "selected" : ""}>${label}</option>`
                  ).join("")}
                </select>
              </label>
              ${detail.role === "admin" ? `
                <button class="danger" data-delete-task="${task.id}" type="button">Delete</button>
              ` : ""}
            </div>
          </article>
        `;
      }).join("") || `<p>No tasks match the current filters.</p>`;

      document.querySelectorAll("[data-status-task]").forEach(select => {
        select.addEventListener("change", async () => {
          await api(`/api/tasks/${select.dataset.statusTask}`, {
            method: "PATCH",
            body: JSON.stringify({ status: select.value })
          });
          await loadProjectDetail(state.selectedProjectId);
        });
      });
      document.querySelectorAll("[data-delete-task]").forEach(button => {
        button.addEventListener("click", async () => {
          await api(`/api/tasks/${button.dataset.deleteTask}`, { method: "DELETE" });
          await loadProjectDetail(state.selectedProjectId);
        });
      });
    }

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
      }[char]));
    }

    $("signupForm").addEventListener("submit", async event => {
      event.preventDefault();
      try {
        const payload = await api("/api/signup", { method: "POST", body: JSON.stringify(formData(event.target)) });
        state.token = payload.token;
        state.user = payload.user;
        localStorage.setItem("ttm_token", state.token);
        setMessage("signupMessage", "Account created.", true);
        showApp();
        await loadProjects();
      } catch (error) {
        setMessage("signupMessage", error.message);
      }
    });

    $("loginForm").addEventListener("submit", async event => {
      event.preventDefault();
      try {
        const payload = await api("/api/login", { method: "POST", body: JSON.stringify(formData(event.target)) });
        state.token = payload.token;
        state.user = payload.user;
        localStorage.setItem("ttm_token", state.token);
        setMessage("loginMessage", "Logged in.", true);
        showApp();
        await loadProjects();
      } catch (error) {
        setMessage("loginMessage", error.message);
      }
    });

    $("logoutBtn").addEventListener("click", logout);
    $("showSignupBtn").addEventListener("click", showSignup);
    $("showLoginBtn").addEventListener("click", showLogin);

    $("projectForm").addEventListener("submit", async event => {
      event.preventDefault();
      try {
        const payload = await api("/api/projects", { method: "POST", body: JSON.stringify(formData(event.target)) });
        event.target.reset();
        state.selectedProjectId = payload.project.id;
        setMessage("projectMessage", "Project created.", true);
        await loadProjects();
      } catch (error) {
        setMessage("projectMessage", error.message);
      }
    });

    $("memberForm").addEventListener("submit", async event => {
      event.preventDefault();
      try {
        await api(`/api/projects/${requireProject()}/members`, { method: "POST", body: JSON.stringify(formData(event.target)) });
        event.target.reset();
        setMessage("memberMessage", "Member added.", true);
        await loadProjectDetail(state.selectedProjectId);
      } catch (error) {
        setMessage("memberMessage", error.message);
      }
    });

    $("taskForm").addEventListener("submit", async event => {
      event.preventDefault();
      try {
        await api(`/api/projects/${requireProject()}/tasks`, { method: "POST", body: JSON.stringify(formData(event.target)) });
        event.target.reset();
        setMessage("taskMessage", "Task created.", true);
        await loadProjects();
      } catch (error) {
        setMessage("taskMessage", error.message);
      }
    });

    ["searchInput", "statusFilter", "assigneeFilter"].forEach(id => {
      $(id).addEventListener("input", renderTasks);
      $(id).addEventListener("change", renderTasks);
    });

    boot();
  </script>
</body>
</html>
"""


class AppHandler(BaseHTTPRequestHandler):
    server_version = "TeamTaskManager/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_html(INDEX_HTML)
            return

        if parsed.path == "/api/me":
            self.handle_me()
            return

        if parsed.path == "/api/projects":
            self.handle_projects_index()
            return

        if parsed.path.startswith("/api/projects/"):
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "projects":
                self.handle_project_detail(int_or_none(parts[2]))
                return

        self.send_error_json(HTTPStatus.NOT_FOUND, "Route not found.")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/signup":
            self.handle_signup()
            return
        if parsed.path == "/api/login":
            self.handle_login()
            return
        if parsed.path == "/api/projects":
            self.handle_create_project()
            return
        if parsed.path.startswith("/api/projects/"):
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "projects" and parts[3] == "members":
                self.handle_add_member(int_or_none(parts[2]))
                return
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "projects" and parts[3] == "tasks":
                self.handle_create_task(int_or_none(parts[2]))
                return
        self.send_error_json(HTTPStatus.NOT_FOUND, "Route not found.")

    def do_PATCH(self) -> None:
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "tasks":
            self.handle_update_task(int_or_none(parts[2]))
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "Route not found.")

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "tasks":
            self.handle_delete_task(int_or_none(parts[2]))
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "Route not found.")

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            raise ValueError("Request body must be valid JSON.")

    def current_user_or_error(self) -> dict[str, Any] | None:
        user = get_current_user(self.headers)
        if user is None:
            self.send_error_json(HTTPStatus.UNAUTHORIZED, "Authentication required.")
        return user

    def handle_signup(self) -> None:
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return

        name, err = require_text(data, "name", 80)
        if err:
            self.send_error_json(HTTPStatus.BAD_REQUEST, err)
            return
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))

        if "@" not in email or len(email) > 120:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "A valid email is required.")
            return
        if len(password) < 8:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Password must be at least 8 characters.")
            return

        try:
            with db_lock, get_db() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (name, email, hash_password(password), iso_now()),
                )
                token = create_session(conn, cursor.lastrowid)
                user = conn.execute("SELECT id, name, email FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
        except sqlite3.IntegrityError:
            self.send_error_json(HTTPStatus.CONFLICT, "Email is already registered.")
            return

        self.send_json({"token": token, "user": public_user(user)}, HTTPStatus.CREATED)

    def handle_login(self) -> None:
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return

        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))

        with db_lock, get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user is None or not verify_password(password, user["password_hash"]):
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "Invalid email or password.")
                return
            token = create_session(conn, user["id"])
            public = conn.execute("SELECT id, name, email FROM users WHERE id = ?", (user["id"],)).fetchone()

        self.send_json({"token": token, "user": public_user(public)})

    def handle_me(self) -> None:
        user = self.current_user_or_error()
        if user is None:
            return
        self.send_json({"user": {"id": user["id"], "name": user["name"], "email": user["email"]}})

    def handle_projects_index(self) -> None:
        user = self.current_user_or_error()
        if user is None:
            return

        with db_lock, get_db() as conn:
            rows = conn.execute(
                """
                SELECT projects.id, projects.name, projects.description, project_members.role,
                       COUNT(tasks.id) AS task_count
                FROM projects
                JOIN project_members ON project_members.project_id = projects.id
                LEFT JOIN tasks ON tasks.project_id = projects.id
                WHERE project_members.user_id = ?
                GROUP BY projects.id, project_members.role
                ORDER BY projects.created_at DESC
                """,
                (user["id"],),
            ).fetchall()
        self.send_json({"projects": [dict(row) for row in rows]})

    def handle_create_project(self) -> None:
        user = self.current_user_or_error()
        if user is None:
            return
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return

        name, err = require_text(data, "name", 120)
        if err:
            self.send_error_json(HTTPStatus.BAD_REQUEST, err)
            return
        description = str(data.get("description", "")).strip()[:500]

        with db_lock, get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO projects (name, description, owner_id, created_at) VALUES (?, ?, ?, ?)",
                (name, description, user["id"], iso_now()),
            )
            project_id = cursor.lastrowid
            conn.execute(
                "INSERT INTO project_members (project_id, user_id, role, joined_at) VALUES (?, ?, 'admin', ?)",
                (project_id, user["id"], iso_now()),
            )
            project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()

        self.send_json({"project": row_to_dict(project)}, HTTPStatus.CREATED)

    def handle_project_detail(self, project_id: int | None) -> None:
        user = self.current_user_or_error()
        if user is None:
            return
        if project_id is None:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Invalid project id.")
            return

        with db_lock, get_db() as conn:
            role = get_project_role(conn, project_id, user["id"])
            if role is None:
                self.send_error_json(HTTPStatus.FORBIDDEN, "You do not have access to this project.")
                return

            project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            members = conn.execute(
                """
                SELECT users.id, users.name, users.email, project_members.role
                FROM project_members
                JOIN users ON users.id = project_members.user_id
                WHERE project_members.project_id = ?
                ORDER BY project_members.role, users.name
                """,
                (project_id,),
            ).fetchall()
            tasks = conn.execute(
                """
                SELECT tasks.*, users.name AS assignee_name, users.email AS assignee_email
                FROM tasks
                LEFT JOIN users ON users.id = tasks.assignee_id
                WHERE tasks.project_id = ?
                ORDER BY
                    CASE tasks.status WHEN 'todo' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
                    COALESCE(tasks.due_date, '9999-12-31'),
                    tasks.created_at DESC
                """,
                (project_id,),
            ).fetchall()

        dashboard = build_dashboard(tasks)
        self.send_json(
            {
                "project": row_to_dict(project),
                "role": role,
                "members": [dict(row) for row in members],
                "tasks": [task_payload(row) for row in tasks],
                "dashboard": dashboard,
            }
        )

    def handle_add_member(self, project_id: int | None) -> None:
        user = self.current_user_or_error()
        if user is None:
            return
        if project_id is None:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Invalid project id.")
            return
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return

        email = str(data.get("email", "")).strip().lower()
        role = str(data.get("role", "member")).strip()
        if role not in ROLES:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Role must be admin or member.")
            return

        with db_lock, get_db() as conn:
            if get_project_role(conn, project_id, user["id"]) != "admin":
                self.send_error_json(HTTPStatus.FORBIDDEN, "Only project admins can add members.")
                return
            member = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if member is None:
                self.send_error_json(HTTPStatus.NOT_FOUND, "No registered user found with that email.")
                return
            conn.execute(
                """
                INSERT INTO project_members (project_id, user_id, role, joined_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role
                """,
                (project_id, member["id"], role, iso_now()),
            )

        self.send_json({"ok": True}, HTTPStatus.CREATED)

    def handle_create_task(self, project_id: int | None) -> None:
        user = self.current_user_or_error()
        if user is None:
            return
        if project_id is None:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Invalid project id.")
            return
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return

        title, err = require_text(data, "title", 140)
        if err:
            self.send_error_json(HTTPStatus.BAD_REQUEST, err)
            return
        description = str(data.get("description", "")).strip()[:800]
        assignee_id = int_or_none(str(data.get("assignee_id") or ""))
        due_date = str(data.get("due_date") or "").strip() or None
        if due_date and parse_json_date(due_date) is None:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Due date must use YYYY-MM-DD format.")
            return

        with db_lock, get_db() as conn:
            if get_project_role(conn, project_id, user["id"]) is None:
                self.send_error_json(HTTPStatus.FORBIDDEN, "You do not have access to this project.")
                return
            if assignee_id is not None and get_project_role(conn, project_id, assignee_id) is None:
                self.send_error_json(HTTPStatus.BAD_REQUEST, "Assignee must be a member of the project.")
                return
            now = iso_now()
            cursor = conn.execute(
                """
                INSERT INTO tasks
                    (project_id, title, description, status, assignee_id, created_by, due_date, created_at, updated_at)
                VALUES (?, ?, ?, 'todo', ?, ?, ?, ?, ?)
                """,
                (project_id, title, description, assignee_id, user["id"], due_date, now, now),
            )
            task = conn.execute("SELECT * FROM tasks WHERE id = ?", (cursor.lastrowid,)).fetchone()

        self.send_json({"task": row_to_dict(task)}, HTTPStatus.CREATED)

    def handle_update_task(self, task_id: int | None) -> None:
        user = self.current_user_or_error()
        if user is None:
            return
        if task_id is None:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Invalid task id.")
            return
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return

        with db_lock, get_db() as conn:
            task, role = get_task_role(conn, task_id, user["id"])
            if task is None:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Task not found.")
                return
            if role is None:
                self.send_error_json(HTTPStatus.FORBIDDEN, "You do not have access to this task.")
                return

            fields: list[str] = []
            values: list[Any] = []

            if "status" in data:
                status = str(data["status"]).strip()
                if status not in STATUSES:
                    self.send_error_json(HTTPStatus.BAD_REQUEST, "Invalid task status.")
                    return
                fields.append("status = ?")
                values.append(status)

            if role == "admin":
                if "title" in data:
                    title, err = require_text(data, "title", 140)
                    if err:
                        self.send_error_json(HTTPStatus.BAD_REQUEST, err)
                        return
                    fields.append("title = ?")
                    values.append(title)
                if "description" in data:
                    fields.append("description = ?")
                    values.append(str(data.get("description", "")).strip()[:800])
                if "due_date" in data:
                    due_date = str(data.get("due_date") or "").strip() or None
                    if due_date and parse_json_date(due_date) is None:
                        self.send_error_json(HTTPStatus.BAD_REQUEST, "Due date must use YYYY-MM-DD format.")
                        return
                    fields.append("due_date = ?")
                    values.append(due_date)
                if "assignee_id" in data:
                    assignee_id = int_or_none(str(data.get("assignee_id") or ""))
                    if assignee_id is not None and get_project_role(conn, task["project_id"], assignee_id) is None:
                        self.send_error_json(HTTPStatus.BAD_REQUEST, "Assignee must be a member of the project.")
                        return
                    fields.append("assignee_id = ?")
                    values.append(assignee_id)

            if not fields:
                self.send_error_json(HTTPStatus.BAD_REQUEST, "No valid task updates were provided.")
                return

            fields.append("updated_at = ?")
            values.append(iso_now())
            values.append(task_id)
            conn.execute(f"UPDATE tasks SET {', '.join(fields)} WHERE id = ?", values)
            updated = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()

        self.send_json({"task": row_to_dict(updated)})

    def handle_delete_task(self, task_id: int | None) -> None:
        user = self.current_user_or_error()
        if user is None:
            return
        if task_id is None:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Invalid task id.")
            return

        with db_lock, get_db() as conn:
            task, role = get_task_role(conn, task_id, user["id"])
            if task is None:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Task not found.")
                return
            if role != "admin":
                self.send_error_json(HTTPStatus.FORBIDDEN, "Only project admins can delete tasks.")
                return
            conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))

        self.send_json({"ok": True})

    def send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: HTTPStatus, message: str) -> None:
        self.send_json({"error": message}, status)


def int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_dashboard(tasks: list[sqlite3.Row]) -> dict[str, int]:
    today = date.today().isoformat()
    dashboard = {"total": len(tasks), "todo": 0, "in_progress": 0, "done": 0, "overdue": 0}
    for task in tasks:
        dashboard[task["status"]] += 1
        if task["due_date"] and task["status"] != "done" and task["due_date"] < today:
            dashboard["overdue"] += 1
    return dashboard


def run_server() -> None:
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), AppHandler)
    print(f"Team Task Manager running at http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
