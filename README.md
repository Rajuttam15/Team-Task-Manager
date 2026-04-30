# Team Task Manager

A dependency-free full-stack Python web app for creating projects, managing team
members, assigning tasks, and tracking progress with Admin/Member access rules.

## Run

```bash
python3 app.py
```

Open `http://127.0.0.1:8000`.

## Features

- Signup and login with hashed passwords and bearer-token sessions
- SQLite database with users, sessions, projects, project members, and tasks
- REST API under `/api`
- Project creation and team membership management
- Admin/Member role-based access control
- Task creation, assignment, status updates, due dates, and deletion
- Dashboard metrics for total tasks, status counts, and overdue work
- Client-side filtering by text, status, and assignee

## Role Rules

- Project creators become `admin` members automatically.
- Admins can add members, promote members, create tasks, edit task metadata, and delete tasks.
- Members can view assigned project data, create tasks, and update task status.

## API Overview

- `POST /api/signup`
- `POST /api/login`
- `GET /api/me`
- `GET /api/projects`
- `POST /api/projects`
- `GET /api/projects/{id}`
- `POST /api/projects/{id}/members`
- `POST /api/projects/{id}/tasks`
- `PATCH /api/tasks/{id}`
- `DELETE /api/tasks/{id}`

The SQLite file is created automatically as `team_task_manager.db` on first run.
# Team-Task-Manager
