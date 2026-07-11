# vps-user-portal

An admin-gated web portal for the [vps-base-template](https://github.com/uppertoe/vps-base-template)
estate that manages the **Authelia file-backend user store** and pre-creates
users in downstream apps — so a new user can be referenced (e.g. assigned to
Planka cards) **before their first SSO login**, and offboarded without anyone
touching a terminal.

It is the sibling of [vps-scaffold-auth](https://github.com/uppertoe/vps-scaffold-auth)
(the forward-auth gateway) and is deliberately NOT part of it: the gateway
manages its own user store and stays tiny; this portal manages Authelia's.

## What it does

- **List** users: the users file joined with each app's view (present? role?
  deactivated?).
- **Invite**: writes the user to `users_database.yml` with a random throwaway
  argon2id hash, pre-creates them in configured apps, and emails them
  instructions to set their own password via Authelia's self-service reset.
  The reset **is** the email verification — the account is unusable until the
  mailbox owner completes it. The welcome mail carries no secret and no
  one-time link, so link-detonating mail scanners (Defender Safe Links) have
  nothing to consume.
- **Edit groups** (checkboxes; app roles follow via OIDC claims at next login).
- **Delete**: removes the Authelia entry (severs SSO — first, because it's the
  security-critical step) and deactivates — never deletes — the user in
  connected apps, preserving their history.

Every mutation is audit-logged (structured stdout) with the acting admin's
identity, and optionally pushed to an ntfy topic.

## Trust model (read before deploying)

The portal can rewrite the SSO user store: treat it like the auth gateway
itself. It is designed to run:

- behind the gateway's `import protected_admin` Caddy guard (email OTP +
  TOTP; unauthenticated requests never reach it). It re-checks
  `Remote-Groups` on every request as defence in depth, and CSRF-protects
  every form with tokens bound to the acting admin;
- with **no** published ports, **no** Docker socket, a read-only root
  filesystem, `cap_drop: ALL`, and exactly two mounts/networks: the Authelia
  users directory (rw) and the app database network its provisioners need;
- with a narrowly-granted database role per provisioner (see below).

Users-file writes are atomic (flock, temp + rename) and self-verifying: the
portal re-parses its own output and refuses the write unless untouched users
are provably identical and exactly the intended change happened. The previous
version is kept at `users_database.yml.bak`.

## Authelia prerequisites

1. Mount the users file via its parent **directory** in both containers
   (e.g. `./users:/config/users`). A single-file bind mount pins the inode
   and Authelia would keep reading the pre-rename file forever.
2. Point the file backend at it and enable hot reload:

   ```yaml
   authentication_backend:
     file:
       path: /config/users/users_database.yml
       watch: true
   ```

   The portal's atomic rename lands as an fsnotify Create event in the
   watched directory, which Authelia reloads on (500 ms debounce).
3. Self-service password reset enabled, with an SMTP notifier.
4. The directory must be writable by the portal's uid (run both containers as
   the file owner, e.g. `user: "1000:1000"`).

## App provisioners

Configured via a mounted `provisioners.yaml`; omit the file for
Authelia-only mode. One type ships today:

### `planka-postgres`

Pre-creates users in Planka's database (with `OIDC_ENFORCED=true` Planka's
own user API is disabled; at first OIDC login Planka links the row by email).
Rows are created with `is_sso_user=true` and `password=NULL` — no password
login path ever exists. Offboarding sets `is_deactivated=true`.

```yaml
provisioners:
  - type: planka-postgres
    name: planka
    dsn_env: PLANKA_DSN     # name of the env var holding the DSN
    roles:                  # SSO group -> Planka role, in privilege order
      planka-admins: admin
      planka-owners: projectOwner
      planka-users: boardUser
```

Create a dedicated, narrowly-granted role:

```sql
CREATE ROLE invite LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE planka TO invite;
GRANT SELECT (email, role, is_deactivated) ON user_account TO invite;
GRANT INSERT ON user_account TO invite;
GRANT UPDATE (is_deactivated, role) ON user_account TO invite;
GRANT USAGE ON SEQUENCE next_id_seq TO invite;
```

Two subtleties:
- **SELECT is column-scoped.** The portal only reads `email`, `role`,
  `is_deactivated`, so it is granted SELECT on just those columns — never the
  whole row (which holds `password`, `api_key_hash`, phone, etc. for every
  user). Table-wide `GRANT SELECT` would work but over-exposes PII/credential
  hashes on a portal or DSN compromise.
- **The sequence grant is required.** `user_account.id` defaults to `next_id()`,
  which calls `nextval('next_id_seq')` as the inserting role, so without it
  every invite fails with *permission denied for sequence next_id_seq*.

Both the schema **and** these grants are guarded: at startup (fail-fast) and
every 5 minutes the provisioner asserts the `user_account` columns it relies on
against `information_schema` **and** probes that the connected role holds exactly
these privileges — including that it is **not a superuser** (a DSN accidentally
pointed at the Planka owner is rejected). A mismatch, a missing grant, or an
over-privileged role turns `/healthz` unhealthy so `docker compose up --wait`
fails loudly instead of risking bad writes or a first-invite surprise.

A user whose groups match none of the `roles` keys is out of the app's scope
and skipped. A provisioner failure during invite is **non-fatal by design**:
the SSO user already exists, so the app simply creates them at first login
(the admin sees a warning; assignment-before-login is lost for that user).

## Configuration (env)

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | Bind address. |
| `USERS_FILE` | `/authelia-users/users_database.yml` | Authelia users file (parent dir must be writable + shared with Authelia). |
| `PROVISIONERS_FILE` | *(empty)* | Path to `provisioners.yaml`; empty = Authelia-only. |
| `ALLOWED_EMAIL_DOMAINS` | *(required)* | Invitable email domains, comma/space-separated. |
| `GROUPS` | *(required)* | Groups offered on the invite form. |
| `GROUP_LABELS` | *(empty)* | Optional human labels for the groups (`group=Label;group2=Label2`), so admins see e.g. "Administrator" instead of `planka-admins`. The raw slug still shows in muted text. |
| `ADMIN_GROUP` | `admin` | `Remote-Groups` entry required on every request. |
| `CSRF_SECRET` | *(required)* | ≥32 chars (`openssl rand -hex 32`). |
| `SSO_URL` | *(required)* | Authelia portal URL, e.g. `https://sso.example.org`. |
| `EMAIL_BACKEND` | `none` | `smtp`, `log` (print, for testing) or `none` (admin forwards instructions shown in the UI). |
| `EMAIL_HOST` / `EMAIL_PORT` / `EMAIL_USERNAME` / `EMAIL_PASSWORD` / `EMAIL_FROM` | — | SMTP submission (STARTTLS), e.g. AWS SES on 587. |
| `EMAIL_SUBJECT_PREFIX` | `[User portal]` | Welcome-mail subject brand. |
| `NTFY_URL` | *(empty)* | Full ntfy topic URL for mutation notifications. |

## Deploying

See [`deploy/`](deploy/) for a worked compose + Caddy example matching the
server-repo layout (`apps/users/`, exposed at `users.<domain>`). The image is published to
`ghcr.io/uppertoe/vps-user-portal` — pin it by digest in production.

Container healthcheck: `/app -healthcheck` probes `/healthz` (which reflects
provisioner check state).

## Local development

```bash
go test ./...
CSRF_SECRET=$(openssl rand -hex 32) ALLOWED_EMAIL_DOMAINS=example.org \
  GROUPS=planka-users SSO_URL=https://sso.example.org EMAIL_BACKEND=log \
  USERS_FILE=./tmp/users_database.yml go run .
# then request pages with identity headers, e.g.:
curl -s localhost:8080/ -H 'Remote-User: admin@example.org' -H 'Remote-Groups: admin'
```

## Known limits

- Authelia's own password-reset persistence takes no file lock; a reset
  landing in the exact instant of a portal write is a (tiny, documented)
  race. The portal's `.bak` file covers recovery.
- Removing a user doesn't revoke live Authelia sessions (in-memory, ≤1 h /
  15 min inactivity); restart Authelia for immediate revocation.
- The users file is the source of truth; hand-editing it on the server
  remains fine (with `watch: true` it hot-reloads too).
