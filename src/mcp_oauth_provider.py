"""
OAuth 2.1 Authorization Server provider for MCP SSH.

Uses the same API tokens as config/tokens.json: after browser login the client
receives that token as access_token (no second secret system). Direct Bearer
tok_* from Cursor/Codex still works via load_access_token -> validate_token.
"""

from __future__ import annotations

import secrets
import time
from html import escape as html_escape
from urllib.parse import quote
from typing import Any

from pydantic import AnyHttpUrl
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from src.config import get_config

MCP_SCOPE = "mcp"


class SSHMcpOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """Minimal AS: login form submits existing MCP API token; code exchange returns it."""

    def __init__(self, auth_callback_url: str, mcp_scope: str = MCP_SCOPE):
        self.auth_callback_url = auth_callback_url.rstrip("/")
        self.mcp_scope = mcp_scope
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.code_to_api_token: dict[str, str] = {}
        self.state_mapping: dict[str, dict[str, Any]] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            raise ValueError("No client_id provided")
        self.clients[client_info.client_id] = client_info

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        state = params.state or secrets.token_hex(16)
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "client_id": client.client_id,
            "resource": params.resource,
        }
        return f"{self.auth_callback_url}/{quote(state, safe='')}"

    async def get_login_page(self, state: str) -> HTMLResponse:
        if not state:
            raise HTTPException(400, "Missing state parameter")
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MCP SSH — sign in</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 520px; margin: 2rem auto; padding: 0 1rem; }}
label {{ display: block; margin: 1rem 0 0.25rem; }}
input[type=text], input[type=password] {{ width: 100%; padding: 8px; box-sizing: border-box; }}
button {{ margin-top: 1rem; padding: 10px 20px; cursor: pointer; }}
p.note {{ color: #555; font-size: 0.9rem; }}
</style></head><body>
<h1>MCP SSH Server</h1>
<p>Enter the API token from <code>python -m src.cli token create</code> (same as Bearer for Cursor).</p>
<form method="post" action="/login/callback">
  <input type="hidden" name="state" value="{html_escape(state, quote=True)}" />
  <label for="api_token">API token</label>
  <input id="api_token" name="api_token" type="password" autocomplete="off" required />
  <button type="submit">Continue</button>
</form>
<p class="note">This page is part of the OAuth flow for MCP clients (e.g. Claude Code).</p>
</body></html>"""
        return HTMLResponse(content=html)

    async def handle_login_callback(self, request: Request) -> Response:
        form = await request.form()
        api_token = form.get("api_token")
        state = form.get("state")
        if not api_token or not state:
            raise HTTPException(400, "Missing api_token or state")
        if not isinstance(api_token, str) or not isinstance(state, str):
            raise HTTPException(400, "Invalid parameter types")
        redirect_url = await self._complete_login(api_token.strip(), state)
        return RedirectResponse(url=redirect_url, status_code=302)

    async def _complete_login(self, api_token: str, state: str) -> str:
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        cfg = get_config()
        if not cfg.validate_token(api_token):
            raise HTTPException(401, "Invalid or disabled API token")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = bool(state_data["redirect_uri_provided_explicitly"])
        client_id = state_data["client_id"]
        resource = state_data.get("resource")

        new_code = f"mcp_{secrets.token_hex(24)}"
        auth_code = AuthorizationCode(
            code=new_code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=[self.mcp_scope],
            code_challenge=code_challenge,
            resource=resource,
        )
        self.auth_codes[new_code] = auth_code
        self.code_to_api_token[new_code] = api_token
        del self.state_mapping[state]
        return construct_redirect_uri(redirect_uri, code=new_code, state=state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        code = authorization_code.code
        if code not in self.auth_codes:
            raise ValueError("Invalid authorization code")
        raw = self.code_to_api_token.pop(code, None)
        if not raw:
            raise ValueError("Authorization code expired or consumed")
        del self.auth_codes[code]
        return OAuthToken(
            access_token=raw,
            token_type="Bearer",
            expires_in=86400 * 365,
            scope=self.mcp_scope,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        cfg = get_config()
        tc = cfg.validate_token(token)
        if not tc:
            return None
        return AccessToken(
            token=token,
            client_id="mcp-ssh",
            scopes=[self.mcp_scope],
            expires_at=None,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        raise NotImplementedError("Refresh tokens are not supported")

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        pass
