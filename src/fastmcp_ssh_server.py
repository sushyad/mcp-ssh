"""FastMCP (official SDK) server exposing SSH tools + optional MCP OAuth (RFC 9728)."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable

from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from src.config import TokenConfig, get_config
from src.mcp_handler import TOOL_RESPONSE_SUFFIX
from src.mcp_oauth_provider import MCP_SCOPE, SSHMcpOAuthProvider
from src.mcp_tools import get_mcp_tools

logger = logging.getLogger(__name__)


def _public_base_url() -> str:
    return os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def _token_config_from_context() -> TokenConfig:
    access = get_access_token()
    if access is None:
        raise RuntimeError("Not authenticated")
    tc = get_config().validate_token(access.token)
    if tc is None:
        raise RuntimeError("Invalid or disabled token")
    return tc


def _token_config_from_env() -> TokenConfig:
    token = os.getenv("MCP_TOKEN")
    if not token:
        raise RuntimeError("MCP_TOKEN environment variable is not set")
    tc = get_config().validate_token(token)
    if tc is None:
        raise RuntimeError("Invalid or disabled MCP_TOKEN")
    return tc


def _suffix(result: dict) -> str:
    return json.dumps(result, indent=2) + TOOL_RESPONSE_SUFFIX


def _register_ssh_tools(mcp: FastMCP, get_tc: Callable[[], TokenConfig]) -> None:
    tools = get_mcp_tools()

    @mcp.tool()
    async def execute_command(server: str, command: str, timeout: int = 300) -> str:
        """Execute a shell command on a remote server."""
        tc = get_tc()
        r = await tools.execute_command_tool(
            token_config=tc, server=server, command=command, timeout=timeout
        )
        return _suffix(r)

    @mcp.tool()
    async def execute_on_multiple(servers: list[str], command: str, timeout: int = 300) -> str:
        """Execute a command on multiple servers in parallel (names or wildcards)."""
        tc = get_tc()
        r = await tools.execute_on_multiple_tool(
            token_config=tc, servers=servers, command=command, timeout=timeout
        )
        return _suffix(r)

    @mcp.tool()
    async def read_file(server: str, file_path: str) -> str:
        """Read a text file from a remote server."""
        tc = get_tc()
        r = await tools.read_file_tool(token_config=tc, server=server, file_path=file_path)
        return _suffix(r)

    @mcp.tool()
    async def write_file(
        server: str, file_path: str, contents: str, mode: str = "overwrite"
    ) -> str:
        """Write or append to a file on a remote server (overwrite or append)."""
        tc = get_tc()
        r = await tools.write_file_tool(
            token_config=tc,
            server=server,
            file_path=file_path,
            contents=contents,
            mode=mode,
        )
        return _suffix(r)

    @mcp.tool()
    async def list_directory(server: str, path: str = ".", detailed: bool = False) -> str:
        """List directory contents on a remote server."""
        tc = get_tc()
        r = await tools.list_directory_tool(
            token_config=tc, server=server, path=path, detailed=detailed
        )
        return _suffix(r)

    @mcp.tool()
    async def check_service_status(server: str, service_name: str) -> str:
        """Check systemd service status on a remote server."""
        tc = get_tc()
        r = await tools.check_service_status_tool(
            token_config=tc, server=server, service_name=service_name
        )
        return _suffix(r)

    @mcp.tool()
    async def install_package(
        server: str, package_name: str, package_manager: str = "auto"
    ) -> str:
        """Install a package (apt/yum/dnf/auto) on a remote server."""
        tc = get_tc()
        r = await tools.install_package_tool(
            token_config=tc,
            server=server,
            package_name=package_name,
            package_manager=package_manager,
        )
        return _suffix(r)

    @mcp.tool()
    async def list_servers(tag: str | None = None) -> str:
        """List SSH servers visible to this token (optional tag filter)."""
        tc = get_tc()
        r = await tools.list_servers_tool(token_config=tc, tag=tag)
        return _suffix(r)

    @mcp.tool()
    async def get_system_info(server: str) -> str:
        """Get hostname, OS, CPU, memory, disk summary from a remote server."""
        tc = get_tc()
        r = await tools.get_system_info_tool(token_config=tc, server=server)
        return _suffix(r)


def create_ssh_fastmcp() -> FastMCP:
    """
    HTTP deployment: Streamable HTTP at /mcp, OAuth AS + RFC 9728 metadata, /login form.
    Mount streamable_http_app() at "/" on the parent ASGI host.
    """
    base = _public_base_url()
    issuer = AnyHttpUrl(base)
    resource = AnyHttpUrl(f"{base}/mcp")

    oauth_provider = SSHMcpOAuthProvider(auth_callback_url=f"{base}/login", mcp_scope=MCP_SCOPE)

    async def _auto_login_from_forwarded_user(request: Request, state: str) -> Response | None:
        """When Traefik forward-auth has Google-authenticated the browser leg, it sends
        X-Forwarded-User (the verified email). If that email maps to a token, complete the
        login silently so the human never pastes an API token."""
        email = request.headers.get("x-forwarded-user")
        if not email:
            return None
        cfg = get_config()
        token = cfg.token_for_email(email)
        if not token:
            logger.warning(f'Forwarded Google user {email!r} has no token mapping; showing manual form')
            return None
        try:
            redirect_url = await oauth_provider._complete_login(token, state)
        except Exception:
            logger.exception('Auto-login failed for forwarded user')
            return None
        logger.info(f'Auto-completed OAuth login for Google user {email!r}')
        return RedirectResponse(url=redirect_url, status_code=302)


    mcp = FastMCP(
        name="mcp-ssh-server",
        instructions=(
            "Remote Linux administration via SSH: run commands, read/write files, "
            "packages, systemd, list servers. Use list_servers to see allowed hosts."
        ),
        website_url="https://github.com/Maxim11111/mcp-ssh",
        auth_server_provider=oauth_provider,
        auth=AuthSettings(
            issuer_url=issuer,
            resource_server_url=resource,
            required_scopes=[MCP_SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=[MCP_SCOPE],
                default_scopes=[MCP_SCOPE],
            ),
        ),
        stateless_http=True,
        json_response=True,
        streamable_http_path="/mcp",
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @mcp.custom_route("/login", methods=["GET"])
    async def oauth_login_page(request: Request) -> Response:
        state = request.query_params.get("state")
        if not state:
            return JSONResponse({"error": "missing state"}, status_code=400)
        auto = await _auto_login_from_forwarded_user(request, state)
        if auto is not None:
            return auto
        return await oauth_provider.get_login_page(state)

    @mcp.custom_route("/login/{state}", methods=["GET"])
    async def oauth_login_page_path(request: Request) -> Response:
        """Path-based login leg; survives Google forward-auth which drops query strings."""
        state = request.path_params.get("state")
        if not state:
            return JSONResponse({"error": "missing state"}, status_code=400)
        auto = await _auto_login_from_forwarded_user(request, state)
        if auto is not None:
            return auto
        return await oauth_provider.get_login_page(state)

    @mcp.custom_route("/login/callback", methods=["POST"])
    async def oauth_login_callback(request: Request) -> Response:
        return await oauth_provider.handle_login_callback(request)

    _register_ssh_tools(mcp, _token_config_from_context)
    return mcp


def create_ssh_fastmcp_stdio() -> FastMCP:
    """Stdio MCP: Bearer token from MCP_TOKEN env (no OAuth web flow)."""
    mcp = FastMCP(
        name="mcp-ssh-server",
        instructions=(
            "Remote Linux administration via SSH. Token is supplied via MCP_TOKEN environment variable."
        ),
        stateless_http=False,
        json_response=False,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    _register_ssh_tools(mcp, _token_config_from_env)
    return mcp
