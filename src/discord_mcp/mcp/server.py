import contextvars

from fastmcp import FastMCP
from fastmcp.contrib.bulk_tool_caller import BulkToolCaller
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token, get_http_request
from fastmcp.server.middleware import Middleware, MiddlewareContext

from discord_mcp.config import settings
from discord_mcp.discord.events import event_stream_manager
from discord_mcp.discord.session import session_manager
from discord_mcp.mcp.oauth import CONSENT_PATH, SCOPE_WRITE, ConsentOAuthProvider
from discord_mcp.utils.logging import get_logger

logger = get_logger(__name__)

READ_TOOL_PREFIXES = ("get_", "list_", "view_", "inspect_", "fetch_", "check_")
BULK_TOOLS = ("call_tools_bulk", "call_tool_bulk")


def _build_oauth_provider() -> ConsentOAuthProvider | None:
    """OAuth is on when an admin token is configured. The server then acts with
    its own bot token and the Authorization header carries one of our tokens;
    otherwise the header is the caller's bot token, as before."""
    if not settings.mcp.admin_token:
        return None
    if not settings.discord.bot_token or not settings.mcp.public_url:
        raise RuntimeError(
            "MCP_ADMIN_TOKEN turns on OAuth, which also needs DISCORD_BOT_TOKEN and MCP_PUBLIC_URL"
        )
    return ConsentOAuthProvider(
        public_url=settings.mcp.public_url,
        admin_token=settings.mcp.admin_token,
        data_dir=settings.mcp.data_dir,
    )


oauth_provider = _build_oauth_provider()

mcp = FastMCP("Discord MCP Server", auth=oauth_provider)

if oauth_provider:
    mcp.custom_route(CONSENT_PATH, methods=["GET", "POST"], include_in_schema=False)(
        oauth_provider.consent_endpoint
    )

current_session_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_session_id", default=None
)


def is_read_tool(name: str, arguments: dict | None = None) -> bool:
    """Whether a call changes nothing on Discord. A bulk call is as harmless as
    the calls inside it; a tool that is not recognizably read-only is not."""
    arguments = arguments or {}
    if name == "call_tool_bulk":
        return is_read_tool(str(arguments.get("tool", "")))
    if name == "call_tools_bulk":
        calls = arguments.get("tool_calls") or []
        return all(
            isinstance(call, dict) and is_read_tool(str(call.get("tool", "")), call.get("arguments"))
            for call in calls
        )
    return name.startswith(READ_TOOL_PREFIXES)


def _can_write() -> bool:
    if not oauth_provider:
        return True
    access_token = get_access_token()
    return access_token is not None and SCOPE_WRITE in access_token.scopes


def _authorization_header() -> str:
    if oauth_provider:
        return settings.discord.bot_token
    try:
        return get_http_request().headers.get("Authorization", "")
    except RuntimeError:
        return ""


async def authenticate_and_get_session(auth_header: str) -> str:
    if not auth_header:
        from discord_mcp.discord.exceptions import AuthenticationException

        raise AuthenticationException("Missing Authorization header")

    # Strip Bearer or Bot prefix if present
    token = auth_header.strip()
    if token.startswith("Bearer "):
        token = token[7:].strip()
    elif token.startswith("Bot "):
        token = token[4:].strip()

    if not token:
        from discord_mcp.discord.exceptions import AuthenticationException

        raise AuthenticationException("Empty token provided")

    logger.info("authentication_attempt", token_prefix=token[:10] + "...")

    existing_session = await session_manager.get_session_by_token(token)
    if existing_session:
        logger.info("existing_session_found", session_id=existing_session.session_id)
        return existing_session.session_id

    try:
        session = await session_manager.create_session(
            token=token,
            max_shards=1,
            event_callback=None,
        )

        stream = event_stream_manager.create_stream(session.session_id)
        await stream.start()

        bot_user = "unknown"
        if session.client and session.client.user:
            bot_user = str(session.client.user)

        logger.info(
            "authentication_success",
            session_id=session.session_id,
            bot_user=bot_user,
        )
        return session.session_id
    except Exception as e:
        logger.error("session_creation_failed", error=str(e))
        raise


class AuthMiddleware(Middleware):
    async def on_initialize(
        self,
        context: MiddlewareContext,
        call_next,
    ):
        # Start Discord bot when MCP session initializes
        auth_header = _authorization_header()
        if auth_header:
            try:
                session_id = await authenticate_and_get_session(auth_header)
                current_session_id.set(session_id)
                logger.info("bot_started_on_session_init", session_id=session_id)
            except Exception as e:
                logger.error("bot_start_failed_on_init", error=str(e))

        return await call_next(context)

    async def on_list_tools(
        self,
        context: MiddlewareContext,
        call_next,
    ):
        tools = await call_next(context)
        if _can_write():
            return tools
        return [tool for tool in tools if tool.name in BULK_TOOLS or is_read_tool(tool.name)]

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next,
    ):
        if not _can_write() and not is_read_tool(context.message.name, context.message.arguments):
            raise ToolError("This connection is read-only: it was approved without manage access")

        auth_header = _authorization_header()

        if auth_header:
            try:
                session_id = await authenticate_and_get_session(auth_header)
                token_var = current_session_id.set(session_id)
                try:
                    result = await call_next(context)
                    return result
                finally:
                    current_session_id.set(None)
                    current_session_id.reset(token_var)
            except Exception as e:
                logger.error("tool_call_auth_error", error=str(e))
                raise
        else:
            return await call_next(context)


mcp.add_middleware(AuthMiddleware())

bulk_tool_caller = BulkToolCaller()
bulk_tool_caller.register_tools(mcp)


def get_current_session_id() -> str | None:
    return current_session_id.get()


async def get_current_session():
    session_id = get_current_session_id()
    if not session_id:
        from discord_mcp.discord.exceptions import SessionException

        raise SessionException("No active session context - Authorization header required")
    return await session_manager.get_session(session_id)
