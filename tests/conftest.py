import os
import tempfile

# The server module builds its OAuth provider from the environment on import.
ADMIN_TOKEN = "test-admin-token-0123456789abcdef0123456789"
PUBLIC_URL = "http://localhost:8000"

os.environ["MCP_ADMIN_TOKEN"] = ADMIN_TOKEN
os.environ["MCP_PUBLIC_URL"] = PUBLIC_URL
os.environ["MCP_DATA_DIR"] = tempfile.mkdtemp(prefix="discord-mcp-test-")
os.environ["DISCORD_BOT_TOKEN"] = "test-bot-token"
