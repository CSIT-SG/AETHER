from .tools import app_provider
from fastmcp import FastMCP

app = FastMCP("AETHER Backend", providers=[app_provider])