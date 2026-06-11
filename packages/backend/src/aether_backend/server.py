from .tools import app_provider
from fastmcp import FastMCP

# TODO: remove debug=True in production
app = FastMCP("AETHER Backend", providers=[app_provider], debug=True)