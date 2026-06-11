from fastmcp import Context
from fastmcp.tools import tool


@tool
async def process_data(data: str, ctx: Context) -> str:
    await ctx.info(f"Processing: {data}")
    return "Done"
