from fastmcp.tools import tool
from fastmcp import Context


@tool
async def process_data(data: str, ctx: Context) -> str:
    await ctx.info(f"Processing: {data}")
    return "Done"
