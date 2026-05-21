import asyncio

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def MCPClient():
    # 1. Define how to start and communicate with your local MCP server
    # This acts as the configuration for your client object.
    server_params = StdioServerParameters(
        command="python",  # The executable used to run the server
        args=["/absolute/path/to/your/mcp_server.py"]  # Path to your server script
    )

    print("[!] Spawning server process and connecting client...")

    # 2. Open the connection pipe (stdio stream) using the server parameters
    async with stdio_client(server_params) as (read_stream, write_stream), ClientSession(read_stream, write_stream) as mcp_client:
            await mcp_client.initialize()
            print("[+] MCP Client object successfully created and initialized!")

            # --- Your client object `mcp_client` is now fully ready to use ---

            # Example: Dynamically discover what tools the server has available
            available_tools = await mcp_client.list_tools()
            print(f"Found tools: {available_tools.tools}")

            # Example: Execute a tool by name using the client object
            # result = await mcp_client.execute_tool(
            #     name="my_tool_name", 
            #     arguments={"param1": "value"}
            # )
