# FAQ
## Common Issues

| Issue | Solution |
|-------|----------|
| "MCP Server not connecting" | Ensure `ida-pro-mcp` is running in a separate terminal at `http://127.0.0.1:8744/sse` |
| "API Key authentication failed" | Verify your API key is correct in Plugin Settings |
| "PyQt5 errors" | See PyQt5 Compatibility section above |
| "Python version error" | Ensure you're using Python 3.11+ (check with `python --version`) |

## Troubleshooting

### PyQt5 Compatibility Issue

If you encounter PyQt5 deprecation warnings or errors (especially on IDA Pro 9.2):

1. Edit the IDA configuration file at:
   ```
   C:\Users\<your_username>\AppData\Roaming\Hex-Rays\IDA Pro\cfg\idapython.cfg
   ```

2. Add or modify this line:
   ```
   IDAPYTHON_USE_PYQT5_SHIM = 1
   ```

## Support

If you encounter issues or have questions:
1. Check [/docs/BUGS.md](../docs/BUGS.md) for known issues
2. Enable verbose logging for detailed error information
3. Open an issue on the project repository with detailed error logs