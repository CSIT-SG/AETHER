from aether_backend.server import app

if __name__ == "__main__":
    app.run(transport="streamable-http", port=8000)