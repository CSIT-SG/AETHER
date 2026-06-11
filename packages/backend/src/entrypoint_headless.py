# from aether_backend.server import app
import uvicorn

if __name__ == "__main__":
    uvicorn.run("aether_backend.server:app", port=8000, reload=True)
