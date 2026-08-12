import httpx
from aether_backend.utils.effect import Log, Program, Progress, Return

from .constants import CHUNK_SIZE, CONNECT_TIMEOUT_SECONDS, TIMEOUT_SECONDS


async def fetch_url_stream(url: str) -> Program:
    timeout = httpx.Timeout(TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS)

    async with (
        httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client,
        client.stream("GET", url) as resp,
    ):
        if resp.status_code >= 400:
            yield Return(f"Failed to fetch {url}: {resp.status_code} {resp.reason_phrase}")

        total = resp.headers.get("Content-Length")
        total = int(total) if total and total.isdigit() else 0

        downloaded = 0
        chunks: list[bytes] = []

        yield Log(f"Fetching: {url}")

        async for chunk in resp.aiter_bytes(CHUNK_SIZE):
            if not chunk:
                continue

            chunks.append(chunk)
            downloaded += len(chunk)

            yield Progress(
                current=downloaded,
                total=total,
                message="downloading",
            )

        yield Log("Fetch complete")

        data = b"".join(chunks)

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")

        yield Return(text)
