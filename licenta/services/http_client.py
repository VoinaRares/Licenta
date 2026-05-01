import httpx

_client: httpx.AsyncClient | None = None


def get() -> httpx.AsyncClient:
    if _client is None:
        raise RuntimeError("HTTP client not initialized — start the app via its lifespan first")
    return _client


def set_client(client: httpx.AsyncClient) -> None:
    global _client
    _client = client


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
