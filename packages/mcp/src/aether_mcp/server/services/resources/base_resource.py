from collections.abc import Iterable

from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.types import Resource
from pydantic import AnyUrl


class BaseResource:
    uri: AnyUrl
    name: str
    description: str
    mime_type: str = "text/plain"

    def to_resource(self) -> Resource:
        return Resource(
            uri=self.uri,
            name=self.name,
            description=self.description,
            mimeType=self.mime_type,
        )

    async def read(self, uri: str) -> Iterable[ReadResourceContents]:
        raise NotImplementedError
