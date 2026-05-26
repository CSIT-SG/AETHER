from abc import ABC, abstractmethod
from collections.abc import Iterable

from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.types import Resource
from pydantic import AnyUrl


class BaseResource(ABC):
    @property
    @abstractmethod
    def uri(self) -> AnyUrl: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    def mime_type(self) -> str:
        return "text/plain"  # has default, not abstract

    def to_resource(self) -> Resource:
        return Resource(
            uri=self.uri,
            name=self.name,
            description=self.description,
            mimeType=self.mime_type,
        )

    @abstractmethod
    async def read(self, uri: str) -> Iterable[ReadResourceContents]:
        raise NotImplementedError
