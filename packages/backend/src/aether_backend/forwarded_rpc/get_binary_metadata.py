from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.misc.types import BinaryMetadataResult
from aether_rpc.capabilities.result import Result


async def get_binary_metadata(service: AnyService) -> Result[BinaryMetadataResult]:
    """Retrieve file hashes, architecture info, and section layout for the binary.

    Returns:
        Ok[BinaryMetadataResult]: A structured object containing:
            - file_name (str): The name of the loaded input file.
            - file_path (str): The full path to the loaded input file.
            - file_size (int): The size in bytes of the input file.
            - sha256 (str): SHA256 hash of the input file, as a hex string.
            - md5 (str): MD5 hash of the input file, as a hex string.
            - crc32 (str): CRC32 checksum of the input file, as a hex string.
            - architecture (str): The processor/architecture name (e.g. "metapc").
            - bitness (int): The address bitness of the binary (16, 32, or 64).
            - file_type (str): The file type description (e.g. "Portable executable for AMD64").
            - entry_point (str): The entry point address as a hex string.
            - image_base (str): The image base address as a hex string.
            - section_count (int): The number of sections in the binary.
            - sections (list): List of section info objects, each containing:
                - name (str): Section name.
                - start (str): Section start address as a hex string.
                - end (str): Section end address as a hex string.
                - size (int): Section size in bytes.
                - perms (str): Section permissions as an "RWX"-style string.
        Err[str]: An error message string if binary metadata could not be retrieved.

    Examples:
        get_binary_metadata()
    """
    return service.get_binary_metadata()
