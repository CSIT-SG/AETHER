import ida_ida
import ida_loader
import ida_nalt
import ida_segment
import idaapi
import idautils

from ...base import Capability
from ...result import Err, Ok, Result
from ...types import BinaryMetadataResult, SectionInfo


class GetBinaryMetadata(Capability):
    """Retrieves identifying and structural metadata about the loaded binary."""

    @property
    def name(self) -> str:
        return "get_binary_metadata"

    def execute(self) -> Result[BinaryMetadataResult]:
        """Return file hashes, architecture info, and section layout for the binary.

        Returns:
            A Result whose ``result`` holds the binary's identity (name, path,
            size, SHA256/MD5/CRC32), architecture/bitness/file type, entry
            point, image base, and the list of sections.
        """
        try:
            sections: list[SectionInfo] = [
                SectionInfo(
                    name=str(ida_segment.get_segm_name(seg) or ""),
                    start=hex(seg.start_ea),
                    end=hex(seg.end_ea),
                    size=int(seg.end_ea - seg.start_ea),
                    perms=self._perms_str(seg),
                )
                for seg in self._iter_segments()
            ]

            metadata = BinaryMetadataResult(
                file_name=str(idaapi.get_root_filename() or ""),
                file_path=str(idaapi.get_input_file_path() or ""),
                file_size=int(ida_nalt.retrieve_input_file_size() or 0),
                sha256=self._sha256(),
                md5=self._md5(),
                crc32=self._crc32(),
                architecture=str(ida_ida.inf_get_procname() or ""),
                bitness=self._bitness(),
                file_type=str(ida_loader.get_file_type_name() or ""),
                entry_point=hex(ida_ida.inf_get_start_ea()),
                image_base=hex(idaapi.get_imagebase()),
                section_count=int(len(sections)),
                sections=sections,
            )
        except Exception as e:
            self.logger.exception("Failed to get binary metadata: %s", e)
            return Err(result=f"Failed to get binary metadata: {e}")

        self.logger.info(f"Retrieved metadata for {metadata['file_name']}")
        return Ok(result=metadata)

    # -- helpers --

    @staticmethod
    def _iter_segments():
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            if seg:
                yield seg

    @staticmethod
    def _perms_str(seg) -> str:
        r = "R" if seg.perm & ida_segment.SEGPERM_READ else "-"
        w = "W" if seg.perm & ida_segment.SEGPERM_WRITE else "-"
        x = "X" if seg.perm & ida_segment.SEGPERM_EXEC else "-"
        return r + w + x

    @staticmethod
    def _sha256() -> str:
        raw = ida_nalt.retrieve_input_file_sha256()
        if not raw:
            return ""
        return raw.hex() if isinstance(raw, (bytes, bytearray)) else str(raw)

    @staticmethod
    def _md5() -> str:
        raw = idautils.GetInputFileMD5()
        if not raw:
            return ""
        return raw.hex() if isinstance(raw, (bytes, bytearray)) else str(raw)

    @staticmethod
    def _crc32() -> str:
        crc = ida_nalt.retrieve_input_file_crc32()
        return f"{crc:08x}" if crc else ""

    @staticmethod
    def _bitness() -> int:
        if ida_ida.inf_is_64bit():
            return 64
        if ida_ida.inf_is_32bit_or_higher():
            return 32
        return 16
