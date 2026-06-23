import math

import ida_bytes
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import idc


class BinaryEnvironment:
    """Lightweight extraction of essential binary metadata, language, and packer detection."""

    # Entropy threshold above which a section is considered suspicious
    ENTROPY_THRESHOLD = 7.2

    @staticmethod
    def _get_entropy(ea: int, size: int) -> float:
        """
        Calculate Shannon entropy of a memory range.
        Caps the read at 1 MB to keep IDA responsive.
        Uses the actual number of bytes read as the denominator,
        guarding against partial reads on unmapped pages.
        """
        if size <= 0:
            return 0.0

        read_size = min(size, 0x100000)
        data = ida_bytes.get_bytes(ea, read_size)
        if not data:
            return 0.0

        # Use actual bytes received, not the requested read_size
        actual_size = len(data)

        occurrences = [0] * 256
        for byte in data:
            occurrences[byte] += 1

        entropy = 0.0
        for count in occurrences:
            if count > 0:
                p_x = count / actual_size
                entropy -= p_x * math.log2(p_x)

        return entropy

    @staticmethod
    def _get_entry_point_section(segments: list) -> str | None:
        """Return the section name that contains the binary entry point, or None."""
        ep = idc.get_inf_attr(idc.INF_START_EA)
        if ep == ida_idaapi.BADADDR:
            return None
        for name, ea, size, _perm in segments:
            if ea <= ep < ea + size:
                return name
        return None

    @staticmethod
    def _detect_packer(segments: list, import_count: int) -> tuple[str, int]:
        """
        Heuristic packer/protector detection.

        Returns:
            (status_string, signal_count) where status is:
              "No"                      — no signals found
              "Low confidence (...)"    — 1 signal
              "Medium confidence (...)" — 2 signals
              "High confidence (...)"   — 3+ signals
        """
        packer_signals = []

        KNOWN_PACKER_NAMES = {"UPX", "VMP", "THEMIDA", "ASPACK", "PROTECT", ".MPRESS", "ENIGMA", "OBSIDIUM"}

        for name, ea, size, perm in segments:
            name_upper = name.upper()

            # 1. Known packer section names
            if any(p in name_upper for p in KNOWN_PACKER_NAMES):
                packer_signals.append(f"Known packer section '{name}'")

            # 2. RWE section (Read + Write + Execute)
            # Standard code is RX, data is RW; RWE is a classic packer/self-modifying hallmark.
            is_write = bool(perm & ida_segment.SEGPERM_WRITE)
            is_exec = bool(perm & ida_segment.SEGPERM_EXEC)
            if is_write and is_exec:
                packer_signals.append(f"RWE section '{name}'")

            # 3. High entropy — likely compressed or encrypted content
            if size > 0:
                entropy = BinaryEnvironment._get_entropy(ea, size)
                if entropy > BinaryEnvironment.ENTROPY_THRESHOLD:
                    packer_signals.append(f"High entropy in '{name}' ({entropy:.2f} bits)")

        # 4. Suspiciously low import count
        # Packed binaries typically import only LoadLibrary + GetProcAddress at rest.
        if import_count <= 3:
            packer_signals.append(f"Very low import count ({import_count} module(s))")

        # 5. Entry point outside .text
        ep_section = BinaryEnvironment._get_entry_point_section(segments)
        if ep_section is not None and ep_section.lower() not in (".text", "text", ".code", "code"):
            packer_signals.append(f"Entry point in unusual section '{ep_section}'")

        if not packer_signals:
            return "No", 0

        # Deduplicate while preserving insertion order
        unique_signals = list(dict.fromkeys(packer_signals))
        n = len(unique_signals)

        if n == 1:
            confidence = "Low confidence"
        elif n == 2:
            confidence = "Medium confidence"
        else:
            confidence = "High confidence"

        signals_str = "; ".join(unique_signals)
        return f"{confidence} ({n} signal(s): {signals_str})", n

    @staticmethod
    def _detect_language(imports: list[str], segment_names: list[str]) -> str:
        """
        Identify the likely source language from imports and segment names.
        Checks are ordered from most specific to least specific.
        """
        import_set = set(imports)
        seg_set = set(segment_names)

        # .NET / C#
        if "mscoree.dll" in import_set:
            return "C# / .NET"

        # Visual Basic 6
        if "msvbvm60.dll" in import_set:
            return "Visual Basic 6"

        # Go — prefer segment name check (reliable), fall back to symbol search
        if any(".gopclntab" in s for s in seg_set):
            return "Go (Golang)"
        if ida_name.get_name_ea(ida_idaapi.BADADDR, "runtime.main") != ida_idaapi.BADADDR:
            return "Go (Golang)"

        # Rust — segment name or panic symbol
        if any(".rustc" in s for s in seg_set):
            return "Rust"
        if ida_name.get_name_ea(ida_idaapi.BADADDR, "rust_panic") != ida_idaapi.BADADDR:
            return "Rust"

        # Swift
        if any("libswiftcore" in n for n in import_set):
            return "Swift"

        # Delphi / Object Pascal
        if ida_name.get_name_ea(ida_idaapi.BADADDR, "TObject") != ida_idaapi.BADADDR:
            return "Delphi (Pascal)"

        return "C / C++"

    @staticmethod
    def get_summary() -> str:
        """
        Collect binary metadata and return a compact context block
        suitable for injecting into an LLM prompt.
        """
        result_container: dict[str, str] = {"data": ""}

        def _collect():
            try:
                # ── Architecture ──────────────────────────────────────────────
                is_64 = ida_ida.inf_is_64bit()
                bitness = "64-bit" if is_64 else "32-bit"
                proc_name = ida_idp.get_idp_name()
                ptr_size = 8 if is_64 else 4
                compiler_name = ida_typeinf.get_compiler_name(ida_ida.inf_get_cc_id())
                endian = "Big" if ida_ida.inf_is_be() else "Little"

                # ── Imports ───────────────────────────────────────────────────
                import_modules: list[str] = []
                import_count = ida_nalt.get_import_module_qty()
                for i in range(import_count):
                    name = ida_nalt.get_import_module_name(i)
                    if name:
                        import_modules.append(name.lower())

                # ── Segments ──────────────────────────────────────────────────
                segments_detailed: list[tuple[str, int, int, int]] = []
                for i in range(ida_segment.get_segm_qty()):
                    seg = ida_segment.getnseg(i)
                    if seg:
                        s_name = ida_segment.get_segm_name(seg) or f"seg_{i}"
                        segments_detailed.append((s_name, seg.start_ea, seg.size(), seg.perm))

                seg_names_lower = [s[0].lower() for s in segments_detailed]

                # ── Detection ─────────────────────────────────────────────────
                lang = BinaryEnvironment._detect_language(import_modules, seg_names_lower)
                packed_status, signal_count = BinaryEnvironment._detect_packer(segments_detailed, len(import_modules))

                # ── Top imports (useful LLM context) ─────────────────────────
                # Show up to 5 imports so the LLM can reason about capabilities
                top_imports = import_modules[:5]
                imports_str = ", ".join(top_imports) if top_imports else "none"
                if len(import_modules) > 5:
                    imports_str += f" (+{len(import_modules) - 5} more)"

                ctx = [
                    "### BINARY INFO",
                    f"Arch     : {proc_name} {bitness} | PtrSize: {ptr_size}B | Endian: {endian}",
                    f"Compiler : {compiler_name}",
                    f"Language : {lang}",
                    f"Imports  : {len(import_modules)} module(s) — {imports_str}",
                    f"Packed   : {packed_status}",
                    "###",
                ]
                result_container["data"] = "\n".join(ctx)

            except Exception as exc:
                # Log detail to IDA output window; keep LLM context clean
                print(f"[AETHER] BinaryEnvironment profiler error: {exc}")
                result_container["data"] = "### BINARY INFO\n[Metadata collection failed]\n###"

            return 1  # required by execute_sync

        # Safety check to ensure we aren't executing while IDA is shutting down
        from ainalyse.qt_shim import QtWidgets

        app = QtWidgets.QApplication.instance()
        if app is None or app.closingDown():
            return "### BINARY INFO\n[Metadata collection aborted (shutdown)]\n###"

        # Execute the collection logic on the main thread
        ida_kernwin.execute_sync(_collect, ida_kernwin.MFF_READ)
        return result_container["data"]
