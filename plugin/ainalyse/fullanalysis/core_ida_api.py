import ida_hexrays
import ida_name
import ida_kernwin
import ida_funcs
import ida_lines
import ida_gdl
import idautils
import idaapi
from . import idc, re
from ainalyse.custom_set_cmt import scmt
from .log_utils import log_fanalysis_error


def _sanitize_identifier(name, prefix="aire"):
    """Normalize potentially unsafe LLM names into valid C-like identifiers."""
    if not isinstance(name, str):
        return ""

    sanitized = re.sub(r"[^0-9a-zA-Z_]", "_", name.strip())
    sanitized = re.sub(r"_+", "_", sanitized)
    if not sanitized:
        return ""
    if sanitized[0].isdigit():
        sanitized = f"{prefix}_{sanitized}"
    return sanitized[:120]

def _run_sync(fn, mode=None):
    """
    Run ``fn()`` on the IDA main thread via execute_sync and return its value.

    ``fn`` must handle its own exceptions — this helper is intentionally thin
    so callers stay responsible for error context.
    """
    if mode is None:
        mode = ida_kernwin.MFF_READ
    result = [None]
    def _wrapper():
        result[0] = fn()
        return 1
    ida_kernwin.execute_sync(_wrapper, mode)
    return result[0]


def get_func_name_sync(ea):
    """Safely retrieves a function name from the main thread."""
    def _get():
        try:
            return ida_funcs.get_func_name(ea)
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Error getting function name for {hex(ea)}: {e}")
            return ""
    return _run_sync(_get) or ""


def decompile_func(ea):
    """Safely decompiles a function and returns the cfunc_t or None."""
    is_main_thread = getattr(ida_kernwin, "is_main_thread", None)
    if callable(is_main_thread) and not is_main_thread():
        msg = f"decompile_func called off main thread for {hex(ea)}"
        print(f"[AETHER] [FullAnalysis] {msg}")
        log_fanalysis_error(msg)
        return None

    if not ida_hexrays.init_hexrays_plugin():
        return None

    ida_func = ida_funcs.get_func(ea)
    if not ida_func:
        return None
    
    # PRE-EMPTIVE COMPLEXITY GUARD: Fast check to catch decompiler timeout risks (e.g., dense Go crypto)
    try:
        func_bytes = ida_func.end_ea - ida_func.start_ea
        if func_bytes > 4000: # 4KB of raw assembly instructions is an automatic red flag for automated waves
            print(f"[AETHER] [FullAnalysis] Bypassing {hex(ea)}: Function size too large ({func_bytes} bytes).")
            return None
        
        insn_count = len(list(idautils.FuncItems(ida_func.start_ea)))
        if insn_count > 600: # More than 600 assembly instructions in an automated sweep is highly unstable
            print(f"[AETHER] [FullAnalysis] Bypassing {hex(ea)}: Too many instructions ({insn_count}).")
            return None
        
        cfg = ida_gdl.qflow_chart_t("", ida_func, ida_func.start_ea, ida_func.end_ea, 0)
        num_blocks = cfg.size()
        num_edges = sum(cfg.nsucc(i) for i in range(num_blocks))
        cyclomatic_complexity = num_edges - num_blocks + 2 # Cyclomatic Complexity Formula: M = E - V + 2
        if num_blocks > 150:
            print(f"[AETHER] [FullAnalysis] Bypassing {hex(ea)}: Complexity too high ({num_blocks} basic blocks).")
            return None
        if cyclomatic_complexity > 250:
            print(f"[AETHER] [FullAnalysis] Bypassing {hex(ea)}: Complexity too high ({cyclomatic_complexity} complexity).")
            return None
    except Exception as e:
        print(f"[AETHER] [FullAnalysis] Error evaluating CFG for {hex(ea)}, bypassing: {e}")
        return None
        
    old_batch = idaapi.cvar.batch
    idaapi.cvar.batch = 1
    try:
        # Use DECOMP_NO_WAIT to prevent the "Please wait" box from flashing in loops
        # Removed DECOMP_WARNINGS to prevent dialog popups when the user stops the analysis wave
        flags = getattr(ida_hexrays, "DECOMP_NO_WAIT", 0x20)
        hf = ida_hexrays.hexrays_failure_t()
        df = ida_hexrays.decompile_func(ida_func, hf, flags)
        
        # ATTEMPT 2: If it fails, Hex-Rays memory might be corrupted/locked. 
        # Forcefully clear the in-memory cache and mark it dirty (similar to restarting IDA)
        if not df:
            try:
                ida_hexrays.clear_cached_cfunc(ea)
            except Exception:
                pass

            try:
                # Mark dirty to force a complete re-analysis of the Hex-Rays AST
                ida_hexrays.mark_cfunc_dirty(ea, False)
            except TypeError:
                # IDA API compatibility fallback
                ida_hexrays.mark_cfunc_dirty(ea)
            except Exception:
                pass

            df = ida_hexrays.decompile_func(ida_func, hf, flags)

        if not df:
            try:
                reason = hf.desc() if hasattr(hf, "desc") else "unknown"
            except Exception:
                reason = "unknown"
            print(f"[AETHER] [FullAnalysis] Decompile returned no cfunc for {hex(ea)}. Reason: {reason}")
            
        return df
    except Exception as e:
        print(f"[AETHER] [FullAnalysis] Decompile failed for {hex(ea)}: {e}")
        return None
    finally:
        idaapi.cvar.batch = old_batch

def get_c_text(cfunc):
    """Extracts C pseudocode text formatted with 0xADDRESS| prefixes."""
    if not cfunc:
        return ""
    try:
        sv = cfunc.get_pseudocode()
        pseudocode = ""
        
        # 1. First get the raw trace with metadata as done in custom_get_pseudocode
        for i, sl in enumerate(sv):
            sl: ida_kernwin.simpleline_t
            item = ida_hexrays.ctree_item_t()
            addr = None if i > 0 else cfunc.entry_ea
            if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                ds = item.dstr().split(": ")
                if len(ds) == 2:
                    try:
                        addr = int(ds[0], 16)
                    except ValueError:
                        pass
            line = ida_lines.tag_remove(sl.line)
            if len(pseudocode) > 0:
                pseudocode += "\n"
            if not addr:
                pseudocode += f"/* line: {i} */ {line}"
            else:
                pseudocode += f"/* line: {i}, address: {hex(addr)} */ {line}"

        # 2. Then immediately reformat it into the pipeline standard
        lines = pseudocode.splitlines()
        result = []
        line_re = re.compile(r'^\s*/\*\s*line:\s*(\d+)(?:,\s*address:\s*(0x[0-9a-fA-F]+))?\s*\*/\s*(.*)$')
        
        for line in lines:
            if line.strip().startswith('cannotComment|') or re.match(r'^\s*0x[0-9a-fA-F]+\|', line):
                result.append(line)
                continue
                
            m = line_re.match(line)
            if m:
                address = m.group(2)
                code = m.group(3)
                if address:
                    result.append(f"{address}| {code}")
                else:
                    result.append(f"cannotComment| {code}")
            else:
                if line.strip():
                    result.append(f"cannotComment| {line}")
                else:
                    result.append(line)
                    
        return "\n".join(result)
    except Exception as e:
        print(f"[AETHER] [FullAnalysis] Error extracting C text: {e}")
        return ""

def rename_function_sync(ea, new_name):
    """Renames a function safely on the main thread."""
    success = False

    def _rename():
        nonlocal success
        try:
            safe_name = _sanitize_identifier(new_name, prefix="aire")
            if not safe_name:
                return 0

            if ida_name.set_name(ea, safe_name, ida_name.SN_NOWARN):
                success = True
                return 1

            fallback_name = f"{safe_name}_{ea:x}"
            if ida_name.set_name(ea, fallback_name, ida_name.SN_NOWARN):
                success = True
                return 1
            log_fanalysis_error(
                f"rename_function_sync failed at {hex(ea)} for requested name '{new_name}'"
            )
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Error renaming function at {hex(ea)}: {e}")
            log_fanalysis_error(
                f"rename_function_sync exception at {hex(ea)} for requested name '{new_name}': {e}"
            )
        return 1

    ida_kernwin.execute_sync(_rename, ida_kernwin.MFF_WRITE)
    return success

def get_name_ea_simple_sync(name):
    """Safely gets an address by name from the main thread."""
    def _get():
        try:
            return idc.get_name_ea_simple(name)
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Error getting EA for name '{name}': {e}")
            return idaapi.BADADDR
    return _run_sync(_get) or idaapi.BADADDR

def clear_cached_cfuncs_sync():
    """Clears Hex-Rays cache on the main thread so next wave sees current changes."""
    def _clear():
        try:
            ida_hexrays.clear_cached_cfuncs()
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Error clearing cached cfuncs: {e}")
    _run_sync(_clear, ida_kernwin.MFF_WRITE)

def set_comment_sync(address, comment):
    """Safely applies a comment via custom_set_cmt.scmt on the main thread."""
    class Ctx:
        success = False

    def _set_comment():
        try:
            scmt(address, comment)
            Ctx.success = True
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Error setting comment at {address}: {e}")
            log_fanalysis_error(f"set_comment_sync exception at {address}: {e}")
            Ctx.success = False
        return 1

    ida_kernwin.execute_sync(_set_comment, ida_kernwin.MFF_WRITE)
    return Ctx.success

def rename_lvar_sync(ea, old_name, new_name):
    """
    Renames a local variable in Hex-Rays safely on the main thread.
    Modifies the existing cached cfuncs directly so the changes are immediately available.
    """
    class Ctx:
        renamed = False

    def _rename_lvar():
        if not ida_hexrays.init_hexrays_plugin():
            return 1
            
        old_batch = idaapi.cvar.batch
        idaapi.cvar.batch = 1
        
        try:
            safe_new_name = _sanitize_identifier(new_name, prefix="v")
            if not safe_new_name:
                return 1

            # Omit DECOMP_WARNINGS to prevent console spam
            flags = getattr(ida_hexrays, "DECOMP_NO_WAIT", 0x20)
            hf = ida_hexrays.hexrays_failure_t()
            cfunc = ida_hexrays.decompile_func(ida_funcs.get_func(ea), hf, flags)
            if not cfunc:
                return 1
                
            for lvar in cfunc.get_lvars():
                if lvar.name == old_name:
                    # Saving to IDB permanently
                    success = ida_hexrays.rename_lvar(ea, lvar.name, safe_new_name)
                    Ctx.renamed = bool(success)
                    # Dirty the cache natively without a full wipe to prevent corrupting Hex-Rays memory graph
                    try:
                        ida_hexrays.mark_cfunc_dirty(ea, False)
                    except TypeError:
                        ida_hexrays.mark_cfunc_dirty(ea)
                    if not Ctx.renamed:
                        log_fanalysis_error(
                            f"rename_lvar_sync failed at {hex(ea)}: {old_name} -> {new_name}"
                        )
                    break
            else:
                log_fanalysis_error(
                    f"rename_lvar_sync could not find variable at {hex(ea)}: {old_name}"
                )
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Error renaming lvar: {e}")
            log_fanalysis_error(
                f"rename_lvar_sync exception at {hex(ea)} for {old_name} -> {new_name}: {e}"
            )
            Ctx.renamed = False
        finally:
            idaapi.cvar.batch = old_batch
            
        return 1
        
    ida_kernwin.execute_sync(_rename_lvar, ida_kernwin.MFF_WRITE)
    return Ctx.renamed

def minify_c_code(c_text):
    """
    Strips repetitive Hex-Rays pseudocode noise like long __fastcall pointer casts
    and common IDA generated types to save tokens before sending to the LLM.
    """
    if not c_text:
        return ""
        
    # Strip overly verbose function pointer casts: (void (__fastcall *)(...))
    minified = re.sub(r'\(\s*[a-zA-Z_0-9\s\*]*\(\s*__fastcall\s*\*\)\s*\([^)]*\)\s*\)', '', c_text)
    
    # Strip redundant (void *) and (_QWORD *) type casts often added by IDA
    minified = re.sub(r'\(\s*(_[A-Z]+|__int\d+|void|int|char|short|long)\s*\**\s*\)', '', minified)
    
    # Strip useless trailing whitespace and multiple blank lines
    minified = re.sub(r'\n\s*\n', '\n', minified)
    return minified.strip()