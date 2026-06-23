"""
AETHER Orchestrator: Autonomous Whole-Binary Analysis Engine
Architecture: Greedy Concurrent Pattern
"""
import os
import time
import requests
import asyncio
import textwrap
import threading
import re
import traceback
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from ainalyse.qt_shim import QtWidgets
QMessageBox = QtWidgets.QMessageBox if QtWidgets else None

import ida_funcs
import idaapi
import ida_kernwin
import ida_hexrays
import ida_lines
import ida_bytes
import ida_name
import idc
import ida_gdl
import idautils

from ainalyse.async_manager import use_async_worker, start_pipeline
from ainalyse.utils import refresh_functions
from ainalyse.indexing.function_index_manager import FunctionIndexManager
from ainalyse.custom_set_cmt import scmt
from .core_db import AetherDB
from .core_llm import LLMClient
from .log_utils import log_fanalysis_error
from .core_graph import CallGraph, is_func_interesting
from .core_ida_api import (
    decompile_func,
    get_c_text,
    get_func_name_sync,
    minify_c_code,
    clear_cached_cfuncs_sync,
    _sanitize_identifier,
)
from .core_chunker import split_code_into_chunks, count_tokens, code_budget, reduce_to_budget

# ---------------------------------------------------------------------------
# Constants & Helpers
# ---------------------------------------------------------------------------


IDA_DUMMY_VAR_RE = re.compile(r'^(v|a|s|arg|var_|low|high|byte_|word_|dword_|qword_|__)\d*$|^result$|^anonymous_\d+$|^(fd|pid|name|flags|src|dest|buf|ptr|len|res|ret|status|val)$', re.IGNORECASE)
IDA_DUMMY_FUNC_RE = re.compile(r'^(aire_|sub|nullsub|loc|unk|off|asc|byte|word|dword|qword|j|__imp|__wrapper)_[0-9a-fA-F]+$|^(aire_|sub|nullsub|loc|unk|off|asc|byte|word|dword|qword|j|__imp|__wrapper)_[a-zA-Z0-9_]+$', re.IGNORECASE)

# Common library/runtime prefixes to skip aggressively
LIB_PREFIXES = {
    # Go Runtime & Standard Lib
    "runtime.", "sync.", "reflect.", "syscall.", "internal/", "os.", "fmt.", "math.", "type..", 
    "time.", "sort.", "errors.", "io.", "unicode.", "context.", "bytes.", "strings.", "net.",
    "google.golang.org", "github.com/golang",
    # C++ Standard Lib
    "std::", "boost::", "__gnu_cxx::", "Qt", "QMessage", "std_",
    # Generic compiler/loader noise
    "__imp_", "__wrapper_", "__security_", "_RTC_", "DllMain", "atexit", "__scrt_",
    "_malloc", "_free", "_memset", "_memcpy", "_memmove", "_strlen"
}

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class AetherOrchestrator:
    def __init__(self, config):
        self.config = config
        self.db = AetherDB()
        self.llm = LLMClient(config)
        self.cg = CallGraph()
        self.is_running = False
        self.stop_requested = False
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.funcs_processed = 0
        self.total_job_time = 0
        self.job_count = 0
        self.context_limit = 64000
        self._stats_lock = threading.Lock()
        self._ida_serial_lock = threading.Lock()
        self._heartbeat_timer = None
        
        # Load prompt template once
        self._minitree_prompt_template = None
        try:
            p_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts", "minitree-prompt.txt")
            if os.path.exists(p_path):
                with open(p_path, "r", encoding="utf-8") as f:
                    self._minitree_prompt_template = f.read()
        except Exception: pass

    def _main_thread_heartbeat(self):
        """Timer callback to prove IDA's main thread isn't frozen."""
        if self.is_running:
            print(f"[AETHER] [FullAnalysis] [HEARTBEAT] IDA Main Thread is ALIVE. Current Progress: {self.funcs_processed}")
            return 30000 # Run again in 30s
        self._heartbeat_timer = None
        return -1

    def close(self):
        """Explicitly shut down resources."""
        self.is_running = False
        if self._heartbeat_timer:
            try:
                ida_kernwin.unregister_timer(self._heartbeat_timer)
                self._heartbeat_timer = None
                print("[AETHER] [FullAnalysis] Orchestrator: Heartbeat timer unregistered.")
            except Exception: pass
        if self.db: self.db.close()
        if self.llm: self.llm.close()

    def stop(self):
        self.stop_requested = True
        self.is_running = False
        print("-" * 50)
        print("[AETHER] [FullAnalysis] STOP REQUESTED BY USER. Waiting for current wave to abort...")
        print("-" * 50)

    def _update_job_perf(self, duration):
        with self._stats_lock:
            self.total_job_time += duration
            self.job_count += 1

    def _print_progress(self, total_funcs, start_time):
        elapsed = time.time() - start_time
        
        # Robust ETA Calculation:
        # Instead of a global average (which is skewed by free 'skips'), we use:
        # ETA = (Remaining Functions * Analysis Probability) * Average Job Duration
        
        processed = max(1, self.funcs_processed)
        analysis_prob = self.job_count / processed
        avg_job_dur = (self.total_job_time / max(1, self.job_count)) if self.job_count > 0 else (elapsed / processed)
        
        remaining_funcs = total_funcs - self.funcs_processed
        eta_seconds = (remaining_funcs * analysis_prob) * avg_job_dur
        
        # Add a small floor for the 'inspection' phase of remaining functions
        inspection_floor = remaining_funcs * 0.05 # 50ms per skip
        eta_seconds += inspection_floor

        m, s = divmod(int(max(0, eta_seconds)), 60)
        h, m = divmod(m, 60)
        print(f"[AETHER] [FullAnalysis] Progress: {self.funcs_processed}/{total_funcs} (ETA: {h:02d}:{m:02d}:{s:02d})")

    def run_analysis(self):
        """Starts the autonomous analysis pipeline."""
        resume_requested = False
        if self.db.has_existing_data():
            msg_box = QMessageBox()
            msg_box.setWindowTitle("AETHER: Existing Analysis Found")
            msg_box.setText("Previous analysis data was found for this binary. Would you like to resume or restart?")
            btn_resume = msg_box.addButton("Resume", QMessageBox.AcceptRole)
            btn_restart = msg_box.addButton("Restart", QMessageBox.DestructiveRole)
            btn_cancel = msg_box.addButton("Cancel", QMessageBox.RejectRole)
            msg_box.exec_()
            if msg_box.clickedButton() == btn_cancel: return
            elif msg_box.clickedButton() == btn_restart: self.db.clear_all_analysis()
            else: resume_requested = True

        self.is_running, self.stop_requested = True, False
        self.total_prompt_tokens, self.total_completion_tokens = 0, 0

        print("-" * 50)
        print("[AETHER] [FullAnalysis] ANALYSIS START")
        print("-" * 50)
        
        model_name = self.config.get("OPENAI_MODEL", "")
        if not model_name:
            print("[AETHER] [FullAnalysis] Error: No model specified in config.")
            self.is_running = False
            return

        self._heartbeat_timer = ida_kernwin.register_timer(30000, self._main_thread_heartbeat)
        self.context_limit = self._fetch_model_limit(model_name)
        
        # Build Waves
        print("[AETHER] [FullAnalysis] Building global call graph and topological waves...")
        waves = []
        active_functions = []
        if resume_requested and self._restore_saved_waves_and_graph():
            waves = self._saved_waves
            active_functions = self._saved_functions
            print("[AETHER] [FullAnalysis] Loaded saved waves and call graph for resume.")
        else:
            def _build_waves_sync():
                nonlocal waves, active_functions
                waves = self.cg.calculate_waves()
                active_functions = list(self.cg.functions)
                return 1
            try:
                ida_kernwin.execute_sync(_build_waves_sync, ida_kernwin.MFF_READ)
            except Exception as e:
                print(f"[AETHER] [FullAnalysis] Error building call graph: {e}")
                self.is_running = False
                return
            self._persist_waves_and_graph(waves)
        total_funcs = len(active_functions)

        print(f"[AETHER] [FullAnalysis] Identified {total_funcs} functions for analysis:")
        if total_funcs <= 50:
            for ea in sorted(active_functions):
                print(f"  - {hex(ea)}: {get_func_name_sync(ea)}")
        else:
            print(f"  - (List truncated, showing first 20/last 20)")
            for ea in sorted(active_functions)[:20]:
                print(f"  - {hex(ea)}: {get_func_name_sync(ea)}")
            print("  - ...")
            for ea in sorted(active_functions)[-20:]:
                print(f"  - {hex(ea)}: {get_func_name_sync(ea)}")

        print(f"[AETHER] [FullAnalysis] Found {total_funcs} functions across {len(waves)} waves.")
        if resume_requested:
            last_wave = self._get_last_completed_wave()
            stale = self.db.reset_stale_pending()
            completed_count = sum(
                1 for wave in waves[:last_wave] for scc in wave for _ in scc
            )
            remaining_count = total_funcs - completed_count
            print(
                f"[AETHER] [FullAnalysis] Resume state: "
                f"{completed_count} functions already done across {last_wave} wave(s), "
                f"{remaining_count} remaining. "
                f"({stale} stale Pending entr{'y' if stale == 1 else 'ies'} cleared.)"
            )
            print(f"[AETHER] [FullAnalysis] Resuming after wave {last_wave}.")
        self._resume_from_wave = self._get_last_completed_wave() if resume_requested else 0

        @use_async_worker("FanalysisAutoAnalysis")
        async def fanalysis_thread(waves_to_process):
            with self.llm: await asyncio.to_thread(self._process_waves, waves_to_process)

        if start_pipeline(fanalysis_thread(waves)) is False:
            self.is_running = False
            if self._heartbeat_timer:
                try:
                    ida_kernwin.unregister_timer(self._heartbeat_timer)
                    self._heartbeat_timer = None
                except Exception: pass
            print("[AETHER] [FullAnalysis] Failed to start analysis pipeline.")

    def _persist_waves_and_graph(self, waves):
        try:
            waves_payload = []
            for wave in waves:
                waves_payload.append([[hex(ea) for ea in scc] for scc in wave])
            adj_payload = {
                hex(caller): [hex(callee) for callee in sorted(list(callees))]
                for caller, callees in self.cg.adj.items()
            }
            self.db.set_meta("fanalysis_waves", json.dumps(waves_payload))
            self.db.set_meta("fanalysis_call_graph", json.dumps(adj_payload))
            self.db.set_meta("fanalysis_wave_count", str(len(waves)))
            self.db.set_meta("fanalysis_last_wave", "0")
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Warning: Failed to persist waves/call graph: {e}")

    def _restore_saved_waves_and_graph(self) -> bool:
        try:
            waves_raw = self.db.get_meta("fanalysis_waves")
            graph_raw = self.db.get_meta("fanalysis_call_graph")
            if not waves_raw or not graph_raw:
                return False

            waves_payload = json.loads(waves_raw)
            adj_payload = json.loads(graph_raw)

            waves = []
            functions = set()
            for wave in waves_payload:
                wave_list = []
                for scc in wave:
                    scc_list = [int(ea, 16) for ea in scc]
                    functions.update(scc_list)
                    wave_list.append(scc_list)
                waves.append(wave_list)

            adj = {}
            rev_adj = {}
            for caller_hex, callee_hexes in adj_payload.items():
                caller = int(caller_hex, 16)
                callees = set(int(ea, 16) for ea in callee_hexes)
                adj[caller] = callees
                for callee in callees:
                    rev_adj.setdefault(callee, set()).add(caller)

            self.cg.adj = adj
            self.cg.rev_adj = rev_adj
            self.cg.functions = set(functions)

            self._saved_waves = waves
            self._saved_functions = list(functions)
            return True
        except Exception as e:
            print(f"[AETHER] [FullAnalysis] Warning: Failed to restore saved waves/call graph: {e}")
            return False

    def _get_last_completed_wave(self) -> int:
        try:
            raw = self.db.get_meta("fanalysis_last_wave", "0")
            return max(0, int(raw or 0))
        except Exception:
            return 0

    def _fetch_model_limit(self, target_id):
        try:
            url = self.config.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
            response = requests.get(f"{url}/models", timeout=10)
            if response.status_code == 200:
                for m in response.json().get('data', []):
                    if m['id'] == target_id: return int(m.get('context_length', 64000))
        except Exception: pass
        return 64000

    def _process_waves(self, waves):
        """Execute the full-analysis waves sequentially."""
        try:
            start_time = time.time()
            total_funcs = sum(len(scc) for wave in waves for scc in wave)

            # Optional index integration
            self._index_by_ea = {}
            if FunctionIndexManager.is_binary_indexed():
                idx = FunctionIndexManager.get_index()
                if getattr(idx, "entries_by_address", None):
                    for addr, entry in idx.entries_by_address.items():
                        if addr: self._index_by_ea[int(addr, 16)] = entry

            # calculate_waves() returns waves leaf-first (waves[0]=leaves, waves[-1]=roots).
            # Process in that order so callee summaries exist before callers are analysed.
            ordered_waves = waves
            max_workers = max(1, int(self.config.get("MAX_CONCURRENT_WORKERS", 5)))
            resume_from = max(0, int(getattr(self, "_resume_from_wave", 0) or 0))
            if resume_from >= len(ordered_waves):
                print("[AETHER] [FullAnalysis] Resume point exceeds wave count; nothing to do.")
                return

            # Initialise to 0, then seed with already-finished waves on resume so
            # progress percentages and ETA reflect the full binary, not just this session.
            self.funcs_processed = sum(
                len(scc) for wave in ordered_waves[:resume_from] for scc in wave
            )

            # Clear Hex-Rays cache every N completions to prevent memory bloat on large waves.
            _CACHE_CLEAR_INTERVAL = 75

            for wave_num, wave in enumerate(ordered_waves[resume_from:], resume_from + 1):
                if self.stop_requested:
                    print(f"[AETHER] [FullAnalysis] Aborting at wave {wave_num}...")
                    break
                clear_cached_cfuncs_sync()
                
                wave_eas = [ea for scc in wave for ea in scc]
                print(f"[AETHER] [FullAnalysis] -> Tree Level {wave_num}/{len(ordered_waves)} ({len(wave_eas)} functions)")

                # Get statuses in batch
                all_related = set(wave_eas)
                for wea in wave_eas:
                    for cea in self.cg.adj.get(wea, []): all_related.add(cea)
                status_cache = self.db.get_function_statuses(list(all_related))

                jobs = []
                for parent_ea in wave_eas:
                    if self.stop_requested: break
                    
                    # Check for skipping (status, name, etc)
                    if self._should_skip_ea(parent_ea, status_cache, wave_num):
                        print(f"[AETHER] [FullAnalysis] Skipping {get_func_name_sync(parent_ea)} ({hex(parent_ea)}) - Already complete or trivial.")
                        self.funcs_processed += 1
                        continue

                    ctx = self._prepare_function_context(parent_ea, wave_num)
                    if ctx: jobs.append(ctx)
                    else: self.funcs_processed += 1
                
                # Mid-wave cache flush: after all decompilations for this wave are done
                # (job prep), clear the cache before the apply phase so mark_cfunc_dirty
                # cycles don't compound across a large wave.
                if len(jobs) > _CACHE_CLEAR_INTERVAL:
                    clear_cached_cfuncs_sync()

                if not jobs:
                    print(f"[AETHER] [FullAnalysis] Wave {wave_num} had no new jobs (all skipped or thunks).")
                    self._print_progress(total_funcs, start_time)
                    continue

                print(f"[AETHER] [FullAnalysis] Dispatching {len(jobs)} LLM jobs...")
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(self._analyze_function, ctx, wave_num): ctx for ctx in jobs}
                    for future in as_completed(futures):
                        if self.stop_requested:
                            # Cancel remaining futures and exit the loop; the
                            # context manager will drain already-running threads.
                            for f in futures:
                                f.cancel()
                            break
                        try:
                            res = future.result()
                            # res is (processed_count, payload)
                            if isinstance(res, tuple) and len(res) == 2:
                                _, payload = res
                                if payload:
                                    ea, fname, fn_result = payload
                                    with self._ida_serial_lock:
                                        touched = self._apply_analysis_result_sync(ea, fname, fn_result, wave_num)
                                        if touched: refresh_functions(sorted(list(touched)), log_prefix="[AETHER]")
                            self.funcs_processed += 1
                            # Periodically clear cache to control Hex-Rays memory growth.
                            if self.funcs_processed % _CACHE_CLEAR_INTERVAL == 0:
                                clear_cached_cfuncs_sync()
                        except Exception as e: print(f"[AETHER] [FullAnalysis] Job error: {e}")

                        self._print_progress(total_funcs, start_time)

                if not self.stop_requested:
                    self.db.set_meta("fanalysis_last_wave", str(wave_num))
        except Exception as e:
            err = f"[AETHER] [FullAnalysis] Unhandled error in wave processing: {e}\n{traceback.format_exc()}"
            print(err)
            log_fanalysis_error(err)
            self.stop_requested = True

        elapsed_time = time.time() - start_time
        print("-" * 50)
        if self.stop_requested:
            print(f"[AETHER] [FullAnalysis] ANALYSIS STOPPED BY USER (Elapsed: {elapsed_time:.2f}s)")
        else:
            print(f"[AETHER] [FullAnalysis] ANALYSIS COMPLETE (Elapsed: {elapsed_time:.2f}s)")

        print(f"[AETHER] Token Usage Summary:")
        print(f"         Prompt Tokens:     {self.total_prompt_tokens}")
        print(f"         Completion Tokens: {self.total_completion_tokens}")
        print(f"         Total Tokens:      {self.total_prompt_tokens + self.total_completion_tokens}")
        print("-" * 50)

        self.is_running = False
        def _cleanup_sync():
            if self._heartbeat_timer:
                try:
                    ida_kernwin.unregister_timer(self._heartbeat_timer)
                    self._heartbeat_timer = None
                    print("[AETHER] [FullAnalysis] Heartbeat timer stopped.")
                except Exception: pass
            ida_kernwin.update_action_label("aether:auto_analyse", "Auto-Analyze Binary")
            return 1
        ida_kernwin.execute_sync(_cleanup_sync, ida_kernwin.MFF_WRITE)
        
        print(f"[AETHER] [FullAnalysis] Analysis pipeline finished for {total_funcs} functions.")

    def _should_skip_ea(self, ea, status_cache, wave_num):
        """Comprehensive skip logic to reduce API requests and decompiler load."""
        if status_cache.get(ea) == "Complete": return True
        name = get_func_name_sync(ea)
        for prefix in LIB_PREFIXES:
            if name.startswith(prefix):
                self.db.upsert_function(ea, name, "Complete", wave_num)
                self.db.save_summary(ea, "Standard library/runtime function.")
                return True
        class Ctx:
            f = None
            is_lib = False
            q_size = None
            instr_count = None
            is_interesting = True

        def _inspect_sync():
            Ctx.f = ida_funcs.get_func(ea)
            if not Ctx.f:
                return 1
            Ctx.is_lib = bool(Ctx.f.flags & ida_funcs.FUNC_LIB)
            try:
                q = ida_gdl.qflow_chart_t("", Ctx.f, idaapi.BADADDR, idaapi.BADADDR, 0)
                Ctx.q_size = q.size()
                if Ctx.q_size < 3:
                    instr_count = 0
                    for _ in idautils.FuncItems(ea):
                        instr_count += 1
                        if instr_count > 15:
                            break
                    Ctx.instr_count = instr_count
            except Exception:
                Ctx.q_size = None
                Ctx.instr_count = None
            try:
                Ctx.is_interesting = self._is_interesting_natively(ea, Ctx.f)
            except Exception:
                Ctx.is_interesting = True
            return 1

        ida_kernwin.execute_sync(_inspect_sync, ida_kernwin.MFF_READ)

        if not Ctx.f:
            return True
        if Ctx.is_lib:
            self.db.upsert_function(ea, name, "Complete", wave_num)
            return True
        if Ctx.q_size is not None and Ctx.q_size < 3 and Ctx.instr_count is not None:
            if Ctx.instr_count <= 15:
                self.db.upsert_function(ea, name, "Complete", wave_num)
                self.db.save_summary(ea, "Trivial function (Small instruction/block count).")
                return True
        if not Ctx.is_interesting:
            self.db.upsert_function(ea, name, "Complete", wave_num)
            self.db.save_summary(ea, "Semantic Pruning: No strings, imports, or global side effects found.")
            return True
        return False

    def _is_interesting_natively(self, ea, f) -> bool:
        """Delegate to the shared module-level heuristic in core_graph."""
        return is_func_interesting(ea, f)

    def _prepare_function_context(self, ea, wave_num):
        """Prepare context for one function."""
        func_name = get_func_name_sync(ea)
        self.db.upsert_function(ea, func_name, "Pending", wave_num)
        
        start_ts = time.time()
        print(f"[AETHER] [FullAnalysis] [{func_name}] Starting decompilation...")
        class Ctx: c_code = ""
        def sync_decomp():
            cf = decompile_func(ea)
            if cf: Ctx.c_code = minify_c_code(get_c_text(cf))
            else: Ctx.c_code = None
            return 1
        with self._ida_serial_lock: ida_kernwin.execute_sync(sync_decomp, ida_kernwin.MFF_READ)
        
        decomp_duration = time.time() - start_ts
        if not Ctx.c_code:
            print(f"[AETHER] [FullAnalysis] [{func_name}] Decompilation FAILED after {decomp_duration:.2f}s.")
            self.db.upsert_function(ea, func_name, "Failed_Decompile", wave_num)
            return None
        print(f"[AETHER] [FullAnalysis] [{func_name}] Decompilation SUCCESS after {decomp_duration:.2f}s.")

        if len(Ctx.c_code.split("\n")) <= 2 or "jmp" in Ctx.c_code:
            def _mark():
                scmt(hex(ea), "Thunk/Jump function")
                self.db.upsert_function(ea, func_name, "Complete", wave_num)
                self.db.save_summary(ea, "Thunk/Jump function")
                return 1
            with self._ida_serial_lock: ida_kernwin.execute_sync(_mark, ida_kernwin.MFF_WRITE)
            return None

        child_sums = []
        # Build a 1-level ASCII tree for context
        tree_lines = [f"{func_name} [{hex(ea)}]"]
        if ea in self.cg.adj:
            callees = sorted(list(self.cg.adj[ea]))
            for i, cea in enumerate(callees):
                s = self.db.get_summary(cea)
                cname = get_func_name_sync(cea)
                if s: child_sums.append(f"- {cname}: {s}")
                
                connector = "└── " if i == len(callees) - 1 else "├── "
                tree_lines.append(f"{connector}{cname} [{hex(cea)}]")

        tree_str = "\n".join(tree_lines)

        idx_info = None
        if ea in self._index_by_ea:
            e = self._index_by_ea[ea]
            cats, imp = e.get_functional_categories(), e.get_importance_level()
            if cats or imp: idx_info = f"Category: {', '.join(cats)}, Importance: {imp}"

        return {
            "ea": ea, 
            "func_name": func_name, 
            "c_code": Ctx.c_code, 
            "child_summaries": child_sums[:50], 
            "idx_info": idx_info,
            "call_tree": tree_str
        }

    def _analyze_function(self, data, wave_num):
        """Parallel LLM inference."""
        ea, func_name = data["ea"], data["func_name"]
        start_ts = time.time()
        print(f"[AETHER] [FullAnalysis] [{func_name}] Starting LLM inference...")
        
        raw_code, summaries = data["c_code"], data["child_summaries"]
        if count_tokens(raw_code) > code_budget(self.context_limit):
            raw_code, summaries, _ = reduce_to_budget(raw_code, summaries, self.context_limit)
        
        prompt = self._minitree_prompt_template.format(
            func_name=func_name, idx_info=data["idx_info"] or "",
            child_summaries="\n".join(summaries), c_code=raw_code,
            call_tree=data.get("call_tree", "")
        ) if self._minitree_prompt_template else f"Analyze {func_name}\nCode: {raw_code}"

        result, usage = None, None
        for attempt in range(3):
            if self.stop_requested: break
            result, usage = self.llm.analyze_function(prompt)
            if result: break
            time.sleep(2 ** attempt)

        if usage:
            with self._stats_lock:
                self.total_prompt_tokens += getattr(usage, "prompt_tokens", 0)
                self.total_completion_tokens += getattr(usage, "completion_tokens", 0)

        if not result:
            print(f"[AETHER] [FullAnalysis] [{func_name}] Analysis FAILED after all attempts.")
            self.db.upsert_function(ea, func_name, "Failed_LLM", wave_num)
            return 1, None

        inference_duration = time.time() - start_ts
        self._update_job_perf(inference_duration)
        print(f"[AETHER] [FullAnalysis] [{func_name}] Inference SUCCESS after {inference_duration:.2f}s.")
        return 1, (ea, func_name, result)

    def _apply_analysis_result_sync(self, ea, func_name, fn_result, wave_num):
        """Atomic IDA update optimized for stability."""
        start_ts = time.time()
        print(f"[AETHER] [FullAnalysis] [{func_name}] Applying analysis results to IDA...")
        def _apply():
            try:
                # 1. Renames
                mn = fn_result.get("function_name")
                if mn and mn != func_name and IDA_DUMMY_FUNC_RE.match(func_name):
                    sn = _sanitize_identifier(mn, "aire")
                    if not sn.startswith("aire_"): sn = "aire_" + sn
                    if not ida_name.set_name(ea, sn, ida_name.SN_NOWARN): ida_name.set_name(ea, f"{sn}_{ea:x}", ida_name.SN_NOWARN)
                
                for o, n in fn_result.get("function_renames", {}).items():
                    if IDA_DUMMY_FUNC_RE.match(o):
                        cea = idc.get_name_ea_simple(o)
                        if cea != idaapi.BADADDR:
                            sn = _sanitize_identifier(n, "aire")
                            if not sn.startswith("aire_"): sn = "aire_" + sn
                            if not ida_name.set_name(cea, sn, ida_name.SN_NOWARN): ida_name.set_name(cea, f"{sn}_{cea:x}", ida_name.SN_NOWARN)

                # 2. Comments/Lvars
                s = fn_result.get("summary")
                if s: self.db.save_summary(ea, s)
                lvars, cmts = fn_result.get("variable_renames", {}), fn_result.get("comments", {})
                # do NOT call decompile_func here.
                if cmts:
                    for addr, txt in cmts.items():
                        if "0x" in addr:
                            cleaned = txt.replace("<NEWLINE>", "\n").replace("\\n", "\n")
                            cleaned_lines = [line.lstrip().lstrip("/").lstrip("/").lstrip() if line.lstrip().startswith("//") else line
                                            for line in cleaned.split("\n")]
                            scmt(addr.strip(), "\n".join([textwrap.fill(p, 80) for p in cleaned_lines]))
                if lvars:
                    for o, n in lvars.items():
                        if IDA_DUMMY_VAR_RE.match(o): ida_hexrays.rename_lvar(ea, o, _sanitize_identifier(n, "v"))

                self.db.upsert_function(ea, mn or func_name, "Complete", wave_num)
                try: ida_hexrays.mark_cfunc_dirty(ea, False)
                except: ida_hexrays.mark_cfunc_dirty(ea)
            except Exception as e: print(f"[AETHER] [FullAnalysis] Stability bypass: Edits for {func_name} skipped: {e}")
            return 1
        ida_kernwin.execute_sync(_apply, ida_kernwin.MFF_WRITE)
        apply_duration = time.time() - start_ts
        print(f"[AETHER] [FullAnalysis] [{func_name}] Application SUCCESS after {apply_duration:.2f}s.")
        return {ea}