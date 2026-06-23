import idautils
import ida_funcs
import ida_nalt
import idaapi
import idc
import ida_gdl


# ---------------------------------------------------------------------------
# Shared importance heuristic — used by CallGraph.find_roots AND the
# orchestrator's _should_skip_ea so the logic lives in exactly one place.
# ---------------------------------------------------------------------------

def is_func_interesting(ea, f=None) -> bool:
    """
    Return True if a non-library function exhibits application-code markers:
      1. Direct call into an import/PLT segment
      2. Reference to a string or .data/.bss global
      3. Indirect branch (call/jmp rax) with no static target
      4. Run of >10 ASCII constant moves (possible obfuscation/decryption loop)

    ``f`` may be pre-fetched to avoid a redundant get_func call.
    Returns True on any exception (safe-fail toward inclusion).
    """
    try:
        if f is None:
            f = ida_funcs.get_func(ea)
        if not f or (f.flags & ida_funcs.FUNC_LIB):
            return False

        const_move_count = 0
        for item_ea in idautils.FuncItems(ea):
            for ref_ea in idautils.CodeRefsFrom(item_ea, False):
                if idc.get_segm_name(ref_ea) in (".idata", ".plt", "extern"):
                    return True
            for ref_ea in idautils.DataRefsFrom(item_ea):
                if idc.get_str_type(ref_ea) != -1:
                    return True
                seg = idaapi.getseg(ref_ea)
                if seg and seg.name in (".data", ".bss"):
                    return True
            mnem = idc.print_insn_mnem(item_ea)
            if mnem in ("call", "jmp"):
                if idc.get_operand_type(item_ea, 0) in (idc.o_reg, idc.o_phrase, idc.o_displ):
                    if not list(idautils.CodeRefsFrom(item_ea, False)):
                        return True
            if mnem == "mov" and idc.get_operand_type(item_ea, 1) == idc.o_imm:
                imm = idc.get_operand_value(item_ea, 1)
                if 0x20 <= imm <= 0x7E:
                    const_move_count += 1
                    if const_move_count > 10:
                        return True
    except Exception:
        return True
    return False


class CallGraph:
    def __init__(self):
        self.adj = {}           # caller -> list of callees
        self.rev_adj = {}       # callee -> list of callers
        self.functions = set()  # set of all non-lib function addresses
        self.sccs = []          # list of strongly connected components
        self.node_to_scc = {}   # ea -> scc_index
        self.scc_adj = {}       # scc_index -> set of scc_indices (callees)
        self.scc_rev_adj = {}   # scc_index -> set of scc_indices (callers)
        self.waves = []         # list of list of eAs

    def find_roots(self):
        """Identify entry points to the binary (Exports, TLS, Main, and Interesting Orphans)."""
        roots = set()
        
        # 1. Exports (Standard IDA entry points)
        for (index, ordinal, ea, name) in idautils.Entries():
            if ea != idaapi.BADADDR:
                roots.add(ea)
        
        # 2. Known named entry points (Broad spectrum)
        entry_patterns = [
            "main", "start", "DllMain", "WinMain", "DriverEntry", "main.main",
            "WinMainCRTStartup", "mainCRTStartup", "ServiceMain", "Handler",
            "TlsCallback_0", "init", ".init_array", "runtime.main", "main.init",
            "std::rt::lang_start", "std::rt::lang_start_internal"
        ]
        for name in entry_patterns:
            ea = idc.get_name_ea_simple(name)
            if ea != idaapi.BADADDR:
                roots.add(ea)

        # 3. "Interesting Orphans" Detection
        # If a function is never called statically, but it looks like real application code,
        # it is likely an indirect entry point or a target of dynamic branching.
        all_funcs = list(idautils.Functions())
        print(f"[AETHER] [FullAnalysis] Scanning {len(all_funcs)} functions for interesting orphans...")
        
        for ea in all_funcs:
            # Skip if already a root
            if ea in roots: continue
            
            # Check for static callers
            refs = list(idautils.CodeRefsTo(ea, False))
            if not refs:
                # No static callers. Is it "Interesting"?
                if self.is_important_native(ea):
                    roots.add(ea)

        return roots

    def is_important_native(self, ea) -> bool:
        """Delegates to module-level is_func_interesting (single source of truth)."""
        return is_func_interesting(ea)

    def build_graph(self):
        """Build a graph of everything reachable from entry points with dynamic awareness."""
        roots = self.find_roots()
        if not roots:
            print("[AETHER] [FullAnalysis] Warning: No entry points found. Falling back to global function list.")
            roots = set(idautils.Functions())

        # Perform BFS to find all reachable non-library functions
        queue = list(roots)
        visited = set()
        orphans = set(idautils.Functions())
        
        dynamic_gateways = set() # Functions with unresolved indirect calls
        
        print(f"[AETHER] [FullAnalysis] Starting reachability analysis from {len(roots)} roots...")

        while queue:
            ea = queue.pop(0)
            if ea in visited:
                continue
            
            func = ida_funcs.get_func(ea)
            if not func:
                continue
            
            base_ea = func.start_ea
            if base_ea in visited:
                continue
                
            visited.add(base_ea)
            if base_ea in orphans:
                orphans.remove(base_ea)

            if func.flags & ida_funcs.FUNC_LIB:
                self.functions.add(base_ea)
                if base_ea not in self.adj: self.adj[base_ea] = set()
                if base_ea not in self.rev_adj: self.rev_adj[base_ea] = set()
                continue

            self.functions.add(base_ea)
            if base_ea not in self.adj: self.adj[base_ea] = set()
            if base_ea not in self.rev_adj: self.rev_adj[base_ea] = set()

            # Find all callees and check for indirect branching
            for item_ea in idautils.FuncItems(base_ea):
                has_static_out = False
                for ref_ea in idautils.CodeRefsFrom(item_ea, False):
                    callee_func = ida_funcs.get_func(ref_ea)
                    if callee_func:
                        has_static_out = True
                        callee_ea = callee_func.start_ea
                        if callee_ea != base_ea:
                            self.adj[base_ea].add(callee_ea)
                            if callee_ea not in visited:
                                queue.append(callee_ea)
                            if callee_ea not in self.rev_adj:
                                self.rev_adj[callee_ea] = set()
                            self.rev_adj[callee_ea].add(base_ea)
                
                # Dynamic Check: If it's a call/jmp with no static target
                mnem = idc.print_insn_mnem(item_ea)
                if mnem in ["call", "jmp"] and not has_static_out:
                    op_type = idc.get_operand_type(item_ea, 0)
                    if op_type in [idc.o_reg, idc.o_phrase, idc.o_displ]:
                        dynamic_gateways.add(base_ea)

        # Speculative Pass: If we found dynamic calls, include "Suspicious Orphans"
        if dynamic_gateways:
            print(f"[AETHER] [FullAnalysis] Detected {len(dynamic_gateways)} dynamic call gateways. Scanning orphans...")
            speculative_added = 0
            for oea in orphans:
                ofunc = ida_funcs.get_func(oea)
                if not ofunc or (ofunc.flags & ida_funcs.FUNC_LIB):
                    continue
                
                # Heuristic: If an orphan is non-trivial, it might be a dynamic target
                # We can refine this using a quick semantic check similar to the orchestrator one
                try:
                    q = ida_gdl.qflow_chart_t("", ofunc, idaapi.BADADDR, idaapi.BADADDR, 0)
                    if q.size() > 3:
                        self.functions.add(oea)
                        if oea not in self.adj: self.adj[oea] = set()
                        if oea not in self.rev_adj: self.rev_adj[oea] = set()
                        # Treat as a root for Wave 1
                        speculative_added += 1
                except Exception: pass
            
            if speculative_added:
                print(f"[AETHER] [FullAnalysis] Speculatively added {speculative_added} orphaned functions as potential dynamic targets.")

        print(f"[AETHER] [FullAnalysis] Reachability complete: {len(self.functions)} active functions found.")

    def find_sccs(self):
        """
        Iterative Tarjan's SCC algorithm.

        The recursive version crashes with RecursionError on binaries whose call
        chains exceed Python's default stack limit (~1000 frames). This iterative
        version uses an explicit work-stack and is behaviourally identical.
        """
        index_counter = [0]
        indices: dict = {}
        lowlinks: dict = {}
        stack: list = []
        on_stack: set = set()
        self.sccs = []
        self.node_to_scc = {}

        for root in self.functions:
            if root in indices:
                continue

            indices[root] = lowlinks[root] = index_counter[0]
            index_counter[0] += 1
            stack.append(root)
            on_stack.add(root)
            work_stack = [(root, iter(self.adj.get(root, [])))]

            while work_stack:
                v, neighbours = work_stack[-1]
                try:
                    w = next(neighbours)
                    if w not in indices:
                        # Tree edge — push and descend
                        indices[w] = lowlinks[w] = index_counter[0]
                        index_counter[0] += 1
                        stack.append(w)
                        on_stack.add(w)
                        work_stack.append((w, iter(self.adj.get(w, []))))
                    elif w in on_stack:
                        lowlinks[v] = min(lowlinks[v], indices[w])
                except StopIteration:
                    # All neighbours of v exhausted — pop and propagate lowlink
                    work_stack.pop()
                    if work_stack:
                        parent = work_stack[-1][0]
                        lowlinks[parent] = min(lowlinks[parent], lowlinks[v])
                    # Root of an SCC?
                    if lowlinks[v] == indices[v]:
                        scc = []
                        while True:
                            w = stack.pop()
                            on_stack.remove(w)
                            scc.append(w)
                            if w == v:
                                break
                        self.sccs.append(scc)

        for scc_idx, scc in enumerate(self.sccs):
            for v in scc:
                self.node_to_scc[v] = scc_idx

    def build_scc_graph(self):
        self.scc_adj = {i: set() for i in range(len(self.sccs))}
        self.scc_rev_adj = {i: set() for i in range(len(self.sccs))}

        for ea in self.functions:
            caller_scc = self.node_to_scc[ea]
            for callee_ea in self.adj[ea]:
                callee_scc = self.node_to_scc[callee_ea]
                if caller_scc != callee_scc:
                    self.scc_adj[caller_scc].add(callee_scc)
                    self.scc_rev_adj[callee_scc].add(caller_scc)

    def calculate_waves(self):
        self.build_graph()
        self.find_sccs()
        self.build_scc_graph()

        # Topological sort (from leaves to roots)
        in_degrees = {i: len(self.scc_adj[i]) for i in range(len(self.sccs))}
        
        # Wave 1: Leaves (out-degree 0 in the original graph, which means out-degree 0 in SCC graph)
        # Note: self.scc_adj stores caller -> callees. So leaves have 0 callees.
        # Wait, if we process Leaves -> Root, we want to pop nodes with 0 *outgoing* edges.
        
        # out-degrees in SCC graph
        out_degrees = {i: len(self.scc_adj[i]) for i in range(len(self.sccs))}
        
        self.waves = []
        queue = [i for i in range(len(self.sccs)) if out_degrees[i] == 0]
        
        while queue:
            current_wave = []
            next_queue = []
            
            for scc_idx in queue:
                # Add all functions in this SCC to the current wave
                # They will be processed together
                current_wave.append(self.sccs[scc_idx])
                
                # For each caller of this SCC, decrement its out-degree
                for caller_scc in self.scc_rev_adj[scc_idx]:
                    out_degrees[caller_scc] -= 1
                    if out_degrees[caller_scc] == 0:
                        next_queue.append(caller_scc)
            
            self.waves.append(current_wave)
            queue = next_queue

        return self.waves

def get_waves():
    cg = CallGraph()
    return cg.calculate_waves()