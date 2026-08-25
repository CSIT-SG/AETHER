---
name: md-report-converter
description: Converts a markdown malware analysis report (written by a human analyst) into a structured AETHER rubrics.yaml file for the Benchmark tool. Use whenever the user provides a markdown/text reverse-engineering report and asks for a rubric, YAML rubric, AETHER rubric, or benchmark scoring file to be generated from it, or asks to "convert this report to YAML."
metadata:
  author: AETHER team
  version: 1.0
---

# MD Report Convertor

Converts a human-written markdown malware analysis report into a `rubrics.yaml` file that conforms to the AETHER Benchmark rubric schema. The output is consumed by AETHER Benchmark to score the *quality of annotations* (naming, structure, documentation) on a reverse-engineered sample — not to score the malware itself.

## Input

A text-based markdown analysis report containing some mix of:
- Function names / labels
- Memory addresses or offsets (e.g. `0x401000`)
- Behavioral observations (what a function/routine does)
- Reverse-engineering notes from the analyst

## Output Schema (must match exactly)

The output is a single YAML document with two parts: **frontmatter** and a **`rubrics` list**.

### Frontmatter fields

| Field | Required | Notes |
| :--- | :--- | :--- |
| `name` | Yes | Report title / malware nickname |
| `version` | No | Semantic version string, e.g. `"1.0.0"` |
| `description` | No | Brief summary of the report and analysis focus |

### Each entry in `rubrics`

| Field | Type | Required | Notes |
| :--- | :--- | :--- | :--- |
| `name` | String | Yes | `snake_case` identifier for the rubric group — normally a single function (e.g. `decrypt_config_string`), or a functional domain (e.g. `packet_parsing_logic`) when function-level grouping doesn't make sense |
| `description` | String | No | Context for the evaluator — include address mapping. Keep to **moderate detail**; do not over-explain. |
| `weight` | Float | No | Importance of this group. Omit to default to `1.0`. |
| `criteria` | List[String] | Yes | Specific, checkable requirements an evaluator would look for. |

## Transformation Logic

1. **Group by function, by default.** Prefer **one rubric entry per named/addressed function** — this keeps each entry's `criteria` tightly scoped to what an evaluator would check on that single function, instead of one criterion silently trying to cover many unrelated functions.
   - Fall back to grouping by **functional domain** (e.g. `networking`, `persistence`, `cryptography`) only when function-level grouping doesn't make sense — e.g. the report doesn't name/address individual functions, or a domain is made up of several trivial helpers (getters, thin wrappers, single-line utility calls) that have nothing independently checkable about them.
   - Don't force a domain-level group into artificial per-function splits either — if the report itself only describes behavior at the domain level (no distinct functions called out), keep it as one domain-level rubric rather than inventing function names.
   - A rubric entry should never be the catch-all for functions that aren't meaningfully related just because they were mentioned near each other in the report.
2. **Extract context and addresses.** Pull the memory address / offset for each rubric's function (or, for a domain-level group, every address in scope) and attach it to that entry. Addresses go in the rubric's `description` field, phrased as `Targets: 0x..., 0x...` per the schema's contextual-mapping convention.
3. **Assign weights.**
   - `weight: 2.0` (or higher) for critical paths: C2 communication, encryption/decryption, payload staging.
   - Omit `weight` (defaults to `1.0`) for standard procedural or supporting code.
4. **Draft criteria.** Rewrite each behavioral observation as an actionable, checkable string — what a human evaluator would verify in the annotated binary (e.g. "Magic numbers replaced with named constants", "C2 decryption routine is tagged with the algorithm name").
5. **Keep descriptions concise.** Per the schema guidance, overly long rubric descriptions hurt evaluation quality more than they help — aim for moderate detail, not exhaustive prose.

## Execution Instructions

1. Read the full markdown report before writing any YAML.
2. Cluster findings into `rubrics` entries **per function by default**; only merge into a functional-domain entry when individual functions aren't distinguishable or are too trivial to check independently.
3. For each entry, write a short `description` with the relevant address(es) and scope (single function, or domain if grouped).
4. Assign `weight` only where the domain is a critical path; otherwise omit it.
5. Convert each observation into 2+ concrete `criteria` strings.
6. Output **only** the final YAML block — no commentary, no markdown fences beyond the YAML code block itself.

## Worked Example

**Report excerpt:**
> "The malware uses a custom XOR routine at 0x405000 to decrypt the C2 address, and it sets a registry key at 0x406200 for persistence. Three small helpers at 0x406300, 0x406310, and 0x406320 just wrap `RegSetValueExA` for different value names with no other logic."

**Resulting rubric entries:**

```yaml
name: "Reference Sample Analysis"
version: "1.0.0"
description: "Evaluates reverse-engineered C2 decryption and persistence routines."

rubrics:
  # Default case: distinct, non-trivial function -> its own rubric entry
  - name: "decrypt_c2_address"
    description: "Targets: 0x405000. Custom XOR routine that decrypts the C2 address."
    weight: 2.0
    criteria:
      - "The XOR key/constant is named rather than left as a magic number"
      - "The function is tagged as the C2-address decryption routine"

  - name: "write_persistence_registry_key"
    description: "Targets: 0x406200. Writes the registry key used for persistence."
    criteria:
      - "The registry key path/value is named meaningfully, not left as a raw string literal"
      - "The function is tagged as a persistence mechanism"

  # Fallback case: three trivial one-line wrappers with nothing independently
  # checkable -> grouped as one domain-level rubric instead of three thin entries
  - name: "registry_value_write_helpers"
    description: "Targets: 0x406300, 0x406310, 0x406320. Thin wrappers around RegSetValueExA for distinct value names; no independent logic per helper."
    criteria:
      - "Each helper's target value name is reflected in its function name or comment"
      - "The helpers are collectively tagged as registry-write utilities rather than left unnamed"
```

Note: `write_persistence_registry_key` has no `weight` field, so it defaults to `1.0` — only the critical-path `decrypt_c2_address` function is weighted higher. The three trivial wrappers are grouped into a single domain-level entry rather than split into three near-empty rubrics.
