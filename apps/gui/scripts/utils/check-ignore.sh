#!/usr/bin/env bash
# utils/check-ignore.sh — sourced/called by install-prod.sh
# Equivalent of Check-Ignore.ps1
#
# Usage:
#   source utils/check-ignore.sh          # to get helper functions
#   run_check_ignore <path> <dest_dir>    # to execute the copy logic
#
# Environment expected when called from install-prod.sh:
#   SCRIPT_DIR  — absolute path to the directory containing install-prod.sh
#                 (used to locate utils/ignore.txt)

# ---------------------------------------------------------------------------
# _load_ignore_rules
#   Populates the global IGNORE_RULES array from utils/ignore.txt,
#   stripping blank lines and comments.  Mirrors the $GitignoreRules setup.
# ---------------------------------------------------------------------------
_load_ignore_rules() {
    local ignore_file="${SCRIPT_DIR}/utils/ignore.txt"
    IGNORE_RULES=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip leading/trailing whitespace
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        # Skip blank lines and comments
        [[ -z "$line" || "$line" == \#* ]] && continue
        IGNORE_RULES+=("$line")
    done < "$ignore_file"
}

# ---------------------------------------------------------------------------
# _glob_to_regex <glob_pattern>
#   Converts a gitignore-style glob into an extended-regex pattern.
#   Mirrors the regex construction in Test-IsMatch.
# ---------------------------------------------------------------------------
_glob_to_regex() {
    local rule="$1"
    local dir_only=false
    [[ "$rule" == */ ]] && dir_only=true

    # Escape regex metacharacters except * and ?
    local escaped
    escaped="$(printf '%s' "$rule" | sed \
        -e 's/[.^$+{}()|\\[]/\\&/g' \
        -e 's/\*/.*/g'              \
        -e 's/?/./g')"

    if $dir_only; then
        local bare="${escaped%/}"
        echo "(^|/)${bare}(/|$)"
    else
        echo "(^|/)${escaped}"
    fi
}

# ---------------------------------------------------------------------------
# test_is_match <relative_path> <is_dir:true|false>
#   Returns 0 (match/ignore) or 1 (allow).
#   Mirrors Test-IsMatch in Check-Ignore.ps1.
# ---------------------------------------------------------------------------
test_is_match() {
    local target="$1"
    local is_dir="$2"   # "true" or "false"

    # Normalise to forward slashes (no-op on Linux, safety net for MSYS paths)
    local normalized="${target//\\//}"

    # Catch dot-files / dot-directories (but allow .gitignore itself)
    if echo "$normalized" | grep -qE '(^|/)\.' ; then
        if ! echo "$normalized" | grep -qE '\.gitignore$'; then
            return 0   # ignored
        fi
    fi

    for rule in "${IGNORE_RULES[@]}"; do
        rule="${rule#"${rule%%[![:space:]]*}"}"
        rule="${rule%"${rule##*[![:space:]]}"}"
        [[ -z "$rule" || "$rule" == \#* ]] && continue

        local rule_is_dir_only=false
        [[ "$rule" == */ ]] && rule_is_dir_only=true

        # Directory-only rules do not match files
        if $rule_is_dir_only && [[ "$is_dir" != "true" ]]; then
            continue
        fi

        local regex
        regex="$(_glob_to_regex "$rule")"

        if echo "$normalized" | grep -qE "$regex"; then
            return 0   # matched → ignored
        fi
    done

    return 1   # no match → allowed
}

# ---------------------------------------------------------------------------
# run_check_ignore <source_root> <dest_dir>
#   Walks <source_root> recursively, copying allowed files to <dest_dir>
#   while pruning ignored directories.  Mirrors the CASE B execution block
#   in Check-Ignore.ps1.
# ---------------------------------------------------------------------------
run_check_ignore() {
    local source_root="${1:?source_root is required}"
    local dest_dir="${2:?dest_dir is required}"

    _load_ignore_rules

    # Resolve to absolute, strip trailing slash
    source_root="$(cd "$source_root" && pwd)"

    echo -e "\033[0;36m[*] Auditing workspace folder: $source_root\033[0m"
    echo -e "\033[0;37m[*] Optimization Active: Ignored folders will be bypassed completely.\n\033[0m"

    # Track pruned directories in an associative set (keys only)
    declare -A pruned_dirs=()

    # find with -print0 for safe handling of filenames with spaces
    while IFS= read -r -d '' abs_path; do
        # Relative path from source_root
        local rel_path="${abs_path#"$source_root/"}"

        local is_dir="false"
        [[ -d "$abs_path" ]] && is_dir="true"

        # STEP 1 — Skip if inside a pruned directory
        local skip=false
        for pruned in "${!pruned_dirs[@]}"; do
            if [[ "$rel_path" == "$pruned" || "$rel_path" == "$pruned/"* ]]; then
                skip=true
                break
            fi
        done
        $skip && continue

        # STEP 2 — Evaluate against ignore rules
        if test_is_match "$rel_path" "$is_dir"; then
            if [[ "$is_dir" == "true" ]]; then
                pruned_dirs["$rel_path"]=1
                echo -e "\033[0;31m[PRUNED DIRECTORY] skipping entry and all contents -> $rel_path\033[0m"
            else
                echo -e "\033[0;33m[IGNORED FILE] -> $rel_path\033[0m"
            fi
        else
            echo -e "\033[0;32m[ALLOWED] -> $abs_path Copying...\033[0m"
            # Preserve directory structure under dest_dir
            local dest_path="$dest_dir/$rel_path"
            mkdir -p "$(dirname "$dest_path")"
            cp -f -r "$abs_path" "$dest_path"
            echo -e "\033[0;32m[COPIED] -> $rel_path\033[0m"
        fi
    done < <(find "$source_root" -mindepth 1 -print0 | sort -z)
}
