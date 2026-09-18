#!/usr/bin/env python3
"""Generate Markdown API docs from Python docstrings using Griffe.

Usage: python griffe_generate.py <dir> [--output <dir>]
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable
from pathlib import Path

from griffe import Alias, Class, Function, Module, Object, load


def iter_py_files(root: Path) -> Iterable[Path]:
    return (
        p for p in root.rglob("*.py") if not p.name.startswith(".") and "__pycache__" not in p.parts
    )


def module_name(root: Path, path: Path) -> str:
    parts = list(path.relative_to(root).parts)
    parts = (
        parts[:-1] if parts[-1] == "__init__.py" else [*parts[:-1], parts[-1].removesuffix(".py")]
    )
    return ".".join(parts)


H: Callable[[int, str], str] = lambda n, t: f"{'#' * n} {t}\n"  # noqa: E731
code: Callable[[str], str] = lambda t: f"```python\n{t.strip()}\n```\n"  # noqa: E731


def escape_mdx(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("{", "&#123;")
        .replace("}", "&#125;")
    )


def doc(o: Object) -> str:
    if not o.docstring:
        return "_No documentation._\n"
    return escape_mdx(o.docstring.value.strip()) + "\n"


def render_func(f: Function) -> str:
    return "\n".join([H(3, f.name), code(f"def {f.signature()}"), doc(f)])


def render_class(cls: Class) -> str:
    methods = [m for m in cls.members.values() if isinstance(m, Function)]
    parts = [H(2, cls.name), doc(cls)]
    if methods:
        parts += [H(3, "Methods"), *[render_func(m) for m in methods]]
    return "\n".join(parts)


def render_module(mod: Module) -> str:
    members = [m for m in mod.members.values() if not isinstance(m, Alias)]
    classes = [m for m in members if isinstance(m, Class)]
    funcs = [m for m in members if isinstance(m, Function)]
    parts = [H(1, mod.name), doc(mod)]
    if classes:
        parts += [H(2, "Classes"), *[render_class(c) for c in classes]]
    if funcs:
        parts += [H(2, "Functions"), *[render_func(f) for f in funcs]]
    return "\n".join(parts)


def load_module(name: str, py_file: Path, root: Path) -> Module | None:
    errors: list[Exception] = []

    try:
        obj = load(name, search_paths=[str(root)])
        if isinstance(obj, Module):
            return obj
    except Exception as e:
        errors.append(e)

    parts = name.split(".")
    alt_root = root / parts[0]
    alt_name = ".".join(parts[1:])
    if alt_name and alt_root.is_dir():
        try:
            obj = load(alt_name, search_paths=[str(alt_root)])
            if isinstance(obj, Module):
                return obj
        except Exception as e:
            errors.append(e)

    try:
        obj = load(py_file)
        if isinstance(obj, Module):
            return obj
    except Exception as e:
        errors.append(e)

    for err in errors:
        print(f"[ERROR] {name}: {err}")
    return None


def process(root: Path, py_file: Path, out_dir: Path) -> None:
    name = module_name(root, py_file)
    mod = load_module(name, py_file, root)
    if not mod:
        return

    out = out_dir / (name.replace(".", "/") + ".mdx")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_module(mod), encoding="utf-8")
    print(f"[OK] {out}")


def main() -> None:
    p = argparse.ArgumentParser(description="Generate Markdown docs from Python docstrings.")
    p.add_argument("dir", help="Root directory to scan.")
    p.add_argument("--output", default="docs", nargs="?", help="Output directory.")
    args = p.parse_args()

    root = Path(args.dir).resolve()
    if not root.exists():
        raise SystemExit(f"Directory does not exist: {root}")

    files = list(iter_py_files(root))
    if not files:
        print("No Python files found.")
        return

    out_dir = Path(args.output).resolve()
    for f in files:
        process(root, f, out_dir)


if __name__ == "__main__":
    main()
