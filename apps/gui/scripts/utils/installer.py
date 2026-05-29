from os.path import join
import re
import os
import fnmatch
import sys
import shutil


IGNORE: list[str] = [".gitignore", "CONTRIBUTING.md", ".git", "pyrightconfig.json", "uv.lock"]
REGEXES: list[re.Pattern[str]] = []


# Convert gitignore patterns to regex
def format_to_regex(pattern: str) -> re.Pattern[str]:
    clean = pattern.strip("/")
    regex = re.compile(fnmatch.translate(clean))
    return regex


# Scan the directory and decide if it should be copied or not based on the regexes
def scan(path: str) -> bool:
    skip: bool = any(regex.match(path) for regex in REGEXES)
    return skip


def main(plugin_dir: str, root: str) -> None:
    # read the .gitignore file
    with open(join(root, '.gitignore')) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                IGNORE.append(line)
    # format patterns into regex
    for pattern in IGNORE:
        REGEXES.append(format_to_regex(pattern))
    paths: list[str] = os.listdir(root)
    # logic for copying files
    for path in paths:
        scan_result = scan(path)
        if not scan_result:
            try:
                print(f"[INSTALLER] Copying {path}...")
                shutil.copytree(join(root, path), join(plugin_dir, path))
            except NotADirectoryError:  # copytree throws this error if the path is a file, so we catch it and copy the file instead
                shutil.copy2(join(root, path), join(plugin_dir, path))
            except Exception as e:
                print(f"[INSTALLER] Error occurred while copying {path}: {e}")
                sys.exit(1)
        else:
            print(f"[INSTALLER] Skipping {path}...")


if __name__ == "__main__":
    # check for cli args
    if len(sys.argv) < 3:
        print("Usage: python installer.py <plugins_dir> <project_root>")
        sys.exit(1)
    plugin_dir: str = sys.argv[1]  # path to ida plugins directory
    root: str = sys.argv[2]  # path to the root of the project
    main(plugin_dir, root)
