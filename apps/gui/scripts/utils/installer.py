from pathlib import Path
import re
import os
import fnmatch
import sys
import shutil


IGNORE :list[str] = [".gitignore", "CONTRIBUTING.md",".git"]
REGEXES : list[re.Pattern[str]] = []
PLUGINS_DIR = sys.argv[1] # path to ida plugins directory
ROOT : str = sys.argv[2] # path to the root of the project


# Convert gitignore patterns to regex
def format_to_regex(pattern: str) -> re.Pattern[str]:
    clean = pattern.strip('/')
    regex = re.compile(fnmatch.translate(clean))
    return regex


# Scan the directory and decide if it should be copied or not based on the regexes
def scan(path : str) -> dict[str, bool]:
    result : dict[str, bool] = {}
    skip : bool = False
    for i in REGEXES:
        if i.match(path):
            skip = True
    result[path] = skip
    return result


if __name__ == '__main__':
    # check for cli args
    if len(sys.argv) < 3:
        print('Usage: python installer.py <plugins_dir> <project_root>')
        sys.exit(1)
    #take the .gitignore file and convert it to regexes
    with open(f'{ROOT}/.gitignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                IGNORE.append(line)
    # format patterns into regex
    for pattern in IGNORE:
        REGEXES.append(format_to_regex(pattern))
    paths : list[str] = os.listdir(ROOT)
    #logic for copying files
    for path in paths:
        scan_result = scan(path)
        if not scan_result[path]:
            print(f'[INSTALLER] Copying {path}...')
            try:
                shutil.copytree(f'{ROOT}\\{path}', f'{PLUGINS_DIR}\\{path}')
            except NotADirectoryError as e: #copytree throws this error if the path is a file, so we catch it and copy the file instead
                shutil.copy2(f'{ROOT}\\{path}', f'{PLUGINS_DIR}\\{path}')
        else:
            print(f'[INSTALLER] Skipping {path}...')
