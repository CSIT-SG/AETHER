import sys
from os import path, remove, symlink
from os.path import islink, join

# Global for links to be created, src: dst
LINKS: dict[str, str] = {
    join("apps", "gui", "src", "plugin.py"): "aether-next-gui.py",
    join("packages", "rpc", "src", "entrypoint_gui.py"): "aether-next-rpc.py",
    join("apps", "gui", "src", "aether-next-config.json"): "aether-next-config.json",
}


def cleanup(dst: str) -> None:
    if islink(dst):
        print(f"Removing existing link: {dst}")
        remove(dst)
    return


def create_link(src: str, dst: str) -> None:
    if not path.exists(src):
        print(f"Invalid Source: {src}")
        return
    try:
        symlink(src, dst)
        print(f"Created Link {src} -> {dst}")
    except FileExistsError:
        print(f"Link already exists: {dst}")
    except Exception as e:
        print(f"Error creating symlink: {e}")
        sys.exit(1)


def main(root: str, dstDir: str) -> None:
    for i in LINKS:
        src: str = join(root, i)
        dst: str = join(dstDir, LINKS[i])
        cleanup(dst)
        create_link(src, dst)


if __name__ == "__main__":
    try:
        repoRoot: str = sys.argv[1]
        dst: str = sys.argv[2]
        main(repoRoot, dst)
    except Exception as e:
        print(f"usage: linker.py <source dir> <destination dir> \n{e}")
        sys.exit(1)
