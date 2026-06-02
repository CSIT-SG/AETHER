import sys
from os import symlink, remove
from os.path import join, islink


#Global for links to be created, src: dst
LINKS: dict[str, str] = {
    "plugin.py":"aether-next-gui.py",
    "gui_plugin.py":"aether-next-rpc.py",
    "aether-next-config.json":"aether-next-config.json"
}

def cleanup(dst: str) -> None:
    if islink(dst):
        print(f"Removing existing link: {dst}")
        remove(dst)
    return

def create_link(src: str, dst: str) -> None:
    try:
        symlink(src, dst)
        print(f'Created Link {src} -> {dst}')
    except FileExistsError:
        print(f"Link already exists: {dst}")
    except Exception as e:
        print(f"Error creating symlink: {e}")
        sys.exit(1)


def main(srcDir: str, dstDir: str) -> None:
    for i in LINKS:
        src: str = join(srcDir, i)
        dst: str = join(dstDir, LINKS[i])
        cleanup(dst)
        create_link(src, dst)



if __name__ == "__main__":
    try:
        src: str = sys.argv[1]
        dst: str = sys.argv[2]
        main(src, dst)
    except Exception as e:
        print(f'usage: linker.py <source dir> <destination dir> \n{e}')
        sys.exit(1)
