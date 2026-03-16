import glob
import shutil
import tempfile
import zipfile

with tempfile.TemporaryDirectory() as tmpdir:
    shutil.make_archive(f"{tmpdir}/plugin", "zip", "plugin")

    with zipfile.ZipFile("AETHER.zip", "w") as zipf:
        # Copy scripts and packages
        for item in glob.glob("**", root_dir="scripts", recursive=True):
            if item == "package.py":
                continue
            zipf.write(f"scripts/{item}", item)

        # Copy main plugin
        zipf.write(f"{tmpdir}/plugin.zip", "packages/plugin.zip")

        # Copy requirements
        zipf.write("requirements.txt")
