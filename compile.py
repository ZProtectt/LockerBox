import os
import subprocess
import sys


ROOT = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(ROOT, "dist", "SecureVault.exe")
VENV_PYTHON = os.path.join(ROOT, ".venv", "Scripts", "python.exe")


def main():
    python = VENV_PYTHON if os.path.isfile(VENV_PYTHON) else sys.executable
    subprocess.check_call([
        python,
        "-m",
        "PyInstaller",
        "gui.py",
        "--onefile",
        "--windowed",
        "--name",
        "SecureVault",
        "--clean",
        "--noconsole",
        "--noupx",
    ], cwd=ROOT)

    if not os.path.isfile(EXE):
        raise FileNotFoundError(EXE)

    os.startfile(EXE)


if __name__ == "__main__":
    main()
