"""Create a local venv, install locked dependencies and apply migrations."""
from pathlib import Path
import subprocess
import sys
import venv

root=Path(__file__).resolve().parents[1]
python=root/('.venv/Scripts/python.exe' if sys.platform=='win32' else '.venv/bin/python')
if not python.exists():
    venv.EnvBuilder(with_pip=True).create(root/'.venv')
for args in [['-m','pip','install','-r','requirements-dev.lock'],['-m','pip','install','--no-deps','-e','.'],['-m','flask','--app','haedam_portal:create_app','db','upgrade']]:
    subprocess.run([str(python),*args],cwd=root,check=True)
print('Backend ready. SQLite is for local use unless DATABASE_URL is configured.')
