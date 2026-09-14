"""MSVC build orchestration via vcvars64."""
import os
import shutil
import subprocess
import time

# override with the LLMVM_VCVARS env var if your VS2017 lives elsewhere
VCVARS = os.environ.get('LLMVM_VCVARS', r'D:\VS17\VC\Auxiliary\Build\vcvars64.bat')


def run_exe(path, args=(), timeout=60, tries=6):
    """Run a fresh exe, dodging AV scan-locks (retry + renamed copy)."""
    candidates = [path]
    alt = path + '.run'
    for attempt in range(tries):
        for c in candidates:
            try:
                return subprocess.run([os.path.abspath(c)] + list(args),
                                      capture_output=True, text=True,
                                      timeout=timeout, errors='replace')
            except PermissionError:
                pass
            except FileNotFoundError:
                break
        try:
            shutil.copy(path, alt)
            candidates = [alt]
        except OSError:
            pass
        time.sleep(1.5)
    raise RuntimeError(f'cannot launch {path} (AV lock?)')


def run(cmd, cwd=None, timeout=300):
    full = f'call "{VCVARS}" >nul 2>&1 && {cmd}'
    p = subprocess.run(full, cwd=cwd, timeout=timeout, shell=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, errors='replace')
    if p.returncode != 0:
        raise RuntimeError('build failed:\n' + p.stdout[-4000:])
    return p.stdout


def build_exe(exe, srcs, link_flags=(), cwd=None):
    srcs = ' '.join(srcs)
    lf = ' '.join(link_flags)
    return run(f'cl /nologo /O2 /W3 /MT {srcs} /Fe:"{exe}" /link {lf}', cwd=cwd)


def compile_native(exe, srcs, force_include=None, cwd=None):
    fi = f'/FI"{force_include}" ' if force_include else ''
    srcs = ' '.join(srcs)
    return run(f'cl /nologo /O2 /W3 /MT {fi}{srcs} /Fe:"{exe}" /link', cwd=cwd)
