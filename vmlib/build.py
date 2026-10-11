"""MSVC build orchestration: locate a toolchain, then drive cl via cmd."""
import glob
import os
import shutil
import subprocess
import time

# explicit override always wins; otherwise the toolchain is auto-located
ENV_VAR = 'LLMVM_VCVARS'
LEGACY_DEFAULT = r'D:\VS17\VC\Auxiliary\Build\vcvars64.bat'

_vcv = []          # resolved once, cached


def _vswhere_paths():
    """Latest VS2017+ installation (any edition incl. Build Tools) via vswhere."""
    exe = os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
                       r'Microsoft Visual Studio\Installer\vswhere.exe')
    if not os.path.isfile(exe):
        return []
    try:
        p = subprocess.run(
            [exe, '-latest', '-products', '*',
             '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
             '-property', 'installationPath'],
            capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return []
    lines = (p.stdout or '').strip().splitlines()
    if not lines or not lines[0]:
        return []
    return [os.path.join(lines[0], r'VC\Auxiliary\Build\vcvars64.bat')]


def _glob_paths():
    """Common install locations (VS2017+ layout, legacy VS2015 env var)."""
    pats = []
    for env in ('ProgramFiles', 'ProgramFiles(x86)'):
        root = os.environ.get(env)
        if root:
            pats.append(os.path.join(root, 'Microsoft Visual Studio', '*',
                                     '*', 'VC', 'Auxiliary', 'Build',
                                     'vcvars64.bat'))
    comn = os.environ.get('VS140COMNTOOLS')   # VS2015 layout
    if comn:
        pats.append(os.path.normpath(os.path.join(
            comn, '..', '..', 'VC', 'bin', 'amd64', 'vcvars64.bat')))
    out = []
    for pat in pats:
        out.extend(glob.glob(pat))
    return out


def find_vcvars():
    r"""Return the vcvars64.bat path, or None when cl is already usable.

    Order: LLMVM_VCVARS env var -> cl on PATH (VS developer prompt) ->
    vswhere -> common install globs -> the legacy D:\VS17 default.
    """
    env = os.environ.get(ENV_VAR)
    if env:
        if os.path.isfile(env):
            return env
        raise RuntimeError(f'{ENV_VAR}={env!r} does not exist')
    if shutil.which('cl'):
        return None            # already inside a VS developer prompt
    for cand in _vswhere_paths() + _glob_paths() + [LEGACY_DEFAULT]:
        if os.path.isfile(cand):
            return cand
    raise RuntimeError(
        'no MSVC toolchain found: install VS2017+ (or the standalone Build '
        'Tools) with the C++ desktop workload, or set '
        f'{ENV_VAR} to your vcvars64.bat')


def vcvars():
    if not _vcv:
        _vcv.append(find_vcvars())
    return _vcv[0]


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
    vc = vcvars()
    full = cmd if vc is None else f'call "{vc}" >nul 2>&1 && {cmd}'
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
