from __future__ import annotations
import argparse, importlib.util, os, pathlib, subprocess, sys
ROOT = pathlib.Path(__file__).resolve().parent

def main() -> int:
    parser = argparse.ArgumentParser(description='HE source-package verification; full verification requires pytest.')
    parser.add_argument('--release-only', action='store_true', help='Run release gate only; result is PARTIAL, never full PASS.')
    args = parser.parse_args()
    if not args.release_only and importlib.util.find_spec('pytest') is None:
        print('DEPENDENCY_MISSING=pytest\nTEST_SUITE=NOT_RUN\nPACKAGE_VERIFY=FAIL')
        print('Install the test dependency: python -m pip install -r requirements-test.txt')
        return 3
    env = os.environ.copy()
    env['PYTHONPATH'] = os.pathsep.join(filter(None, [str(ROOT/'src'), env.get('PYTHONPATH', '')]))
    env['PYTHONIOENCODING'] = 'utf-8'
    steps = [('release gate', [sys.executable, 'run_release.py'])]
    if not args.release_only:
        steps.append(('regression tests', [sys.executable, '-m', 'pytest', '-q']))
    for label, command in steps:
        result = subprocess.run(command, cwd=ROOT, env=env, text=True, encoding='utf-8', errors='replace', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(f'\n=== {label} ===\n{result.stdout.rstrip()}')
        if result.returncode:
            print(f'STEP_FAILED={label}\nEXIT_CODE={result.returncode}\nPACKAGE_VERIFY=FAIL')
            return result.returncode
    print('TEST_SUITE=SKIPPED\nPACKAGE_VERIFY=PARTIAL' if args.release_only else 'TEST_SUITE=PASS\nPACKAGE_VERIFY=PASS')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
