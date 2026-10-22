"""Cross-repo check: KeyCheck's signer and the app's verifier agree.

The two implementations must sign identical bytes, or every key issued by
KeyCheck will be rejected by the customer's app. That failure is silent at
issue time and only appears on the customer's machine, so it is worth a
dedicated check that runs both real implementations against each other.

Why a script and not a pytest test
----------------------------------
KeyCheck's venv deliberately has no Django (the service does not need it), and
the app's venv has no FastAPI, so neither interpreter can import both sides.
This script runs under the *app's* interpreter and loads KeyCheck's `signing.py`
by path -- it is pure Python with no third-party imports, so that just works.
It is invoked by the test suite as a subprocess when the app checkout is present.

Usage (from the keycheck repo):
    python tools/check_roundtrip.py --app-path ../clinic-manager \
        --app-python ../clinic-manager/env/Scripts/python.exe

Exit code 0 = the two sides agree. Non-zero = do not ship keys.
"""

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROBE = r'''
import importlib.util, os, sys
app_path, kc_signing_path = sys.argv[1], sys.argv[2]
sys.path.insert(0, app_path)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "conf.settings")
import django
import django.conf
if not django.conf.settings.configured:
    django.conf.settings.configure(
        INSTALLED_APPS=[], LICENSE_PUBLIC_KEY="", LICENSE_ENFORCED=False,
        DATA_DIR=".")
    django.setup()
from core import licensing as app_lic

spec = importlib.util.spec_from_file_location("kc_signing", kc_signing_path)
kc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kc)

seed = bytes.fromhex("1f" * 32)
pub = app_lic.ed25519_public_key(seed)
M = "3ARN-47PE-L5RN-WPVU"
O = "ZZZZ-ZZZZ-ZZZZ-ZZZZ"

if kc.ed25519_public_key(seed) != pub:
    sys.exit("FAIL: the two implementations derive different public keys")

cases = [
    ("John's Eye Clinic", "0007", ""),
    ("John's Eye Clinic", "0007", M),
    ("Cafe \u2014 Eyecare", "S/42", M),
]
for clinic, serial, machine in cases:
    a = app_lic.make_key(seed, clinic, serial, machine)
    b = kc.make_key(seed, clinic, serial, machine,
                    issued=app_lic.parse_key(a)["issued"])
    if a != b:
        sys.exit(f"FAIL: key bytes differ for machine={machine!r}\n  app: {a}\n  kc : {b}")

# Both directions must verify, and both must reject the wrong machine.
k = kc.make_key(seed, "Cross Clinic", "1234", M)
if not app_lic.verify_key(k, pub.hex(), expected_machine=M):
    sys.exit("FAIL: a KeyCheck key did not verify in the app")
if app_lic.verify_key(k, pub.hex(), expected_machine=O) is not None:
    sys.exit("FAIL: the app accepted a KeyCheck key bound to another machine")

k2 = app_lic.make_key(seed, "Cross Clinic", "5678", M)
if not kc.verify_key(k2, pub, expected_machine=M):
    sys.exit("FAIL: an app key did not verify in KeyCheck")
if kc.verify_key(k2, pub, expected_machine=O) is not None:
    sys.exit("FAIL: KeyCheck accepted an app key bound to another machine")

print("OK: the two signers are byte-identical and cross-verify both ways")
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-path", required=True,
                        help="path to the clinic-manager checkout")
    parser.add_argument("--app-python", required=True,
                        help="python.exe from the clinic-manager venv")
    args = parser.parse_args()

    kc_signing = HERE.parent / "app" / "signing.py"
    if not kc_signing.exists():
        sys.exit(f"cannot find {kc_signing}")

    app_path = Path(args.app_path)
    if not (app_path / "core" / "licensing.py").exists():
        sys.exit(f"cannot find core/licensing.py under {app_path}")

    result = subprocess.run(
        [args.app_python, "-c", PROBE, str(app_path), str(kc_signing)],
        text=True, capture_output=True,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
