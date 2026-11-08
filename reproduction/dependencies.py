import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = json.loads((ROOT / "reproduction/versions.json").read_text())


def checkout(path, repository, revision):
    if not path.exists():
        subprocess.run(["git", "clone", "--no-checkout", "--depth", "1", repository, str(path)],
                       check=True)
        subprocess.run(["git", "fetch", "--depth", "1", "origin", revision], cwd=path, check=True)
        subprocess.run(["git", "checkout", "--detach", revision], cwd=path, check=True)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain", "--", ".", ":!cedar"],
                                     cwd=path, text=True).strip()
    if actual != revision or status:
        raise ValueError(f"dependency must be clean at {revision}: {path}")


def prepare():
    spec = ROOT / "oopsla2024-benchmarks/cedar-spec"
    checkout(spec, "https://github.com/cedar-policy/cedar-spec", VERSIONS["spec_commit"])
    checkout(spec / "cedar", "https://github.com/cedar-policy/cedar", VERSIONS["cedar_commit"])


if __name__ == "__main__":
    prepare()
