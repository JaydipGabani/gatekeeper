import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


DESTINATION_PREFIX = "ghcr.io/jaydipgabani/copa-staging/pr-4756-20260915/"
METADATA_KEYS = (
    "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
    "GITHUB_REF", "IMAGE", "RELEASE", "MODE", "SOURCE_REF", "PRIMARY_REPO",
    "PATCHED_REF", "REV", "HAS_FIXES", "PUBLISH", "REPORT_DIR",
)


def execute(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode == 0:
        output = result.stdout.strip()
        try:
            output = json.loads(output)
        except json.JSONDecodeError:
            pass
        return {"state": "present", "exit_code": 0, "value": output}
    absent = re.search(r"MANIFEST_UNKNOWN|NAME_UNKNOWN|manifest unknown|name unknown|404", result.stderr, re.IGNORECASE)
    return {"state": "absent" if absent else "error", "exit_code": result.returncode}


def save_oci_metadata(layout, destination):
    destination.mkdir(parents=True, exist_ok=True)
    for filename in ("index.json", "oci-layout"):
        source = layout / filename
        if source.is_file():
            shutil.copyfile(source, destination / filename)
    pending = list(json.loads((layout / "index.json").read_text()).get("manifests", []))
    seen = set()
    while pending:
        descriptor = pending.pop()
        digest = descriptor.get("digest", "")
        if digest in seen:
            continue
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ValueError("Unexpected OCI metadata digest")
        seen.add(digest)
        relative = Path("blobs/sha256") / digest.split(":", 1)[1]
        document = json.loads((layout / relative).read_text())
        (destination / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(layout / relative, destination / relative)
        if "manifests" in document:
            pending.extend(document["manifests"])
        elif document.get("schemaVersion") == 2 and "config" in document:
            pending.append(document["config"])


def capture(phase):
    metadata = {key: os.environ.get(key, "") for key in METADATA_KEYS}
    image = metadata["IMAGE"]
    if image not in ("gatekeeper", "gator"):
        raise ValueError("Unexpected validation image")
    if metadata["GITHUB_REPOSITORY"] != "JaydipGabani/gatekeeper":
        raise ValueError("Validation harness is restricted to the fork")
    if metadata["MODE"] not in ("dry-run", "staging"):
        raise ValueError("Validation harness does not allow canonical mode")
    if metadata["PRIMARY_REPO"] != DESTINATION_PREFIX + image:
        raise ValueError("Unexpected validation destination")
    release = metadata["RELEASE"]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release):
        raise ValueError("Unexpected validation release")
    source = f"ghcr.io/open-policy-agent/{image}:{release}"
    if metadata["SOURCE_REF"] != source:
        raise ValueError("Unexpected upstream source")
    destination = metadata["PRIMARY_REPO"]
    commands = {
        "source_digest": ["crane", "digest", source],
        "source_index": ["crane", "manifest", source],
        "destination_tags": ["crane", "ls", destination],
        "floating_digest": ["crane", "digest", f"{destination}:{release}-patched"],
    }
    if phase == "after" and metadata["MODE"] == "staging" and metadata["PATCHED_REF"]:
        if metadata["PATCHED_REF"] != f"{destination}:{release}-{metadata['REV']}":
            raise ValueError("Unexpected candidate reference")
        commands.update({
            "candidate_digest": ["crane", "digest", metadata["PATCHED_REF"]],
            "candidate_index": ["crane", "manifest", metadata["PATCHED_REF"]],
        })
    evidence = Path("validation-evidence")
    evidence.mkdir(exist_ok=True)
    snapshot = {"phase": phase, "metadata": metadata,
                "registry": {name: execute(command) for name, command in commands.items()}}
    (evidence / f"registry-{phase}.json").write_text(json.dumps(snapshot, indent=2) + "\n")
    if phase == "before":
        versions = {name: execute(command) for name, command in {
            "trivy": ["trivy", "--version"], "copa": ["copa", "--version"],
            "crane": ["crane", "version"], "buildx": ["docker", "buildx", "version"],
        }.items()}
        (evidence / "tool-versions.json").write_text(json.dumps(versions, indent=2) + "\n")
    layout = Path("patched-oci")
    if phase == "after" and (layout / "index.json").is_file():
        save_oci_metadata(layout, evidence / "oci-metadata")
    print(json.dumps({"phase": phase, "image": image, "release": release, "mode": metadata["MODE"],
                      "run_id": metadata["GITHUB_RUN_ID"], "sha": metadata["GITHUB_SHA"],
                      "registry_states": {name: value["state"] for name, value in snapshot["registry"].items()}}, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Capture fork-only Copa validation evidence without publishing")
    subcommands = parser.add_subparsers(dest="command", required=True)
    capture_parser = subcommands.add_parser("capture")
    capture_parser.add_argument("phase", choices=("before", "after"))
    args = parser.parse_args()
    if args.command == "capture":
        capture(args.phase)


if __name__ == "__main__":
    main()
