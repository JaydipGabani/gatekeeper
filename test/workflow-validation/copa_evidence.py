import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


DESTINATION = "ghcr.io/jaydipgabani/copa-staging/pr-4756-20261013/"
METADATA_KEYS = (
    "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REF",
    "IMAGE", "RELEASE", "MODE", "SOURCE_REF", "PRIMARY_REPO", "PATCHED_REF",
    "VERIFIED_REF", "RC_REF", "RC_TAG", "REV", "HAS_FIXES", "PUBLISH", "REPORT_DIR",
)


def observe(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        absent = re.search(r"MANIFEST_UNKNOWN|NAME_UNKNOWN|unexpected status code 404", result.stderr)
        return {"state": "absent" if absent else "error", "exit_code": result.returncode}
    output = result.stdout.strip()
    try:
        output = json.loads(output)
    except json.JSONDecodeError:
        pass
    return {"state": "present", "exit_code": 0, "value": output}


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def capture_layout(layout, destination):
    destination.mkdir(parents=True, exist_ok=True)
    for filename in ("index.json", "oci-layout"):
        if (layout / filename).is_file():
            shutil.copyfile(layout / filename, destination / filename)
    pending = list(json.loads((layout / "index.json").read_text())["manifests"])
    seen = set()
    while pending:
        descriptor = pending.pop()
        digest = descriptor.get("digest", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Unexpected metadata digest")
        if digest in seen:
            continue
        seen.add(digest)
        relative = Path("blobs/sha256") / digest.split(":", 1)[1]
        content = (layout / relative).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest.split(":", 1)[1]:
            raise ValueError("Metadata digest mismatch")
        document = json.loads(content)
        (destination / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(layout / relative, destination / relative)
        if document.get("schemaVersion") == 2:
            pending.extend(document.get("manifests", []))
            if "config" in document:
                pending.append(document["config"])


def capture(phase):
    metadata = {name: os.environ.get(name, "") for name in METADATA_KEYS}
    image = metadata["IMAGE"]
    release = metadata["RELEASE"]
    if metadata["GITHUB_REPOSITORY"] != "JaydipGabani/gatekeeper" or image not in ("gatekeeper", "gator"):
        raise ValueError("Unexpected validation repository or image")
    if metadata["MODE"] not in ("dry-run", "staging") or not re.fullmatch(r"v\d+\.\d+\.\d+", release):
        raise ValueError("Unexpected mode or release")
    primary = DESTINATION + image
    if metadata["PRIMARY_REPO"] != primary:
        raise ValueError("Unexpected staging repository")
    source = f"ghcr.io/open-policy-agent/{image}:{release}"
    if metadata["SOURCE_REF"] != source:
        raise ValueError("Unexpected original source")
    commands = {
        "source_digest": ["crane", "digest", source],
        "source_index": ["crane", "manifest", source],
        "destination_tags": ["crane", "ls", primary],
        "floating_digest": ["crane", "digest", f"{primary}:{release}-patched"],
    }
    for name, reference in (("candidate", metadata["VERIFIED_REF"]), ("rc", metadata["RC_REF"])):
        if phase == "after" and metadata["MODE"] == "staging" and reference:
            if not re.fullmatch(re.escape(primary) + r"@sha256:[0-9a-f]{64}", reference):
                raise ValueError("Unexpected immutable validation reference")
            commands[f"{name}_index"] = ["crane", "manifest", reference]
            commands[f"{name}_digest"] = ["crane", "digest", reference]
    if phase == "after" and metadata["MODE"] == "staging" and metadata["REV"]:
        if not metadata["REV"].isdigit():
            raise ValueError("Unexpected revision")
        commands["revision_digest"] = ["crane", "digest", f"{primary}:{release}-{metadata['REV']}"]
    evidence = Path("validation-evidence")
    registry = {name: observe(command) for name, command in commands.items()}
    tags = registry["destination_tags"]
    if tags["state"] == "present" and isinstance(tags["value"], str):
        revisions = [tag for tag in tags["value"].splitlines() if re.fullmatch(re.escape(release) + r"-[0-9]+", tag)]
        registry["revision_digests"] = {tag: observe(["crane", "digest", primary + ":" + tag]) for tag in revisions}
    save_json(evidence / f"registry-{phase}.json", {"phase": phase, "metadata": metadata, "registry": registry})
    if phase == "before":
        save_json(evidence / "tool-versions.json", {name: observe(command) for name, command in {
            "trivy": ["trivy", "--version"], "copa": ["copa", "--version"],
            "crane": ["crane", "version"], "buildx": ["docker", "buildx", "version"],
        }.items()})
    if phase == "after" and Path("patched-oci/index.json").is_file():
        capture_layout(Path("patched-oci"), evidence / "oci-metadata")
    if phase == "after" and registry.get("rc_index", {}).get("state") == "present":
        descriptors = registry["rc_index"]["value"].get("manifests", [])
        for descriptor in descriptors:
            digest = descriptor.get("digest", "")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError("Unexpected RC descriptor")
            manifest = observe(["crane", "manifest", primary + "@" + digest])
            save_json(evidence / "rc-manifests" / (digest.split(":", 1)[1] + ".json"), manifest)
    print(json.dumps({"phase": phase, "image": image, "release": release, "mode": metadata["MODE"],
                      "sha": metadata["GITHUB_SHA"], "run_id": metadata["GITHUB_RUN_ID"],
                      "registry_states": {name: value.get("state", "collection") for name, value in registry.items()}}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture explicit non-secret evidence for fork-only Copa validation")
    parser.add_argument("phase", choices=("before", "after"))
    capture(parser.parse_args().phase)
