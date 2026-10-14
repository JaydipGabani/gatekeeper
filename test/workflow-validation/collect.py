import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


PREFIX = "ghcr.io/jaydipgabani/copa-staging/pr4756-20261014/"
FIELDS = ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REF",
          "IMAGE", "RELEASE", "MODE", "PRIMARY_REPO", "SOURCE_TAG", "SOURCE_PINNED",
          "CANDIDATE_TAG", "CANDIDATE_PINNED", "RC_TAG", "RC_PINNED", "REV", "HAS_FIXES",
          "PUBLISH", "BASELINE_DIGEST", "TRIVY_VERSION", "COPA_VERSION", "CRANE_VERSION")


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def query(*arguments):
    result = subprocess.run(["crane", *arguments], capture_output=True, text=True, timeout=120)
    if result.returncode:
        absent = re.search(r"^Error: (GET|HEAD) https?://\S+/manifests/\S+: (MANIFEST_UNKNOWN:|NAME_UNKNOWN:|unexpected status code 404(?: |$))", result.stderr, re.MULTILINE)
        return {"state": "absent" if absent else "error", "code": result.returncode}
    text = result.stdout.strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = text
    return {"state": "present", "value": value}


def collect_index(reference):
    index = query("manifest", reference)
    if index["state"] != "present":
        return index
    repository = reference.split("@", 1)[0].split(":", 1)[0]
    details = []
    for descriptor in index["value"].get("manifests", []):
        digest = descriptor["digest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Invalid manifest digest")
        manifest = query("manifest", repository + "@" + digest)
        record = {"descriptor": descriptor, "manifest": manifest}
        if descriptor.get("platform", {}).get("os") == "linux":
            config = query("config", repository + "@" + digest)
            if config["state"] == "present":
                raw = config["value"]
                config["value"] = {key: raw.get(key) for key in ("architecture", "os", "variant")}
                config["value"]["config"] = {key: raw.get("config", {}).get(key) for key in ("Entrypoint", "Cmd", "User", "WorkingDir")}
            record["config"] = config
        details.append(record)
    index["platforms"] = details
    return index


def collect_layout(layout, destination):
    destination.mkdir(parents=True, exist_ok=True)
    for filename in ("index.json", "oci-layout"):
        if (layout / filename).is_file():
            shutil.copyfile(layout / filename, destination / filename)
    pending = list(json.loads((layout / "index.json").read_text()).get("manifests", []))
    seen = set()
    while pending:
        descriptor = pending.pop()
        digest = descriptor["digest"]
        if digest in seen:
            continue
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Invalid OCI metadata digest")
        seen.add(digest)
        relative = Path("blobs/sha256") / digest.split(":", 1)[1]
        content = (layout / relative).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest.split(":", 1)[1]:
            raise ValueError("OCI metadata hash mismatch")
        (destination / relative).parent.mkdir(parents=True, exist_ok=True)
        (destination / relative).write_bytes(content)
        document = json.loads(content)
        if document.get("schemaVersion") == 2:
            pending.extend(document.get("manifests", []))
            if "config" in document:
                pending.append(document["config"])


def main(phase):
    metadata = {key: os.environ.get(key, "") for key in FIELDS}
    if metadata["GITHUB_REPOSITORY"] != "JaydipGabani/gatekeeper" or metadata["MODE"] not in ("dry-run", "staging"):
        raise ValueError("Only fork validation is allowed")
    if metadata["IMAGE"] not in ("gatekeeper", "gator") or metadata["PRIMARY_REPO"] != PREFIX + metadata["IMAGE"]:
        raise ValueError("Unexpected validation destination")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", metadata["RELEASE"]):
        raise ValueError("Unexpected release")
    source = "ghcr.io/open-policy-agent/" + metadata["IMAGE"] + ":" + metadata["RELEASE"]
    if metadata["SOURCE_TAG"] != source:
        raise ValueError("Unexpected source image")
    references = {"source": source}
    if metadata["MODE"] == "staging":
        references["floating"] = metadata["PRIMARY_REPO"] + ":" + metadata["RELEASE"] + "-patched"
        for name in ("CANDIDATE_TAG", "CANDIDATE_PINNED", "RC_TAG", "RC_PINNED"):
            reference = metadata[name]
            if reference:
                if not reference.startswith(metadata["PRIMARY_REPO"] + ":") and not reference.startswith(metadata["PRIMARY_REPO"] + "@sha256:"):
                    raise ValueError("Reference outside isolated fork repository")
                references[name.lower()] = reference
    snapshot = {"phase": phase, "metadata": metadata,
                "digests": {name: query("digest", reference) for name, reference in references.items()}}
    if phase == "after" and metadata["MODE"] == "staging":
        snapshot["indexes"] = {name: collect_index(reference) for name, reference in references.items() if name.endswith("pinned")}
    evidence = Path("validation-evidence")
    save(evidence / (phase + ".json"), snapshot)
    if phase == "after" and Path("patched-oci/index.json").is_file():
        collect_layout(Path("patched-oci"), evidence / "oci-metadata")
    print(json.dumps({"phase": phase, "image": metadata["IMAGE"], "mode": metadata["MODE"], "run": metadata["GITHUB_RUN_ID"], "publish": metadata["PUBLISH"]}))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("before", "after"):
        raise SystemExit("Expected before or after")
    main(sys.argv[1])
