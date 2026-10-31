from pathlib import Path
import hashlib, json, re

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"
CHUNK_SIZE = 1024 * 1024
SCRIPT = re.compile(r"^v(\d+)$")
RELEASE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
ARTIFACTS = {
    "users_e2ee": ("e2ee", None, False),
    "users_session": ("session", None, False),
    "users_uploads": ("uploads", None, False),
    "users_vodozemac": ("vodozemac", "vodozemac_bg.js", False),
    "users_vodozemac_wasm": ("vodozemac", "vodozemac_bg.wasm", True)
}
NORMALIZATION = ("Hashes cover the content as stored in git: in text artifacts CRLF line endings count as LF, "
                 "binary artifacts (.wasm) are hashed byte for byte.")


def _sha256_file(path: Path, binary: bool) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    pending = b""

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            if binary:
                hasher.update(chunk)
                size += len(chunk)
                continue
            data = pending + chunk
            pending = b"\r" if data.endswith(b"\r") else b""
            data = (data[:-1] if pending else data).replace(b"\r\n", b"\n")
            hasher.update(data)
            size += len(data)

    hasher.update(pending)
    return hasher.hexdigest(), size + len(pending)


def _versions(directory: Path, name: str | None) -> list[tuple[str, Path]]:
    if name is None:
        files = [file for file in directory.glob("*.js") if SCRIPT.match(file.stem)]
        return [(file.stem, file) for file in sorted(files, key=lambda file: int(SCRIPT.match(file.stem).group(1)))]
    releases = [folder for folder in directory.iterdir() if folder.is_dir() and RELEASE.match(folder.name)]
    releases.sort(key=lambda folder: tuple(int(part) for part in RELEASE.match(folder.name).groups()))
    return [(folder.name, folder / name) for folder in releases if (folder / name).is_file()]


def _artifact(artifact: str, directory: Path, name: str | None, binary: bool) -> dict:
    hashes = directory / "hashes"
    hashes.mkdir(exist_ok=True)

    versions = []
    for version, file in _versions(directory, name):
        digest, size = _sha256_file(file, binary)
        label = version if name is None else f"{artifact}-{version}"
        with open(hashes / f"{label}.sha256", "w", encoding="ascii", newline="\n") as f:
            f.write(digest)
        versions.append({
            "version": version,
            "file": file.relative_to(ROOT).as_posix(),
            "sha256": digest,
            "size": size
        })

    return {
        "path": directory.relative_to(ROOT).as_posix(),
        "latest": versions[-1]["version"] if versions else None,
        "versions": versions
    }


def main():
    manifest = {
        "format": 2,
        "algorithm": "sha256",
        "normalization": NORMALIZATION,
        "artifacts": {
            artifact: _artifact(artifact, ROOT / directory, name, binary)
            for artifact, (directory, name, binary) in ARTIFACTS.items()
        }
    }
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__": main()
