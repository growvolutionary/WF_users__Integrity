from pathlib import Path
import hashlib

E2EE_LIB = (Path(__file__).parent / "e2ee").resolve()
CHUNK_SIZE = 1024 * 1024


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)

    return hasher.hexdigest()


def main():
    hashes = E2EE_LIB / "hashes"
    hashes.mkdir(exist_ok=True)

    for file in E2EE_LIB.glob("*.js"):
        hash_file = hashes / f"{file.stem}.sha256"
        with open(hash_file, "w") as f:
            f.write(_sha256_file(file))


if __name__ == "__main__": main()
