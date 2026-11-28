from pathlib import Path
import base64, hashlib, json, pytest, shutil, subprocess, sys

ROOT = Path(__file__).resolve().parents[1]
ADDITIVE = ROOT.parent
KNOWN_DRIFT = {}


def manifest(root: Path = ROOT) -> dict:
    return json.loads((root / "manifest.json").read_text(encoding="utf-8"))


def generate(root: Path) -> bytes:
    subprocess.run([sys.executable, "-I", str(root / "generate.py")], check=True, cwd=root, capture_output=True)
    return (root / "manifest.json").read_bytes()


def copy(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git", "__pycache__", "hashes", "tests"))
    return target


def latest(data: dict, artifact: str) -> dict:
    entry = data["artifacts"][artifact]
    return next(item for item in entry["versions"] if item["version"] == entry["latest"])


def source_of(file: str) -> str:
    folder, _, rest = file.partition("/")
    return f"static/vendor/{file}" if "/" in rest else f"static/js/{folder}.js"


SERVED = {artifact: source_of(latest(manifest(), artifact)["file"]) for artifact in manifest()["artifacts"]}


def test_generator_reproduces_the_committed_manifest(tmp_path):
    target = copy(tmp_path)
    committed = (ROOT / "manifest.json").read_bytes().replace(b"\r\n", b"\n")
    assert generate(target) == committed
    assert generate(target) == committed


def test_every_version_separates_content_http_and_sri(tmp_path):
    data = manifest()
    assert data["format"] == 2 and data["normalization"] and data["http"]
    for artifact, entry in data["artifacts"].items():
        for item in entry["versions"]:
            raw = (ROOT / item["file"]).read_bytes()
            binary = item["file"].endswith(".wasm")
            served = raw if binary else raw.replace(b"\r\n", b"\n")
            assert item["http"]["sha256"] == hashlib.sha256(served).hexdigest(), artifact
            digest = hashlib.sha384(served).digest()
            assert item["http"]["sri"] == "sha384-" + base64.b64encode(digest).decode("ascii")
            assert item["http"]["size"] == len(served)


def test_a_crlf_copy_keeps_the_content_digest_but_fails_the_byte_digest(tmp_path):
    target = copy(tmp_path)
    data = manifest(target)
    artifact, item = next((name, latest(data, name)) for name in data["artifacts"]
                          if not latest(data, name)["file"].endswith(".wasm"))
    path = target / item["file"]
    lf = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(lf.replace(b"\n", b"\r\n"))
    regenerated = json.loads(generate(target).decode("utf-8"))
    fresh = latest(regenerated, artifact)
    assert fresh["sha256"] == item["sha256"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() != fresh["http"]["sha256"]


def test_one_changed_byte_changes_every_digest(tmp_path):
    target = copy(tmp_path)
    data = manifest(target)
    artifact = next(iter(data["artifacts"]))
    item = latest(data, artifact)
    path = target / item["file"]
    raw = bytearray(path.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    path.write_bytes(bytes(raw))
    fresh = latest(json.loads(generate(target).decode("utf-8")), artifact)
    assert fresh["sha256"] != item["sha256"] and fresh["http"]["sha256"] != item["http"]["sha256"]
    assert fresh["http"]["sri"] != item["http"]["sri"]


@pytest.mark.parametrize("artifact", sorted(SERVED))
def test_the_additive_serves_the_latest_reference(artifact):
    served = ADDITIVE / SERVED[artifact]
    if not served.is_file(): pytest.skip(f"{SERVED[artifact]} is not next to this repository")
    expected = latest(manifest(), artifact)["http"]["sha256"]
    actual = hashlib.sha256(served.read_bytes()).hexdigest()
    if artifact in KNOWN_DRIFT:
        assert actual != expected, f"{artifact} matches again; remove it from KNOWN_DRIFT"
        pytest.xfail(KNOWN_DRIFT[artifact])
    assert actual == expected


def fake_additive(tmp_path: Path, scripts: dict) -> Path:
    additive = tmp_path / "additive"
    (additive / "services").mkdir(parents=True)
    (additive / "static" / "js").mkdir(parents=True)
    names = "\n".join(f'{key.upper()} = "{key}"' for key in scripts)
    listed = ", ".join(f'{key.upper()}: ("{file}", "label")' for key, (file, _) in scripts.items())
    (additive / "services" / "integrity.py").write_text(f"{names}\n\n\nclass IntegrityService:\n"
                                                        f"    SCRIPTS = {{{listed}}}\n", encoding="utf-8")
    for file, content in scripts.values(): (additive / "static" / "js" / file).write_bytes(content)
    vendor = additive / "static" / "vendor" / "vodozemac" / "0.1.0"
    vendor.mkdir(parents=True)
    for name in ("vodozemac_bg.js", "vodozemac_bg.wasm"):
        shutil.copy(ROOT / "vodozemac" / "0.1.0" / name, vendor / name)
    pins = additive / "flutter_sdk" / "lib" / "src" / "trust"
    pins.mkdir(parents=True)
    (pins / "script_pins.dart").write_bytes(b"abstract final class ScriptPins {\n"
                                            b"  static const String e2ee = 'users_e2ee';\n\n"
                                            b"  static const Map<String, String> e2eeHashes = {\n"
                                            b"    'v1': 'old',\n  };\n}\n")
    return additive


def empty_repo(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    target.mkdir()
    for name in ("generate.py", "sync.py", ".gitattributes"): shutil.copy(ROOT / name, target / name)
    return target


def sync(target: Path, additive: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(target / "sync.py"), "--additive", str(additive), *extra],
                          cwd=target, capture_output=True, text=True)


def test_a_listed_script_enters_the_chain_with_pins_and_lf_bytes(tmp_path):
    additive = fake_additive(tmp_path, {"users_e2ee": ("e2ee.js", b"a\r\nb\n"),
                                        "users_new_thing": ("new-thing.js", b"x\n")})
    target = empty_repo(tmp_path)
    assert sync(target, additive).returncode == 0
    data = manifest(target)
    assert set(data["artifacts"]) == {"users_e2ee", "users_new_thing", "users_vodozemac", "users_vodozemac_wasm"}
    assert (target / "e2ee" / "v1.js").read_bytes() == b"a\nb\n"
    assert latest(data, "users_new_thing")["file"] == "new-thing/v1.js"
    pins = (additive / "flutter_sdk" / "lib" / "src" / "trust" / "script_pins.dart").read_text(encoding="utf-8")
    assert f"'v1': '{latest(data, 'users_e2ee')['http']['sha256']}'," in pins and "'old'" not in pins
    first = (target / "manifest.json").read_bytes()
    assert sync(target, additive).returncode == 0 and (target / "manifest.json").read_bytes() == first


def test_a_changed_script_rewrites_the_open_version_and_never_a_frozen_one(tmp_path):
    additive = fake_additive(tmp_path, {"users_e2ee": ("e2ee.js", b"one\n")})
    target = empty_repo(tmp_path)
    assert sync(target, additive, "--no-pins").returncode == 0
    (additive / "static" / "js" / "e2ee.js").write_bytes(b"two\n")
    assert sync(target, additive, "--no-pins").returncode == 0
    assert (target / "e2ee" / "v1.js").read_bytes() == b"two\n" and not (target / "e2ee" / "v2.js").exists()
    script = (target / "sync.py").read_bytes()
    (target / "sync.py").write_bytes(script.replace(b"FROZEN = {}", b'FROZEN = {"users_e2ee": {"v1"}}'))
    (additive / "static" / "js" / "e2ee.js").write_bytes(b"three\n")
    assert sync(target, additive, "--no-pins").returncode == 0
    assert (target / "e2ee" / "v1.js").read_bytes() == b"two\n"
    assert (target / "e2ee" / "v2.js").read_bytes() == b"three\n"
    assert manifest(target)["artifacts"]["users_e2ee"]["latest"] == "v2"


def test_a_script_whose_id_breaks_the_folder_convention_is_refused(tmp_path):
    additive = fake_additive(tmp_path, {"users_other": ("e2ee.js", b"x\n")})
    target = empty_repo(tmp_path)
    completed = sync(target, additive, "--no-pins")
    assert completed.returncode != 0 and "users_e2ee" in completed.stderr
    assert not (target / "manifest.json").exists()
