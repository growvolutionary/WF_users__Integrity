from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import argparse, ast, json, re, sys

ROOT = Path(__file__).resolve().parent
FROZEN = {}
PINS = Path("flutter_sdk") / "lib" / "src" / "trust" / "script_pins.dart"
PIN_NAME = re.compile(r"static const String (\w+) = '([a-z0-9_.:-]+)';")


def _generator():
    sys.dont_write_bytecode = True
    spec = spec_from_file_location("generate", ROOT / "generate.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generate = _generator()


def _constants(tree: ast.Module) -> dict:
    return {target.id: node.value.value for node in tree.body if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)}


def _key(node: ast.expr, constants: dict) -> str:
    if isinstance(node, ast.Constant): return node.value
    if isinstance(node, ast.Name) and node.id in constants: return constants[node.id]
    sys.exit(f"SCRIPTS key {ast.unparse(node)} is not a string constant")


def _version(path: Path) -> int:
    return int(generate.SCRIPT.match(path.stem).group(1))


def _text(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def _write(target: Path, data: bytes, changes: list):
    if target.is_file() and target.read_bytes() == data: return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    changes.append(target.relative_to(ROOT).as_posix())


def _script(artifact: str, source: Path, changes: list):
    folder = ROOT / source.stem
    versions = sorted((file for file in folder.glob("v*.js") if generate.SCRIPT.match(file.stem)), key=_version)
    data = _text(source)
    if not versions:
        return _write(folder / "v1.js", data, changes)
    latest = versions[-1]
    if latest.stem in FROZEN.get(artifact, ()) and latest.read_bytes().replace(b"\r\n", b"\n") != data:
        return _write(folder / f"v{_version(latest) + 1}.js", data, changes)
    _write(latest, data, changes)


def _vendor(additive: Path, changes: list):
    for folder, name, binary in generate.RELEASES.values():
        base = additive / "static" / "vendor" / folder
        for release in sorted(base.iterdir()) if base.is_dir() else []:
            source = release / name
            if release.is_dir() and generate.RELEASE.match(release.name) and source.is_file():
                _write(ROOT / folder / release.name / name, source.read_bytes() if binary else _text(source), changes)


def _pins(additive: Path, manifest: dict, changes: list):
    path = additive / PINS
    if not path.is_file(): return
    text = original = path.read_bytes().decode("utf-8")
    for name, artifact in PIN_NAME.findall(text):
        entry = manifest["artifacts"].get(artifact)
        if entry is None: sys.exit(f"{PINS.as_posix()} pins {artifact}, which this repository does not publish")
        body = "".join(f"    '{item['version']}': '{item['http']['sha256']}',\n" for item in entry["versions"])
        text, found = re.subn(rf"(static const Map<String, String> {name}Hashes = \{{\n)(.*?)(  \}};)",
                              lambda match: match.group(1) + body + match.group(3), text, flags=re.S)
        if found != 1: sys.exit(f"{PINS.as_posix()} has no map {name}Hashes for {artifact}")
    if text != original:
        path.write_bytes(text.encode("utf-8"))
        changes.append(path.as_posix())


def scripts(additive: Path) -> dict:
    tree = ast.parse((additive / "services" / "integrity.py").read_text(encoding="utf-8"))
    constants = _constants(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "SCRIPTS" for t in node.targets):
            return {_key(key, constants): ast.literal_eval(value)[0]
                    for key, value in zip(node.value.keys, node.value.values)}
    sys.exit("services/integrity.py defines no SCRIPTS")


def sync(additive: Path, pins: bool = True) -> list:
    changes = []
    listed = scripts(additive)
    for artifact, file in listed.items():
        source = additive / "static" / "js" / file
        if not source.is_file(): sys.exit(f"static/js/{file} of {artifact} does not exist")
        if generate.artifact_id(source.stem) != artifact:
            sys.exit(f"{artifact} must be named {generate.artifact_id(source.stem)} to match the folder {source.stem}/")
        _script(artifact, source, changes)
    _vendor(additive, changes)
    generate.main()
    manifest = json.loads(generate.MANIFEST.read_text(encoding="utf-8"))
    unlisted = sorted(set(generate.scripts()) - set(listed))
    if pins: _pins(additive, manifest, changes)
    return [*changes, *(f"warning: {artifact} is published here but no longer listed" for artifact in unlisted)]


def main():
    parser = argparse.ArgumentParser(description="Copy the served scripts into their latest version, regenerate "
                                                 "manifest.json and the SDK pins.")
    parser.add_argument("--additive", type=Path, default=ROOT.parent)
    parser.add_argument("--no-pins", action="store_true")
    options = parser.parse_args()
    for line in sync(options.additive.resolve(), not options.no_pins): print(line)
    print("manifest.json regenerated")


if __name__ == "__main__": main()
