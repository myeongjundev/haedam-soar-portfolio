"""Package only the selected PPT and public submission documents (stdlib only)."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import quote, unquote
import zipfile


DOCUMENTS = {
    "제출안내.md": "docs/submission-note.md",
    "발표-시연-예상질문.md": "docs/demo-guide.md",
    "이력서-자기소개서-기본문안.md": "docs/application-materials.md",
    "새클론-검증결과.md": "docs/installation-audit-20261111.md",
    "제출-상태와-남은확인.md": "docs/submission-readiness-20261111.md",
}


def standalone(root: Path, path: str, repo: str, ref: str) -> bytes:
    source = root / path

    def replace(match: re.Match[str]) -> str:
        dest = match.group(1)
        if "://" in dest or dest.startswith(("#", "mailto:")):
            return match.group(0)
        file_part, separator, anchor = dest.partition("#")
        target = (source.parent / unquote(file_part)).resolve()
        relative = target.relative_to(root).as_posix()
        if not target.exists():
            raise ValueError(f"Missing public document link: {path} -> {dest}")
        url = f"{repo}/blob/{quote(ref, safe='/')}/{quote(relative)}"
        return "](" + url + ("#" + anchor if separator else "") + ")"

    text = source.read_text(encoding="utf-8-sig")
    return re.sub(r"\]\(([^\s)]+)\)", replace, text).encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ppt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ref", default="main", help="GitHub link ref; does not merge or publish")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    ppt = args.ppt.resolve()
    ppt.relative_to(root / "output" / "portfolio")
    if ppt.suffix.lower() != ".pptx":
        parser.error("--ppt must select a PPTX in output/portfolio")
    output = args.output.resolve()
    output.relative_to(root / "output" / "submission")
    if output.suffix.lower() != ".zip":
        parser.error("--output must be a ZIP in output/submission")
    remote = subprocess.check_output(
        ["git", "remote", "get-url", "origin"], cwd=root, text=True
    ).strip()
    if remote.startswith("git@github.com:"):
        remote = "https://github.com/" + remote.removeprefix("git@github.com:")
    repo = remote.removesuffix(".git").rstrip("/")
    if not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+", repo):
        parser.error("origin must be a GitHub repository URL without embedded credentials")
    files = {ppt.name: ppt.read_bytes()}
    for name, source in DOCUMENTS.items():
        files[name] = standalone(root, source, repo, args.ref)
    manifest = [
        {"file": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        for name, data in files.items()
    ]
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            # Stable metadata keeps repeated builds of identical input byte-identical.
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None
        for record in manifest:
            data = archive.read(record["file"])
            assert hashlib.sha256(data).hexdigest() == record["sha256"]
            assert len(data) == record["bytes"]
    print(json.dumps({"files": len(files), "ppt_sha256": manifest[0]["sha256"],
                      "zip_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                      "output": str(output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
