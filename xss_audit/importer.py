"""Download public GitHub snapshots with bounded, defensive ZIP extraction."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
import threading
import zipfile
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_DOWNLOAD = 60 * 1024 * 1024
MAX_EXTRACT = 250 * 1024 * 1024
MAX_MEMBERS = 15000
MAX_MEMBER = 20 * 1024 * 1024


def app_directory() -> Path:
    parent = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
    return parent / "XSSAudit"


def parse_repository(value: str) -> tuple[str, str]:
    value = value.strip()
    if not value.startswith("https://"):
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
            value = "https://github.com/" + value
        else:
            raise ValueError("请输入 https://github.com/作者/仓库 或 作者/仓库。")
    url = urlsplit(value)
    parts = url.path.strip("/").split("/")
    if url.hostname != "github.com" or url.netloc != "github.com" or url.query or url.fragment or len(parts) != 2:
        raise ValueError("仅支持 github.com 仓库首页；分支 / 标签请在 Ref 栏填写。")
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) and part not in {".", ".."} for part in (owner, repo)):
        raise ValueError("GitHub 仓库地址不合法。")
    return owner, repo


class GitHubRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.netloc not in {"api.github.com", "codeload.github.com", "github.com"}:
            raise ValueError("已拒绝 GitHub 以外的下载重定向。")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def extract_archive(archive: Path, target: Path, cancel=None):
    """Target must be a fresh empty directory owned by this import operation."""
    base = target.resolve(strict=True)
    if not base.is_dir() or any(base.iterdir()):
        raise ValueError("解压目录必须为空。")
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > MAX_MEMBERS or sum(m.file_size for m in members) > MAX_EXTRACT:
            raise ValueError("仓库压缩包超过文件数量 / 解压大小限制。")
        checked = []
        occupied = set()
        for member in members:
            name = member.orig_filename
            path = PurePosixPath(name)
            mode = member.external_attr >> 16
            # Block Windows drive paths, alternate data streams, devices, aliases,
            # traversal, links and special files before extracting any member.
            if (not name or "\\" in name or any(ord(char) < 32 for char in name) or path.is_absolute() or ".." in path.parts
                    or any(":" in part or part.endswith((".", " ")) or re.fullmatch(r"(?i)(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?", part) for part in path.parts)
                    or (stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR})
                    or member.flag_bits & 1 or member.file_size > MAX_MEMBER):
                raise ValueError("压缩包含不安全路径、特殊文件或超大文件。")
            destination = base.joinpath(*path.parts)
            if not destination.resolve().is_relative_to(base):
                raise ValueError("已拒绝范围外解压路径。")
            normalized = str(destination).casefold()
            if normalized in occupied:
                raise ValueError("压缩包含重复 / 大小写冲突路径。")
            occupied.add(normalized)
            checked.append((member, destination))
        total = 0
        for member, destination in checked:
            if cancel and cancel.is_set():
                raise ValueError("导入已取消。")
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            actual = 0
            with source.open(member) as incoming, destination.open("xb") as outgoing:
                while chunk := incoming.read(65536):
                    actual += len(chunk)
                    total += len(chunk)
                    if actual > MAX_MEMBER or total > MAX_EXTRACT:
                        raise ValueError("压缩包实际解压大小超过限制。")
                    outgoing.write(chunk)
                    if cancel and cancel.is_set():
                        raise ValueError("导入已取消。")
            if actual != member.file_size:
                raise ValueError("压缩包文件大小不一致。")
    children = list(base.iterdir())
    return children[0] if len(children) == 1 and children[0].is_dir() else base


def import_github(repository: str, ref: str = "", destination: str | Path | None = None,
                  cancel: threading.Event | None = None, progress=None, *, transport=None) -> tuple[Path, dict]:
    owner, repo = parse_repository(repository)
    ref = ref.strip()
    if len(ref) > 200 or any(ord(c) < 32 for c in ref):
        raise ValueError("Ref 长度或格式不合法。")
    parent = Path(destination) if destination else app_directory() / "imports"
    parent = parent.expanduser().resolve()
    parent.mkdir(parents=True, exist_ok=True)
    # Own this unique directory; cleanup never touches a user-selected existing tree.
    work = Path(tempfile.mkdtemp(prefix=repo[:60] + "-", dir=parent)).resolve()
    if not work.is_relative_to(parent) or work == parent:
        raise ValueError("导入目录校验失败。")
    archive = work / "snapshot.zip"
    target = work / "source"
    target.mkdir()
    url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    if ref:
        url += "/" + quote(ref, safe="")
    request = Request(url, headers={"User-Agent": "XSS-Audit-Desktop/0.2.0", "Accept": "application/vnd.github+json"})
    send = transport or build_opener(GitHubRedirects()).open
    digest = hashlib.sha256()
    try:
        if progress:
            progress("正在下载 GitHub 源码快照…")
        with send(request, timeout=60) as incoming, archive.open("xb") as output:
            size = 0
            while chunk := incoming.read(65536):
                if cancel and cancel.is_set():
                    raise ValueError("导入已取消。")
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise ValueError("下载超过 60 MiB 限制，请下载后选择较小的子目录。")
                output.write(chunk)
                digest.update(chunk)
        if progress:
            progress("正在检查压缩包并解压…")
        root = extract_archive(archive, target, cancel)
        archive.unlink()
        return root, {"repository": f"https://github.com/{owner}/{repo}", "requested_ref": ref or "默认分支",
                      "archive_sha256": digest.hexdigest(), "snapshot_directory": root.name,
                      "notice": "源码快照；不包括 Git 历史、子模块内容或 Git LFS 对象。未执行项目文件。"}
    except Exception as error:
        # work came from mkdtemp and was verified above; preserve the selected parent.
        if work.is_relative_to(parent) and work != parent:
            shutil.rmtree(work)
        if isinstance(error, HTTPError):
            raise ValueError(f"GitHub 下载失败（HTTP {error.code}）；核查仓库 / Ref 是否公开存在，或稍后重试限流。") from None
        if isinstance(error, (URLError, TimeoutError, OSError, zipfile.BadZipFile)):
            raise ValueError("GitHub 下载 / 解压失败；检查网络、磁盘空间与压缩包格式。") from None
        raise
