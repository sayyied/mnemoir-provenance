"""Install the packaged Hermes memory-provider payload into an explicit home."""
from __future__ import annotations

import errno
import os
import secrets
import stat
from importlib import resources
from pathlib import Path
from typing import Any

from .db import sha256_text


class PluginInstallError(ValueError):
    pass


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _open_absolute_directory(path: Path, *, create_final: bool = False) -> int:
    descriptor = os.open("/", _DIR_FLAGS)
    try:
        parts = path.parts[1:]
        for index, component in enumerate(parts):
            if component in {"", ".", ".."}:
                raise PluginInstallError("hermes_home_denied")
            final = index == len(parts) - 1
            if final and create_final:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            try:
                child = os.open(component, _DIR_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise PluginInstallError("hermes_home_denied") from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_or_create_child(parent_fd: int, name: str, denied: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        descriptor = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise PluginInstallError(denied) from exc
    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or not _same_object(metadata, os.fstat(descriptor)):
        os.close(descriptor)
        raise PluginInstallError(denied)
    return descriptor


def _assert_path_binding(path: Path, descriptor: int, error: str) -> None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise PluginInstallError(error) from exc
    if not stat.S_ISDIR(metadata.st_mode) or not _same_object(metadata, os.fstat(descriptor)):
        raise PluginInstallError(error)


def _write_atomic(directory_fd: int, target_name: str, data: bytes) -> None:
    temporary = f".{target_name}.tmp-{secrets.token_hex(16)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
    except OSError as exc:
        raise PluginInstallError("plugin_temp_create_denied") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "short plugin payload write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise PluginInstallError("plugin_payload_write_denied") from exc
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, target_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as exc:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise PluginInstallError("plugin_atomic_replace_denied") from exc


def install_hermes_plugin(hermes_home: str | Path) -> dict[str, Any]:
    home = Path(hermes_home).expanduser()
    if not home.is_absolute() or ".." in home.parts:
        raise PluginInstallError("hermes_home_must_be_absolute")
    home_fd = _open_absolute_directory(home, create_final=True)
    plugins_fd = target_fd = None
    try:
        _assert_path_binding(home, home_fd, "hermes_home_replaced")
        plugins_fd = _open_or_create_child(home_fd, "plugins", "plugin_parent_denied")
        _assert_path_binding(home, home_fd, "hermes_home_replaced")
        target_fd = _open_or_create_child(plugins_fd, "mnemoir_provenance", "plugin_target_denied")
        payload = resources.files("mnemoir_provenance.hermes_plugin")
        installed: list[dict[str, str]] = []
        for source_name, target_name in (("provider.py", "__init__.py"), ("plugin.yaml", "plugin.yaml")):
            data = payload.joinpath(source_name).read_bytes()
            _write_atomic(target_fd, target_name, data)
            _assert_path_binding(home, home_fd, "hermes_home_replaced")
            _assert_path_binding(home / "plugins", plugins_fd, "plugin_parent_replaced")
            _assert_path_binding(home / "plugins" / "mnemoir_provenance", target_fd, "plugin_target_replaced")
            installed.append({"name": target_name, "sha256": sha256_text(data.decode("utf-8"))})
        return {"status": "ok", "plugin": "mnemoir_provenance", "installed_files": installed, "discovery_path": "HERMES_HOME/plugins/mnemoir_provenance", "config_mutated": False}
    finally:
        if target_fd is not None:
            os.close(target_fd)
        if plugins_fd is not None:
            os.close(plugins_fd)
        os.close(home_fd)