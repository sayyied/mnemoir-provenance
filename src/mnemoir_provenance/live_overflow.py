"""Safe, externally-authorized and recoverable Hermes Markdown writeback."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import tempfile
import time
from typing import Any, Callable

from .db import configure_connection, json_dumps, now_utc, sha256_text, stable_id
from .overflow_policy import DEFAULT_POLICY, OverflowPolicy, compute_markdown_pressure

# Retained only as a migration sentinel. It is deliberately never accepted.
LIVE_OVERFLOW_AUTHORIZATION = "RETIRED_SELF_AUTHORIZATION_NOT_ACCEPTED"
DEFAULT_PROFILE_IDS = ("default", "ada", "adila", "amara", "lakshmi", "makeda", "shifa", "designer")
MARKDOWN_FILES = ("MEMORY.md", "USER.md")
POLICY_VERSION = "mnemoir-live-overflow-v2"

class LiveOverflowError(Exception):
    """Fail-closed writeback error containing only safe error codes."""


def _with_sqlite_lock_retry(conn, operation, *, label, attempts=8, base_sleep_seconds=.25, busy_timeout_ms=None):
    """Compatibility utility used by older DB contention tests."""
    configure_connection(conn)
    if busy_timeout_ms is not None:
        conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    for attempt in range(attempts):
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            if not any(x in str(exc).lower() for x in ("locked", "busy")):
                raise
            conn.rollback()
            if attempt + 1 == attempts:
                raise LiveOverflowError(f"sqlite_lock_retry_exhausted:{label}")
            time.sleep(base_sleep_seconds * (2 ** attempt))

@dataclass(frozen=True)
class WritebackRequest:
    operation_id: str
    profile_id: str
    target_path: str
    allowed_root: str
    expected_before_hash: str
    authorization_id: str
    policy_version: str = POLICY_VERSION
    operation_type: str = "live_overflow_trim"
    proposal_id: str | None = None
    request_time: str | None = None

@dataclass(frozen=True)
class WritebackAuthorization:
    authorization_id: str
    operation_id: str
    profile_id: str
    target_path: str
    allowed_root: str
    expected_before_hash: str
    operation_type: str
    policy_version: str
    approving_actor: str
    issued_at: str
    expires_at: str
    nonce: str
    capability: str
    proposal_id: str | None = None

@dataclass(frozen=True)
class LiveProfileTarget:
    profile_id: str
    memory_root: Path

def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def _safe_profile_id(value: str) -> str:
    if not value or value in {".", ".."} or any(c in value for c in "/\\:\0"):
        raise LiveOverflowError("unauthorized_profile_id")
    return value

def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False

def profile_memory_root(profile_id: str, *, hermes_home: str | Path | None = None) -> Path:
    profile_id = _safe_profile_id(profile_id)
    home = Path(hermes_home or os.environ.get("HERMES_HOME") or Path.home()/".hermes").expanduser()
    if home.name == profile_id and home.parent.name == "profiles":
        return home/"memories"
    return home/"memories" if profile_id == "default" else home/"profiles"/profile_id/"memories"

def enumerate_live_profile_targets(profile_ids=DEFAULT_PROFILE_IDS, *, hermes_home=None):
    return [LiveProfileTarget(p, profile_memory_root(p, hermes_home=hermes_home)) for p in profile_ids]

def _canonical_target(target: str | Path, allowed_root: str | Path, *, must_exist=True) -> tuple[Path, Path]:
    raw, raw_root = Path(target).expanduser(), Path(allowed_root).expanduser()
    try:
        if stat.S_ISLNK(os.lstat(raw_root).st_mode):
            raise LiveOverflowError("symlink_root_denied")
    except FileNotFoundError as exc:
        raise LiveOverflowError("target_resolution_denied") from exc
    try:
        root = raw_root.resolve(strict=True)
        path = raw.resolve(strict=must_exist)
    except OSError as exc:
        raise LiveOverflowError("target_resolution_denied") from exc
    if not _is_under(path, root) or path.parent != root or path.name not in MARKDOWN_FILES:
        raise LiveOverflowError("target_scope_denied")
    if any(part.lower() in {"backup", "backups", ".backup"} for part in root.parts):
        raise LiveOverflowError("backup_root_denied")
    try:
        target_stat = os.lstat(raw)
        if stat.S_ISLNK(target_stat.st_mode):
            raise LiveOverflowError("symlink_target_denied")
        if not stat.S_ISREG(target_stat.st_mode):
            raise LiveOverflowError("non_regular_target_denied")
    except FileNotFoundError:
        if must_exist:
            raise LiveOverflowError("target_resolution_denied")
    return path, root


def _read_regular_nofollow(path: Path) -> tuple[str, tuple[int, int, int, int, int]]:
    """Read one regular target without following a final-component symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LiveOverflowError("target_open_denied") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise LiveOverflowError("non_regular_target_denied")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            text = handle.read()
        identity = (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))
        return text, identity
    finally:
        if fd >= 0:
            os.close(fd)


def _split_blocks(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"\n?§\n?|\n\s*\n", text) if p.strip()]

def _join_blocks(blocks: list[str]) -> str:
    return ("\n§\n".join(x.strip() for x in blocks)+"\n") if blocks else ""

def _protected(block: str) -> bool:
    return any(x in block.lower() for x in ("api key", "api_key", "token", "password", "secret", "credential"))

def _trim_blocks(text: str, *, file_name: str, policy: OverflowPolicy=DEFAULT_POLICY):
    pressure = compute_markdown_pressure(file_name=file_name, text=text, profile_id="live", policy=policy)
    if not pressure["trigger_state"]:
        return text, [], {"reason":"below_trigger", "pressure":pressure}
    kept, removed = _split_blocks(text), []
    i = 0
    while len(_join_blocks(kept)) > int(pressure["trim_target_chars"]) and len(kept)>1 and i<len(kept):
        if _protected(kept[i]): i += 1
        else: removed.append(kept.pop(i))
    after = _join_blocks(kept)
    target_reached = len(after) <= int(pressure["trim_target_chars"])
    return after, removed, {
        "reason": "trimmed" if removed and target_reached else "target_unreachable",
        "pressure": pressure,
        "target_reached": target_reached,
    }

def _validate_backup_root(backup_root: str | Path, target: Path, allowed_root: Path) -> Path:
    raw = Path(backup_root).expanduser()
    if raw.exists():
        st = os.lstat(raw)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise LiveOverflowError("backup_root_denied")
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise LiveOverflowError("backup_root_permissions_denied")
    base = raw.resolve(strict=False)
    if _is_under(base, allowed_root) or _is_under(allowed_root, base) or base == target:
        raise LiveOverflowError("backup_root_overlap_denied")
    return base


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)

def _private_write(path: Path, data: str) -> None:
    _private_dir(path.parent)
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
    except Exception:
        path.unlink(missing_ok=True); raise
    os.chmod(path, 0o600)

@dataclass
class _PreparedPrivateRoot:
    fd: int
    missing: tuple[str, ...]
    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd); self.fd = -1

def _prepare_private_root(path: Path) -> _PreparedPrivateRoot:
    absolute = path if path.is_absolute() else path.absolute()
    parts = absolute.parts[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os,"O_NOFOLLOW",0)
    fd = os.open("/", flags)
    try:
        for index, part in enumerate(parts):
            try: next_fd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError: return _PreparedPrivateRoot(fd, tuple(parts[index:]))
            os.close(fd); fd = next_fd
        meta=os.fstat(fd)
        if meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:
            raise LiveOverflowError("backup_root_permissions_denied")
        return _PreparedPrivateRoot(fd, ())
    except Exception:
        os.close(fd); raise

def _materialize_private_root(prepared: _PreparedPrivateRoot) -> int:
    fd=prepared.fd; prepared.fd=-1
    flags=os.O_RDONLY|os.O_DIRECTORY|getattr(os,"O_NOFOLLOW",0)
    try:
        for part in prepared.missing:
            try: os.mkdir(part,0o700,dir_fd=fd)
            except FileExistsError: pass
            next_fd=os.open(part,flags,dir_fd=fd); meta=os.fstat(next_fd)
            if meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:
                os.close(next_fd); raise LiveOverflowError("backup_root_permissions_denied")
            os.close(fd); fd=next_fd
        return fd
    except Exception:
        os.close(fd); raise

def _open_private_child(parent_fd:int,name:str,*,create:bool)->int:
    flags=os.O_RDONLY|os.O_DIRECTORY|getattr(os,"O_NOFOLLOW",0)
    if create:
        try: os.mkdir(name,0o700,dir_fd=parent_fd)
        except FileExistsError: pass
    fd=os.open(name,flags,dir_fd=parent_fd); meta=os.fstat(fd)
    if meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:
        os.close(fd); raise LiveOverflowError("private_directory_permissions_denied")
    return fd

def _private_write_at(parent_fd:int,name:str,data:str)->None:
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(name,flags,0o600,dir_fd=parent_fd)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf-8",closefd=False) as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
    finally: os.close(fd)

def _read_private_at(parent_fd:int,name:str)->tuple[str,tuple[int,int]]:
    fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=parent_fd)
    try:
        meta=os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid()
            or stat.S_IMODE(meta.st_mode)!=0o600 or meta.st_nlink!=1):
            raise LiveOverflowError("private_artifact_invalid")
        chunks=[]
        while True:
            chunk=os.read(fd,65536)
            if not chunk: break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8"),(meta.st_dev,meta.st_ino)
    finally: os.close(fd)

def _open_existing_directory(path:Path)->int:
    absolute=path if path.is_absolute() else path.absolute(); flags=os.O_RDONLY|os.O_DIRECTORY|getattr(os,"O_NOFOLLOW",0)
    fd=os.open("/",flags)
    try:
        for part in absolute.parts[1:]:
            next_fd=os.open(part,flags,dir_fd=fd); os.close(fd); fd=next_fd
        return fd
    except Exception:
        os.close(fd); raise

def _read_regular_at(parent_fd:int,name:str)->tuple[str,tuple[int,int]]:
    fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=parent_fd)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode): raise LiveOverflowError("non_regular_target_denied")
        chunks=[]
        while True:
            chunk=os.read(fd,65536)
            if not chunk: break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8"),(meta.st_dev,meta.st_ino)
    finally: os.close(fd)

def _create_target_temp_at(parent_fd:int,prefix:str)->tuple[int,str]:
    for _ in range(128):
        name=prefix+secrets.token_hex(12)
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=parent_fd)
            return fd,name
        except FileExistsError: continue
    raise LiveOverflowError("target_temp_creation_failed")

def create_writeback_authorization(conn: sqlite3.Connection, *, operation_id: str, profile_id: str,
    target_path: str|Path, allowed_root: str|Path, expected_before_hash: str, approving_actor: str,
    expires_at: str|None=None, operation_type="live_overflow_trim", policy_version=POLICY_VERSION,
    proposal_id: str|None=None, authorization_id: str|None=None, nonce: str|None=None) -> WritebackAuthorization:
    """External authority entry point. Executors never call this function."""
    configure_connection(conn)
    path, root = _canonical_target(target_path, allowed_root)
    if len(expected_before_hash)!=64 or operation_type not in {"live_overflow_trim","rollback"} or not approving_actor:
        raise LiveOverflowError("malformed_authorization")
    issued = datetime.now(timezone.utc); expiry = _parse_time(expires_at) if expires_at else issued+timedelta(minutes=10)
    nonce, capability = nonce or secrets.token_urlsafe(24), secrets.token_urlsafe(32)
    auth_id = authorization_id or stable_id("wbauth", operation_id, nonce)
    auth = WritebackAuthorization(auth_id, operation_id, _safe_profile_id(profile_id), str(path), str(root), expected_before_hash,
        operation_type, policy_version, approving_actor, issued.isoformat().replace("+00:00","Z"), expiry.isoformat().replace("+00:00","Z"), nonce, capability, proposal_id)
    conn.execute("INSERT INTO writeback_authorizations(authorization_id,operation_id,nonce_hash,capability_hash,profile_id,target_path_hash,allowed_root_hash,expected_before_hash,operation_type,policy_version,approving_actor,proposal_id,issued_at,expires_at,consumed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?)", (
        auth.authorization_id, auth.operation_id, _hash(auth.nonce), _hash(auth.capability), auth.profile_id,
        _hash(auth.target_path), _hash(auth.allowed_root), auth.expected_before_hash, auth.operation_type,
        auth.policy_version, auth.approving_actor, auth.proposal_id, auth.issued_at, auth.expires_at, now_utc()))
    conn.commit()
    return auth

def request_from_authorization(auth: WritebackAuthorization) -> WritebackRequest:
    return WritebackRequest(auth.operation_id, auth.profile_id, auth.target_path, auth.allowed_root,
        auth.expected_before_hash, auth.authorization_id, auth.policy_version, auth.operation_type, auth.proposal_id, now_utc())

def _validate_and_consume(conn, req, auth, preconsume: Callable[[Path,Path],None] | None = None) -> tuple[Path,Path]:
    # Authenticate the external capability in SQLite before probing caller paths.
    basic = (req.operation_id==auth.operation_id, req.authorization_id==auth.authorization_id,
      req.profile_id==auth.profile_id, req.expected_before_hash==auth.expected_before_hash,
      req.policy_version==auth.policy_version, req.operation_type==auth.operation_type,
      req.proposal_id==auth.proposal_id)
    if not all(basic): raise LiveOverflowError("authorization_binding_mismatch")
    if auth.policy_version != POLICY_VERSION or auth.operation_type not in {"live_overflow_trim", "rollback"}:
        raise LiveOverflowError("authorization_policy_denied")
    now = datetime.now(timezone.utc)
    issued, expires = _parse_time(auth.issued_at), _parse_time(auth.expires_at)
    if issued.tzinfo is None or expires.tzinfo is None or issued > now or expires <= now or expires <= issued:
        raise LiveOverflowError("authorization_expired")
    conn.execute("BEGIN IMMEDIATE")
    row=conn.execute("SELECT * FROM writeback_authorizations WHERE authorization_id=?",(auth.authorization_id,)).fetchone()
    if row is None: conn.rollback(); raise LiveOverflowError("authorization_not_found")
    if row["consumed_at"] is not None: conn.rollback(); raise LiveOverflowError("authorization_replay_rejected")
    checks = {"operation_id":auth.operation_id,"nonce_hash":_hash(auth.nonce),"capability_hash":_hash(auth.capability),
      "profile_id":auth.profile_id,"target_path_hash":_hash(auth.target_path),"allowed_root_hash":_hash(auth.allowed_root),
      "expected_before_hash":auth.expected_before_hash,"operation_type":auth.operation_type,"policy_version":auth.policy_version,
      "approving_actor":auth.approving_actor,"proposal_id":auth.proposal_id}
    if any(row[k]!=v for k,v in checks.items()): conn.rollback(); raise LiveOverflowError("authorization_invalid")
    try:
        path, root = _canonical_target(req.target_path, req.allowed_root)
    except Exception:
        conn.rollback(); raise
    if str(path)!=auth.target_path or str(root)!=auth.allowed_root:
        conn.rollback(); raise LiveOverflowError("authorization_binding_mismatch")
    try:
        if preconsume is not None:
            preconsume(path, root)
    except Exception:
        conn.rollback(); raise
    when=now_utc()
    updated=conn.execute("UPDATE writeback_authorizations SET consumed_at=? WHERE authorization_id=? AND consumed_at IS NULL",(when,auth.authorization_id)).rowcount
    if updated!=1: conn.rollback(); raise LiveOverflowError("authorization_replay_rejected")
    conn.execute("INSERT INTO writeback_operations(operation_id,authorization_id,profile_id,target_path_hash,allowed_root_hash,expected_before_hash,policy_version,operation_type,proposal_id,state,created_at,updated_at,evidence_state,audit_state,rollback_available) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
      (req.operation_id,auth.authorization_id,auth.profile_id,_hash(auth.target_path),_hash(auth.allowed_root),auth.expected_before_hash,auth.policy_version,auth.operation_type,auth.proposal_id,"authorized",when,when,"none","pending"))
    conn.commit(); return path,root

def _authenticate_recovery_authorization(conn,auth:WritebackAuthorization)->None:
    row=conn.execute("SELECT * FROM writeback_authorizations WHERE authorization_id=?",(auth.authorization_id,)).fetchone()
    if not row or row["consumed_at"] is None: raise LiveOverflowError("recovery_authorization_invalid")
    checks={"operation_id":auth.operation_id,"profile_id":auth.profile_id,"target_path_hash":_hash(auth.target_path),
      "allowed_root_hash":_hash(auth.allowed_root),"expected_before_hash":auth.expected_before_hash,
      "operation_type":auth.operation_type,"policy_version":auth.policy_version,"approving_actor":auth.approving_actor,
      "proposal_id":auth.proposal_id,"issued_at":auth.issued_at,"expires_at":auth.expires_at}
    if any(row[k]!=v for k,v in checks.items()): raise LiveOverflowError("recovery_authorization_invalid")
    if not hmac.compare_digest(row["nonce_hash"],_hash(auth.nonce)) or not hmac.compare_digest(row["capability_hash"],_hash(auth.capability)):
        raise LiveOverflowError("recovery_authorization_invalid")

def _state(conn, op, state, **values):
    allowed={"expected_after_hash","error_code","backup_ref","spool_ref","evidence_state","audit_state","rollback_available","completed_at"}
    values={k:v for k,v in values.items() if k in allowed}; values.update(state=state,updated_at=now_utc())
    conn.execute("UPDATE writeback_operations SET "+",".join(f"{k}=?" for k in values)+" WHERE operation_id=?",(*values.values(),op)); conn.commit()

def _spool_payload(auth, before_hash, after_hash, removed, *, target_reached: bool, plan_reason: str):
    base={"schema":"cmc_writeback_spool_v2","authorization_id":auth.authorization_id,"operation_id":auth.operation_id,
      "profile_id":auth.profile_id,"target_path_hash":_hash(auth.target_path),"allowed_root_hash":_hash(auth.allowed_root),
      "before_hash":before_hash,"after_hash":after_hash,"policy_version":auth.policy_version,
      "removed_blocks":removed,"target_reached":bool(target_reached),"plan_reason":plan_reason,"expires_at":auth.expires_at}
    base["mac"]=hmac.new(auth.capability.encode(),json_dumps(base).encode(),hashlib.sha256).hexdigest(); return base

def _verify_spool(payload, auth):
    mac=payload.pop("mac",None); expected=hmac.new(auth.capability.encode(),json_dumps(payload).encode(),hashlib.sha256).hexdigest(); payload["mac"]=mac
    if not hmac.compare_digest(str(mac),expected): raise LiveOverflowError("spool_authentication_failed")
    if payload.get("authorization_id")!=auth.authorization_id or payload.get("operation_id")!=auth.operation_id or payload.get("profile_id")!=auth.profile_id:
        raise LiveOverflowError("spool_binding_mismatch")
    expected = {
        "target_path_hash": _hash(auth.target_path),
        "allowed_root_hash": _hash(auth.allowed_root),
        "before_hash": auth.expected_before_hash,
        "policy_version": auth.policy_version,
        "expires_at": auth.expires_at,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise LiveOverflowError("spool_binding_mismatch")

def _record_removed_blocks(conn, *, operation_id,profile_id,file_name,removed_blocks,before_hash,after_hash):
    timestamp=now_utc(); source_id=f"live_overflow_trim:{profile_id}:{file_name}"; ref=f"hermes-profile://{profile_id}/{file_name}"
    conn.execute("INSERT OR IGNORE INTO sources(source_id,source_type,display_name,external_ref,profile_id,overflow_kind,read_authority,write_authority,authority_level,health,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
      (source_id,"hermes_markdown_overflow",f"Overflow {profile_id} {file_name}",ref,profile_id,"memory_md" if file_name=="MEMORY.md" else "user_md","read_only","write_allowed","primary","healthy",timestamp,timestamp))
    row=conn.execute("SELECT source_id FROM sources WHERE source_type='hermes_markdown_overflow' AND external_ref=?",(ref,)).fetchone(); source_id=row[0]
    ids=[]
    for i,block in enumerate(removed_blocks,1):
      bh=sha256_text(block); eid=stable_id("live_overflow_removed",source_id,bh,str(i),before_hash); evid=stable_id("evidence",eid,bh); pointer=f"hermes-profile://{profile_id}/{file_name}#removed-block-{i}"
      conn.execute("INSERT OR IGNORE INTO raw_events(event_id,source_id,event_type,content,content_hash,occurred_at,ingested_at,visibility,privacy_class,source_pointer,provenance_json,write_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(eid,source_id,"memory_block",block,bh,timestamp,timestamp,"private","private",pointer,json_dumps({"operation":"compat17a","operation_id":operation_id,"before_hash":before_hash,"after_hash":after_hash}),"committed"))
      conn.execute("INSERT OR IGNORE INTO evidence_items(evidence_id,kind,source_id,raw_event_id,uri,locator_json,quote_text,content_hash,trust_score,privacy_class,observed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(evid,"receipt",source_id,eid,pointer,json_dumps({"profile_id":profile_id,"file":file_name,"index":i}),block,bh,1.0,"private",timestamp,timestamp)); ids.append(evid)
    return ids

def execute_writeback(conn: sqlite3.Connection, request: WritebackRequest, authorization: WritebackAuthorization, *,
    backup_root: str|Path, policy: OverflowPolicy=DEFAULT_POLICY, fault: Callable[[str],None]|None=None,
    before_replace: Callable[[],None]|None=None) -> dict[str,Any]:
    configure_connection(conn); fault=fault or (lambda _:None)
    fault("authorization_lookup")
    validated: dict[str,Any] = {}
    def validate_artifacts(path: Path, root: Path) -> None:
        validated["target_fd"]=_open_existing_directory(path.parent)
        try:
            base=_validate_backup_root(backup_root,path,root)
            validated["prepared"]=_prepare_private_root(base)
        except Exception:
            os.close(validated.pop("target_fd")); raise
    try: path,root=_validate_and_consume(conn,request,authorization,preconsume=validate_artifacts)
    except Exception:
        prepared=validated.get("prepared")
        if prepared: prepared.close()
        if "target_fd" in validated: os.close(validated["target_fd"])
        raise
    op=request.operation_id; root_fd=-1; op_fd=-1; target_fd=validated["target_fd"]
    parent_meta=os.fstat(target_fd)
    conn.execute("UPDATE writeback_operations SET target_parent_dev=?,target_parent_ino=?,updated_at=? WHERE operation_id=?",(parent_meta.st_dev,parent_meta.st_ino,now_utc(),op)); conn.commit()
    try:
      fault("artifact_root_materialize"); root_fd=_materialize_private_root(validated["prepared"])
      fault("lock_acquisition")
      lock_name="target-"+_hash(str(path))+".lock"
      fd=os.open(lock_name,os.O_RDWR|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=root_fd); os.fchmod(fd,0o600)
      with os.fdopen(fd,"r+") as lock:
       fcntl.flock(lock,fcntl.LOCK_EX); _state(conn,op,"locked")
       before, identity = _read_regular_at(target_fd,path.name); before_hash=sha256_text(before)
       if before_hash!=request.expected_before_hash: _state(conn,op,"concurrent_edit_detected",error_code="expected_hash_mismatch"); return _result(conn,op,False)
       after,removed,plan=_trim_blocks(before,file_name=path.name,policy=policy)
       if after==before:
        blocked = plan.get("reason") == "target_unreachable"
        _state(conn,op,"blocked_target_unreachable" if blocked else "completed",expected_after_hash=before_hash,
               error_code="target_unreachable" if blocked else None,evidence_state="none",audit_state="committed",completed_at=now_utc())
        return {**_result(conn,op,False),"target_reached":not blocked,"plan_reason":plan.get("reason")}
       st=os.stat(path.name,dir_fd=target_fd,follow_symlinks=False); op_fd=_open_private_child(root_fd,op,create=True)
       recovery_auth_name="recovery-authorization.json"
       _private_write_at(op_fd,recovery_auth_name,json.dumps(asdict(authorization),sort_keys=True))
       backup_name=path.name+"."+before_hash[:12]+".bak"
       fault("backup_creation"); _private_write_at(op_fd,backup_name,before); fault("backup_fsync"); _state(conn,op,"backup_durable",backup_ref=f"writeback-backup://{op}/{backup_name}",rollback_available=1)
       payload=_spool_payload(authorization,before_hash,sha256_text(after),removed,
            target_reached=bool(plan.get("target_reached")),plan_reason=str(plan.get("reason")))
       spool_name=path.name+".pending.json"
       fault("pending_evidence"); _private_write_at(op_fd,spool_name,json.dumps(payload,sort_keys=True)); _state(conn,op,"evidence_pending",spool_ref=f"writeback-spool://{op}/{spool_name}",evidence_state="pending"); fault("pending_evidence_commit")
       fd,temp_name=_create_target_temp_at(target_fd,".mnemoir-"); os.fchmod(fd,0o600)
       try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
          f.write(after); f.flush(); fault("temp_write"); os.fsync(f.fileno()); fault("temp_fsync")
        os.chmod(temp_name,stat.S_IMODE(st.st_mode),dir_fd=target_fd,follow_symlinks=False)
        try: os.chown(temp_name,st.st_uid,st.st_gid,dir_fd=target_fd,follow_symlinks=False)
        except PermissionError: pass
        fault("final_hash_recheck"); before_replace and before_replace()
        current, current_identity = _read_regular_at(target_fd,path.name)
        if current_identity != identity or sha256_text(current)!=before_hash:
          _state(conn,op,"concurrent_edit_detected",error_code="immediate_cas_mismatch"); return _result(conn,op,False)
        fault("replace"); os.replace(temp_name,path.name,src_dir_fd=target_fd,dst_dir_fd=target_fd); _state(conn,op,"file_replaced",expected_after_hash=sha256_text(after))
        os.fsync(target_fd); fault("directory_fsync"); fault("readback")
        readback,_=_read_regular_at(target_fd,path.name)
        if sha256_text(readback)!=sha256_text(after): raise LiveOverflowError("readback_mismatch")
        _state(conn,op,"readback_verified")
        spool_text,_=_read_private_at(op_fd,spool_name); loaded=json.loads(spool_text); _verify_spool(loaded,authorization); fault("evidence_finalize")
        conn.execute("BEGIN IMMEDIATE"); ids=_record_removed_blocks(conn,operation_id=op,profile_id=request.profile_id,file_name=path.name,removed_blocks=loaded["removed_blocks"],before_hash=before_hash,after_hash=sha256_text(after)); conn.commit()
        os.rename(spool_name,spool_name.replace(".json",".committed.json"),src_dir_fd=op_fd,dst_dir_fd=op_fd); fault("audit_finalize")
        target_reached=bool(plan.get("target_reached")); final_state="completed" if target_reached else "completed_partial"
        _state(conn,op,final_state,error_code=None if target_reached else "target_unreachable",evidence_state="committed",audit_state="committed",completed_at=now_utc())
        try: os.unlink(recovery_auth_name,dir_fd=op_fd)
        except FileNotFoundError: pass
        return {**_result(conn,op,True),"removed_block_count":len(ids),"before_chars":len(before),"after_chars":len(after),
                "target_reached":target_reached,"plan_reason":plan.get("reason")}
       finally:
        try: os.unlink(temp_name,dir_fd=target_fd)
        except FileNotFoundError: pass
    except Exception as exc:
      try: conn.rollback()
      except sqlite3.Error: pass
      row=conn.execute("SELECT state FROM writeback_operations WHERE operation_id=?",(op,)).fetchone(); state=row[0] if row else "authorized"
      terminal="failed_before_mutation" if state in {"authorized","locked"} else "recovery_required"
      _state(conn,op,terminal,error_code=exc.args[0] if isinstance(exc,LiveOverflowError) else type(exc).__name__)
      return _result(conn,op,False)
    finally:
      if op_fd>=0: os.close(op_fd)
      if root_fd>=0: os.close(root_fd)
      os.close(target_fd)

def _result(conn,op,mutated):
    row=conn.execute("SELECT operation_id,authorization_id,state,expected_before_hash,expected_after_hash,error_code,evidence_state,audit_state,rollback_available FROM writeback_operations WHERE operation_id=?",(op,)).fetchone()
    return {**dict(row),"mutation_performed":mutated,"content_included":False,"path_redacted":True}

def reconcile_writeback(conn, operation_id: str, *, backup_root: str|Path,
                        authorization: WritebackAuthorization | None = None) -> dict[str,Any]:
    row=conn.execute("SELECT * FROM writeback_operations WHERE operation_id=?",(operation_id,)).fetchone()
    if not row: raise LiveOverflowError("operation_not_found")
    if row["state"] in {"completed","completed_partial","blocked_target_unreachable","rolled_back","failed_before_mutation"}:
        return {**_result(conn,operation_id,False),"next_action":"none"}
    if authorization is None:
        return {**_result(conn,operation_id,False),"next_action":"authorization_required"}
    _authenticate_recovery_authorization(conn,authorization)
    if (authorization.operation_id != operation_id or authorization.authorization_id != row["authorization_id"]
        or authorization.profile_id != row["profile_id"]
        or _hash(authorization.target_path) != row["target_path_hash"]
        or _hash(authorization.allowed_root) != row["allowed_root_hash"]
        or authorization.expected_before_hash != row["expected_before_hash"]
        or authorization.policy_version != row["policy_version"]
        or authorization.operation_type != row["operation_type"]
        or authorization.proposal_id != row["proposal_id"]):
        raise LiveOverflowError("recovery_authorization_mismatch")
    path,root=_canonical_target(authorization.target_path,authorization.allowed_root)
    target_fd=_open_existing_directory(path.parent); parent_meta=os.fstat(target_fd)
    if (row["target_parent_dev"] is None or row["target_parent_ino"] is None
        or (parent_meta.st_dev,parent_meta.st_ino)!=(row["target_parent_dev"],row["target_parent_ino"])):
        os.close(target_fd); raise LiveOverflowError("target_parent_identity_mismatch")
    if authorization.operation_type=="rollback":
        original_id=authorization.proposal_id
        original=conn.execute("SELECT * FROM writeback_operations WHERE operation_id=?",(original_id,)).fetchone()
        if not original or authorization.expected_before_hash!=original["expected_after_hash"]:
            raise LiveOverflowError("recovery_authorization_mismatch")
        base=_validate_backup_root(backup_root,path,root); prepared=_prepare_private_root(base)
        if prepared.missing:
            prepared.close(); return {**_result(conn,operation_id,False),"next_action":"manual_recovery"}
        root_fd=_materialize_private_root(prepared)
        try:
            lock_name="target-"+_hash(str(path))+".lock"
            lfd=os.open(lock_name,os.O_RDWR|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=root_fd); os.fchmod(lfd,0o600)
            with os.fdopen(lfd,"r+") as lock:
                fcntl.flock(lock,fcntl.LOCK_EX); current,identity=_read_regular_at(target_fd,path.name); current_hash=sha256_text(current)
                latest,latest_identity=_read_regular_at(target_fd,path.name)
                if latest_identity!=identity or sha256_text(latest)!=current_hash:
                    _state(conn,operation_id,"recovery_required",error_code="rollback_reconcile_cas_mismatch")
                    return {**_result(conn,operation_id,False),"next_action":"manual_recovery"}
                if current_hash==original["expected_before_hash"]:
                    conn.execute("UPDATE raw_events SET write_status='tombstoned' WHERE json_extract(provenance_json,'$.operation_id')=? AND write_status='committed'",(original_id,)); conn.commit()
                    _state(conn,operation_id,"rolled_back",expected_after_hash=current_hash,evidence_state="reconciled",audit_state="committed",completed_at=now_utc())
                    _state(conn,original_id,"rolled_back",evidence_state="reconciled",audit_state="committed",rollback_available=0,completed_at=now_utc())
                    return {**_result(conn,operation_id,False),"next_action":"none"}
                if current_hash==authorization.expected_before_hash:
                    _state(conn,operation_id,"failed_before_mutation",audit_state="committed",completed_at=now_utc())
                    return {**_result(conn,operation_id,False),"next_action":"retry_with_new_authorization"}
                _state(conn,operation_id,"recovery_required",error_code="unknown_target_hash")
                return {**_result(conn,operation_id,False),"next_action":"manual_recovery"}
        finally:
            os.close(root_fd); os.close(target_fd)
    base=_validate_backup_root(backup_root,path,root); prepared=_prepare_private_root(base)
    if prepared.missing:
        prepared.close(); os.close(target_fd); return {**_result(conn,operation_id,False),"next_action":"manual_recovery"}
    root_fd=_materialize_private_root(prepared); op_fd=-1
    try:
        op_fd=_open_private_child(root_fd,operation_id,create=False)
        if not row["spool_ref"]: return {**_result(conn,operation_id,False),"next_action":"rollback" if row["rollback_available"] else "manual_recovery"}
        pending_name=str(row["spool_ref"]).rsplit("/",1)[-1]; committed_name=pending_name.replace(".json",".committed.json")
        is_pending=True
        try: spool_text,_=_read_private_at(op_fd,pending_name)
        except FileNotFoundError:
            is_pending=False
            try: spool_text,_=_read_private_at(op_fd,committed_name)
            except FileNotFoundError: return {**_result(conn,operation_id,False),"next_action":"rollback" if row["rollback_available"] else "manual_recovery"}
        payload=json.loads(spool_text); _verify_spool(payload,authorization)
        lock_name="target-"+_hash(str(path))+".lock"
        lfd=os.open(lock_name,os.O_RDWR|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=root_fd); os.fchmod(lfd,0o600)
        with os.fdopen(lfd,"r+") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            current,identity=_read_regular_at(target_fd,path.name); current_hash=sha256_text(current)
            if current_hash==payload["after_hash"]:
                latest,latest_identity=_read_regular_at(target_fd,path.name)
                if latest_identity!=identity or sha256_text(latest)!=payload["after_hash"]:
                    _state(conn,operation_id,"recovery_required",error_code="reconcile_cas_mismatch")
                    return {**_result(conn,operation_id,False),"next_action":"manual_recovery"}
                conn.execute("BEGIN IMMEDIATE")
                ids=_record_removed_blocks(conn,operation_id=operation_id,profile_id=authorization.profile_id,
                    file_name=path.name,removed_blocks=payload["removed_blocks"],before_hash=payload["before_hash"],after_hash=payload["after_hash"])
                conn.commit()
                if is_pending: os.rename(pending_name,committed_name,src_dir_fd=op_fd,dst_dir_fd=op_fd)
                target_reached=bool(payload.get("target_reached",True)); final_state="completed" if target_reached else "completed_partial"
                _state(conn,operation_id,final_state,error_code=None if target_reached else "target_unreachable",
                       expected_after_hash=payload["after_hash"],evidence_state="committed",audit_state="committed",completed_at=now_utc())
                try: os.unlink("recovery-authorization.json",dir_fd=op_fd)
                except FileNotFoundError: pass
                return {**_result(conn,operation_id,False),"next_action":"none","reconciled_evidence_count":len(ids),
                        "target_reached":target_reached,"plan_reason":payload.get("plan_reason")}
            if current_hash==payload["before_hash"]:
                _state(conn,operation_id,"failed_before_mutation",evidence_state="pending",audit_state="committed",completed_at=now_utc())
                return {**_result(conn,operation_id,False),"next_action":"retry_with_new_authorization"}
            _state(conn,operation_id,"recovery_required",error_code="unknown_target_hash")
            return {**_result(conn,operation_id,False),"next_action":"manual_recovery"}
    finally:
        if op_fd>=0: os.close(op_fd)
        os.close(root_fd); os.close(target_fd)

def rollback_writeback(conn, original_operation_id: str, request: WritebackRequest, authorization: WritebackAuthorization, *,
                       backup_root: str|Path, fault: Callable[[str],None]|None=None) -> dict[str,Any]:
    fault=fault or (lambda _:None)
    if request.operation_type!="rollback": raise LiveOverflowError("rollback_authorization_required")
    original=conn.execute("SELECT * FROM writeback_operations WHERE operation_id=?",(original_operation_id,)).fetchone()
    if not original or not original["rollback_available"]: raise LiveOverflowError("rollback_unavailable")
    if (authorization.proposal_id != original_operation_id or authorization.profile_id != original["profile_id"]
        or _hash(authorization.target_path) != original["target_path_hash"]
        or authorization.expected_before_hash != original["expected_after_hash"]):
        raise LiveOverflowError("rollback_binding_mismatch")
    validated: dict[str,Any]={}
    def validate_artifacts(path:Path,root:Path)->None:
        validated["target_fd"]=_open_existing_directory(path.parent)
        try:
            base=_validate_backup_root(backup_root,path,root); validated["prepared"]=_prepare_private_root(base)
            if validated["prepared"].missing:
                validated["prepared"].close(); raise LiveOverflowError("rollback_backup_invalid")
        except Exception:
            os.close(validated.pop("target_fd")); raise
    try: path,root=_validate_and_consume(conn,request,authorization,preconsume=validate_artifacts)
    except Exception:
        prepared=validated.get("prepared")
        if prepared: prepared.close()
        if "target_fd" in validated: os.close(validated["target_fd"])
        raise
    root_fd=-1; backup_fd=-1; target_fd=validated["target_fd"]
    parent_meta=os.fstat(target_fd)
    conn.execute("UPDATE writeback_operations SET target_parent_dev=?,target_parent_ino=?,updated_at=? WHERE operation_id=?",(parent_meta.st_dev,parent_meta.st_ino,now_utc(),request.operation_id)); conn.commit()
    try:
        fault("rollback_backup_open"); root_fd=_materialize_private_root(validated["prepared"])
        backup_fd=_open_private_child(root_fd,original_operation_id,create=False)
        if not original["backup_ref"]: raise LiveOverflowError("rollback_backup_invalid")
        backup_name=str(original["backup_ref"]).rsplit("/",1)[-1]
        data,_=_read_private_at(backup_fd,backup_name); fault("rollback_backup_read")
        if sha256_text(data)!=original["expected_before_hash"]: raise LiveOverflowError("rollback_backup_hash_mismatch")
        lock_name="target-"+_hash(str(path))+".lock"; fault("rollback_lock")
        lfd=os.open(lock_name,os.O_RDWR|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=root_fd); os.fchmod(lfd,0o600)
        with os.fdopen(lfd,"r+") as lock:
          fcntl.flock(lock,fcntl.LOCK_EX); _state(conn,request.operation_id,"rollback_locked")
          current,identity=_read_regular_at(target_fd,path.name)
          if sha256_text(current)!=request.expected_before_hash:
              _state(conn,request.operation_id,"concurrent_edit_detected",error_code="rollback_cas_mismatch"); return _result(conn,request.operation_id,False)
          st=os.stat(path.name,dir_fd=target_fd,follow_symlinks=False); fd,temp_name=_create_target_temp_at(target_fd,".mnemoir-rollback-"); os.fchmod(fd,0o600)
          try:
            with os.fdopen(fd,"w",encoding="utf-8") as f:
                f.write(data); f.flush(); fault("rollback_temp_write"); os.fsync(f.fileno()); fault("rollback_temp_fsync")
            os.chmod(temp_name,stat.S_IMODE(st.st_mode),dir_fd=target_fd,follow_symlinks=False)
            try: os.chown(temp_name,st.st_uid,st.st_gid,dir_fd=target_fd,follow_symlinks=False)
            except PermissionError: pass
            fault("rollback_final_cas"); latest,latest_identity=_read_regular_at(target_fd,path.name)
            if latest_identity!=identity or sha256_text(latest)!=request.expected_before_hash:
                _state(conn,request.operation_id,"concurrent_edit_detected",error_code="rollback_cas_mismatch"); return _result(conn,request.operation_id,False)
            fault("rollback_replace"); os.replace(temp_name,path.name,src_dir_fd=target_fd,dst_dir_fd=target_fd); _state(conn,request.operation_id,"rollback_file_replaced",expected_after_hash=sha256_text(data))
            os.fsync(target_fd); fault("rollback_directory_fsync")
            restored,_=_read_regular_at(target_fd,path.name); fault("rollback_readback")
            if sha256_text(restored)!=original["expected_before_hash"]: raise LiveOverflowError("rollback_readback_mismatch")
          finally:
            try: os.unlink(temp_name,dir_fd=target_fd)
            except FileNotFoundError: pass
        fault("rollback_evidence_reconcile")
        conn.execute("UPDATE raw_events SET write_status='tombstoned' WHERE json_extract(provenance_json,'$.operation_id')=? AND write_status='committed'",(original_operation_id,)); conn.commit()
        _state(conn,request.operation_id,"rollback_evidence_reconciled",expected_after_hash=sha256_text(data),evidence_state="reconciled")
        fault("rollback_audit_finalize")
        _state(conn,request.operation_id,"rolled_back",audit_state="committed",completed_at=now_utc())
        _state(conn,original_operation_id,"rolled_back",evidence_state="reconciled",audit_state="committed",rollback_available=0,completed_at=now_utc())
        return _result(conn,request.operation_id,True)
    except Exception as exc:
        try: conn.rollback()
        except sqlite3.Error: pass
        state_row=conn.execute("SELECT state FROM writeback_operations WHERE operation_id=?",(request.operation_id,)).fetchone()
        state=state_row[0] if state_row else "authorized"
        terminal="failed_before_mutation" if state in {"authorized","rollback_locked"} else "recovery_required"
        _state(conn,request.operation_id,terminal,error_code=exc.args[0] if isinstance(exc,LiveOverflowError) else type(exc).__name__)
        return _result(conn,request.operation_id,False)
    finally:
        if backup_fd>=0: os.close(backup_fd)
        if root_fd>=0: os.close(root_fd)
        os.close(target_fd)

def live_overflow_status(*,profile_ids=DEFAULT_PROFILE_IDS,hermes_home=None,policy=DEFAULT_POLICY):
    home=Path(hermes_home or os.environ.get("HERMES_HOME") or Path.home()/".hermes").expanduser().resolve(strict=False); rows=[]
    for target in enumerate_live_profile_targets(profile_ids,hermes_home=home):
      for name in MARKDOWN_FILES:
       try:
        path,_=_canonical_target(target.memory_root/name,target.memory_root)
        text=path.read_text(); p=compute_markdown_pressure(file_name=name,text=text,profile_id=target.profile_id,policy=policy,source_mtime=path.stat().st_mtime)
        rows.append({k:p[k] for k in ("profile_id","file_basename","current_chars","percent_full","pressure_state","trigger_state","source_snapshot_hash","content_included","path_redacted")})
       except LiveOverflowError: rows.append({"profile_id":target.profile_id,"file_basename":name,"status":"missing","trigger_state":False,"content_included":False,"path_redacted":True})
    return {"status":"trigger" if any(r.get("trigger_state") for r in rows) else "ok","surface":"live_overflow_status","rows":rows,"trigger_count":sum(bool(r.get("trigger_state")) for r in rows),"file_mutation_performed":False,"content_included":False,"path_redacted":True}

def _load_recovery_authorization(private_root: Path, operation_id: str) -> WritebackAuthorization:
    """Load the operation-bound capability from its private 0700/0600 journal area."""
    prepared = _prepare_private_root(private_root)
    if prepared.missing:
        prepared.close()
        raise LiveOverflowError("recovery_authorization_not_found")
    root_fd = _materialize_private_root(prepared)
    op_fd = -1
    try:
        op_fd = _open_private_child(root_fd, operation_id, create=False)
        payload, _ = _read_private_at(op_fd, "recovery-authorization.json")
        return WritebackAuthorization(**json.loads(payload))
    except (FileNotFoundError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LiveOverflowError("recovery_authorization_not_found") from exc
    finally:
        if op_fd >= 0:
            os.close(op_fd)
        os.close(root_fd)


def run_live_overflow_coordinator(conn: sqlite3.Connection, *, profile_ids=DEFAULT_PROFILE_IDS,
                                  hermes_home=None, backup_root: str|Path|None=None,
                                  policy: OverflowPolicy=DEFAULT_POLICY,
                                  approving_actor="operator-configured-live-overflow-policy") -> dict[str,Any]:
    """Catch up pressured profile Markdown through the protected transaction path.

    ``writeback_mode=live_overflow_trim`` is durable operator authorization for
    this bounded automatic policy. The coordinator observes a concrete snapshot,
    mints one internal transaction capability, and passes it to the compat 17A
    executor. It is not a separate human or external per-operation approval.
    The stable operation id makes lifecycle retries idempotent. Removed content
    is authenticated in the private spool before replacement and committed as
    cited Mnemoir evidence only after read-back succeeds.
    """
    configure_connection(conn)
    home=Path(hermes_home or os.environ.get("HERMES_HOME") or Path.home()/".hermes").expanduser().resolve(strict=False)
    private_root=Path(backup_root or home/"mnemoir-provenance"/"writeback-private").expanduser()
    rows=[]
    for target in enumerate_live_profile_targets(profile_ids,hermes_home=home):
      for name in MARKDOWN_FILES:
       try:
        path,root=_canonical_target(target.memory_root/name,target.memory_root)
        target_path_hash=_hash(str(path))
        pending=conn.execute(
            "SELECT operation_id,state FROM writeback_operations WHERE profile_id=? AND target_path_hash=? AND state IN ('recovery_required','concurrent_edit_detected','file_replaced','readback_verified','evidence_pending','backup_durable','locked') ORDER BY created_at",
            (target.profile_id,target_path_hash),
        ).fetchall()
        for pending_row in pending:
            pending_op=pending_row["operation_id"]
            auth=_load_recovery_authorization(private_root,pending_op)
            recovered=reconcile_writeback(conn,pending_op,backup_root=private_root,authorization=auth)
            rows.append({"profile_id":target.profile_id,"file_basename":name,"operation_id":pending_op,
                "recovery_attempted":True,**recovered})
        text,_=_read_regular_nofollow(path); before_hash=sha256_text(text)
        pressure=compute_markdown_pressure(file_name=name,text=text,profile_id=target.profile_id,policy=policy,source_mtime=path.stat().st_mtime)
        if not pressure["trigger_state"]:
            rows.append({"profile_id":target.profile_id,"file_basename":name,"state":"below_trigger","mutation_performed":False,"content_included":False,"path_redacted":True})
            continue
        operation_id=stable_id("live_overflow",target.profile_id,name,before_hash,POLICY_VERSION)
        existing=conn.execute("SELECT state FROM writeback_operations WHERE operation_id=?",(operation_id,)).fetchone()
        if existing:
            rows.append({"profile_id":target.profile_id,"file_basename":name,"operation_id":operation_id,"state":existing["state"],"mutation_performed":False,"idempotent_replay":True,"content_included":False,"path_redacted":True})
            continue
        orphan=conn.execute("SELECT 1 FROM writeback_authorizations WHERE operation_id=?",(operation_id,)).fetchone()
        if orphan:
            attempt=conn.execute("SELECT COUNT(*) FROM writeback_authorizations WHERE profile_id=? AND expected_before_hash=? AND operation_type='live_overflow_trim'",(target.profile_id,before_hash)).fetchone()[0]
            operation_id=stable_id("live_overflow_retry",target.profile_id,name,before_hash,POLICY_VERSION,str(attempt))
        auth=create_writeback_authorization(conn,operation_id=operation_id,profile_id=target.profile_id,
            target_path=path,allowed_root=root,expected_before_hash=before_hash,
            approving_actor=approving_actor,operation_type="live_overflow_trim")
        result=execute_writeback(conn,request_from_authorization(auth),auth,backup_root=private_root,policy=policy)
        rows.append({"profile_id":target.profile_id,"file_basename":name,"operation_id":operation_id,
            "authorization_id":auth.authorization_id,**result})
       except Exception as exc:
        code=exc.args[0] if isinstance(exc,LiveOverflowError) and exc.args else type(exc).__name__
        rows.append({"profile_id":target.profile_id,"file_basename":name,"state":"failed","error_code":code,
            "mutation_performed":False,"content_included":False,"path_redacted":True})
    mutated=sum(bool(row.get("mutation_performed")) for row in rows)
    hard_failures=sum(row.get("state") in {"failed","recovery_required","concurrent_edit_detected"} for row in rows)
    partial=sum(row.get("state") in {"blocked_target_unreachable","completed_partial"} for row in rows)
    unresolved=hard_failures+partial
    status="failed" if hard_failures else ("partial" if partial else "succeeded")
    return {"status":status,"surface":"live_overflow_coordinator","rows":rows,
        "mutated_file_count":mutated,"unresolved_count":unresolved,"file_mutation_performed":bool(mutated),
        "content_included":False,"path_redacted":True}

def execute_live_overflow_trim(conn, **kwargs):
    """Retired unsafe batch adapter. Use execute_writeback with one external grant."""
    raise LiveOverflowError("external_writeback_request_and_authorization_required")

def ingest_pending_evidence_spools(conn, **kwargs):
    """Unauthenticated legacy spools can no longer be ingested."""
    return {"status":"DENIED","surface":"live_overflow_pending_evidence_ingest","error":"authenticated_operation_reconciliation_required","ingested_count":0,"file_mutation_performed":False,"content_included":False,"path_redacted":True}
