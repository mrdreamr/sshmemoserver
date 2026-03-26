#!/usr/bin/env python3
"""
sshmemo-server — Web browser UI for SSHMemo markdown files.

Reads the same .md files written by the SSHMemo Android/iOS app and lets you
view, create, and edit tasks and notes from a browser.

Usage (run from the SSHMemo root directory):
    sshmemo [--port 8080] [--host 0.0.0.0]

Authentication:
    Users are configured by the SSHMemo app via .sshmemo_web.meta in the root
    folder. If no users are configured, the server accepts no logins.
    Each user's password is their note passphrase (also used to decrypt private
    files). The meta file stores passwords as base64-encoded strings.

Install:
    pip install sshmemo-server
"""

from __future__ import annotations

import argparse
import base64
import functools
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from flask import Flask, abort, redirect, render_template_string, request, session, url_for
except ImportError:
    raise SystemExit("Flask is required: pip install flask")

_USERS_META = '.sshmemo_web.meta'

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import markdown as md_lib
except ImportError:
    raise SystemExit("markdown is required: pip install markdown")


# ── Crypto (mirrors ItemCryptoAndroid exactly) ─────────────────────────────
# Wire format: [16-byte salt][12-byte IV][ciphertext + 16-byte GCM tag]

_SALT_LEN = 16
_IV_LEN = 12
_TAG_BYTES = 16
_PBKDF2_ITERATIONS = 100_000
_KEY_BYTES = 32  # 256 bits


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode())


def decrypt_file(ciphertext: bytes, passphrase: str) -> Optional[bytes]:
    if not CRYPTO_AVAILABLE:
        return None
    if len(ciphertext) < _SALT_LEN + _IV_LEN + _TAG_BYTES:
        return None
    salt = ciphertext[:_SALT_LEN]
    iv = ciphertext[_SALT_LEN:_SALT_LEN + _IV_LEN]
    data = ciphertext[_SALT_LEN + _IV_LEN:]
    try:
        return AESGCM(_derive_key(passphrase, salt)).decrypt(iv, data, None)
    except Exception:
        return None


def encrypt_file(plaintext: bytes, passphrase: str) -> bytes:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("pip install cryptography")
    salt = os.urandom(_SALT_LEN)
    iv = os.urandom(_IV_LEN)
    return salt + iv + AESGCM(_derive_key(passphrase, salt)).encrypt(iv, plaintext, None)


# ── Filename utils (mirrors FilenameUtils.kt) ──────────────────────────────

def _slug(title: str) -> str:
    s = title.strip()
    s = re.sub(r'[/\\:*?"<>|]', '', s)
    s = re.sub(r'\s+', '_', s)
    s = s.lower()[:80].rstrip('_.')
    return s or 'untitled'


def task_filename(title: str) -> str:
    return f"{_slug(title)}.md"


def note_filename(title: str) -> str:
    return f"{_slug(title)}.md"


def sanitize_cat_folder(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]', '_', name)


def sanitize_user_folder(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]', '_', name.strip())


# ── Reminder format (mirrors ReminderFormat.kt) ────────────────────────────

def format_reminder_stamp(epoch_ms: int) -> str:
    """YYYY-MM-DDTHH:MM — stored in file, matches app format."""
    dt = datetime.fromtimestamp(epoch_ms / 1000)
    return dt.strftime("%Y-%m-%dT%H:%M")


def parse_reminder_stamp(stamp: str) -> Optional[int]:
    for fmt in ("%Y-%m-%dT%H:%M",):
        try:
            return int(datetime.strptime(stamp.strip(), fmt).timestamp() * 1000)
        except ValueError:
            pass
    return None


def format_reminder_display(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000).strftime("%d %b %Y %H:%M")


def format_edited_display(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000).strftime("%d %b %Y")


# ── Data models ────────────────────────────────────────────────────────────

@dataclass
class Attachment:
    id: str
    mime_type: str
    remote_name: str


@dataclass
class Task:
    title: str
    description: str = ""
    done: bool = False
    sync_mode: str = "NORMAL"
    remind_at: Optional[int] = None
    edited_at: int = field(default_factory=lambda: int(time.time() * 1000))
    deleted_at: Optional[int] = None
    category: Optional[str] = None
    edited_by: Optional[str] = None
    attachments: list = field(default_factory=list)
    path: Optional[Path] = field(default=None, repr=False)


@dataclass
class Note:
    title: str
    content: str = ""
    sync_mode: str = "NORMAL"
    remind_at: Optional[int] = None
    edited_at: int = field(default_factory=lambda: int(time.time() * 1000))
    deleted_at: Optional[int] = None
    category: Optional[str] = None
    edited_by: Optional[str] = None
    attachments: list = field(default_factory=list)
    path: Optional[Path] = field(default=None, repr=False)


@dataclass
class CustomCategory:
    name: str
    icon: str
    color: Optional[str] = None


# ── Markdown parsing (mirrors Kotlin mappers) ──────────────────────────────

def _parse_meta_lines(lines: list[str], start: int) -> tuple[dict, int]:
    """Parse key:value metadata lines starting at `start`. Returns (meta_dict, body_start)."""
    meta: dict = {}
    attachments = []
    i = start
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            break
        lo = line.lower()
        def val(prefix_len): return line[prefix_len:].strip()
        if lo.startswith("done:"):
            meta['done'] = val(5).lower() == 'true'
        elif lo.startswith("sync:"):
            if val(5).lower() == 'false':
                meta['sync_mode'] = 'DISABLED'
        elif lo.startswith("shared:"):
            if val(7).lower() == 'true':
                meta['sync_mode'] = 'SHARED'
        elif lo.startswith("private:"):
            if val(8).lower() == 'true':
                meta['sync_mode'] = 'PRIVATE'
        elif lo.startswith("remind:"):
            meta['remind_at'] = parse_reminder_stamp(val(7))
        elif lo.startswith("deletedat:"):
            v = val(10)
            meta['deleted_at'] = int(v) if v.isdigit() else None
        elif lo.startswith("category:"):
            v = val(9)
            meta['category'] = v or None
        elif lo.startswith("editedby:"):
            v = val(9)
            meta['edited_by'] = v or None
        elif lo.startswith("editedat:"):
            v = val(9)
            try:
                meta['edited_at'] = int(v)
            except ValueError:
                pass
        elif lo.startswith("attachment:"):
            parts = val(11).split("|", 2)
            if len(parts) == 3:
                attachments.append(Attachment(id=parts[0], mime_type=parts[1], remote_name=parts[2]))
        else:
            break
        i += 1
    meta['attachments'] = attachments
    return meta, i


def parse_task(text: str) -> Optional[Task]:
    lines = text.splitlines()
    if not lines or not lines[0].startswith('#'):
        return None
    title = lines[0].lstrip('# ').strip()
    if not title:
        return None
    meta, body_start = _parse_meta_lines(lines, 1)
    body = "\n".join(lines[body_start:]).strip()
    return Task(
        title=title,
        description=body,
        done=meta.get('done', False),
        sync_mode=meta.get('sync_mode', 'NORMAL'),
        remind_at=meta.get('remind_at'),
        edited_at=meta.get('edited_at', int(time.time() * 1000)),
        deleted_at=meta.get('deleted_at'),
        category=meta.get('category'),
        edited_by=meta.get('edited_by'),
        attachments=meta.get('attachments', []),
    )


def parse_note(text: str) -> Optional[Note]:
    lines = text.splitlines()
    if not lines or not lines[0].startswith('#'):
        return None
    title = lines[0].lstrip('# ').strip()
    if not title:
        return None
    meta, body_start = _parse_meta_lines(lines, 1)
    body = "\n".join(lines[body_start:]).strip()
    return Note(
        title=title,
        content=body,
        sync_mode=meta.get('sync_mode', 'NORMAL'),
        remind_at=meta.get('remind_at'),
        edited_at=meta.get('edited_at', int(time.time() * 1000)),
        deleted_at=meta.get('deleted_at'),
        category=meta.get('category'),
        edited_by=meta.get('edited_by'),
        attachments=meta.get('attachments', []),
    )


def task_to_markdown(task: Task) -> str:
    lines = [f"# {task.title.strip()}"]
    if task.done:
        lines.append("Done: true")
    if task.sync_mode == 'DISABLED':
        lines.append("Sync: false")
    elif task.sync_mode == 'SHARED':
        lines.append("Shared: true")
    elif task.sync_mode == 'PRIVATE':
        lines.append("Private: true")
    if task.remind_at:
        lines.append(f"Remind: {format_reminder_stamp(task.remind_at)}")
    if task.category:
        lines.append(f"Category: {task.category}")
    for a in task.attachments:
        lines.append(f"Attachment: {a.id}|{a.mime_type}|{a.remote_name}")
    lines.append("")
    lines.append(task.description.strip())
    return "\n".join(lines)


def note_to_markdown(note: Note) -> str:
    lines = [f"# {note.title.strip()}"]
    if note.sync_mode == 'DISABLED':
        lines.append("Sync: false")
    elif note.sync_mode == 'SHARED':
        lines.append("Shared: true")
    elif note.sync_mode == 'PRIVATE':
        lines.append("Private: true")
    if note.remind_at:
        lines.append(f"Remind: {format_reminder_stamp(note.remind_at)}")
    for a in note.attachments:
        lines.append(f"Attachment: {a.id}|{a.mime_type}|{a.remote_name}")
    if note.category:
        lines.append(f"Category: {note.category}")
    lines.append("")
    lines.append(note.content.strip())
    return "\n".join(lines)


# ── File store ─────────────────────────────────────────────────────────────

class FileStore:
    """Reads/writes SSHMemo .md files using the same layout as the app."""

    def __init__(self, root: Path, passphrase: Optional[str] = None):
        self.root = root
        self.passphrase = passphrase

    # ── I/O helpers ────────────────────────────────────────────────────────

    def read_text(self, path: Path) -> Optional[str]:
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        if path.name.startswith('.') and not path.name.endswith('.meta'):
            # Try decryption first (private files); fall back to plain text
            # (dot-prefixed deleted files that were not private).
            if self.passphrase:
                plain = decrypt_file(raw, self.passphrase)
                if plain is not None:
                    return plain.decode('utf-8', errors='replace')
            # Not encrypted — read as plain text
            try:
                return raw.decode('utf-8', errors='replace')
            except Exception:
                return None
        return raw.decode('utf-8', errors='replace')

    def write_text(self, path: Path, text: str, private: bool = False) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = text.encode('utf-8')
        if private:
            if not self.passphrase:
                raise ValueError("Passphrase required to write private files")
            data = encrypt_file(data, self.passphrase)
        tmp = path.with_suffix('.tmp')
        tmp.write_bytes(data)
        tmp.replace(path)

    def safe_abs(self, rel: str) -> Path:
        """Resolve a relative path safely (no path traversal)."""
        clean = re.sub(r'\.\.', '', rel).lstrip('/')
        return (self.root / clean).resolve()

    def rel(self, path: Path) -> str:
        return str(path.relative_to(self.root))

    # ── Sidecar .meta helpers ───────────────────────────────────────────────

    @staticmethod
    def _sidecar_path(md_path: Path) -> Path:
        """foo/bar.md and foo/.bar.md both → foo/.bar.meta"""
        stem = md_path.name[:-3] if md_path.name.endswith('.md') else md_path.name
        stem = stem.lstrip('.')  # normalise: .bar.md and bar.md share a sidecar
        return md_path.parent / f'.{stem}.meta'

    def read_sidecar(self, md_path: Path) -> dict:
        """Read sidecar and return dict with any of: edited_at, edited_by, deleted_at."""
        sp = self._sidecar_path(md_path)
        try:
            text = sp.read_text(encoding='utf-8')
        except OSError:
            return {}
        result = {}
        for line in text.splitlines():
            if '=' not in line:
                continue
            k, _, v = line.partition('=')
            k, v = k.strip(), v.strip()
            if k == 'edited_at':
                try:
                    result['edited_at'] = int(v)
                except ValueError:
                    pass
            elif k == 'deleted_at':
                try:
                    result['deleted_at'] = int(v)
                except ValueError:
                    pass
            elif k == 'edited_by':
                result['edited_by'] = v or None
        return result

    def write_sidecar(self, md_path: Path, edited_at: int,
                      edited_by: Optional[str] = None,
                      deleted_at: Optional[int] = None) -> None:
        lines = [f'edited_at={edited_at}']
        if edited_by:
            lines.append(f'edited_by={edited_by}')
        if deleted_at:
            lines.append(f'deleted_at={deleted_at}')
        sp = self._sidecar_path(md_path)
        sp.parent.mkdir(parents=True, exist_ok=True)
        tmp = sp.with_suffix('.tmp')
        tmp.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        tmp.replace(sp)

    # ── Scanning ───────────────────────────────────────────────────────────

    def _md_files(self, folder: Path):
        if not folder.is_dir():
            return
        for p in sorted(folder.iterdir()):
            if p.name.endswith('.md'):
                yield p

    def _user_dirs(self):
        for p in sorted(self.root.iterdir()):
            if p.is_dir() and not p.name.startswith('.') and p.name != 'shared':
                yield p

    def load_tasks(self, folder: Path) -> list[Task]:
        tasks = []
        for path in self._md_files(folder):
            text = self.read_text(path)
            if text is None:
                continue
            task = parse_task(text)
            if task:
                task.path = path
                sc = self.read_sidecar(path)
                if 'edited_at' in sc:
                    task.edited_at = sc['edited_at']
                if 'edited_by' in sc:
                    task.edited_by = sc['edited_by']
                if 'deleted_at' in sc:
                    task.deleted_at = sc['deleted_at']
                # Only treat dot-prefix as private if the item is not deleted
                if path.name.startswith('.') and not task.deleted_at:
                    task.sync_mode = 'PRIVATE'
                tasks.append(task)
        return tasks

    def load_notes(self, folder: Path) -> list[Note]:
        notes = []
        for path in self._md_files(folder):
            text = self.read_text(path)
            if text is None:
                continue
            note = parse_note(text)
            if note:
                note.path = path
                sc = self.read_sidecar(path)
                if 'edited_at' in sc:
                    note.edited_at = sc['edited_at']
                if 'edited_by' in sc:
                    note.edited_by = sc['edited_by']
                if 'deleted_at' in sc:
                    note.deleted_at = sc['deleted_at']
                # Only treat dot-prefix as private if the item is not deleted
                if path.name.startswith('.') and not note.deleted_at:
                    note.sync_mode = 'PRIVATE'
                notes.append(note)
        return notes

    def load_categories(self, user_dir: Path) -> list[CustomCategory]:
        path = user_dir / 'custom' / '.categories.meta'
        text = self.read_text(path) if path.exists() else None
        if not text:
            return []
        cats = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split('|')
            if parts[0] == 'cat' and len(parts) >= 6:
                deleted = parts[5].strip() if len(parts) > 5 else ''
                if deleted:
                    continue  # skip deleted categories
                cats.append(CustomCategory(
                    name=parts[2].strip(),
                    icon=parts[1].strip(),
                    color=parts[3].strip() or None,
                ))
            elif len(parts) >= 2 and parts[0] != 'cat':
                # Legacy format: icon|name|color
                cats.append(CustomCategory(
                    name=parts[1].strip(),
                    icon=parts[0].strip(),
                    color=parts[2].strip() if len(parts) > 2 and parts[2].strip() else None,
                ))
        return cats

    def save_categories(self, user_dir: Path, categories: list[CustomCategory]) -> None:
        now_ms = int(time.time() * 1000)
        lines = ['|'.join(['cat', c.icon, c.name, c.color or '', str(now_ms), '', ''])
                 for c in categories]
        path = user_dir / 'custom' / '.categories.meta'
        self.write_text(path, '\n'.join(lines))

    def load_all(self) -> dict:
        """
        Returns:
          shared_tasks, shared_notes: lists of active Task/Note
          users: { username: { tasks, notes, categories, category_notes } }
        """
        shared = self.root / 'shared'
        result = {
            'shared_tasks': self.load_tasks(shared / 'todo'),
            'shared_notes': self.load_notes(shared / 'note'),
            'users': {},
        }
        for user_dir in self._user_dirs():
            cats = self.load_categories(user_dir)
            cat_notes: dict[str, list[Note]] = {}
            custom_base = user_dir / 'custom'
            if custom_base.is_dir():
                for cat_dir in sorted(custom_base.iterdir()):
                    if cat_dir.is_dir() and not cat_dir.name.startswith('.'):
                        notes = self.load_notes(cat_dir)
                        for n in notes:
                            if n.category is None:
                                n.category = cat_dir.name
                        cat_notes[cat_dir.name] = notes
            result['users'][user_dir.name] = {
                'tasks': self.load_tasks(user_dir / 'todo'),
                'notes': self.load_notes(user_dir / 'note'),
                'categories': cats,
                'category_notes': cat_notes,
            }
        return result

    # ── Writes ─────────────────────────────────────────────────────────────

    def write_task(self, task: Task, user: Optional[str], shared: bool) -> Path:
        task.edited_at = int(time.time() * 1000)
        private = task.sync_mode == 'PRIVATE'
        prefix = '.' if private else ''
        filename = f"{prefix}{task_filename(task.title)}"
        if shared or task.sync_mode == 'SHARED':
            folder = self.root / 'shared' / 'todo'
        elif user:
            folder = self.root / sanitize_user_folder(user) / 'todo'
        else:
            folder = self.root / 'shared' / 'todo'
        path = folder / filename
        self.write_text(path, task_to_markdown(task), private=private)
        self.write_sidecar(path, task.edited_at, task.edited_by, task.deleted_at)
        task.path = path
        return path

    def write_note(self, note: Note, user: Optional[str], shared: bool) -> Path:
        note.edited_at = int(time.time() * 1000)
        private = note.sync_mode == 'PRIVATE'
        prefix = '.' if private else ''
        filename = f"{prefix}{note_filename(note.title)}"
        cat = note.category
        if cat and not shared and note.sync_mode != 'SHARED':
            folder = self.root / sanitize_user_folder(user or 'shared') / 'custom' / sanitize_cat_folder(cat)
        elif shared or note.sync_mode == 'SHARED':
            folder = self.root / 'shared' / 'note'
        elif user:
            folder = self.root / sanitize_user_folder(user) / 'note'
        else:
            folder = self.root / 'shared' / 'note'
        path = folder / filename
        self.write_text(path, note_to_markdown(note), private=private)
        self.write_sidecar(path, note.edited_at, note.edited_by, note.deleted_at)
        note.path = path
        return path

    def mark_deleted(self, path: Path) -> Path:
        """Dot-prefix the file (making it invisible) and stamp deleted_at in sidecar.
        Returns the final path (may differ from input if renamed)."""
        text = self.read_text(path)
        if text is None:
            return path
        now_ms = int(time.time() * 1000)
        sc = self.read_sidecar(path)
        item = parse_task(text) or parse_note(text)
        edited_by = sc.get('edited_by') or (item.edited_by if item else None)

        # Rename to dot-prefixed path if not already
        if path.name.startswith('.'):
            dest = path  # already hidden (was private)
        else:
            dest = path.parent / f'.{path.name}'
            if dest.exists():
                dest.unlink()  # overwrite stale hidden copy
            path.rename(dest)
        # Sidecar path is the same for both path and dest (see _sidecar_path)
        self.write_sidecar(dest, now_ms, edited_by, now_ms)
        return dest

    def load_for_user(self, username: str) -> dict:
        """Load shared items + the named user's items only."""
        shared = self.root / 'shared'
        user_dir = self.root / sanitize_user_folder(username)
        cats = self.load_categories(user_dir) if user_dir.is_dir() else []
        cat_notes: dict[str, list[Note]] = {}
        custom_base = user_dir / 'custom'
        if custom_base.is_dir():
            for cat_dir in sorted(custom_base.iterdir()):
                if cat_dir.is_dir() and not cat_dir.name.startswith('.'):
                    notes = self.load_notes(cat_dir)
                    for n in notes:
                        if n.category is None:
                            n.category = cat_dir.name
                    cat_notes[cat_dir.name] = notes
        return {
            'shared_tasks': self.load_tasks(shared / 'todo'),
            'shared_notes': self.load_notes(shared / 'note'),
            'user_tasks': self.load_tasks(user_dir / 'todo'),
            'user_notes': self.load_notes(user_dir / 'note'),
            'categories': cats,
            'category_notes': cat_notes,
        }


# ── User registry ───────────────────────────────────────────────────────────

def load_web_users(root: Path) -> dict[str, str]:
    """
    Read {root}/.sshmemo_web.meta and return {username: passphrase}.
    Each line format: webuser|username|base64_password
    Returns empty dict if the file does not exist (no logins accepted).
    """
    path = root / _USERS_META
    if not path.exists():
        return {}
    users = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        if len(parts) >= 3 and parts[0] == 'webuser':
            username = parts[1].strip()
            try:
                passphrase = base64.b64decode(parts[2].strip()).decode('utf-8')
            except Exception:
                continue
            if username:
                users[username] = passphrase
    return users


# ── HTML templates ─────────────────────────────────────────────────────────

_STYLE = """<style>
:root{--bg:#f4f4f8;--sur:#ffffff;--sur2:#f0f0f5;--txt:#1a1a2e;--mut:#667;
  --acc:#2274a5;--bdr:#dde;--rad:8px;--sha:0 1px 4px rgba(0,0,0,.1);
  --done-bg:#e8f5e9;--done-txt:#2e7d32;--pri-bg:#f3e5f5;--pri-txt:#7b1fa2;
  --shr-bg:#e3f2fd;--shr-txt:#1565c0;--red:#c62828;--warn-bg:#fff8e1;--warn-txt:#e65100}
@media(prefers-color-scheme:dark){:root{
  --bg:#1e2030;--sur:#282a3a;--sur2:#32354a;--txt:#e4e5ed;--mut:#9496a6;
  --acc:#ffaa44;--bdr:#3c3f52;--sha:0 1px 4px rgba(0,0,0,.4);
  --done-bg:#1b3d1b;--done-txt:#81c784;--pri-bg:#2d1b3d;--pri-txt:#ce93d8;
  --shr-bg:#0d2137;--shr-txt:#90caf9;--red:#ef5350;--warn-bg:#2d2000;--warn-txt:#ffb74d}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--txt);font-size:15px;line-height:1.5}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
nav{background:var(--sur);border-bottom:1px solid var(--bdr);padding:0 16px;display:flex;
  align-items:center;gap:12px;height:52px;position:sticky;top:0;z-index:100;box-shadow:var(--sha)}
nav .brand{font-weight:700;font-size:18px;flex-shrink:0}
nav a{color:var(--txt);font-size:14px;padding:4px 8px;border-radius:4px;white-space:nowrap}
nav a:hover{background:var(--sur2);text-decoration:none}
nav .sp{flex:1}
nav .root-label{font-size:12px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px}
main{max-width:880px;margin:24px auto;padding:0 16px}
h1{font-size:20px;margin-bottom:16px;font-weight:700}
.section{margin-top:24px;margin-bottom:4px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.section h2{font-size:15px;font-weight:600;color:var(--mut);flex-shrink:0}
.card{background:var(--sur);border:1px solid var(--bdr);border-radius:var(--rad);
  padding:10px 14px;margin-bottom:6px;display:flex;align-items:center;gap:10px;box-shadow:var(--sha)}
.card.done{background:var(--done-bg)}
.card.deleted{opacity:.45}
.card-body{flex:1;min-width:0}
.card-title{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card.done .card-title{color:var(--done-txt);text-decoration:line-through}
.card-meta{font-size:12px;color:var(--mut);margin-top:2px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.tag{font-size:11px;padding:1px 7px;border-radius:10px;white-space:nowrap}
.tag-pri{background:var(--pri-bg);color:var(--pri-txt)}
.tag-shr{background:var(--shr-bg);color:var(--shr-txt)}
.tag-done{background:var(--done-bg);color:var(--done-txt)}
.tag-del{background:#f5f5f5;color:#999}
@media(prefers-color-scheme:dark){.tag-del{background:#2a2a2a;color:#666}}
.remind{font-size:12px;background:var(--warn-bg);color:var(--warn-txt);padding:1px 7px;border-radius:10px}
.card-actions{display:flex;gap:5px;flex-shrink:0}
.btn{display:inline-flex;align-items:center;padding:5px 12px;border-radius:6px;font-size:13px;
  font-weight:500;cursor:pointer;border:1px solid transparent;text-decoration:none!important;
  background:var(--sur2);color:var(--txt);border-color:var(--bdr)}
.btn:hover{filter:brightness(.95);text-decoration:none}
.btn-primary{background:var(--acc);color:#fff;border-color:transparent}
.btn-primary:hover{filter:brightness(1.1)}
.btn-danger{background:var(--red);color:#fff;border-color:transparent}
.btn-sm{padding:3px 9px;font-size:12px}
form.il{display:inline}
.flash{padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px}
.flash-ok{background:var(--done-bg);color:var(--done-txt)}
.flash-err{background:#ffebee;color:var(--red)}
@media(prefers-color-scheme:dark){.flash-err{background:#3d1b1b;color:#ef9a9a}}
input,textarea,select{width:100%;padding:8px 10px;border:1px solid var(--bdr);border-radius:6px;
  background:var(--sur2);color:var(--txt);font-size:14px;font-family:inherit}
textarea{resize:vertical;min-height:240px}
.fr{margin-bottom:12px}
.fr label{display:block;font-size:12px;font-weight:600;color:var(--mut);margin-bottom:4px}
.cb-row{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.cb-row input{width:auto}
.item-view{background:var(--sur);border:1px solid var(--bdr);border-radius:var(--rad);padding:20px 24px}
.item-view h1{font-size:22px;margin-bottom:8px}
.item-meta{font-size:13px;color:var(--mut);margin-bottom:16px;display:flex;flex-wrap:wrap;gap:8px}
.content p{margin-bottom:10px}.content ul,.content ol{padding-left:20px;margin-bottom:10px}
.content h1,.content h2,.content h3,.content h4{margin:14px 0 6px;font-weight:600}
.content code{background:var(--sur2);padding:1px 5px;border-radius:3px;font-size:13px}
.content pre{background:var(--sur2);padding:12px;border-radius:6px;overflow-x:auto;margin-bottom:10px}
.content pre code{background:none;padding:0}
.content blockquote{border-left:3px solid var(--bdr);padding-left:12px;color:var(--mut)}
.content table{border-collapse:collapse;width:100%;margin-bottom:10px}
.content th,.content td{border:1px solid var(--bdr);padding:6px 10px;text-align:left}
.content th{background:var(--sur2)}
.content h5,.content h6{margin:12px 0 4px;font-weight:600}
.content a{color:var(--acc)}
.content img{max-width:100%;border-radius:6px;display:block;margin:8px 0}
.attach-section{margin-top:20px;border-top:1px solid var(--bdr);padding-top:14px}
.attach-label{font-size:12px;font-weight:600;color:var(--mut);margin-bottom:10px;text-transform:uppercase;letter-spacing:.5px}
.attach-item{margin-bottom:12px}
.attach-img{max-width:100%;border-radius:6px;display:block;margin-bottom:4px}
.attach-name{font-size:12px;color:var(--mut);margin-top:2px}
audio{width:100%;margin-bottom:4px}
.empty{color:var(--mut);font-size:13px;padding:6px 0}
.cat-stripe{border-left-width:3px;border-left-style:solid}
</style>"""

_NAV = """<nav>
  <span class="brand">🗒 SSHMemo</span>
  <a href="{{ url_for('index') }}">Dashboard</a>
  <a href="{{ url_for('new_task') }}">+ Task</a>
  <a href="{{ url_for('new_note') }}">+ Note</a>
  <a href="{{ url_for('history') }}">History</a>
  <span class="sp"></span>
  <span class="root-label">{{ root_label }}</span>
  {% if current_user %}
  <span style="font-size:13px;color:var(--mut)">👤 {{ current_user }}</span>
  <form class="il" method="post" action="{{ url_for('logout') }}">
    <button class="btn btn-sm" style="font-size:12px">Log out</button>
  </form>
  {% endif %}
</nav>"""

_BASE = _STYLE + _NAV

_LOGIN = _STYLE + """
<main style="max-width:380px;margin:80px auto;padding:0 16px">
  <div style="text-align:center;margin-bottom:28px">
    <div style="font-size:40px;margin-bottom:8px">🗒</div>
    <h1 style="font-size:22px">SSHMemo</h1>
    <p style="color:var(--mut);font-size:14px;margin-top:4px">{{ subtitle }}</p>
  </div>
  {% if no_users %}
  <div class="flash flash-err">
    No users are configured. Set up web access from the SSHMemo app first.
  </div>
  {% else %}
  {{ flash | safe }}
  <div style="background:var(--sur);border:1px solid var(--bdr);border-radius:var(--rad);padding:24px;box-shadow:var(--sha)">
    <form method="post" action="{{ url_for('login') }}">
      <div class="fr"><label>Username</label>
        <input type="text" name="username" autocomplete="username" autofocus required>
      </div>
      <div class="fr"><label>Password (note passphrase)</label>
        <input type="password" name="password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;margin-top:4px">Sign in</button>
    </form>
  </div>
  {% endif %}
</main>"""

_INDEX = _BASE + """
<main>
<h1>Dashboard</h1>
{{ flash | safe }}

{# ── Shared ── #}
{% set st = data.shared_tasks | selectattr('deleted_at', 'none') | list %}
{% set sn = data.shared_notes | selectattr('deleted_at', 'none') | list %}
{% if st or sn %}
<div class="section"><h2>🌐 Shared</h2></div>
{% for task in st %}
<div class="card {{ 'done' if task.done }}">
  <div class="card-body">
    <div class="card-title"><a href="{{ url_for('view', rel=rrel(task.path), type='task') }}">{{ task.title }}</a></div>
    <div class="card-meta">
      <span class="tag tag-shr">shared</span>
      {% if task.remind_at %}<span class="remind">⏰ {{ task.remind_at | disp }}</span>{% endif %}
      {% if task.edited_by %}<span>{{ task.edited_by }}</span>{% endif %}
    </div>
  </div>
  <div class="card-actions">
    <form class="il" method="post" action="{{ url_for('toggle') }}">
      <input type="hidden" name="rel" value="{{ rrel(task.path) }}">
      <button class="btn btn-sm">{{ '☑' if task.done else '☐' }}</button>
    </form>
    <a class="btn btn-sm" href="{{ url_for('edit', rel=rrel(task.path), type='task') }}">Edit</a>
  </div>
</div>
{% endfor %}
{% for note in sn %}
<div class="card">
  <div class="card-body">
    <div class="card-title"><a href="{{ url_for('view', rel=rrel(note.path), type='note') }}">{{ note.title }}</a></div>
    <div class="card-meta">
      <span class="tag tag-shr">shared</span>
      {% if note.remind_at %}<span class="remind">⏰ {{ note.remind_at | disp }}</span>{% endif %}
      {% if note.edited_by %}<span>{{ note.edited_by }}</span>{% endif %}
    </div>
  </div>
  <div class="card-actions">
    <a class="btn btn-sm" href="{{ url_for('edit', rel=rrel(note.path), type='note') }}">Edit</a>
  </div>
</div>
{% endfor %}
{% endif %}

{# ── My Tasks ── #}
{% set utasks = data.user_tasks | selectattr('deleted_at', 'none') | list %}
{% set unotes = data.user_notes | selectattr('deleted_at', 'none') | list %}
<div class="section">
  <h2>☑ My Tasks</h2>
  <a class="btn btn-sm btn-primary" href="{{ url_for('new_task') }}">+ Task</a>
</div>
{% for task in utasks %}
<div class="card {{ 'done' if task.done }}">
  <div class="card-body">
    <div class="card-title"><a href="{{ url_for('view', rel=rrel(task.path), type='task') }}">{{ task.title }}</a></div>
    <div class="card-meta">
      {% if task.sync_mode == 'PRIVATE' %}<span class="tag tag-pri">🔒 private</span>{% endif %}
      {% if task.remind_at %}<span class="remind">⏰ {{ task.remind_at | disp }}</span>{% endif %}
      {% if task.edited_by %}<span>{{ task.edited_by }}</span>{% endif %}
    </div>
  </div>
  <div class="card-actions">
    <form class="il" method="post" action="{{ url_for('toggle') }}">
      <input type="hidden" name="rel" value="{{ rrel(task.path) }}">
      <button class="btn btn-sm">{{ '☑' if task.done else '☐' }}</button>
    </form>
    <a class="btn btn-sm" href="{{ url_for('edit', rel=rrel(task.path), type='task') }}">Edit</a>
  </div>
</div>
{% endfor %}
{% if not utasks %}<p class="empty">No tasks yet.</p>{% endif %}

{# ── My Notes ── #}
<div class="section">
  <h2>✎ My Notes</h2>
  <a class="btn btn-sm" href="{{ url_for('new_note') }}">+ Note</a>
</div>
{% for note in unotes %}
<div class="card">
  <div class="card-body">
    <div class="card-title"><a href="{{ url_for('view', rel=rrel(note.path), type='note') }}">{{ note.title }}</a></div>
    <div class="card-meta">
      {% if note.sync_mode == 'PRIVATE' %}<span class="tag tag-pri">🔒 private</span>{% endif %}
      {% if note.remind_at %}<span class="remind">⏰ {{ note.remind_at | disp }}</span>{% endif %}
      {% if note.edited_by %}<span>{{ note.edited_by }}</span>{% endif %}
    </div>
  </div>
  <div class="card-actions">
    <a class="btn btn-sm" href="{{ url_for('edit', rel=rrel(note.path), type='note') }}">Edit</a>
  </div>
</div>
{% endfor %}
{% if not unotes %}<p class="empty">No notes yet.</p>{% endif %}

{# ── Categories ── #}
{% for cat_name, cnotes in data.category_notes.items() %}
{% set active = cnotes | selectattr('deleted_at', 'none') | list %}
{% if active %}
{% set cat = data.categories | selectattr('name', 'equalto', cat_name) | first | default(None) %}
<div class="section" style="margin-left:14px">
  <h2>{{ cat.icon if cat else '📁' }} {{ cat_name }}</h2>
  <a class="btn btn-sm" href="{{ url_for('new_note', category=cat_name) }}">+ Note</a>
</div>
{% for note in active %}
<div class="card{% if cat and cat.color %} cat-stripe{% endif %}"
     {% if cat and cat.color %}style="border-left-color:{{ cat.color }};margin-left:14px"{% else %}style="margin-left:14px"{% endif %}>
  <div class="card-body">
    <div class="card-title"><a href="{{ url_for('view', rel=rrel(note.path), type='note') }}">{{ note.title }}</a></div>
    <div class="card-meta">
      {% if note.remind_at %}<span class="remind">⏰ {{ note.remind_at | disp }}</span>{% endif %}
      {% if note.edited_by %}<span>{{ note.edited_by }}</span>{% endif %}
    </div>
  </div>
  <div class="card-actions">
    <a class="btn btn-sm" href="{{ url_for('edit', rel=rrel(note.path), type='note') }}">Edit</a>
  </div>
</div>
{% endfor %}
{% endif %}
{% endfor %}
</main>"""

_VIEW = _BASE + """
<main>
{{ flash | safe }}
<div class="item-view">
  <div style="display:flex;gap:8px;margin-bottom:14px">
    {% if type == 'task' %}
    <form class="il" method="post" action="{{ url_for('toggle') }}">
      <input type="hidden" name="rel" value="{{ rel }}">
      <input type="hidden" name="next" value="{{ url_for('view', rel=rel, type='task') }}">
      <button class="btn">{{ '☑ Mark undone' if item.done else '☐ Mark done' }}</button>
    </form>
    {% endif %}
    <a class="btn" href="{{ url_for('edit', rel=rel, type=type) }}">✏ Edit</a>
    <a class="btn" href="{{ url_for('index') }}">← Back</a>
  </div>
  <h1>{{ item.title }}</h1>
  <div class="item-meta">
    {% if item.done %}<span class="tag tag-done">✓ Done</span>{% endif %}
    {% if item.sync_mode == 'PRIVATE' %}<span class="tag tag-pri">🔒 Private</span>{% endif %}
    {% if item.sync_mode == 'SHARED' %}<span class="tag tag-shr">🌐 Shared</span>{% endif %}
    {% if item.category %}<span class="tag" style="background:var(--sur2)">📁 {{ item.category }}</span>{% endif %}
    {% if item.remind_at %}<span class="remind">⏰ {{ item.remind_at | disp }}</span>{% endif %}
    {% if item.edited_by %}<span>by {{ item.edited_by }}</span>{% endif %}
    {% if item.edited_at %}<span>{{ item.edited_at | eddate }}</span>{% endif %}
  </div>
  <div class="content">{{ content_html | safe }}</div>
  {% if item.attachments %}
  <div class="attach-section">
    <div class="attach-label">Attachments</div>
    {% for a in item.attachments %}
    <div class="attach-item">
      {% if a.mime_type.startswith('image/') %}
      <img class="attach-img" src="{{ url_for('serve_attachment', rel=rel, name=a.remote_name) }}" alt="{{ a.remote_name }}">
      <div class="attach-name">{{ a.remote_name }}</div>
      {% elif a.mime_type.startswith('audio/') %}
      <audio controls src="{{ url_for('serve_attachment', rel=rel, name=a.remote_name) }}"></audio>
      <div class="attach-name">{{ a.remote_name }}</div>
      {% elif a.mime_type.startswith('video/') %}
      <video controls style="max-width:100%;border-radius:6px" src="{{ url_for('serve_attachment', rel=rel, name=a.remote_name) }}"></video>
      <div class="attach-name">{{ a.remote_name }}</div>
      {% else %}
      <a class="btn" href="{{ url_for('serve_attachment', rel=rel, name=a.remote_name) }}" download="{{ a.remote_name }}">⬇ {{ a.remote_name }}</a>
      {% endif %}
    </div>
    {% endfor %}
  </div>
  {% endif %}
</div>
</main>"""

_EDIT = _BASE + """
<main>
<h1>{{ 'Edit' if is_edit else 'New' }} {{ 'Task' if type == 'task' else 'Note' }}</h1>
{{ flash | safe }}
<form method="post">
  <div class="fr"><label>Title</label>
    <input type="text" name="title" value="{{ item.title }}" required autofocus>
  </div>
  <div class="fr"><label>{{ 'Description' if type == 'task' else 'Content' }} (Markdown)</label>
    <textarea name="body">{{ item.description if type == 'task' else item.content }}</textarea>
  </div>
  {% if type == 'task' %}
  <div class="cb-row">
    <input type="checkbox" name="done" id="done" {{ 'checked' if item.done }}>
    <label for="done" style="font-weight:normal;font-size:14px">Done</label>
  </div>
  {% endif %}
  <div class="fr"><label>Reminder — YYYY-MM-DDTHH:MM (leave blank for none)</label>
    <input type="text" name="remind_at"
           value="{{ item.remind_at | stamp if item.remind_at else '' }}"
           placeholder="e.g. 2026-06-01T09:00">
  </div>
  <div class="fr"><label>Sync mode</label>
    <select name="sync_mode">
      <option value="NORMAL"   {{ 'selected' if item.sync_mode == 'NORMAL' }}>Normal (personal)</option>
      <option value="SHARED"   {{ 'selected' if item.sync_mode == 'SHARED' }}>Shared</option>
      <option value="PRIVATE"  {{ 'selected' if item.sync_mode == 'PRIVATE' }}>Private (encrypted)</option>
      <option value="DISABLED" {{ 'selected' if item.sync_mode == 'DISABLED' }}>Disabled (local only)</option>
    </select>
  </div>
  {% if type == 'note' and categories %}
  <div class="fr"><label>Category</label>
    <select name="category">
      <option value="">— none —</option>
      {% for cat in categories %}
      <option value="{{ cat.name }}" {{ 'selected' if item.category == cat.name }}>
        {{ cat.icon }} {{ cat.name }}
      </option>
      {% endfor %}
    </select>
  </div>
  {% endif %}
  <div class="fr"><label>Edited by</label>
    <input type="text" name="edited_by" value="{{ item.edited_by or default_user or '' }}" placeholder="your name / handle">
  </div>
  <input type="hidden" name="user" value="{{ user or '' }}">
  {% if is_edit %}<input type="hidden" name="rel" value="{{ rel }}">{% endif %}
  <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
    <button type="submit" class="btn btn-primary">💾 Save</button>
    <a class="btn" href="{{ url_for('index') }}">Cancel</a>
  </div>
</form>
{% if is_edit %}
<form method="post" action="{{ url_for('delete') }}" style="display:inline;margin-top:10px"
      onsubmit="return confirm('Mark this item as deleted?')">
  <input type="hidden" name="rel" value="{{ rel }}">
  <input type="hidden" name="type" value="{{ type }}">
  <button type="submit" class="btn btn-danger btn-sm" style="margin-top:10px">🗑 Mark deleted</button>
</form>
{% endif %}
</main>"""

_HISTORY = _BASE + """
<main>
<h1>History</h1>
{{ flash | safe }}
<p style="font-size:13px;color:var(--mut);margin-bottom:16px">
  Deleted items on this server. Restoring creates a new copy that will sync to all devices.
  If a file with the same name already exists you will be warned before overwriting.
</p>

{% set del_tasks = (data.user_tasks + data.shared_tasks) | rejectattr('deleted_at', 'none') | list %}
{% set del_notes = (data.user_notes + data.shared_notes) | rejectattr('deleted_at', 'none') | list %}
{% set del_cat_notes = [] %}
{% for cat_name, cnotes in data.category_notes.items() %}
  {% set _ = del_cat_notes.extend(cnotes | rejectattr('deleted_at', 'none') | list) %}
{% endfor %}

{% if not del_tasks and not del_notes and not del_cat_notes %}
<p class="empty" style="margin-top:24px">No deleted items.</p>
{% endif %}

{% if del_tasks %}
<div class="section"><h2>☑ Tasks</h2></div>
{% for task in del_tasks %}
<div class="card deleted">
  <div class="card-body">
    <div class="card-title">{{ task.title }}</div>
    <div class="card-meta">
      {% if task.done %}<span class="tag tag-done">✓ Done</span>{% endif %}
      {% if task.deleted_at %}<span>deleted {{ task.deleted_at | eddate }}</span>{% endif %}
      {% if task.edited_by %}<span>by {{ task.edited_by }}</span>{% endif %}
    </div>
  </div>
  <div class="card-actions">
    <form class="il" method="post" action="{{ url_for('restore') }}"
          onsubmit="return confirm('Restore? It will sync to all devices as a new item.')">
      <input type="hidden" name="rel" value="{{ rrel(task.path) }}">
      <button class="btn btn-sm btn-primary">↩ Restore</button>
    </form>
  </div>
</div>
{% endfor %}
{% endif %}

{% if del_notes or del_cat_notes %}
<div class="section"><h2>✎ Notes</h2></div>
{% for note in del_notes + del_cat_notes %}
<div class="card deleted">
  <div class="card-body">
    <div class="card-title">{{ note.title }}</div>
    <div class="card-meta">
      {% if note.category %}<span class="tag" style="background:var(--sur2)">📁 {{ note.category }}</span>{% endif %}
      {% if note.deleted_at %}<span>deleted {{ note.deleted_at | eddate }}</span>{% endif %}
      {% if note.edited_by %}<span>by {{ note.edited_by }}</span>{% endif %}
    </div>
  </div>
  <div class="card-actions">
    <form class="il" method="post" action="{{ url_for('restore') }}"
          onsubmit="return confirm('Restore? It will sync to all devices as a new item.')">
      <input type="hidden" name="rel" value="{{ rrel(note.path) }}">
      <button class="btn btn-sm btn-primary">↩ Restore</button>
    </form>
  </div>
</div>
{% endfor %}
{% endif %}
</main>"""


# ── Flask app factory ───────────────────────────────────────────────────────

def create_app(root: Path) -> Flask:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)
    # Trust X-Forwarded-* headers from one reverse proxy (nginx).
    # x_prefix reads X-Forwarded-Prefix and sets SCRIPT_NAME so that
    # url_for() and redirects include the subpath when proxied under a prefix.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    def get_store() -> FileStore:
        username = session.get('username', '')
        passphrase = load_web_users(root).get(username)
        return FileStore(root, passphrase)

    def require_login(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if not session.get('username'):
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapped

    def render_md(text: str) -> str:
        return md_lib.markdown(text, extensions=['extra', 'nl2br'])

    def rewrite_attach_urls(body: str, rel: str) -> str:
        """Rewrite relative attachment links (slug/filename) embedded in markdown to the /attachment route."""
        stem = rel.rsplit('/', 1)[-1] if '/' in rel else rel
        if stem.endswith('.md'):
            stem = stem[:-3]
        stem = stem.lstrip('.')
        if not stem:
            return body
        return re.sub(
            r'\(' + re.escape(stem) + r'/([^)\s]+)\)',
            lambda m: f'(/attachment?rel={rel}&name={m.group(1)})',
            body,
        )

    def rrel(path: Optional[Path]) -> str:
        return str(path.relative_to(root)) if path else ''

    def flash_msg() -> str:
        from markupsafe import escape
        ok = request.args.get('ok')
        err = request.args.get('err')
        if ok:
            return f'<div class="flash flash-ok">{escape(ok)}</div>'
        if err:
            return f'<div class="flash flash-err">{escape(err)}</div>'
        return ''

    def ctx() -> dict:
        username = session.get('username', '')
        return dict(root_label=str(root), rrel=rrel,
                    current_user=username, default_user=username)

    # Template filters
    @app.template_filter('disp')
    def f_disp(v): return format_reminder_display(v) if v else ''

    @app.template_filter('stamp')
    def f_stamp(v): return format_reminder_stamp(v) if v else ''

    @app.template_filter('eddate')
    def f_eddate(v): return f"edited {format_edited_display(v)}" if v else ''

    @app.template_filter('urlencode')
    def f_urlencode(v):
        from urllib.parse import quote
        return quote(str(v), safe='')

    # ── Auth routes ────────────────────────────────────────────────────────

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        users = load_web_users(root)
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            if username in users and hmac.compare_digest(users[username], password):
                session['username'] = username
                return redirect(url_for('index'))
            flash_html = '<div class="flash flash-err">Invalid username or password.</div>'
            return render_template_string(_LOGIN,
                                          subtitle='Sign in to access your items',
                                          no_users=False, flash=flash_html)
        return render_template_string(_LOGIN,
                                      subtitle='Sign in to access your items',
                                      no_users=not users, flash='')

    @app.route('/logout', methods=['POST'])
    def logout():
        session.clear()
        return redirect(url_for('login'))

    # ── Routes ─────────────────────────────────────────────────────────────

    @app.route('/')
    @require_login
    def index():
        store = get_store()
        return render_template_string(_INDEX, data=store.load_for_user(session['username']),
                                      flash=flash_msg(), **ctx())

    @app.route('/view')
    @require_login
    def view():
        store = get_store()
        rel = request.args.get('rel', '')
        itype = request.args.get('type', 'note')
        path = store.safe_abs(rel)
        text = store.read_text(path)
        if text is None:
            abort(404)
        item = parse_task(text) if itype == 'task' else parse_note(text)
        if item is None:
            abort(404)
        body = item.description if itype == 'task' else item.content
        body = rewrite_attach_urls(body, rel)
        return render_template_string(_VIEW, item=item, type=itype,
                                      rel=rel, content_html=render_md(body),
                                      flash=flash_msg(), **ctx())

    @app.route('/attachment')
    @require_login
    def serve_attachment():
        import mimetypes
        from flask import Response
        store = get_store()
        rel = request.args.get('rel', '')
        name = request.args.get('name', '')
        # Reject empty or path-traversal attempts in name
        if not rel or not name or '/' in name or '\\' in name or '..' in name:
            abort(400)
        md_path = store.safe_abs(rel)
        stem = md_path.name
        if stem.endswith('.md'):
            stem = stem[:-3]
        stem = stem.lstrip('.')
        attach_path = (md_path.parent / stem / name).resolve()
        # Safety: must stay inside root
        if not str(attach_path).startswith(str(root.resolve())):
            abort(403)
        if not attach_path.is_file():
            abort(404)
        mime, _ = mimetypes.guess_type(name)
        return Response(attach_path.read_bytes(), mimetype=mime or 'application/octet-stream')

    @app.route('/new/task', methods=['GET', 'POST'])
    @require_login
    def new_task():
        store = get_store()
        username = session['username']
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            if not title:
                return redirect(url_for('new_task', err='Title is required'))
            task = Task(
                title=title,
                description=request.form.get('body', '').strip(),
                done='done' in request.form,
                sync_mode=request.form.get('sync_mode', 'NORMAL'),
                remind_at=parse_reminder_stamp(request.form.get('remind_at', '')),
                edited_by=request.form.get('edited_by', '').strip() or None,
            )
            try:
                store.write_task(task, user=username, shared=task.sync_mode == 'SHARED')
                return redirect(url_for('index', ok=f'Task "{title}" created'))
            except Exception as e:
                return redirect(url_for('new_task', err=str(e)))
        item = Task(title='', sync_mode='NORMAL', edited_by=username)
        return render_template_string(_EDIT, item=item, type='task', is_edit=False,
                                      rel=None, user=username, categories=[],
                                      flash=flash_msg(), **ctx())

    @app.route('/new/note', methods=['GET', 'POST'])
    @require_login
    def new_note():
        store = get_store()
        username = session['username']
        category = request.args.get('category', '') or request.form.get('category', '')
        cats = store.load_categories(root / sanitize_user_folder(username))
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            if not title:
                return redirect(url_for('new_note', err='Title is required'))
            note = Note(
                title=title,
                content=request.form.get('body', '').strip(),
                sync_mode=request.form.get('sync_mode', 'NORMAL'),
                remind_at=parse_reminder_stamp(request.form.get('remind_at', '')),
                edited_by=request.form.get('edited_by', '').strip() or None,
                category=request.form.get('category', '').strip() or None,
            )
            try:
                store.write_note(note, user=username, shared=note.sync_mode == 'SHARED')
                return redirect(url_for('index', ok=f'Note "{title}" created'))
            except Exception as e:
                return redirect(url_for('new_note', err=str(e)))
        item = Note(title='', sync_mode='NORMAL', category=category or None,
                    edited_by=username)
        return render_template_string(_EDIT, item=item, type='note', is_edit=False,
                                      rel=None, user=username, categories=cats,
                                      flash=flash_msg(), **ctx())

    @app.route('/edit', methods=['GET', 'POST'])
    @require_login
    def edit():
        store = get_store()
        username = session['username']
        rel = request.args.get('rel') or request.form.get('rel', '')
        itype = request.args.get('type') or request.form.get('type', 'note')
        path = store.safe_abs(rel)
        text = store.read_text(path)
        if text is None:
            abort(404)
        cats = store.load_categories(root / sanitize_user_folder(username))

        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            if not title:
                return redirect(url_for('edit', rel=rel, type=itype, err='Title is required'))
            sync_mode = request.form.get('sync_mode', 'NORMAL')
            remind_at = parse_reminder_stamp(request.form.get('remind_at', ''))
            edited_by = request.form.get('edited_by', '').strip() or None
            now_ms = int(time.time() * 1000)
            private = sync_mode == 'PRIVATE'
            sc = store.read_sidecar(path)
            old_deleted_at = sc.get('deleted_at')
            if itype == 'task':
                old = parse_task(text)
                if old_deleted_at is None:
                    old_deleted_at = old.deleted_at if old else None
                task = Task(
                    title=title,
                    description=request.form.get('body', '').strip(),
                    done='done' in request.form,
                    sync_mode=sync_mode,
                    remind_at=remind_at,
                    edited_at=now_ms,
                    deleted_at=old_deleted_at,
                    attachments=old.attachments if old else [],
                    edited_by=edited_by,
                )
                store.write_text(path, task_to_markdown(task), private=private)
                store.write_sidecar(path, now_ms, edited_by, old_deleted_at)
            else:
                old = parse_note(text)
                if old_deleted_at is None:
                    old_deleted_at = old.deleted_at if old else None
                cat = request.form.get('category', '').strip() or None
                note = Note(
                    title=title,
                    content=request.form.get('body', '').strip(),
                    sync_mode=sync_mode,
                    remind_at=remind_at,
                    edited_at=now_ms,
                    deleted_at=old_deleted_at,
                    attachments=old.attachments if old else [],
                    category=cat,
                    edited_by=edited_by,
                )
                store.write_text(path, note_to_markdown(note), private=private)
                store.write_sidecar(path, now_ms, edited_by, old_deleted_at)
            return redirect(url_for('index', ok=f'{title} saved'))

        item = parse_task(text) if itype == 'task' else parse_note(text)
        if item is None:
            abort(404)
        return render_template_string(_EDIT, item=item, type=itype, is_edit=True,
                                      rel=rel, user=username, categories=cats,
                                      flash=flash_msg(), **ctx())

    @app.route('/toggle', methods=['POST'])
    @require_login
    def toggle():
        store = get_store()
        rel = request.form.get('rel', '')
        path = store.safe_abs(rel)
        text = store.read_text(path)
        if text is None:
            abort(404)
        task = parse_task(text)
        if task is None:
            abort(400)
        task.done = not task.done
        task.edited_at = int(time.time() * 1000)
        store.write_text(path, task_to_markdown(task), private=path.name.startswith('.'))
        next_url = request.form.get('next') or url_for('index')
        return redirect(next_url)

    @app.route('/delete', methods=['POST'])
    @require_login
    def delete():
        store = get_store()
        rel = request.form.get('rel', '')
        path = store.safe_abs(rel)
        store.mark_deleted(path)
        return redirect(url_for('history', ok='Item moved to history'))

    @app.route('/history')
    @require_login
    def history():
        store = get_store()
        return render_template_string(_HISTORY, data=store.load_for_user(session['username']),
                                      flash=flash_msg(), **ctx())

    @app.route('/restore', methods=['POST'])
    @require_login
    def restore():
        store = get_store()
        rel = request.form.get('rel', '')
        path = store.safe_abs(rel)
        if not path.name.startswith('.'):
            return redirect(url_for('history', err='Not a deleted item'))
        # Compute restored path by stripping the leading dot
        restored = path.parent / path.name[1:]
        if restored.exists():
            title = restored.name
            return redirect(url_for('history',
                                    err=f'"{title}" already exists — edit or delete it first'))
        path.rename(restored)
        sc = store.read_sidecar(restored)
        store.write_sidecar(restored,
                            edited_at=int(time.time() * 1000),
                            edited_by=sc.get('edited_by'),
                            deleted_at=None)
        return redirect(url_for('index', ok=f'{restored.stem} restored'))

    return app


# ── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="sshmemo-server — Web UI for SSHMemo markdown files",
        epilog="Run from the SSHMemo root directory: sshmemo [--port 8080]",
    )
    parser.add_argument('--host', default='0.0.0.0',
                        help='Bind host (default: 0.0.0.0 — all interfaces)')
    parser.add_argument('--port', type=int, default=8080,
                        help='Port (default: 8080)')
    parser.add_argument('--root', default='.',
                        help='SSHMemo root directory (default: current directory)')
    parser.add_argument('--debug', action='store_true',
                        help='Flask debug mode')
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        raise SystemExit(f"Root directory not found: {root}")

    if not CRYPTO_AVAILABLE:
        print("WARNING: 'cryptography' not installed — private files unreadable. pip install cryptography")

    users = load_web_users(root)
    if not users:
        print(f"NOTE: No web users configured.")
        print(f"  Create {root / _USERS_META} with lines:")
        print(f"  webuser|<username>|<base64_of_passphrase>")
        print(f"  (No logins will be accepted until users are configured.)")
    else:
        print(f"Web users: {', '.join(users)}")

    app = create_app(root=root)
    print(f"SSHMemo server → http://{args.host}:{args.port}")
    print(f"  Root: {root}")
    print(f"  Subpath proxying: set X-Forwarded-Prefix in nginx (already handled automatically)")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
