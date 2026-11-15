#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backupd — сервер резервного копирования файлов на базе rsync.

Источником является Linux-сервер, целью — Windows-машина
(SMB-шара или SSH + rsync), либо локальный каталог (для тестов).

Возможности (по аналогии с rsnapshot / backupninja):
  * инкрементальные снапшоты через rsync --link-dest (жёсткие ссылки);
  * режимы: инкрементальный, полный, зеркало;
  * расписание: вручную / каждые N минут / ежедневно / раз в неделю;
  * политики удержания (последние N дней / недель / месяцев);
  * исключаемые файлы, сжатие, ограничение скорости, проверка контрольных сумм;
  * HTML-интерфейс для управления заданиями и просмотра журнала.

Запуск:
  python3 backupd.py --port 8420 --data-dir /var/lib/backupd
  python3 backupd.py -v          # расширенное логирование в консоль
  python3 backupd.py -vv         # максимальная детализация (HTTP, состояние)
  # -v / -vv включают также расширенное логирование FTP в журнал заданий:
  # детали предпроверки (DNS, TCP, баннер) и протокол подключения lftp;
  # подробные операции mirror: без ключей не пишутся в журнал заданий
  # (lftp при этом запускается с --verbose=2 — только чтобы по выводу
  # считать процент прогресса копирования для GUI),
  # с -v — только директорные, с -vv — и файловые
"""

import argparse
import base64
import fnmatch
import hashlib
import hmac
import json
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import urllib.request
from urllib.parse import parse_qs, quote

APP_VERSION = "1.0"
BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
TS_FMT = "%Y%m%d_%H%M%S"
SNAP_RE = re.compile(r"^\d{8}_\d{6}$")

DATA_DIR = None   # устанавливается в main()
CONFIG = None
STATE = None
START_TIME = time.time()
RUNNING = {}      # job_id -> Popen
RUN_LOCKS = {}    # job_id -> threading.Lock
MOUNT_LOCKS = {}  # mount_id -> threading.Lock (последовательные mount на одну точку)
VERBOSE = 0       # логирование в консоль: 0 — выкл, 1 — -v, 2 — -vv
SUDO = []         # ["sudo"], если сервер запущен с --use-sudo

SESSIONS = {}     # токен сессии -> время истечения (epoch)
SESSION_TTL = 12 * 3600  # срок действия сессии, с (12 часов)


def hash_password(pw, salt=None):
    """Хеш пароля (scrypt, стандартная библиотека). Формат: соль$хеш (hex)."""
    salt = salt or os.urandom(16)
    h = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
    return salt.hex() + "$" + h.hex()


def check_password(pw, stored):
    try:
        salt_hex, _, h_hex = stored.partition("$")
        salt = bytes.fromhex(salt_hex)
        h = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
        return hmac.compare_digest(h.hex(), h_hex)
    except Exception:
        return False


def clog(level, msg):
    """Выводит сообщение в консоль (только при запуске с -v / -vv).

    Уровни: DEBUG — только при -vv; INFO / WARN / ERROR / JOB — при -v.
    """
    if VERBOSE == 0:
        return
    need = 2 if level == "DEBUG" else 1
    if VERBOSE < need:
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {level:<5} {msg}", flush=True)


# --------------------------------------------------------------------------
# Конфигурация
# --------------------------------------------------------------------------

class Config:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.data = {"auth_token": "", "jobs": []}
        if path.exists():
            try:
                self.data.update(json.loads(path.read_text(encoding="utf-8")))
            except Exception as e:
                sys.exit(f"Ошибка чтения {path}: {e}")
        self.data.setdefault("auth_token", "")
        self.data.setdefault("password_hash", "")
        self.data.setdefault("jobs", [])
        # push-уведомления (ntfy): включены/выключены, адрес сервера
        # (публичный ntfy.sh или свой в локальной сети), топик — случайный,
        # его нужно вписать в приложение-клиент на устройстве
        nt = self.data.setdefault("notify", {})
        nt.setdefault("enabled", False)
        nt.setdefault("url", "https://ntfy.sh")
        if not nt.get("topic"):
            nt["topic"] = "backupd-" + uuid.uuid4().hex[:8]
        clog("INFO", f"Конфигурация загружена: {path} "
              f"(заданий: {len(self.data['jobs'])}, "
              f"пароль доступа: "
              f"{'вкл' if self.data.get('password_hash') else 'выкл'})")

    def save(self):
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            tmp.replace(self.path)
            clog("DEBUG", f"Конфигурация сохранена: {self.path}")

    @property
    def jobs(self):
        return self.data["jobs"]

    def find_job(self, job_id):
        for j in self.data["jobs"]:
            if j.get("id") == job_id:
                return j
        return None

    def upsert_job(self, job):
        with self.lock:
            for i, j in enumerate(self.data["jobs"]):
                if j.get("id") == job.get("id"):
                    self.data["jobs"][i] = job
                    break
            else:
                self.data["jobs"].append(job)
            self.save()

    def remove_job(self, job_id):
        with self.lock:
            self.data["jobs"] = [j for j in self.data["jobs"]
                                 if j.get("id") != job_id]
            self.save()


# --------------------------------------------------------------------------
# Состояние (последний запуск, следующий запуск, история)
# --------------------------------------------------------------------------

class State:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.data = {"jobs": {}, "history": []}
        if path.exists():
            try:
                self.data.update(json.loads(path.read_text(encoding="utf-8")))
            except Exception:
                pass
        self.data.setdefault("jobs", {})
        self.data.setdefault("history", [])

    def save(self):
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            tmp.replace(self.path)
            clog("DEBUG", f"Состояние сохранено: {self.path}")

    def get(self, job_id):
        with self.lock:
            return self.data["jobs"].setdefault(job_id, {
                "running": False,
                "started_at": None,     # epoch: начало текущего прогона
                "last_run": None,
                "last_status": None,     # ok | error
                "last_error": None,
                "last_duration": None,   # секунды
                "last_size": None,       # байты
                "next_run": None,        # epoch
            })

    def update(self, job_id, **kw):
        with self.lock:
            self.data["jobs"].setdefault(job_id, {}).update(kw)
            self.save()

    def add_history(self, entry):
        with self.lock:
            self.data["history"].insert(0, entry)
            self.data["history"] = self.data["history"][:200]
            self.save()


# --------------------------------------------------------------------------
# Журнал задания
# --------------------------------------------------------------------------

class JobLog:
    def __init__(self, path: Path, label=None):
        self.path = path
        self.label = label or path.stem
        self.lock = threading.Lock()

    def write(self, line):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {line}"
        with self.lock:
            if self.path.exists() and self.path.stat().st_size > 5_000_000:
                data = self.path.read_text(encoding="utf-8", errors="replace")
                self.path.write_text(data[-1_000_000:], encoding="utf-8")
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        # зеркалируем строку в консоль (при -v) — без дубля таймстампа
        clog("JOB", f"[{self.label}] {line[len('[%s] ' % ts):]}")

    def tail(self, n=400):
        if not self.path.exists():
            return ""
        lines = self.path.read_text(encoding="utf-8",
                                    errors="replace").splitlines()
        return "\n".join(lines[-n:])


def job_log(job_id, name=None):
    return JobLog(DATA_DIR / "logs" / (job_id + ".log"), name)


# --------------------------------------------------------------------------
# Цели копирования
# --------------------------------------------------------------------------

def parse_smb(p):
    """Разбирает адрес SMB-шары.

    Возвращает (share, subpath): share — //сервер/шара (для mount),
    subpath — путь внутри шары (без ведущего '/'), может быть пустым.
    """
    p = p.strip()
    if p.lower().startswith("smb://"):
        p = p[6:]
    if "\\" in p and "//" not in p:
        host, _, rest = p.partition("\\")
        p = "//" + host + "/" + rest.replace("\\", "/")
    if not p.startswith("//"):
        p = "//" + p
    parts = [x for x in p[2:].split("/") if x]
    if len(parts) < 2:
        return p, ""
    return "//" + parts[0] + "/" + parts[1], "/".join(parts[2:])


def win_quote(p):
    """Кавычки для cmd.exe (удалённый shell на Windows при SSH)."""
    return '"' + p.replace('"', '\\"') + '"'


def ssh_argv(end):
    return ["ssh", f"-p {int(end.get('port') or 22)}",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15",
            f"{end['user']}@{end['host']}"]


def ssh_source_arg(src):
    """Аргумент удалённого источника для rsync (Windows через SSH)."""
    path = src.get("path", "").rstrip("\\/")
    return f"{src['user']}@{src['host']}:{path}/"


def rsyncd_spec(end, sub=""):
    """Адрес rsyncd-конца: rsync://[user@]host[:port]/module[/подпуть].

    Порт указывается только если отличается от стандартного 873.
    """
    user = (end.get("user") or "").strip()
    port = _to_int(end.get("port"), 873)
    module = (end.get("module") or "").strip().strip("/")
    sub = (sub or "").strip().strip("/")
    spec = "rsync://" + (user + "@" if user else "") + end["host"].strip()
    if port != 873:
        spec += f":{port}"
    spec += "/" + module
    if sub:
        spec += "/" + sub
    return spec


def ftp_url(end, subpath="", with_password=True):
    """Адрес FTP-конца: ftp://[user[:pass]@]host[:port]/путь.

    Порт указывается только если отличается от стандартного 21.
    Имя пользователя, пароль и путь экранируются (URL-encoding),
    чтобы специальные символы не ломали адрес. with_password=False —
    для отображения (пароль в адрес не подставляется).
    """
    from urllib.parse import quote
    host = (end.get("host") or "").strip()
    port = _to_int(end.get("port"), 21)
    user = (end.get("user") or "").strip()
    pw = (end.get("password") or "").strip()
    base = (end.get("path") or "").strip().strip("/")
    sub = (subpath or "").strip().strip("/")
    path = "/".join(p for p in (base, sub) if p)
    auth = ""
    if user:
        auth = quote(user, safe="")
        if with_password and pw:
            auth += ":" + quote(pw, safe="")
        auth += "@"
    url = "ftp://" + auth + host
    if port != 21:
        url += f":{port}"
    if path:
        url += "/" + quote(path, safe="/")
    else:
        # явный корень «/»: без пути в URL lftp не подключается к
        # хосту («mirror: Not connected») и использует домашний
        # каталог пользователя, а не корень FTP-сервера
        url += "/"
    return url


def mask_ftp_password(url):
    """Замаскирует пароль в ftp://-адресе (для журнала)."""
    if not url.startswith("ftp://"):
        return url
    return re.sub(r"://([^:/@]+):[^@]*@", r"://\1:***@", url)


def ftp_safe_script(script, mopts_log):
    """Копия сценария lftp без пароля (для хранения/диагностики).

    Строка mirror в сценарии заменяется на mopts_log — версию
    с замаскированным паролем (см. mask_ftp_password). Остальные
    строки (set ...) пароля не содержат и сохраняются как есть.
    """
    out, replaced = [], False
    for ln in script:
        if not replaced and ln.startswith("mirror "):
            out.append(" ".join(mopts_log))
            replaced = True
        else:
            out.append(ln)
    if not replaced:
        out.append(" ".join(mopts_log))
    return out


def source_label(job):
    s = job.get("source") or {}
    if isinstance(s, str):
        return s
    t = s.get("type")
    if t == "smb":
        return "SMB " + (s.get("path") or "")
    if t == "ssh":
        return (f"SSH {s.get('user', '')}@{s.get('host', '')}:"
                f"{s.get('path', '')}")
    if t == "rsyncd":
        return "rsyncd " + rsyncd_spec(s, s.get("path", ""))
    if t == "ftp":
        return "FTP " + ftp_url(s, with_password=False)
    return s.get("path") or ""


def dest_label(job):
    d = job.get("destination") or {}
    if isinstance(d, str):
        return d
    t = d.get("type")
    if t == "smb":
        return "SMB " + (d.get("path") or "")
    if t == "ssh":
        return (f"SSH {d.get('user', '')}@{d.get('host', '')}:"
                f"{d.get('path', '')}")
    if t == "rsyncd":
        return "rsyncd " + rsyncd_spec(d, d.get("path", ""))
    if t == "ftp":
        return "FTP " + ftp_url(d, with_password=False)
    return d.get("path") or ""


class LocalDest:
    """Локальный каталог (включая смонтированную SMB-шару)."""
    kind = "local"

    def __init__(self, root: Path):
        self.root = root

    def abs_path(self, rel):
        return str(self.root / rel)

    def target(self, rel):
        return str(self.root / rel)

    def mkdir(self, rel):
        (self.root / rel).mkdir(parents=True, exist_ok=True)

    def listdir(self, rel):
        p = self.root / rel
        return sorted(os.listdir(p)) if p.is_dir() else []

    def rmtree(self, rel):
        shutil.rmtree(self.root / rel, ignore_errors=True)

    def size(self, rel):
        total = 0
        for dirpath, _, files in os.walk(self.root / rel):
            for f in files:
                try:
                    total += os.lstat(os.path.join(dirpath, f)).st_size
                except OSError:
                    pass
        return total


class SshDest:
    """Windows-машина через SSH (OpenSSH Server + DeltaRSync).

    Удалённый shell — cmd.exe, поэтому служебные команды
    (mkdir / dir / rmdir) выполняются в Windows-синтаксисе.
    """
    kind = "ssh"

    def __init__(self, dest):
        self.dest = dest
        self.base = dest["path"].rstrip("\\/")

    def _run(self, cmd, timeout=180):
        clog("DEBUG", f"Удалённая команда "
              f"({self.dest['user']}@{self.dest['host']}): {cmd}")
        r = subprocess.run(ssh_argv(self.dest) + [cmd],
                           capture_output=True, text=True, timeout=timeout)
        clog("DEBUG", f"Удалённая команда завершена: код {r.returncode}")
        return r

    def _p(self, rel):
        return self.base + "\\" + rel.replace("/", "\\")

    def abs_path(self, rel):
        return self._p(rel)

    def target(self, rel):
        return (f"{self.dest['user']}@{self.dest['host']}:" + self._p(rel))

    def mkdir(self, rel):
        # cmd.exe: mkdir сам создаёт вложенные каталоги
        self._run("mkdir " + win_quote(self._p(rel)))

    def listdir(self, rel):
        r = self._run("dir /b /ad " + win_quote(self._p(rel)))
        if r.returncode != 0:
            return []
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]

    def rmtree(self, rel):
        self._run("rmdir /s /q " + win_quote(self._p(rel)))

    def size(self, rel):
        return None  # du на Windows недоступен


class RsyncdDest:
    """Удалённая цель — rsync-демон (rsyncd) без SSH.

    Адрес: rsync://[user@]host[:port]/module[/подпуть]. Каталог снапшота
    создаёт приёмник (демон) при копировании, поэтому mkdir не нужен.
    Жёсткие ссылки (--link-dest) на удалённом конце недоступны —
    снапшоты для такой цели всегда полные копии.
    """
    kind = "rsyncd"

    def __init__(self, dest, passfile=None):
        self.dest = dest
        self.base = (dest.get("path") or "").strip().strip("/")
        self.passfile = passfile  # Path к временному файлу пароля (или None)

    def _sub(self, rel):
        rel = (rel or "").strip("/")
        if self.base:
            return self.base + "/" + rel if rel else self.base
        return rel

    def _spec(self, rel):
        return rsyncd_spec(self.dest, self._sub(rel))

    def _pf_args(self):
        return (["--password-file=" + self.passfile.as_posix()]
                if self.passfile else [])

    def abs_path(self, rel):
        return self._spec(rel)

    def target(self, rel):
        return self._spec(rel)

    def mkdir(self, rel):
        pass  # приёмник rsyncd создаёт каталог назначения сам

    def _listonly(self, spec, timeout=120):
        """Список записей каталога через `rsync --list-only`.

        Имена каталогов возвращаются с завершающим '/'.
        """
        try:
            r = subprocess.run(
                ["rsync", "--list-only"] + self._pf_args() + [spec],
                capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if r.returncode != 0:
            return []
        names = []
        for ln in r.stdout.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            name = ln.split()[-1]
            if name not in names:
                names.append(name)
        return names

    def listdir(self, rel):
        # пустые каталоги (остатки удалённых снапшотов) не учитываем:
        # rsyncd не умеет удалять сам каталог, только его содержимое
        out = []
        for n in self._listonly(self._spec(rel)):
            if n.endswith("/"):
                if self._listonly(self._spec(self._sub(rel + "/" + n))):
                    out.append(n.rstrip("/"))
            else:
                out.append(n)
        return sorted(out)

    def rmtree(self, rel):
        # удалённого rmdir нет: синхронизируем пустой каталог с --delete —
        # приёмник удалит всё содержимое цели (каталог останется пустым)
        try:
            empty = DATA_DIR / "rsyncd-empty"
            empty.mkdir(parents=True, exist_ok=True)
            for child in empty.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink()
            subprocess.run(
                ["rsync", "-a", "--delete"] + self._pf_args() +
                [empty.as_posix() + "/", self._spec(rel)],
                capture_output=True, text=True, timeout=600)
        except Exception:
            pass  # удаление снапшотов — не критично для самого бэкапа

    def size(self, rel):
        return None  # размер по rsyncd не определяется


# --------------------------------------------------------------------------
# SMB (CIFS)
# --------------------------------------------------------------------------

def is_mounted(mountpoint: Path) -> bool:
    try:
        for line in Path("/proc/mounts").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == mountpoint.as_posix().replace(" ", "\\040"):
                return True
    except OSError:
        pass
    return False


def check_smb_server(share: str, vers: str):
    """Предмонтажная проверка доступности SMB-сервера (TCP).

    Возвращает (ok, err, target): target — «хост:порт»,
    err — человекочитаемая причина недоступности (на русском).
    """
    host = share[2:].split("/")[0] if share.startswith("//") else share
    # SMB1 (vers=1.x) использует порт 139, SMB2/3 — 445
    port = 139 if str(vers or "").startswith("1") else 445
    target = f"{host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=5):
            return True, None, target
    except socket.gaierror:
        return False, (f"не удалось разрешить имя сервера «{host}» — "
                       f"проверьте адрес/имя хоста и DNS"), target
    except ConnectionRefusedError:
        return False, (f"сервер {target} отклоняет соединения — "
                       f"проверьте, что служба SMB (Server) запущена "
                       f"и файрвол не блокирует порт"), target
    except OSError:  # таймаут, нет маршрута и пр.
        return False, (f"сервер {target} недоступен (таймаут 5 с) — "
                       f"проверьте сеть и файрвол"), target


def check_rsyncd_server(end):
    """Предпроверка доступности rsyncd (TCP) перед запуском rsync.

    Возвращает (ok, err): err — причина недоступности на русском.
    """
    host = (end.get("host") or "").strip()
    port = _to_int(end.get("port"), 873)
    target = f"{host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=5):
            return True, None
    except socket.gaierror:
        return False, (f"не удалось разрешить имя сервера «{host}» — "
                       f"проверьте адрес/имя хоста и DNS")
    except ConnectionRefusedError:
        return False, (f"сервер {target} отклоняет соединения — "
                       f"проверьте, что служба rsync (rsyncd) запущена "
                       f"и файрвол открывает порт {port}")
    except OSError:  # таймаут, нет маршрута и пр.
        return False, (f"сервер {target} недоступен (таймаут 5 с) — "
                       f"проверьте сеть и файрвол")


def ftp_connect_details(end):
    """Детальная проверка подключения к FTP-серверу по шагам.

    Последовательно выполняется: DNS-разрешение имени, TCP-соединение,
    чтение приветственного сообщения сервера (баннер 220). Каждый шаг
    замеряется. Возвращает dict:
      ok, err, host, port, target, ip, dns_secs, tcp_secs,
      banner, total_secs
    """
    host = (end.get("host") or "").strip()
    port = _to_int(end.get("port"), 21)
    info = {"host": host, "port": port, "target": f"{host}:{port}",
            "ok": False, "err": None, "ip": None, "dns_secs": None,
            "tcp_secs": None, "banner": None, "total_secs": None}
    t0 = time.monotonic()
    sock = None
    try:
        t1 = time.monotonic()
        res = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                 socket.SOCK_STREAM)
        info["dns_secs"] = time.monotonic() - t1
        info["ip"] = res[0][4][0]
        t1 = time.monotonic()
        sock = socket.create_connection((host, port), timeout=5)
        info["tcp_secs"] = time.monotonic() - t1
        sock.settimeout(5)
        f = sock.makefile("rb")
        banner = f.readline(512)
        if not banner:
            raise OSError("сервер закрыл соединение без ответа")
        parts = [banner.decode("utf-8", "replace").strip()]
        # многострочный баннер: «220- …» продолжается до «220  …»
        while (len(parts) < 4 and len(parts[-1]) > 3
               and parts[-1][3] == "-"):
            nxt = f.readline(512)
            if not nxt:
                break
            parts.append(nxt.decode("utf-8", "replace").strip())
        info["banner"] = " | ".join(parts)
        try:
            sock.sendall(b"QUIT\r\n")
        except OSError:
            pass
        info["ok"] = True
    except socket.gaierror:
        info["err"] = (f"не удалось разрешить имя сервера «{host}» — "
                       f"проверьте адрес/имя хоста и DNS")
    except ConnectionRefusedError:
        info["err"] = (f"сервер {info['target']} отклоняет соединения — "
                       f"проверьте, что FTP-служба запущена "
                       f"и файрвол открывает порт {port}")
    except socket.timeout:
        info["err"] = (f"сервер {info['target']} принял TCP-соединение, "
                       f"но не прислал приветственное сообщение "
                       f"(баннер 220) за 5 с")
    except OSError:  # таймаут, нет маршрута и пр.
        info["err"] = (f"сервер {info['target']} недоступен "
                       f"(таймаут 5 с) — проверьте сеть и файрвол")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        info["total_secs"] = time.monotonic() - t0
    return info


def check_ftp_server(end):
    """Предпроверка доступности FTP-сервера перед запуском lftp.

    Возвращает (ok, err): err — причина недоступности на русском.
    """
    d = ftp_connect_details(end)
    return d["ok"], d["err"]


def ftp_conn_report_lines(d, label):
    """Строки журнала для результата ftp_connect_details (чистая).

    d — dict из ftp_connect_details, label — «FTP-источник:»/«FTP-цель:».
    """
    if d.get("ok"):
        out = [f"{label} подключение к FTP-серверу {d['target']}"]
        if d.get("ip"):
            out.append(f"  IP-адрес: {d['ip']} "
                       f"(DNS-разрешение: {d['dns_secs']:.3f} с)")
        if d.get("tcp_secs") is not None:
            out.append(f"  TCP-соединение: установлено "
                       f"за {d['tcp_secs'] * 1000:.0f} мс")
        if d.get("banner"):
            out.append(f"  Баннер сервера: {d['banner']}")
        if d.get("total_secs") is not None:
            out.append(f"  Проверка подключения завершена "
                       f"за {d['total_secs']:.2f} с")
        return out
    return [f"{label} НЕ удалось подключиться к FTP-серверу "
            f"{d.get('target')}: {d.get('err')}"]


_LFTP_LOG_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ")
_LFTP_XFER_CMD_RE = re.compile(r" \S+ ---> (?:RETR|STOR) ")


def ftp_conn_section(lftp_log_text, passwords=()):
    """Этап подключения к FTP из журнала lftp (чистая функция).

    Журнал создаётся настройками log:enabled/log:level 9/log:show-time.
    Вырезаются строки до первой передачи файла (RETR/STOR): все
    параллельные соединения, вход в систему, пассивный режим,
    первичные списки каталогов. Возвращает (lines, secs):
    lines — строки протокола (не более 400), secs — длительность
    этапа по таймстампам lftp (None, если разобрать не удалось).
    Пароли (список passwords) маскируются на ***.
    """
    lines = [ln for ln in (lftp_log_text or "").splitlines() if ln.strip()]
    if not lines:
        return [], None
    cut = len(lines)
    for i, ln in enumerate(lines):
        if _LFTP_XFER_CMD_RE.search(ln):
            cut = i
            break
    sec = lines[:cut] if cut else lines
    if len(sec) > 400:
        sec = sec[:400]
        sec.append("… (протокол сокращён до 400 строк)")
    for pw in passwords:
        if pw:
            sec = [ln.replace(pw, "***") for ln in sec]

    def parse_ts(ln):
        m = _LFTP_LOG_TS_RE.match(ln)
        if not m:
            return None
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

    first = last = None
    for ln in sec:
        t = parse_ts(ln)
        if t is None:
            continue
        if first is None:
            first = t
        last = t
    secs = (max(0.0, (last - first).total_seconds())
            if first is not None else None)
    return sec, secs


# Соответствие типовых ошибок mount.cifs вероятным причинам (на русском).
# Проверка идёт по порядку: первый найденный фрагмент stderr задаёт подсказку.
CIFS_ERROR_HINTS = [
    (("no matching hosts found", "name or service not known", "invalid name"),
     "не удалось разрешить имя сервера — проверьте адрес/имя хоста (DNS)"),
    (("nt_status_bad_network_name", "bad network name",
      "network path", "nt_status_share_not_found"),
     "шара не найдена — проверьте имя шары в адресе //сервер/шара"),
    (("nt_status_logon_failure", "bad username and/or password",
      "wrong username or password", "invalid user"),
     "неверное имя пользователя или пароль"),
    (("nt_status_access_denied", "access is denied"),
     "доступ к шаре запрещён — проверьте права пользователя на шару"),
    (("unknown cipher", "nt_status_not_supported", "unsupported protocol",
      "connection reset by peer"),
     "версия протокола (vers) не поддерживается сервером — "
     "попробуйте 3.1.1, 3.0 или 2.1"),
    (("connection refused",),
     "сервер отклоняет соединения — проверьте, что служба SMB запущена"),
    (("no route to host",),
     "нет маршрута к серверу — проверьте сеть"),
    (("host is down", "mount error(112)"),
     "сервер недоступен (host is down) — проверьте сеть и файрвол"),
    (("timed out", "timeout"),
     "таймаут соединения — проверьте сеть/файрвол и загрузку сервера"),
    (("mount point is not empty", "mountpoint is not empty",
      "device or resource busy"),
     "точка монтирования не пуста или занята другим процессом"),
    (("permission denied", "operation not permitted"),
     "недостаточно прав для монтирования — запустите сервер с --use-sudo "
     "или под пользователем root"),
    (("unknown filesystem type", "mount.cifs"),
     "не найдена утилита mount.cifs — установите пакет cifs-utils "
     "(apt install cifs-utils / dnf install cifs-utils)"),
    (("bad usage",),
     "некорректные параметры команды mount — проверьте значение vers "
     "и адрес шары"),
    (("transport endpoint is not connected",),
     "соединение с сервером потеряно в процессе монтирования"),
    (("input/output error",),
     "ошибка ввода/вывода — проверьте подключение к серверу"),
]


def _cifs_error_hint(stderr: str) -> str:
    """Подбирает вероятную причину по тексту ошибки mount.cifs."""
    s = (stderr or "").lower()
    for pats, hint in CIFS_ERROR_HINTS:
        if any(p in s for p in pats):
            return hint
    return ""


def mount_smb(share: str, user: str, password: str, vers: str,
              mount_id: str, log=None) -> Path:
    """Монтирует SMB-шару в data/mounts/<mount_id>.

    mount_id различает шару-источник и шару-назначение (<job_id>-src/-dst).
    Перед монтированием выполняются проверки: наличие программ
    (sudo/mount/mount.cifs) и доступность сервера по TCP.
    Все результаты записываются в журнал задания (если передан log).
    """
    mp = DATA_DIR / "mounts" / mount_id
    if mp.exists() and not mp.is_dir():
        raise RuntimeError(f"Точка монтирования недоступна: "
                           f"{mp} — не каталог")
    mp.mkdir(parents=True, exist_ok=True)
    if is_mounted(mp):
        clog("DEBUG", f"SMB-шара уже смонтирована: {share} -> {mp}")
        return mp
    lock = MOUNT_LOCKS.setdefault(mount_id, threading.Lock())
    with lock:
        # повторная проверка под локаком: другой поток мог смонтировать
        if is_mounted(mp):
            return mp
        return _mount_smb_locked(share, user, password, vers, mount_id, mp, log)


def _mount_smb_locked(share, user, password, vers, mount_id, mp, log):
    def mlog(level, msg):
        """В журнал задания (или в консоль, если журнала нет)."""
        if log is not None:
            log.write(msg)
        else:
            clog(level, msg)

    mlog("INFO", f"Подключаю SMB-шару {share} -> {mp}")

    # --- проверки до запуска mount ---
    if SUDO and not shutil.which("sudo"):
        raise RuntimeError(f"Не удалось подключить SMB-шару {share}: "
                           "программа 'sudo' не найдена в PATH "
                           "(запустите сервер без --use-sudo или "
                           "установите sudo)")
    if not shutil.which("mount"):
        raise RuntimeError(f"Не удалось подключить SMB-шару {share}: "
                           "программа 'mount' не найдена в PATH")
    if not shutil.which("mount.cifs"):
        mlog("WARN", "Внимание: утилита mount.cifs не найдена — "
                     "вероятно, не установлен пакет cifs-utils")
    ok, err, target = check_smb_server(share, vers)
    mlog("INFO", f"Проверка доступности SMB-сервера {target}…")
    if not ok:
        mlog("ERROR", f"SMB-сервер недоступен: {err}")
        raise RuntimeError(f"Не удалось подключить SMB-шару {share}: {err}")
    mlog("DEBUG", f"SMB-сервер {target} доступен")

    cred = DATA_DIR / "mounts" / (mount_id + ".cred")
    cred.write_text(f"username={user}\npassword={password}\n",
                    encoding="utf-8")
    os.chmod(cred, 0o600)
    opts = f"credentials={cred.as_posix()}"
    if vers:
        opts += f",vers={vers}"
    # uid/gid — пользователь, от которого запущен сервер: cifs присваивает
    # им владение файлами шары, поэтому процесс бэкапа (даже при монтировании
    # через sudo от root) может читать/писать смонтированный каталог
    uid, gid = os.getuid(), os.getgid()
    opts += (f",uid={uid},gid={gid},"
             "file_mode=0660,dir_mode=0770,iocharset=utf8")
    fallback = ("нет доступа к mount: запустите сервер с флагом --use-sudo "
                "или под пользователем root" if not SUDO else
                "нет доступа к sudo mount (проверьте /etc/sudoers)")
    # полная строка команды (пароль не попадает в строку —
    # он хранится во временном файле credentials=)
    cmd = SUDO + ["mount", "-t", "cifs", "-o", opts, share, mp.as_posix()]
    mlog("INFO", f"Команда монтирования: {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        cred.unlink(missing_ok=True)
        raise RuntimeError(f"Не удалось подключить SMB-шару {share}: "
                           f"программа '{(SUDO or ['mount'])[0]}' не найдена в PATH")
    if r.returncode != 0:
        cred.unlink(missing_ok=True)
        detail = (r.stderr or r.stdout or "").strip() or fallback
        hint = _cifs_error_hint(r.stderr or "") or fallback
        mlog("ERROR", f"Монтирование SMB-шары завершилось с кодом "
                      f"{r.returncode}: {detail}")
        mlog("ERROR", f"Возможная причина: {hint}")
        raise RuntimeError(f"Не удалось подключить SMB-шару {share}: "
                           f"{detail} ({hint})")
    cred.unlink(missing_ok=True)
    mlog("INFO", f"SMB-шара смонтирована: {share} -> {mp}")
    return mp


def _fusermount_bin():
    """Возвращает доступный fusermount (fusermount или fusermount3) или None."""
    for name in ("fusermount", "fusermount3"):
        if shutil.which(name):
            return name
    return None


def unmount_smb(mount_id: str, log=None):
    mp = DATA_DIR / "mounts" / mount_id
    if not is_mounted(mp):
        return

    def mlog(level, msg):
        if log is not None:
            log.write(msg)
        else:
            clog(level, msg)

    steps = []
    fm = _fusermount_bin()
    if fm:
        mlog("DEBUG", f"Отключение через {fm} (найден в PATH)")
        steps.append((fm, ["-u"]))
    else:
        mlog("WARN", "fusermount и fusermount3 не найдены в PATH — "
                     "установите пакет fuse/fuse3 (например: "
                     "apt install fuse3 / dnf install fuse3); "
                     "попробую umount")
    steps.append(("umount", []))
    for binary, args in steps:
        cmd = SUDO + [binary] + args + [mp.as_posix()]
        mlog("INFO", f"Команда отключения: {' '.join(cmd)}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            mlog("WARN", f"Программа '{binary}' не найдена в PATH")
            continue
        if r.returncode != 0:
            mlog("WARN", f"Команда отключения завершилась с кодом "
                         f"{r.returncode} ({binary}): "
                         f"{(r.stderr or r.stdout or '').strip()}")
        if not is_mounted(mp):
            mlog("INFO", f"SMB-шара отключена: {mp}")
            return
    mlog("ERROR", f"Не удалось отключить SMB-шару: {mp}")


# --------------------------------------------------------------------------
# Расписание
# --------------------------------------------------------------------------

def compute_next_run(job, now: datetime, last_run):
    """Возвращает datetime следующего запуска или None."""
    st = job.get("schedule") or {}
    kind = st.get("kind", "manual")
    if kind == "interval":
        mins = max(1, _to_int(st.get("minutes"), 60))
        base = last_run or now.timestamp()
        return datetime.fromtimestamp(base + mins * 60)
    if kind in ("daily", "weekly"):
        m = re.match(r"^(\d{1,2}):(\d{2})$", st.get("time") or "")
        hh, mm = (int(m.group(1)), int(m.group(2))) if m else (2, 0)
        if kind == "daily":
            cand = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if cand <= now:
                cand += timedelta(days=1)
            return cand
        if kind == "weekly":
            wd = int(st.get("weekday") or 0) % 7  # 0 = понедельник
            delta = (wd - now.weekday()) % 7
            cand = (now + timedelta(days=delta)).replace(
                hour=hh, minute=mm, second=0, microsecond=0)
            if cand <= now:
                cand += timedelta(days=7)
            return cand
    return None


def init_next_runs():
    now = datetime.now()
    for job in CONFIG.jobs:
        st = STATE.get(job["id"])
        nr = compute_next_run(job, now, st.get("last_run"))
        if nr and nr.timestamp() < time.time() - 5:
            # пропуск по расписанию (сервер был выключен) — запускаем скоро
            clog("INFO", f"Задание '{job['name']}': время по расписанию "
                  "пропущено (сервер был выключен) — запуск через 1 минуту")
            nr = now + timedelta(seconds=60)
        STATE.update(job["id"], next_run=nr.timestamp() if nr else None)
        clog("DEBUG", f"Задание '{job['name']}': следующий запуск — "
              f"{nr.strftime('%Y-%m-%d %H:%M:%S') if nr else 'нет расписания'}")


# --------------------------------------------------------------------------
# Удержание снапшотов (принцип rsnapshot)
# --------------------------------------------------------------------------

def latest_snapshot(d, job_rel):
    names = [n for n in d.listdir(job_rel) if SNAP_RE.match(n)]
    return max(names) if names else None


def prune_snapshots(job, d, job_rel):
    ret = job.get("retention") or {}
    keep_latest_n = int(ret.get("snapshots") or 0)
    keep_daily = int(ret.get("daily") or 0)
    keep_weekly = int(ret.get("weekly") or 0)
    keep_monthly = int(ret.get("monthly") or 0)
    if not (keep_latest_n or keep_daily or keep_weekly or keep_monthly):
        return []
    snaps = []
    for n in d.listdir(job_rel):
        if not SNAP_RE.match(n):
            continue
        try:
            snaps.append((datetime.strptime(n, TS_FMT), n))
        except ValueError:
            pass
    if not snaps:
        return []
    snaps.sort()
    by_day, by_week, by_month = {}, {}, {}
    for dt, n in snaps:
        by_day[dt.strftime("%Y-%m-%d")] = (dt, n)
        iso = dt.isocalendar()
        by_week[(iso[0], iso[1])] = (dt, n)
        by_month[dt.strftime("%Y-%m")] = (dt, n)
    now = datetime.now()
    # самые свежие N снапшотов храним всегда (как период alpha в rsnapshot)
    keep = {n for _, n in snaps[-keep_latest_n:]} if keep_latest_n else set()
    keep.add(snaps[-1][1])  # самый свежий всегда храним
    if keep_daily:
        for _, (dt, n) in by_day.items():
            if (now - dt).days < keep_daily:
                keep.add(n)
    if keep_weekly:
        for _, (dt, n) in by_week.items():
            if (now - dt).days < keep_weekly * 7:
                keep.add(n)
    if keep_monthly:
        for _, (dt, n) in by_month.items():
            if (now - dt).days < keep_monthly * 31:
                keep.add(n)
    removed = []
    for _, n in snaps:
        if n not in keep:
            d.rmtree(f"{job_rel}/{n}")
            removed.append(n)
    return removed


# --------------------------------------------------------------------------
# Запуск задания
# --------------------------------------------------------------------------

def sanitize_name(name):
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return s or "job"


def build_rsync(job, d, target_rel, link_dest, dry, src_path, ssh_src=None,
                password_files=None):
    opts = job.get("options") or {}
    # --stats — итоговая статистика (файлы, размер, скорость) для отчёта
    cmd = ["rsync", "-a", "--partial", "--timeout=900", "--stats"]
    if opts.get("checksum"):
        cmd.append("--checksum")
    if opts.get("compress"):
        cmd.append("--compress")
    bw = int(opts.get("bwlimit") or 0)
    if bw > 0:
        cmd.append(f"--bwlimit={bw}")
    if dry:
        cmd.append("--dry-run")
    for pat in job.get("exclude") or []:
        cmd.append("--exclude=" + pat)
    # пароль rsyncd — только из файла (ни в командной строке, ни в логе)
    for pf in password_files or []:
        cmd.append(f"--password-file={pf}")
    if link_dest:
        cmd.append(f"--link-dest={link_dest}")
    if job.get("mode") == "mirror" and opts.get("delete"):
        cmd.append("--delete")
    # удалённый конец — только один (источник ИЛИ цель), поэтому -e ssh
    # нужен в любом случае, когда используется SSH-конец
    if ssh_src is not None:
        cmd[1:1] = ["-e", " ".join(ssh_argv(ssh_src))]
    elif isinstance(d, SshDest):
        cmd[1:1] = ["-e", " ".join(ssh_argv(d.dest))]
    # источник: trailing "/" означает «содержимое каталога»
    cmd.append(src_path.rstrip("/") + "/")
    cmd.append(d.target(target_rel))
    return cmd


# --------------------------------------------------------------------------
# Отчет о выполнении заданий (data/reports/report.txt)
# --------------------------------------------------------------------------

REPORT_LOCK = threading.Lock()


def plural_ru(n, one, few, many):
    """Русская плюрализация: plural_ru(3, "файл", "файла", "файлов")
    -> "файла"; 1 -> "файл", 5 -> "файлов", 11 -> "файлов", 21 -> "файл"."""
    n = abs(int(n)) % 100
    if 11 <= n <= 14:
        return many
    n %= 10
    if n == 1:
        return one
    if 2 <= n <= 4:
        return few
    return many


def human_size(n):
    """Человекочитаемый размер: 12345678 -> '11.8 МБ'."""
    n = float(n)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return f"{int(n)} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def _parse_rsync_stats(lines):
    """Извлекает статистику из вывода `rsync --stats`.

    Возвращает dict со всеми найденными ключами (files, size, sent, recv)
    или None, если статистика не распознана.
    """
    st = {}
    for ln in lines:
        if ln.startswith("Number of files transferred:"):
            m = re.search(r":\s*(\d+)", ln)
            if m:
                st["files"] = int(m.group(1))
        elif ln.startswith("Total transferred file size:"):
            m = re.search(r":\s*(\d+)", ln)
            if m:
                st["size"] = int(m.group(1))
        elif ln.startswith("sent ") and "received" in ln:
            m = re.search(r"sent\s+(\d+)\s+bytes\s+received\s+(\d+)", ln)
            if m:
                st["sent"], st["recv"] = int(m.group(1)), int(m.group(2))
    return st or None


def append_job_report(job_name, started, finished, dur, dry, mode,
                      stats, errors, dur_raw=None):
    """Добавляет запись о выполнении задания в data/reports/report.txt."""
    speed = None
    t = dur_raw if (dur_raw is not None and dur_raw > 0) else dur
    if t > 0:
        if stats and stats.get("size") is not None:
            speed = stats["size"] / t
        elif stats:
            # размер переданных файлов неизвестен — берём трафик
            speed = (stats.get("sent", 0) + stats.get("recv", 0)) / t
    lines = [
        "=" * 60,
        f"Задание: {job_name}",
        f"Прогон: {'тестовый (dry-run)' if dry else 'обычный'} | режим: {mode}",
        f"Начало: {started}",
        f"Завершение: {finished}",
        f"Длительность: {dur} с",
        f"Скопировано файлов: "
        f"{stats['files'] if stats and 'files' in stats else '—'}",
        f"Размер скопированных файлов: "
        f"{human_size(stats['size']) if stats and 'size' in stats else '—'}",
        f"Средняя скорость: "
        f"{human_size(speed) + '/с' if speed is not None else '—'}",
    ]
    if errors:
        lines.append("Ошибки копирования:")
        lines.extend("  " + e for e in errors)
    else:
        lines.append("Ошибки копирования: нет")
    lines.append("=" * 60)
    reports_dir = DATA_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / "report.txt"
    with REPORT_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n\n")
    return path


# подробные операции lftp mirror (формат вывода --verbose=3):
# файловые операции — показываются только с -vv:
#   «Transferring file `x'», «Finished transfer `x' (N B/s)»,
#   «Removing old file `x'»
# операции с директориями — показываются с -v и выше:
#   «Mirroring directory `x'», «Making directory `x'»,
#   «Finished mirror `x'», «Removing old directory `x'»
_MIRROR_FILE_RE = re.compile(
    r"^(?:Transferring file|Finished transfer|Removing old file) `")
_MIRROR_DIR_RE = re.compile(
    r"^(?:Mirroring directory|Making directory|Finished mirror"
    r"|Removing old directory) `")
# тестовый прогон (--dry-run): lftp печатает ПЛАНИРУЕМЫЕ команды
# независимо от уровня --verbose (проверено на lftp 4.9.2):
#   «get -O <dst> <src>» — передача файла,
#   «chmod -f <права> <путь>» — права,
#   «rm file:<путь>» / «rm ftp://…/<путь>» — удаление файла;
#   «mkdir file:<путь>», «mkdir [-p] ftp://…/<путь>» — создание
#   каталога, «rm -r file:<путь>» / «rm -r ftp://…/<путь>» — удаление
#   каталога. Уровни те же, что у подробных операций.
_MIRROR_DRY_FILE_RE = re.compile(
    r"^(?:get -O |chmod -f |rm (?:file:|ftp://))")
_MIRROR_DRY_DIR_RE = re.compile(
    r"^(?:mkdir |rm -r (?:file:|ftp://))")


def mirror_out_visible(ln):
    """Писать ли строку вывода lftp mirror в журнал задания.

    Уровень зависит от ключа запуска сервиса:
    0 (без -v)  — подробные операции (файлы, директории) и
      планируемые команды dry-run не пишутся (тихо; сам lftp
      при этом запускается с --verbose=0, но dry-run-команды
      печатает всегда — их отфильтровываем);
    1 (-v)      — пишутся только операции с директориями
      («Mirroring directory», «Making directory»,
      «Finished mirror», «Removing old directory») и
      dry-run-команды с каталогами («mkdir …», «rm -r …»);
    2 (-vv)     — пишутся все подробные операции, включая
      файловые («Transferring file», «Finished transfer»,
      «Removing old file»), и все dry-run-команды
      («get -O …», «chmod -f …», «rm …»).
    Остальные строки (ошибки, сводка) пишутся всегда.
    """
    if _MIRROR_FILE_RE.match(ln):
        return VERBOSE >= 2
    if _MIRROR_DIR_RE.match(ln):
        return VERBOSE >= 1
    if _MIRROR_DRY_FILE_RE.match(ln):
        return VERBOSE >= 2
    if _MIRROR_DRY_DIR_RE.match(ln):
        return VERBOSE >= 1
    return True


# --------------------------------------------------------------------------
# Прогресс FTP-копирования (отображение процентов в GUI)
# --------------------------------------------------------------------------
# Процент считается по строкам вывода lftp mirror, которые и так
# стримятся из процесса построчно («Finished transfer `x' (N B/s)») —
# без дополнительных соединений с FTP-сервером и без опросов. Для
# знаменателя (всего файлов и байт) источник просматривается ОДИН раз
# (локальный — os.walk, FTP — LIST по каталогам, одно дополнительное
# соединение, без передач). Скан выполняется ПАРАЛЛЕЛЬНО с копированием
# в фоновом потоке: старт прогона не ждёт скан, итог подтягивается в
# процессе (пока он считается, GUI показывает «итог определяется…»,
# файлы, завершившиеся до прихода итога, пересчитываются по карте
# размеров). Если просмотр не удался, GUI показывает число
# скопированных файлов без процента. Хранится только в памяти
# (не пишется в state.json).
FTP_PROGRESS = {}      # job_id -> {total_files, total_bytes,
                       #            total_pending, done_files,
                       #            done_bytes, pct | None}
# служебные данные скана (карта размеров и список завершённых
# файлов) — отдельно, чтобы не попадать в /api/jobs (иначе
# размер ответа раздувается на десятки тысяч записей)
FTP_SCAN_EXTRAS = {}   # job_id -> {"size_map": {...},
                       #            "done_names": [...]}
FTP_PROGRESS_LOCK = threading.Lock()


class ScanLimitExceeded(Exception):
    """Просмотр источника превысил лимит (каталогов/файлов/времени)."""


def _plural_ru(n, one, few, many):
    """Склонение русского существительного: 1 файл, 2 файла, 5 файлов."""
    n %= 100
    if 11 <= n <= 14:
        return many
    n %= 10
    if n == 1:
        return one
    if 2 <= n <= 4:
        return few
    return many


_FTP_FINISHED_RE = re.compile(r"^Finished transfer `([^`]*)' \(")
_FTP_TRANSFERRING_RE = re.compile(r"^Transferring file `([^`]*)'")


def ftp_track_transfer(inflight, ln):
    """Обновляет словарь незавершённых передач по строке lftp (чистая).

    inflight — dict (порядок вставки): имя файла, передача которого
    началась («Transferring file `x'»), но ещё не закончилась
    («Finished transfer `x'»). При остановке задания до конца
    прогона в этом словаре остаются файлы, чья передача была
    прервана — на цели они могут оказаться обрезанными.
    """
    if ln.startswith("Transferring file `"):
        m = _FTP_TRANSFERRING_RE.match(ln)
        if m:
            inflight[m.group(1)] = None
    elif ln.startswith("Finished transfer `"):
        m = _FTP_FINISHED_RE.match(ln)
        if m:
            inflight.pop(m.group(1), None)


def ftp_progress_on_line(prog, sizes, ln, done_names=None):
    """Подсчёт завершённой передачи по строке вывода lftp (чистая).

    prog — dict прогресса, sizes — {относительный путь: байты} по
    результатам предварительного просмотра источника, ln — строка
    вывода lftp. done_names — список (опционально), куда
    дописываются имена завершённых файлов: карта размеров может
    прийти позже начала копирования (скан параллелен прогону), и
    по этому списку при её приходе пересчитываются байты.
    Возвращает True, если строка — «Finished transfer …».
    """
    m = _FTP_FINISHED_RE.match(ln)
    if not m:
        return False
    name = m.group(1)
    prog["done_files"] += 1
    prog["done_bytes"] += sizes.get(name, 0)
    if done_names is not None:
        done_names.append(name)
    if prog.get("pct") is not None:
        tb, tf = prog["total_bytes"], prog["total_files"]
        if tb and tb > 0:
            prog["pct"] = min(100.0, prog["done_bytes"] * 100.0 / tb)
        elif tf and tf > 0:
            prog["pct"] = min(100.0, prog["done_files"] * 100.0 / tf)
    return True


def progress_view(prog, now):
    """Копия прогресса для /api/jobs: + скорость и остаток времени.

    speed — средняя скорость передачи за прогон, байт/с
    (done_bytes / время с начала прогона; None, пока прогон
    слишком короткий или карта размеров ещё не пришла);
    eta — оценка оставшегося времени, сек: максимум двух
    оценок — остаток байт / скорость и остаток файлов /
    частоту файлов (max — потому что при многих маленьких
    файлах «узкое место» — накладные расходы на файл, а не
    байты; None, пока нет итога или скорости). Вычисляется
    при каждом чтении — вызывайте под FTP_PROGRESS_LOCK.
    """
    out = dict(prog)
    out.pop("started_at", None)  # служебное (monotonic), клиенту не нужно
    speed = fspeed = None
    started = prog.get("started_at")
    el = (now - started) if started is not None else 0.0
    if el >= 1.0:  # первые секунды — шум, не показываем
        if prog.get("done_bytes", 0) > 0:
            speed = prog["done_bytes"] / el
        if prog.get("done_files", 0) > 0:
            fspeed = prog["done_files"] / el
    out["speed"] = speed
    eta = None
    cand = []
    total_b, total_f = prog.get("total_bytes"), prog.get("total_files")
    if speed and total_b and total_b > 0:
        rem = total_b - prog.get("done_bytes", 0)
        if rem > 0:
            cand.append(rem / speed)
    if fspeed and total_f and total_f > 0:
        rem = total_f - prog.get("done_files", 0)
        if rem > 0:
            cand.append(rem / fspeed)
    if cand:
        eta = int(max(cand))
    out["eta"] = eta
    return out


def _scan_excluded(rel, name, patterns):
    """Файл/каталог попадает под --exclude-glob задания?

    lftp сопоставляет шаблон с именем файла (и с путём относительно
    корня зеркала) — проверяем оба варианта.
    """
    for p in patterns or []:
        if fnmatch.fnmatch(name, p):
            return True
        if "/" in p and fnmatch.fnmatch(rel, p):
            return True
    return False


def scan_local_source(path, patterns):
    """Просмотр локального источника: (файлов, байты, {rel: size}).

    Один проход os.walk по каталогу — дёшево, сетевых запросов нет.
    """
    sizes = {}
    n = 0
    root = str(path)
    for dp, _dns, fns in os.walk(root):
        for fn in fns:
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if _scan_excluded(rel, fn, patterns):
                continue
            try:
                sizes[rel] = os.lstat(full).st_size
            except OSError:
                sizes[rel] = 0
            n += 1
    return n, sum(sizes.values()), sizes


def scan_ftp_source(end, patterns, timeout=30, max_dirs=100000,
                    max_files=1000000, max_secs=1800, passive=True,
                    stop=None):
    """Просмотр FTP-источника: (файлов, байты, {rel: size}).

    Одно дополнительное FTP-соединение, LIST на каталог (без передач)
    — то, что mirror и так делает сам. passive — режим данных
    (PASV/PORT), должен совпадать с настройкой задания (lftp.passive),
    иначе скан может упасть там, где сам mirror работает. Лимиты
    (каталоги/файлы/время) — защита от аномально больших источников:
    скан выполняется параллельно с копированием и не задерживает
    старт прогона. stop — опциональный threading.Event остановки:
    при установке (кнопка «Остановить») бросает _StopRequested.
    При любой другой ошибке бросает исключение (прогресс будет
    показан без процента; при превышении лимита —
    ScanLimitExceeded).
    """
    import ftplib
    sizes = {}
    n = [0]
    dirs = [0]
    t0 = time.monotonic()
    src_root = (end.get("path") or "/").strip()
    if not src_root.startswith("/"):
        src_root = "/" + src_root

    def walk(absdir):
        dirs[0] += 1
        if stop is not None and stop.is_set():
            raise _StopRequested()
        if time.monotonic() - t0 > max_secs:
            raise ScanLimitExceeded(
                "превышен лимит времени просмотра источника "
                "(> %d с)" % max_secs)
        if dirs[0] > max_dirs:
            raise ScanLimitExceeded(
                "превышен лимит числа каталогов источника "
                "(> %d)" % max_dirs)
        if n[0] > max_files:
            raise ScanLimitExceeded(
                "превышен лимит числа файлов источника "
                "(> %d)" % max_files)
        if absdir == "/":
            ftp.cwd("/")
        else:
            ftp.cwd(absdir)
        lines = []
        ftp.retrlines("LIST", lines.append)
        for ln in lines:
            parts = ln.split(None, 8)
            if len(parts) < 9:
                continue  # «total …», пустые строки и т.п.
            kind = parts[0][0]
            try:
                sz = int(parts[4])
            except ValueError:
                sz = 0
            name = parts[8].strip()
            if kind == "l" and " -> " in name:
                name = name.split(" -> ", 1)[0].strip()
            if not name or name in (".", ".."):
                continue
            rel = (absdir.rstrip("/") + "/" + name)[len(src_root):].lstrip("/")
            if not rel:
                continue
            if _scan_excluded(rel, name, patterns):
                continue  # исключённый каталог не обходим
            if kind == "d":
                walk(absdir.rstrip("/") + "/" + name)
            else:
                sizes[rel] = sz
                n[0] += 1

    ftp = ftplib.FTP(timeout=timeout)
    ftp.set_pasv(passive)
    try:
        ftp.connect(end.get("host", ""), int(end.get("port") or 21),
                    timeout=timeout)
        user = (end.get("user") or "").strip()
        pwd = (end.get("password") or "").strip()
        ftp.login(user or None, pwd or None)
        walk(src_root)
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass
    return n[0], sum(sizes.values()), sizes


def _rc_stopped_by_user(rc):
    """Процесс завершён сигналом SIGTERM — это остановка кнопкой
    «Остановить» (stop_job шлёт SIGTERM в группу процесса).
    Остановка не является ошибкой — отдельный статус "stopped".
    """
    return rc == -signal.SIGTERM


def lftp_buffer_line(buffer_kib):
    """Строка сценария lftp для буфера передач (xfer:buffer-size).

    buffer_kib — размер буфера, КиБ (настройка lftp.buffer задания).
    0 — строку не писать (оставить дефолт lftp 64 КБ).
    """
    if buffer_kib and buffer_kib > 0:
        return "set xfer:buffer-size 0x%x" % (buffer_kib * 1024)
    return None


# ---------------------------------------------------------------------------
# Продолжение после обрыва БЕЗ mirror: сравнение списков
# «источник − скопировано» и копирование недостающих файлов
# прямыми FTP-передачами (ftplib, параллельные потоки)
# ---------------------------------------------------------------------------

STOP_EVENTS = {}   # job_id -> threading.Event: впроцессный движок
                   # копирования (продолжение без mirror) — процесса
                   # lftp, в который шлать SIGTERM, нет; остановка
                   # по флагу, проверяется между файлами и в ходе
                   # приёма (RETR) по каждому чанку

# Кавычки в аргументах FTP-команд не используются (см. _ftp_quote):
# FileZilla Server 1.12.6 (production) отказывает (550 Unknown error)
# на ЛЮБЫХ кавычках, в т.ч. при пробелах в имени.


class _StopRequested(Exception):
    """Остановка запрошена в ходе передачи файла."""


def _ftp_quote(name):
    """Аргумент команды FTP (RETR/STOR/MKDIR): имя отправляется как
    есть, без кавычек. Аргумент команды FTP — всё до конца строки
    (RFC 959), пробелы и не-ASCII в нём легальны; проверено на
    FileZilla Server 1.12.6 (production). Кавычки НЕ ставятся ни
    при каких символах: FileZilla 1.12.6 на любых кавычках (даже
    при пробелах в имени) отвечает 550 Unknown error.
    RFC 3659 рекомендует кавычки для «специальных» имён, но этот
    сервер их не понимает — совместимость с production важнее."""
    return name


def ftp_missing_list(sizes, copied):
    """Недостающие на цели файлы (чистая функция).

    sizes — {относительный путь: байты} по источнику, copied —
    {относительный путь: байты} на цели (скан локального каталога
    или сохранённая карта). Файл считается недостающим, если его
    нет на цели или размер отличается от исходного (обрезанный
    при обрыве файл будет скопирован заново целиком).
    """
    return {r: s for r, s in sizes.items() if copied.get(r) != s}


def load_copied_map(jid):
    """Сохранённая карта «скопировано» {относительный путь: байты}.

    Ведётся только для FTP-цели (перечисление удалённой цели
    дорогое); после каждого прогона: при успехе — полный список
    источника, при остановке/ошибке — реально скопированное.
    """
    try:
        d = json.loads((DATA_DIR / "ftp_state" / f"{jid}.json")
                       .read_text(encoding="utf-8"))
        return {str(k): int(v) for k, v in d.get("copied", {}).items()}
    except (OSError, ValueError, TypeError):
        return {}


def save_copied_map(jid, m):
    """Атомарно сохранить карту «скопировано»; True при успехе."""
    try:
        p = DATA_DIR / "ftp_state" / f"{jid}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(p) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"copied": {k: int(v) for k, v in m.items()}}, f)
        os.replace(tmp, p)
        return True
    except OSError:
        return False


def _ftp_connect(end, passive=True, timeout=30):
    """Соединение ftplib с FTP-концом (без SSL — как в lftp:
    set ftp:ssl-allow no)."""
    import ftplib
    ftp = ftplib.FTP(timeout=timeout)
    ftp.set_pasv(passive)
    ftp.connect((end.get("host") or "").strip(),
                int(end.get("port") or 21), timeout=timeout)
    user = (end.get("user") or "").strip()
    pwd = (end.get("password") or "").strip()
    ftp.login(user or None, pwd or None)
    return ftp


def _ftp_close(ftp):
    if ftp is None:
        return
    try:
        ftp.quit()
    except Exception:
        try:
            ftp.close()
        except Exception:
            pass


def _ftp_mkdirs(ftp, rdir, created):
    """Создать удалённый каталог (с родителями), если его нет.

    created — общий набор каталогов, наличие которых гарантировано
    (доступ под замком на стороне вызывающего): каталоги создаются
    лениво, при первом файле в них.
    """
    import ftplib
    cur = ""
    for p in [x for x in rdir.split("/") if x]:
        cur += "/" + p
        if cur in created:
            continue
        try:
            ftp.mkd(cur)
        except ftplib.error_perm:
            pass  # уже существует (550) — передача это проверит
        created.add(cur)


def _ftp_retr(ftp, rpath, local_path, stop, block):
    """RETR → локальный файл (существующий обрезается с начала).
    Проверка остановки — по каждому чанку данных."""
    f = open(local_path, "wb")

    def cb(chunk):
        if stop.is_set():
            raise _StopRequested()
        f.write(chunk)

    try:
        ftp.retrbinary("RETR " + _ftp_quote(rpath), cb, block)
    finally:
        f.close()


def _ftp_stor(ftp, lpath, rpath, stop, block):
    """STOR из локального файла (на сервере файл обрезается с
    начала). Проверка остановки — только между файлами: у
    storbinary нет колбэка по чанкам."""
    if stop.is_set():
        raise _StopRequested()
    with open(lpath, "rb") as f:
        ftp.storbinary("STOR " + _ftp_quote(rpath), f, block)


def _walk_dir_stats(path):
    """(число файлов, байты) в дереве каталога."""
    n = tot = 0
    for dp, _, fns in os.walk(path):
        for fn in fns:
            try:
                tot += os.lstat(os.path.join(dp, fn)).st_size
                n += 1
            except OSError:
                pass
    return n, tot


def _ftp_copy_engine(job, src, dest, missing, prog, stop):
    """Параллельное копирование списка недостающих файлов без mirror.

    Потоков — lftp.parallel, у каждого свои соединения ftplib
    (по одному на FTP-конец); передачи — прямые RETR/STOR, lftp
    не участвует. FTP→FTP — через временный файл. Остановка —
    по флагу stop: проверяется между файлами и в ходе приёма
    (RETR) по каждому чанку; незавершённый файл остаётся на цели
    обрезанным и в следующем продолжении скопируется заново
    (его нет в списке «скопировано»).

    Возвращает (stopped, errors, interrupted, copied_map):
    errors — список «путь: ошибка», interrupted — файлы, чья
    передача была прервана (возможны обрезки на цели),
    copied_map — скопированные в этом прогоне файлы (для
    локальной цели — None).
    """
    jid = job.get("id", "")
    lf = job.get("lftp") or {}
    parallel = max(1, _to_int(lf.get("parallel"), 4))
    passive = bool(lf.get("passive", True))
    buffer_kib = max(64, _to_int(lf.get("buffer"), 1024))
    block = buffer_kib * 1024
    src_is_ftp = src.get("type") == "ftp"
    dst_is_ftp = dest.get("type") == "ftp"
    mirror_rel = sanitize_name(job.get("name", jid)) + "/mirror"

    # lftp mirror кладёт имя каталога-источника ВНУТРЬ цели —
    # движок повторяет ту же раскладку
    if src_is_ftp:
        src_root = (src.get("path") or "/").strip()
        if not src_root.startswith("/"):
            src_root = "/" + src_root
        base = src_root.rstrip("/").rsplit("/", 1)[-1]
    else:
        local_src = Path(src.get("path", "")).expanduser()
        base = local_src.name
    if dst_is_ftp:
        dst_prefix = "/".join(
            p for p in ((dest.get("path") or "").strip().strip("/"),
                        mirror_rel, base) if p)
        dst_prefix = "/" + dst_prefix if dst_prefix else "/"
    else:
        local_target = Path(dest["path"]).expanduser() / mirror_rel
        if base:
            local_target = local_target / base

    q = queue.Queue()
    for rel, sz in missing.items():
        q.put((rel, sz))
    errors, errors_lock = [], threading.Lock()
    created_dirs, dirs_lock = set(), threading.Lock()
    inflight, inflight_lock = {}, threading.Lock()
    copied_map = {} if dst_is_ftp else None
    copied_lock, flush_n = threading.Lock(), [0]

    def worker(wi):
        sftp = dftp = None
        try:
            while True:
                if stop.is_set():
                    break
                try:
                    rel, sz = q.get_nowait()
                except queue.Empty:
                    break
                with inflight_lock:
                    inflight[wi] = rel
                ok = False
                for attempt in (0, 1):
                    if stop.is_set():
                        break
                    try:
                        if src_is_ftp and sftp is None:
                            sftp = _ftp_connect(src, passive)
                        if dst_is_ftp and dftp is None:
                            dftp = _ftp_connect(dest, passive)
                        parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
                        if parent:
                            if dst_is_ftp:
                                with dirs_lock:
                                    _ftp_mkdirs(
                                        dftp, dst_prefix + "/" + parent,
                                        created_dirs)
                            else:
                                (local_target / parent).mkdir(
                                    parents=True, exist_ok=True)
                        if src_is_ftp:
                            src_path = src_root + "/" + rel
                        else:
                            src_path = str(local_src / rel)
                        if src_is_ftp and dst_is_ftp:
                            tf = tempfile.NamedTemporaryFile(
                                prefix="ftpcopy-", delete=False)
                            tf.close()
                            try:
                                _ftp_retr(sftp, src_path, tf.name,
                                          stop, block)
                                _ftp_stor(dftp, tf.name,
                                          dst_prefix + "/" + rel,
                                          stop, block)
                            finally:
                                try:
                                    os.unlink(tf.name)
                                except OSError:
                                    pass
                        elif src_is_ftp:
                            _ftp_retr(sftp, src_path,
                                      str(local_target / rel),
                                      stop, block)
                        else:
                            _ftp_stor(dftp, src_path,
                                      dst_prefix + "/" + rel,
                                      stop, block)
                        ok = True
                        break
                    except _StopRequested:
                        break  # файл остаётся в inflight —
                               # передача была прервана
                    except Exception as e:
                        # соединение могло пропасть — переподключаемся
                        # и повторяем файл с начала (один раз)
                        _ftp_close(sftp)
                        _ftp_close(dftp)
                        sftp = dftp = None
                        if attempt == 0:
                            continue
                        with errors_lock:
                            errors.append(f"{rel}: {e}")
                if ok:
                    with inflight_lock:
                        inflight.pop(wi, None)
                    with FTP_PROGRESS_LOCK:
                        prog["done_files"] += 1
                        prog["done_bytes"] += sz
                        if prog.get("total_bytes"):
                            prog["pct"] = min(
                                100.0, prog["done_bytes"] * 100.0
                                / prog["total_bytes"])
                        elif prog.get("total_files"):
                            prog["pct"] = min(
                                100.0, prog["done_files"] * 100.0
                                / prog["total_files"])
                    if copied_map is not None:
                        with copied_lock:
                            copied_map[rel] = sz
                            flush_n[0] += 1
                            if flush_n[0] >= 500:
                                # периодический сброс карты «скопировано»:
                                # после сбоя сервера уже скопированное
                                # не будет скопировано повторно
                                flush_n[0] = 0
                                save_copied_map(jid, dict(copied_map))
                elif not stop.is_set():
                    with inflight_lock:
                        inflight.pop(wi, None)
        finally:
            _ftp_close(sftp)
            _ftp_close(dftp)

    if dst_is_ftp:
        # корень копии должен существовать до первых STOR (lftp
        # mirror создаёт целевой каталог сам; здесь — явно)
        conn = _ftp_connect(dest, passive)
        try:
            with dirs_lock:
                _ftp_mkdirs(conn, dst_prefix, created_dirs)
        finally:
            _ftp_close(conn)

    nthreads = min(parallel, max(1, len(missing)))
    threads = [threading.Thread(target=worker, args=(wi,), daemon=True)
               for wi in range(nthreads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    interrupted = []
    with inflight_lock:
        interrupted = [v for v in inflight.values() if v]
    return stop.is_set(), errors, interrupted, copied_map


def _run_ftp_continue(job, src, dest, log, dry):
    """Продолжение прерванного FTP-копирования: сравнение списков,
    без mirror.

    1. Формируется список всех файлов источника (просмотр).
    2. Формируется список скопированных файлов: локальная цель —
       свежий скан каталога цели; FTP-цель — карта, сохраняемая
       между прогонами (после каждого прогона: при успехе — полный
       список источника, при остановке/ошибке — скопированное).
    3. Копируются только отсутствующие на цели (или отличающиеся
       по размеру — обрезанные при обрыве) файлы, повторно,
       целиком; копирование — прямыми FTP-передачами в параллельных
       потоках, команда mirror не используется.

    Возвращает (status, error, size, stats, errors) — как
    _run_ftp_mirror.
    """
    jid = job.get("id", "")
    lf = job.get("lftp") or {}
    passive = bool(lf.get("passive", True))
    src_is_ftp = src.get("type") == "ftp"
    dst_is_ftp = dest.get("type") == "ftp"
    ext_log = VERBOSE >= 1
    pats = job.get("exclude") or []

    # предпроверка: каждый FTP-конец доступен (быстрая ошибка при
    # недоступном сервере)
    for end in (src, dest):
        if end.get("type") == "ftp":
            label = ("FTP-источник:" if end is src else "FTP-цель:")
            det = ftp_connect_details(end)
            if det["ok"] and ext_log:
                for ln in ftp_conn_report_lines(det, label):
                    log.write(ln)
            if not det["ok"]:
                log.write(ftp_conn_report_lines(det, label)[0])
                return "error", \
                    "Не удалось подключиться к FTP-серверу: " + det["err"], \
                    None, None, [det["err"]]

    # флаг остановки: регистрируется ДО просмотра, чтобы кнопка
    # «Остановить» работала на всех этапах (просмотр источника,
    # сравнение списков, копирование); проверяется на входе в
    # каждый каталог скана, между файлами и по каждому чанку RETR
    stop = threading.Event()
    STOP_EVENTS[jid] = stop
    try:
        mirror_rel = sanitize_name(job.get("name", jid)) + "/mirror"
        local_target = None
        if src_is_ftp:
            src_root = (src.get("path") or "/").strip()
            if not src_root.startswith("/"):
                src_root = "/" + src_root
            base = src_root.rstrip("/").rsplit("/", 1)[-1]
            log.write("FTP-источник: " + ftp_url(src, with_password=False))
        else:
            local_src = Path(src.get("path", "")).expanduser()
            if not local_src.is_dir():
                return "error", f"Источник недоступен: {local_src}", \
                    None, None, []
            base = local_src.name
            log.write("Локальный источник: " + str(local_src))
        if dst_is_ftp:
            log.write("FTP-цель: " + ftp_url(dest, mirror_rel,
                                             with_password=False))
        else:
            local_target = Path(dest["path"]).expanduser() / mirror_rel
            if base:
                local_target = local_target / base
            local_target.mkdir(parents=True, exist_ok=True)
            log.write("Локальная цель: " + str(local_target))
        log.write("FTP-копирование: продолжение сравнением списков "
                  "(источник − скопировано) — недостающие файлы "
                  "копируются без mirror, обрезанный файл — заново "
                  "целиком")

        # 1) список всех файлов источника
        log.write("Просмотр источника (список всех файлов)…")
        t0 = time.monotonic()
        try:
            if src_is_ftp:
                n, total, sizes = scan_ftp_source(src, pats, passive=passive, stop=stop)
            else:
                n, total, sizes = scan_local_source(str(local_src), pats)
        except _StopRequested:
            log.write("Остановлено пользователем "
                      "(запрошено во время просмотра источника)")
            return "stopped", None, None, None, []
        except Exception as e:
            log.write("ОШИБКА: не удалось просмотреть источник: " + repr(e))
            return "error", f"Не удалось просмотреть источник: {e}", \
                None, None, [str(e)]
        log.write(f"Источник: {n} {_plural_ru(n, 'файл', 'файла', 'файлов')}, "
                  f"{human_size(total)} "
                  f"(просмотр: {time.monotonic() - t0:.1f} с)")
        if n == 0:
            log.write("Источник пуст — копировать нечего")
            if dst_is_ftp:
                save_copied_map(jid, {})
            return "ok", None, None, None, []

        # 2) список скопированных файлов
        if dst_is_ftp:
            copied = load_copied_map(jid)
            log.write(f"Скопировано (сохранённый список): {len(copied)} "
                      f"{_plural_ru(len(copied), 'файл', 'файла', 'файлов')}")
        else:
            dn, dtot, copied = scan_local_source(str(local_target), pats)
            log.write(f"Скопировано (каталог цели): {dn} "
                      f"{_plural_ru(dn, 'файл', 'файла', 'файлов')}, "
                      f"{human_size(dtot)}")

        # 3) чего не хватает
        missing = ftp_missing_list(sizes, copied)
        mtotal = sum(missing.values())
        log.write(f"Отсутствует на цели (будет скопировано): {len(missing)} "
                  f"{_plural_ru(len(missing), 'файл', 'файла', 'файлов')}, "
                  f"{human_size(mtotal)}")
        if not missing:
            log.write("Все файлы источника уже на цели (по имени и размеру) "
                      "— копировать нечего")
            if dst_is_ftp:
                save_copied_map(jid, sizes)
            size = stats = None
            if not dry and local_target is not None and local_target.is_dir():
                n2, tot2 = _walk_dir_stats(local_target)
                size, stats = tot2, {"files": n2, "size": tot2}
                log.write(f"Размер копии: {tot2 / 1024 / 1024:.1f} МБ "
                          f"({n2} файлов)")
            return "ok", None, size, stats, []
        if dry:
            log.write("Тестовый прогон: копирование не выполняется")
            for r in list(missing)[:50]:
                log.write(f"  {r} ({human_size(missing[r])})")
            if len(missing) > 50:
                log.write(f"  … ещё {len(missing) - 50}")
            return "ok", None, None, None, []

        # 4) прогресс (GUI) + параллельное копирование недостающего
        prog = {"total_files": len(missing), "total_bytes": mtotal,
                "total_pending": False, "done_files": 0, "done_bytes": 0,
                "pct": 0.0, "started_at": time.monotonic()}
        with FTP_PROGRESS_LOCK:
            FTP_PROGRESS[jid] = prog
        try:
            stopped, errors, interrupted, copied_map = _ftp_copy_engine(
                job, src, dest, missing, prog, stop)
        except Exception as e:
            # предпроверка прошла (TCP + баннер), но реальное
            # соединение/вход не удалось — чистая ошибка, а не сбой
            log.write("ОШИБКА: не удалось начать копирование: " + repr(e))
            return "error", f"Не удалось начать копирование: {e}", \
                None, None, [str(e)]
        finally:
            with FTP_PROGRESS_LOCK:
                FTP_PROGRESS.pop(jid, None)

        # сохраняем список «скопировано» для следующих продолжений
        # (только FTP-цель): при остановке/ошибке — то, что реально
        # скопировалось в этом прогоне
        if dst_is_ftp:
            if stopped or errors:
                save_copied_map(jid, copied_map)
                log.write(f"Сохранён список «скопировано»: {len(copied_map)} "
                          f"{_plural_ru(len(copied_map), 'файл', 'файла', 'файлов')}"
                          " (реально скопировано в этом прогоне)")
            else:
                save_copied_map(jid, sizes)
                log.write(f"Сохранён список «скопировано»: {len(sizes)} "
                          f"{_plural_ru(len(sizes), 'файл', 'файла', 'файлов')} "
                          "(полный список источника)")

        if stopped:
            log.write("Остановлено пользователем "
                      "(запрошено до завершения копирования)")
            if interrupted:
                log.write(f"Прерваны передачи {len(interrupted)} "
                          f"{_plural_ru(len(interrupted), 'файл', 'файла', 'файлов')} "
                          "(на цели возможны обрезки — при следующем "
                          "продолжении будут скопированы заново):")
                for nm in interrupted[:50]:
                    log.write("  " + nm)
            return "stopped", None, None, None, []
        if errors:
            for e in errors[:10]:
                log.write("Ошибка копирования файла: " + e)
            if len(errors) > 10:
                log.write(f"… ещё {len(errors) - 10}")
            return "error", f"Не удалось скопировать {len(errors)} " \
                f"{_plural_ru(len(errors), 'файл', 'файла', 'файлов')}", \
                None, None, errors[:20]
        done_files, done_bytes = prog["done_files"], prog["done_bytes"]
        log.write(f"Продолжение завершено успешно: скопировано {done_files} "
                  f"{_plural_ru(done_files, 'файл', 'файла', 'файлов')}, "
                  f"{human_size(done_bytes)}")
        size = stats = None
        if local_target is not None and local_target.is_dir():
            n2, tot2 = _walk_dir_stats(local_target)
            size, stats = tot2, {"files": n2, "size": tot2}
            log.write(f"Размер копии: {tot2 / 1024 / 1024:.1f} МБ ({n2} файлов)")
        return "ok", None, size, stats, []
    finally:
        # событие снято: повторная остановка уже не примется
        STOP_EVENTS.pop(jid, None)


_LFTP_LOCALE = None


def _lftp_env():
    """Окружение для запуска lftp (UTF-8-локаль).

    Под LC_ALL=C lftp при отправке FTP-команд (RETR/DELE) заменяет
    не-ASCII символы имён файлов на «?», и сервер отвечает
    550 No such file or directory — кириллические имена не копируются
    (проверено на lftp 4.9.2 + FileZilla Server 1.12.6). Поэтому
    запускаем lftp в UTF-8-локали: берём первую доступную на системе
    (C.UTF-8/C.utf8 — стандарт Debian 12+/Ubuntu 20.04+, иначе любая
    *UTF-8 из `locale -a`); если UTF-8-локаль не нашлась — C.UTF-8
    (в современных дистрибутивах она есть всегда).
    """
    global _LFTP_LOCALE
    if _LFTP_LOCALE is None:
        avail = set()
        try:
            r = subprocess.run(["locale", "-a"], capture_output=True,
                               text=True, timeout=10)
            avail = {x.strip() for x in r.stdout.split() if x.strip()}
        except (OSError, subprocess.SubprocessError):
            avail = set()
        low = {a.lower(): a for a in avail}
        _LFTP_LOCALE = (low.get("c.utf-8") or low.get("c.utf8")
                        or low.get("en_us.utf-8") or low.get("ru_ru.utf-8")
                        or next(iter(a for a in sorted(avail)
                                    if a.lower().endswith(("utf-8", "utf8"))),
                                None)
                        or "C.UTF-8")
    return dict(os.environ, LC_ALL=_LFTP_LOCALE, LANG=_LFTP_LOCALE)


def _run_ftp_mirror(job, src, dest, log, dry):
    """Копирование по FTP через lftp (команда mirror).

    FTP-сервер — на одном из концов, на другом — локальный каталог
    или другой FTP-сервер. Всегда ОДНА актуальная копия (режим
    «зеркало»), снапшоты не создаются.

    Пароль передаётся lftp только из временного файла сценария
    (права 600), который удаляется после прогона; в командной строке
    и в журнале пароль не появляется.

    Уровень подробного вывода операций mirror и dry-run-команд
    в журнале задания задаётся ключами запуска (-v / -vv,
    см. mirror_out_visible). Расширенное логирование подключения
    (детали предпроверки и протокол lftp) — только при запуске
    сервиса с -v / -vv.

    Прогресс копирования (процент) для GUI: источник просматривается
    один раз (всего файлов/байт) ПАРАЛЛЕЛЬНО с копированием в
    фоновом потоке (старт прогона не задерживается; итог
    подтягивается в процессе, строка с итогом — в конце журнала),
    далее процент считается по строкам «Finished transfer» уже
    стримируемого вывода lftp (без дополнительных соединений с
    сервером); состояние живёт в FTP_PROGRESS и подмешивается в
    /api/jobs (state.progress), из памяти убирается в finally.

    Возвращает (status, error, size, stats, errors).
    """
    jid = job.get("id", "")
    lf = job.get("lftp") or {}
    parallel = max(1, _to_int(lf.get("parallel"), 4))
    pget = max(1, _to_int(lf.get("pget"), 1))
    passive = bool(lf.get("passive", True))
    # буфер передач, КиБ: 1024 (1 МБ) — результат бенчмарка мелких
    # файлов (см. README); 0 — дефолт lftp (64 КБ)
    buffer = max(0, _to_int(lf.get("buffer"), 1024))
    # только новые файлы (mirror --only-newer): включено по умолчанию
    only_newer = bool(lf.get("only_newer", True))
    # продолжать незавершённые передачи; выключено по умолчанию.
    # ЗАМЕТКА: прогон с continue=true на самом деле идёт через
    # _run_ftp_continue (сравнение списков «источник − скопировано»,
    # без mirror) — сюда cont=true не попадает, флаг --continue
    # остаётся как резервный путь
    cont = bool(lf.get("continue", False))
    opts = job.get("options") or {}
    bw = int(opts.get("bwlimit") or 0)
    job_rel = sanitize_name(job.get("name", jid))
    mirror_rel = job_rel + "/mirror"

    if not shutil.which("lftp"):
        return "error", ("lftp не найден в PATH — установите его "
                         "(apt install lftp / dnf install lftp)"), \
            None, None, []

    # расширенное логирование FTP-подключения (детали предпроверки
    # + протокол lftp) — только при запуске сервиса с -v или -vv
    ext_log = VERBOSE >= 1

    # предпроверка: каждый FTP-конец доступен (быстрая ошибка при
    # недоступном сервере); подробные шаги (DNS, TCP, баннер 220)
    # в журнал пишутся только при -v/-vv
    for end in (src, dest):
        if end.get("type") == "ftp":
            label = ("FTP-источник:" if end is src else "FTP-цель:")
            det = ftp_connect_details(end)
            if det["ok"] and ext_log:
                for ln in ftp_conn_report_lines(det, label):
                    log.write(ln)
            if not det["ok"]:
                log.write(ftp_conn_report_lines(det, label)[0])
                return "error", "Не удалось подключиться к FTP-серверу: " \
                    + det["err"], None, None, [det["err"]]

    src_is_ftp = src.get("type") == "ftp"
    dst_is_ftp = dest.get("type") == "ftp"

    # сохранённый список «скопировано» (FTP-цель): если прогон не
    # завершится, к нему добавим реально скопированные в нём файлы —
    # продолжение сравнением списков (_run_ftp_continue) использует
    # этот список, чтобы доскопировать недостающее
    old_copied_map = load_copied_map(jid) if (dst_is_ftp and not dry) \
        else None

    # --- источник ---
    if src_is_ftp:
        src_spec = ftp_url(src)
        log.write("FTP-источник: " + ftp_url(src, with_password=False))
    else:
        local_src = src.get("path", "")
        if not Path(local_src).is_dir():
            return "error", f"Источник недоступен: {local_src}", \
                None, None, []
        log.write("Локальный источник: " + local_src)
        if dst_is_ftp:
            # lftp 4.9.x не подключается к серверу, если ftp://-URL
            # указан целью, а источник — «голый» локальный путь
            # («mirror: Not connected»); источник передаём полным
            # file:// URL (проверено: в этом виде mirror работает)
            src_spec = ("file://"
                        + str(Path(local_src).expanduser().resolve())
                        .rstrip("/") + "/")
        else:
            src_spec = local_src

    # --- место хранения: одна актуальная копия (mirror) ---
    local_target = None
    if dst_is_ftp:
        dst_spec = ftp_url(dest, mirror_rel)
        log.write("FTP-цель: " + ftp_url(dest, mirror_rel,
                                         with_password=False))
    else:
        local_target = Path(dest["path"]).expanduser() / mirror_rel
        dst_spec = str(local_target)
        log.write("Локальная цель: " + dst_spec)
    log.write("FTP-копирование через lftp (mirror) — одна актуальная "
              "копия, снапшоты не создаются")

    # каталог создаём всегда (в т.ч. при тестовом прогоне)
    if local_target is not None:
        local_target.mkdir(parents=True, exist_ok=True)

    # --- прогресс копирования (GUI) ---
    # предварительный просмотр источника (знаменатель процента):
    # локальный — os.walk, FTP — LIST по каталогам; далее процент
    # считается по уже стримируемому выводу lftp (см.
    # ftp_progress_on_line). Скан идёт ПАРАЛЛЕЛЬНО с копированием
    # в фоновом потоке: старт прогона не задерживается, итог
    # подтягивается в процессе; строка с итогом (или причиной
    # сбоя скана) дописывается в журнал после завершения прогона
    if not dry:
        pats = job.get("exclude") or []
        extras = {"size_map": {}, "done_names": []}
        prog = {"total_files": None, "total_bytes": None,
                "total_pending": True, "done_files": 0,
                "done_bytes": 0, "pct": None,
                "started_at": time.monotonic()}
        scan_lock = threading.Lock()
        scan_result = {}  # "res": (n, bytes, sizes) | "err": Exception

        def _scan_worker():
            # режим данных — как у самого mirror (в задании passive
            # может быть отключён), иначе скан может не пройти там,
            # где mirror работает (или наоборот)
            atts = 2 if src_is_ftp else 1
            for att in range(atts):
                try:
                    if src_is_ftp:
                        res = scan_ftp_source(src, pats, passive=passive)
                    else:
                        res = scan_local_source(local_src, pats)
                    with scan_lock:
                        scan_result["res"] = res
                    break
                except ScanLimitExceeded as e:
                    # лимит — не сбой сети, повторять бессмысленно
                    with scan_lock:
                        scan_result["err"] = e
                    break
                except Exception as e:
                    # FTP-скан — сетевое соединение: одна повторная
                    # попытка (lftp у mirror делает до 3 повторных
                    # подключений)
                    with scan_lock:
                        scan_result["err"] = e
                    if att + 1 < atts:
                        time.sleep(2)
            # публикуем итог, если задание ещё выполняется (поток
            # может «доживать» до лимитов после конца прогона)
            with FTP_PROGRESS_LOCK:
                if jid not in FTP_PROGRESS:
                    return
                with scan_lock:
                    res = scan_result.get("res")
                if res is not None:
                    n, total, sizes = res
                    prog["total_files"] = n
                    prog["total_bytes"] = total
                    prog["total_pending"] = False
                    ex = FTP_SCAN_EXTRAS.get(jid)
                    if ex is not None:
                        ex["size_map"] = sizes
                        # файлы, завершившиеся до прихода карты
                        # размеров: пересчитываем по именам
                        prog["done_bytes"] = sum(
                            sizes.get(nm, 0) for nm in ex["done_names"])
                    if total and total > 0:
                        prog["pct"] = min(
                            100.0, prog["done_bytes"] * 100.0 / total)
                    elif n and n > 0:
                        prog["pct"] = min(
                            100.0, prog["done_files"] * 100.0 / n)
                    elif n == 0:
                        # пустой источник: итог определён, копировать
                        # нечего (после скана прогон завершится сам)
                        prog["pct"] = 0.0
                else:
                    # просмотр не удался (или лимит) — только
                    # счётчик файлов, без процента
                    prog["total_pending"] = False

        with FTP_PROGRESS_LOCK:
            FTP_PROGRESS[jid] = prog
            FTP_SCAN_EXTRAS[jid] = extras
        scan_thread = threading.Thread(target=_scan_worker, daemon=True)
        scan_thread.start()
    else:
        prog = None
        scan_thread = None
        scan_lock = None
        scan_result = None

    # журнал lftp (протокол подключения) — только при расширенном
    # логировании (-v/-vv); файл рядом со сценарием, удаляется после
    # прогона, выдержка попадает в журнал задания
    lftp_log_path = (DATA_DIR / "creds" / f"{jid}.lftp-log"
                     if ext_log else None)
    if lftp_log_path is not None:
        try:
            lftp_log_path.unlink()  # lftp дописывает, а не обрезает файл
        except OSError:
            pass

    # --- сценарий lftp (пароль — только внутри файла) ---
    script = []
    if ext_log:
        # подробный протокол: все команды/ответы FTP с таймстампами
        script += [
            "set log:enabled yes",
            'set log:file "'
            + str(lftp_log_path).replace('"', '\\"') + '"',
            # журнал самих передач (RETR/STOR) не нужен — достаточно
            # протокола подключения и вывода mirror в основной журнал
            "set log:enabled/xfer no",
            "set log:level 9",
            "set log:show-time yes",
        ]
    script += [
        "set cmd:fail-exit true",
        "set ftp:passive-mode " + ("true" if passive else "false"),
        # подключение без шифрования (FTPS/SSL не используем)
        "set ftp:ssl-allow no",
        # не пытаться сохранить права файлов на удалённом конце
        # (SITE CHMOD / MFF): если сервер эти команды не поддерживает,
        # операция «chmod» завершается ошибкой — и при --verbose=3
        # lftp считает это фатальной ошибкой (код выхода 1); права
        # на файлах при FTP-копировании нам не важны
        "set mirror:set-permissions no",
        "set net:timeout 30",
        "set net:max-retries 3",
    ]
    # буфер передач (бенчмарк мелких файлов: 1 МБ стабильно чуть
    # быстрее дефолтных 64 КБ; 0 — строку не писать)
    buf_line = lftp_buffer_line(buffer)
    if buf_line:
        script.append(buf_line)
    if bw > 0:
        script.append(f"set net:limit-rate {bw * 1024}")
    mopts = ["mirror"]
    if job.get("mode") == "mirror" and opts.get("delete"):
        mopts.append("-e")
    mopts.append(f"--parallel={parallel}")
    if pget > 1:
        mopts.append(f"--use-pget-n={pget}")
    if only_newer:
        # копировать только файлы, новые на стороне источника
        # (по дате изменения); включено по умолчанию
        mopts.append("--only-newer")
    if cont:
        # докачка неполных файлов после обрыва (см. выше);
        # без флага lftp копирует их заново с начала
        mopts.append("--continue")
    # уровень подробного вывода lftp mirror: с -v / -vv — 3, а в журнал
    # задания попадает по уровню (mirror_out_visible: -v — только
    # директорные, -vv — и файловые); без -v — 2, а не 0: по строкам
    # «Transferring/Finished transfer» из этого вывода считается
    # процент прогресса для GUI (в сам журнал они не пишутся —
    # отфильтровывает mirror_out_visible); тестовый прогон — 0
    # (планируемые команды lftp печатает независимо от уровня)
    if dry:
        mopts.append("--verbose=0")
    elif VERBOSE >= 1:
        mopts.append("--verbose=3")
    else:
        mopts.append("--verbose=2")
    if dry:
        mopts.append("--dry-run")
    for pat in job.get("exclude") or []:
        mopts.append(f"--exclude-glob={pat}")
    mopts.append(src_spec)
    mopts.append(dst_spec)
    script.append(" ".join(mopts))

    script_path = DATA_DIR / "creds" / f"{jid}.lftp-script"
    lines = []
    rc = None
    run_error = None
    lftp_log_text = None
    first_out_secs = None   # время до первой операции с файлами
    inflight = {}           # передачи, начавшиеся и не завершившиеся
    try:
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text("\n".join(script) + "\n", encoding="utf-8")
        os.chmod(script_path, 0o600)
        cmd = ["lftp", "-f", str(script_path)]
        # в журнал пароль не пишем — маскируем в URL
        mopts_log = list(mopts)
        mopts_log[-2] = mask_ftp_password(mopts_log[-2])
        mopts_log[-1] = mask_ftp_password(mopts_log[-1])
        # копия сценария без пароля — хранится постоянно
        # (перезаписывается каждым прогоном), для диагностики
        safe_path = DATA_DIR / "scripts" / f"{jid}.lftp-script"
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        safe_path.write_text("\n".join(ftp_safe_script(script, mopts_log))
                             + "\n", encoding="utf-8")
        os.chmod(safe_path, 0o600)
        log.write("Команда: " + " ".join(cmd)
                  + "  (пароль передаётся только из файла сценария, "
                    "в журнал не попадает)")
        log.write("Полная команда с параметрами (пароль не показан): "
                  + " ".join(mopts_log))
        log.write("Копия сценария lftp (без пароля): " + str(safe_path))
        t0 = time.monotonic()
        # UTF-8-локаль: иначе lftp шлёт в FTP-командах имена файлов
        # с «?» вместо не-ASCII (550, кириллица не копируется);
        # вывод декодируем явно в UTF-8, независимо от локали сервиса
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace",
                                start_new_session=True,
                                env=_lftp_env())
        RUNNING[jid] = proc
        for line in proc.stdout:
            ln = line.rstrip()
            if ln:
                if first_out_secs is None:
                    first_out_secs = time.monotonic() - t0
                lines.append(ln)
                # незавершённые передачи: при остановке до конца
                # прогона в inflight останутся файлы, чья передача
                # прервана (на цели могут оказаться обрезанными)
                ftp_track_transfer(inflight, ln)
                # прогресс для GUI: по строкам «Finished transfer»
                # из уже прочитанного вывода (без доп. запросов);
                # карта размеров и список завершённых файлов
                # обновляются параллельным сканом под тем же локом
                if prog is not None:
                    with FTP_PROGRESS_LOCK:
                        ex = FTP_SCAN_EXTRAS.get(jid)
                        if ex is not None:
                            ftp_progress_on_line(
                                prog, ex["size_map"], ln,
                                ex["done_names"])
                # подробные операции с файлами/директориями и
                # dry-run-команды — по уровню -v / -vv
                # (mirror_out_visible); на всякий случай пароль в
                # URL маскируем (сам lftp пароль в вывод не печатает)
                if mirror_out_visible(ln):
                    log.write(mask_ftp_password(ln))
        rc = proc.wait()
        run_secs = time.monotonic() - t0
        # читаем журнал lftp, пока файл не удалён в finally
        if lftp_log_path is not None:
            try:
                lftp_log_text = lftp_log_path.read_text(
                    encoding="utf-8", errors="replace")
            except OSError:
                lftp_log_text = None
    except Exception as e:
        run_error = e
    finally:
        RUNNING.pop(jid, None)
        if scan_thread is not None:
            # скан обычно успевает до конца копирования (он не
            # делает передач) — короткий довод, чтобы результат
            # попал в журнал
            scan_thread.join(timeout=5)
        with FTP_PROGRESS_LOCK:
            # забираем до удаления: карта размеров и список
            # завершённых файлов нужны для обновления сохранённого
            # списка «скопировано» (продолжение без mirror)
            ex = FTP_SCAN_EXTRAS.get(jid) or {}
            cont_done_names = list(ex.get("done_names") or [])
            cont_size_map = dict(ex.get("size_map") or {})
            FTP_PROGRESS.pop(jid, None)
            FTP_SCAN_EXTRAS.pop(jid, None)
        try:
            script_path.unlink()
        except OSError:
            pass
        if lftp_log_path is not None:
            try:
                lftp_log_path.unlink()
            except OSError:
                pass

    # итог параллельного просмотра источника — в журнал задания
    # (строка появляется после прогона: скан шёл параллельно)
    if scan_thread is not None:
        with scan_lock:
            sres = scan_result.get("res")
            serr = scan_result.get("err")
        if sres is not None:
            n, total, _sizes = sres
            log.write(f"Источник (итог для прогресса): {n} "
                      f"{_plural_ru(n, 'файл', 'файла', 'файлов')}, "
                      f"{human_size(total)}")
        elif serr is not None:
            # полная причина (а не только класс исключения): лимит
            # просмотра, таймаут контрольного или данных соединения
            log.write(f"Прогресс: итог по источнику не определён "
                      f"({serr}) — процент в GUI не показывается")
        else:
            log.write("Прогресс: просмотр источника не завершился "
                      "к концу прогона")

    # обновляем сохранённый список «скопировано» (FTP-цель): при
    # успехе mirror цель полна — карта равна списку источника, при
    # остановке/ошибке — к прошлому списку добавляем реально
    # скопированные в этом прогоне файлы (по строкам «Finished
    # transfer»; обрезанный при обрыве файл не добавляется — при
    # продолжении он будет скопирован заново)
    if old_copied_map is not None:
        if rc == 0 and cont_size_map:
            save_copied_map(jid, cont_size_map)
        else:
            new_map = dict(old_copied_map)
            for nm in cont_done_names:
                new_map[nm] = cont_size_map.get(nm, 0)
            save_copied_map(jid, new_map)

    if run_error is not None:
        log.write("ОШИБКА: " + repr(run_error))
        return "error", str(run_error), None, None, [str(run_error)]

    # расширенный лог этапа подключения: выдержка протокола из
    # журнала lftp (соединения, вход, пассивный режим, списки) —
    # до первой передачи файла; пароли маскируются
    if lftp_log_text:
        ftp_pwds = [e.get("password") for e in (src, dest)
                    if e.get("type") == "ftp"]
        sec_lines, conn_secs = ftp_conn_section(lftp_log_text, ftp_pwds)
        if sec_lines:
            log.write("— Протокол подключения к FTP (журнал lftp, "
                      "до передачи файлов) —")
            for ln in sec_lines:
                log.write(ln)
            if conn_secs is not None:
                log.write(f"Длительность этапа подключения "
                          f"(по таймстампам lftp): {conn_secs:.1f} с")
            if first_out_secs is not None:
                log.write(f"До первой операции с файлами "
                          f"(подключение + списки каталогов): "
                          f"{first_out_secs:.1f} с")
            log.write("— конец протокола подключения —")

    lftp_errors = [ln for ln in lines if re.search(
        r"(error|denied|failed|cannot|can't|timeout)", ln, re.IGNORECASE)]
    status, error, size, stats = "ok", None, None, None
    if rc == 0:
        log.write("FTP-копирование завершено успешно "
                  f"(lftp отработал за {run_secs:.1f} с)")
        # статистику считаем по локальной копии (у удалённой цели
        # размер/число файлов без лишнего соединения не определить);
        # при тестовом прогоне файлы не копировались — показываем «—»
        if local_target is not None and not dry and local_target.is_dir():
            n, tot = 0, 0
            for dp, _, fns in os.walk(local_target):
                for fn in fns:
                    try:
                        tot += os.lstat(os.path.join(dp, fn)).st_size
                        n += 1
                    except OSError:
                        pass
            size = tot
            stats = {"files": n, "size": tot}
            log.write(f"Размер копии: {tot / 1024 / 1024:.1f} МБ "
                      f"({n} файлов)")
    elif _rc_stopped_by_user(rc):
        # остановка кнопкой «Остановить» — не ошибка
        status = "stopped"
        error = None
        log.write("Остановлено пользователем "
                  "(запрошено до завершения копирования)")
        if inflight:
            # файлы, чья передача была прервана: на цели они
            # могут оказаться обрезанными. Повторный запуск
            # доскопирует отсутствующие, но файл с «новым»
            # mtime (обрезанный) --only-newer не перескочит —
            # такие файлы стоит перепроверить отдельно (или
            # сделать один прогон без «Копировать только
            # изменившиеся»)
            log.write(
                f"Прерваны передачи {len(inflight)} "
                f"{_plural_ru(len(inflight), 'файл', 'файла', 'файлов')} "
                "(на цели возможны обрезки — проверьте после повторного "
                "запуска):")
            for nm in list(inflight)[:50]:
                log.write("  " + nm)
    else:
        status = "error"
        error = (f"Завершено сигналом {abs(rc)}" if rc < 0
                 else f"lftp завершился с кодом {rc}")
        log.write("ОШИБКА: " + error)
    return status, error, size, stats, lftp_errors


# --------------------------------------------------------------------------
# Push-уведомления (ntfy)
#
# Протокол ntfy: один HTTP POST на <сервер>/<топик>, тело — текст,
# заголовки Title/Tag/Priority. Клиенты: Android (приложение ntfy),
# Linux (desktop-приложение/скрипт), Windows (ntfy for Windows).
# Сервер — публичный https://ntfy.sh (через интернет) или собственный
# в локальной сети (http://host:2000). Пароли в уведомлениях не
# попадают: метки концов построены без паролей.
# --------------------------------------------------------------------------

def _ntfy_post(url, topic, message, title=None, tag=None,
               priority="default", timeout=10):
    """Один POST на ntfy-сервер. Возвращает (ok, error).

    Заголовки HTTP — latin-1, поэтому не-ASCII в Title/Tag
    (кириллица, эмодзи) передаётся закодированным RFC 2047
    («=?UTF-8?B?...?=" — base64): ntfy декодирует такие
    «email-style» заголовки нативно (см. docs.ntfy.sh/publish).
    Percent-кодирование НЕ используется — ntfy его не декодирует,
    и оно отображается в уведомлении как есть."""
    target = url.rstrip("/") + "/" + quote(topic, safe="")

    def hdr(v):
        if v.isascii():
            return v
        b64 = base64.b64encode(v.encode("utf-8")).decode("ascii")
        return "=?UTF-8?B?" + b64 + "?="

    headers = {"Content-Type": "text/plain; charset=utf-8",
               "Priority": priority}
    if title:
        headers["Title"] = hdr(title)
    if tag:
        headers["Tag"] = hdr(tag)
    req = urllib.request.Request(target,
                                 data=message.encode("utf-8"),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if getattr(r, "status", 200) == 200:
                return True, None
            return False, "HTTP %d" % getattr(r, "status", "?")
    except Exception as e:
        return False, repr(e)


def notify_push(title, message, tag=None, priority="default",
                force=False):
    """Push о событии (начало/завершение задания). force=True — отправить
    даже при выключенных уведомлениях (кнопка «Отправить тест»).
    Асинхронно: сетевые сбои не блокируют завершение прогона."""
    nt = CONFIG.data.get("notify") or {}
    if not nt.get("enabled") and not force:
        return False
    url = (nt.get("url") or "https://ntfy.sh").strip()
    topic = (nt.get("topic") or "").strip()
    if not topic:
        return False

    def send():
        ok, err = _ntfy_post(url, topic, message, title=title, tag=tag,
                             priority=priority)
        if ok:
            clog("INFO", f"Push-уведомление (ntfy {url}, топик {topic}): "
                         + title)
        else:
            clog("WARN", f"Не удалось отправить push-уведомление "
                         f"(ntfy {url}, топик {topic}): {err}")

    threading.Thread(target=send, daemon=True).start()
    return True


def notify_job_started(job, dry):
    title = ("Начало (тестовый прогон): " if dry else "Начало: ") \
        + job.get("name", job.get("id", ""))
    notify_push(title,
                "Источник: " + source_label(job) + "\n"
                + "Цель: " + dest_label(job),
                tag="▶️")


def notify_job_finished(job, status, error, dur, size, dry, stats):
    name = job.get("name", job.get("id", ""))
    pre = "тестовый прогон: " if dry else ""
    files = (stats or {}).get("files")
    sz = (stats or {}).get("size", size)
    if status == "ok":
        parts = []
        if files is not None:
            parts.append("скопировано " + str(files)
                         + " " + plural_ru(files, "файл", "файла",
                                           "файлов"))
        if sz:
            parts.append(human_size(sz))
        msg = (pre + ", ".join(parts)) if parts else pre
        if msg:
            msg += f" · {dur} с"
        notify_push(f"Завершено: {name}", msg or f"{dur} с",
                    tag="✅")
    elif status == "stopped":
        notify_push(f"Остановлено: {name}",
                    pre + f"остановлено пользователем · {dur} с",
                    tag="⏸️")
    else:
        notify_push(f"Ошибка: {name}",
                    (pre + (error or "неизвестная ошибка"))[:250]
                    + f" · {dur} с",
                    tag="❌", priority="urgent")


def run_job(job_id, dry=False, lftp_overrides=None):
    job = CONFIG.find_job(job_id)
    if not job:
        return {"error": "Задание не найдено"}
    if lftp_overrides:
        # разовые опции lftp только для этого прогона (кнопка
        # «Продолжить»: --continue и без --only-newer); сами
        # настройки задания не изменяются
        job = dict(job)
        lf = dict(job.get("lftp") or {})
        lf.update(lftp_overrides)
        job["lftp"] = lf
    lock = RUN_LOCKS.setdefault(job_id, threading.Lock())
    if not lock.acquire(blocking=False):
        return {"error": "Задание уже выполняется"}
    STATE.update(job_id, running=True, started_at=time.time())

    def worker():
        start = time.time()
        status, error, size = "ok", None, None
        mode = job.get("mode", "incremental")
        stats, rsync_lines, rsync_errors = None, [], []
        log = job_log(job_id, job.get("name", job_id))
        unmount_ids = []
        pass_files = {}  # rsyncd: "src"/"dst" -> Path к временному паролю
        clog("INFO", f"Запуск задания '{job.get('name', job_id)}' "
              f"({'тестовый прогон' if dry else 'обычный'} | "
              f"режим: {job.get('mode', 'incremental')})")
        try:
            log.write("=== Начало резервного копирования "
                      f"({'тестовый прогон' if dry else 'обычный'} | "
                      f"режим: {job.get('mode', 'incremental')}) ===")
            log.write("Источник: " + source_label(job))
            notify_job_started(job, dry)
            if lftp_overrides:
                log.write("Прогон с изменёнными опциями lftp: "
                          + ", ".join(f"{k}={v}"
                                      for k, v in sorted(
                                          lftp_overrides.items())))

            dest = job["destination"]
            src = job["source"] if isinstance(job.get("source"), dict) \
                else {"type": "local", "path": job.get("source", "")}

            # --- FTP (lftp mirror): отдельная ветка копирования ---
            # FTP-сервер на одном из концов, на другом — локальный
            # каталог или другой FTP. Всегда одна актуальная копия.
            if src.get("type") == "ftp" or dest.get("type") == "ftp":
                # continue=true (чекбокс задания или разовые опции
                # кнопки «Продолжить») — продолжение сравнением
                # списков без mirror; иначе обычный прогон lftp mirror
                if bool((job.get("lftp") or {}).get("continue", False)):
                    status, error, size, stats, rsync_errors = \
                        _run_ftp_continue(job, src, dest, log, dry)
                else:
                    status, error, size, stats, rsync_errors = \
                        _run_ftp_mirror(job, src, dest, log, dry)
                return

            # --- пароли rsyncd (временные файлы, удаляются после прогона) ---
            for tag, end in (("src", src), ("dst", dest)):
                pw = (end.get("password") or "").strip()
                if end.get("type") == "rsyncd" and pw:
                    pf = DATA_DIR / "creds" / f"{job_id}-{tag}.rsync-pass"
                    pf.parent.mkdir(parents=True, exist_ok=True)
                    pf.write_text(pw, encoding="utf-8")
                    os.chmod(pf, 0o600)
                    pass_files[tag] = pf

            # --- место хранения (цель) ---
            if dest.get("type") == "smb":
                share, sub = parse_smb(dest["path"])
                mp = mount_smb(share, dest.get("user", ""),
                               dest.get("password", ""), dest.get("vers", ""),
                               job_id + "-dst", log)
                unmount_ids.append(job_id + "-dst")
                d = LocalDest(mp / sub if sub else mp)
                log.write(f"SMB-шара (цель) подключена: {share}"
                          + (f" + {sub}" if sub else ""))
            elif dest.get("type") == "ssh":
                d = SshDest(dest)
                log.write(f"SSH-цель: {dest['user']}@{dest['host']}:{dest['path']}")
            elif dest.get("type") == "rsyncd":
                d = RsyncdDest(dest, pass_files.get("dst"))
                log.write("rsyncd-цель: "
                          + rsyncd_spec(dest, dest.get("path", "")))
                if mode == "incremental":
                    log.write("rsyncd-цель: жёсткие ссылки на прошлый "
                              "снапшот недоступны (удалённый конец) — "
                              "выполняется полное копирование")
            else:
                d = LocalDest(Path(dest["path"]).expanduser())
                log.write(f"Локальная цель: {dest['path']}")

            # --- источник ---
            if src.get("type") == "smb":
                share, sub = parse_smb(src["path"])
                mp = mount_smb(share, src.get("user", ""),
                               src.get("password", ""), src.get("vers", ""),
                               job_id + "-src", log)
                unmount_ids.append(job_id + "-src")
                src_path = str(mp / sub if sub else mp)
                log.write(f"SMB-шара (источник) подключена: {share}"
                          + (f" + {sub}" if sub else ""))
            elif src.get("type") == "ssh":
                src_path = ssh_source_arg(src)
                log.write(f"SSH-источник: {src['user']}@{src['host']}:{src['path']}")
            elif src.get("type") == "rsyncd":
                src_path = rsyncd_spec(src, src.get("path", ""))
                log.write("rsyncd-источник: " + src_path)
            else:
                src_path = src.get("path", "")
                if not Path(src_path).is_dir():
                    raise RuntimeError(f"Источник недоступен: {src_path}")

            # предпроверка: сервер rsyncd доступен по TCP (каждый rsyncd-конец)
            for end in (src, dest):
                if end.get("type") == "rsyncd":
                    ok, err = check_rsyncd_server(end)
                    if not ok:
                        raise RuntimeError(
                            "Не удалось подключиться к rsyncd: " + err)

            job_rel = sanitize_name(job["name"])
            if mode == "mirror":
                target_rel = f"{job_rel}/mirror"
            else:
                target_rel = f"{job_rel}/{datetime.now().strftime(TS_FMT)}"

            # предыдущий снапшот ищем ДО создания нового каталога;
            # для rsyncd-цели link-dest невозможен (абсолютный путь на
            # машине демона неизвестен клиенту) — снапшот будет полным
            link_dest = None
            if not dry and mode in ("incremental", "full") \
                    and not isinstance(d, RsyncdDest):
                prev = latest_snapshot(d, job_rel)
                if mode == "incremental":
                    if prev:
                        full_every = max(1, int(job.get("full_every_days") or 7))
                        try:
                            prev_dt = datetime.strptime(prev, TS_FMT)
                        except ValueError:
                            prev_dt = None
                        if prev_dt and (datetime.now() - prev_dt).days < full_every:
                            link_dest = d.abs_path(f"{job_rel}/{prev}")
                            log.write(f"Инкрементальный снапшот (link-dest: {prev})")
                        else:
                            log.write(f"Предыдущий снапшот старше {full_every} дн. "
                                      "— выполняется полное копирование")
                    else:
                        log.write("Предыдущий снапшот не найден — "
                                  "выполняется полное копирование")

            # каталог снапшота создаём всегда (в т.ч. при тестовом прогоне):
            # rsync --dry-run не создаёт каталоги на стороне приёмника
            d.mkdir(target_rel)
            ssh_src = src if src.get("type") == "ssh" else None
            cmd = build_rsync(job, d, target_rel, link_dest, dry,
                              src_path, ssh_src,
                              password_files=list(pass_files.values()))
            log.write("Команда: " + " ".join(cmd))
            # LC_ALL=C — стабильные (не локализованные) метки статистики
            # rsync независимо от локали системы
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    start_new_session=True,
                                    env=dict(os.environ,
                                             LC_ALL="C", LANG="C"))
            RUNNING[job_id] = proc
            for line in proc.stdout:
                ln = line.rstrip()
                log.write(ln)
                rsync_lines.append(ln)
            rc = proc.wait()
            stats = _parse_rsync_stats(rsync_lines)
            rsync_errors = [ln for ln in rsync_lines
                            if ln.startswith("rsync:")
                            or ln.startswith("rsync error")]
            RUNNING.pop(job_id, None)
            if rc == 0:
                log.write("Резервное копирование завершено успешно")
                if not dry and mode in ("incremental", "full"):
                    size = d.size(target_rel)
                    if size is not None:
                        log.write(f"Размер снапшота: {size / 1024 / 1024:.1f} МБ")
                    removed = prune_snapshots(job, d, job_rel)
                    if removed:
                        log.write("Удалено устаревших снапшотов: "
                                  + ", ".join(removed))
            elif _rc_stopped_by_user(rc):
                # остановка кнопкой «Остановить» — не ошибка
                status = "stopped"
                error = None
                log.write("Остановлено пользователем "
                          "(запрошено до завершения копирования)")
            else:
                status = "error"
                if rc < 0:
                    error = f"Завершено сигналом {abs(rc)}"
                else:
                    error = f"rsync завершился с кодом {rc}"
                log.write("ОШИБКА: " + error)
        except Exception as e:
            status = "error"
            error = str(e)
            log.write("ОШИБКА: " + repr(e))
            clog("ERROR", f"Задание '{job.get('name', job_id)}': {e!r}")
            traceback.print_exc()
        finally:
            for mid in unmount_ids:
                try:
                    unmount_smb(mid, log)
                except Exception:
                    pass
            for pf in pass_files.values():
                try:
                    pf.unlink()
                except OSError:
                    pass
            raw_dur = time.time() - start
            dur = round(raw_dur, 1)
            nxt = compute_next_run(job, datetime.now(), time.time())
            status_ru = {"ok": "успешно", "error": "с ошибкой",
                         "stopped": "остановлено"}.get(status, status)
            log.write(f"=== Завершено: {status_ru} за {dur} с ===")
            # запись в текстовый отчет (после завершения, в любом исходе);
            # ДО обновления состояния: когда API покажет «завершено»,
            # журнал и отчет уже записаны (нет гонки у наблюдателей)
            try:
                fmt = "%Y-%m-%d %H:%M:%S"
                rep = append_job_report(
                    job.get("name", job_id),
                    datetime.fromtimestamp(start).strftime(fmt),
                    datetime.fromtimestamp(time.time()).strftime(fmt),
                    dur, dry, mode, stats,
                    ([error] if error else []) + rsync_errors,
                    dur_raw=raw_dur)
                log.write(f"Отчет: {rep}")
            except Exception as e:
                clog("WARN", f"Не удалось записать отчет: {e!r}")
            STATE.update(job_id, running=False, started_at=None,
                         last_run=time.time(),
                         last_status=status, last_error=error,
                         last_duration=dur, last_size=size,
                         next_run=nxt.timestamp() if nxt else None)
            STATE.add_history({"ts": time.time(), "job": job["name"],
                               "status": status, "duration": dur,
                               "dry": dry, "error": error})
            clog("INFO", f"Задание '{job.get('name', job_id)}' завершено: "
                  f"{status}, {dur} с" + (f", ошибка: {error}" if error else ""))
            # push о завершении — после записи журнала/отчёта и обновления
            # состояния; асинхронно, не блокирует освобождение лока
            notify_job_finished(job, status, error, dur, size, dry, stats)
            lock.release()

    threading.Thread(target=worker, daemon=True).start()
    return {"ok": True}


def stop_job(job_id):
    ev = STOP_EVENTS.get(job_id)
    if ev is not None:
        # впроцессный движок (продолжение без mirror): процесса
        # lftp нет, SIGTERM шлать некуда — останавливаем по флагу;
        # потоки заметят его между файлами и в ходе приёма
        clog("INFO", f"Остановка запрошена для задания '{job_id}' "
                     "(продолжение без mirror)")
        ev.set()
        job_log(job_id).write("Остановка запрошена пользователем")
        return {"ok": True}
    proc = RUNNING.get(job_id)
    if not proc:
        return {"error": "Задание сейчас не выполняется"}
    clog("INFO", f"Остановка запрошена для задания '{job_id}'")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        job_log(job_id).write("Остановка запрошена пользователем")
        return {"ok": True}
    except Exception as e:
        clog("ERROR", f"Не удалось остановить задание '{job_id}': {e}")
        return {"error": str(e)}


def scheduler_loop():
    clog("INFO", "Поток планировщика запущен (проверка раз в 15 с)")
    while True:
        time.sleep(15)
        try:
            now = datetime.now()
            for job in list(CONFIG.jobs):
                if not job.get("enabled", True):
                    continue
                st = STATE.get(job["id"])
                if st.get("running"):
                    clog("DEBUG", f"Задание '{job['name']}' — уже выполняется, "
                          "пропуск по расписанию")
                    continue
                nr = st.get("next_run")
                if nr and time.time() >= nr:
                    clog("INFO", f"Расписание: запускаю задание "
                          f"'{job['name']}' ({job['id']})")
                    run_job(job["id"])
        except Exception:
            clog("ERROR", "Поток планировщика: необработанная ошибка")
            traceback.print_exc()


# --------------------------------------------------------------------------
# Валидация и нормализация
# --------------------------------------------------------------------------

def _to_int(v, default=0):
    """Безопасное преобразование в int для входящих данных API."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def normalize_job(job):
    job["name"] = (job.get("name") or "").strip()
    # источник: строка (старый формат) → {"type": "local", "path": ...}
    s = job.get("source")
    if isinstance(s, str):
        s = {"type": "local", "path": s}
    s = dict(s or {})
    for k in ("path", "user", "password", "vers", "host", "module"):
        if isinstance(s.get(k), str):
            s[k] = s[k].strip()
    if s.get("port"):
        try:
            s["port"] = int(s["port"])
        except (TypeError, ValueError):
            s["port"] = 22
    if not s.get("type"):
        s["type"] = "local"
    if s.get("type") == "rsyncd" and not s.get("port"):
        s["port"] = 873
    if s.get("type") == "ftp" and not s.get("port"):
        s["port"] = 21
    if s.get("type") == "ftp" and not s.get("path"):
        s["path"] = "/"  # пусто = корень FTP-сервера
    job["source"] = s
    ex = job.get("exclude")
    if isinstance(ex, str):
        job["exclude"] = [l.strip() for l in ex.splitlines() if l.strip()]
    else:
        job["exclude"] = [str(x).strip() for x in (ex or []) if str(x).strip()]
    d = job.get("destination") or {}
    for k in ("path", "user", "password", "vers", "host", "module"):
        if isinstance(d.get(k), str):
            d[k] = d[k].strip()
    if d.get("port"):
        d["port"] = _to_int(d.get("port"), 22)
    if d.get("type") == "rsyncd" and not d.get("port"):
        d["port"] = 873
    if d.get("type") == "ftp" and not d.get("port"):
        d["port"] = 21
    if d.get("type") == "ftp" and not d.get("path"):
        d["path"] = "/"  # пусто = корень FTP-сервера
    # путь SMB хранится как ввёл пользователь (включая подкаталог);
    # на шаре //сервер/шара + подпуть разбивается в parse_smb() в момент запуска
    job["destination"] = d
    # FTP (lftp mirror) — всегда одна актуальная копия (режим «зеркало»)
    if s.get("type") == "ftp" or d.get("type") == "ftp":
        job["mode"] = "mirror"
    st = job.get("schedule") or {}
    if st.get("kind") == "interval":
        st["minutes"] = max(1, _to_int(st.get("minutes"), 60))
    if st.get("kind") in ("daily", "weekly"):
        st["time"] = st.get("time") or "02:00"
    if st.get("kind") == "weekly":
        st["weekday"] = _to_int(st.get("weekday"), 0)
    job["schedule"] = st
    ret = job.get("retention") or {}
    for k in ("snapshots", "daily", "weekly", "monthly"):
        ret[k] = max(0, _to_int(ret.get(k), 0))
    job["retention"] = ret
    job["full_every_days"] = max(1, _to_int(job.get("full_every_days"), 7))
    o = job.get("options") or {}
    o["checksum"] = bool(o.get("checksum"))
    o["compress"] = bool(o.get("compress"))
    o["delete"] = bool(o.get("delete"))
    o["bwlimit"] = max(0, _to_int(o.get("bwlimit"), 0))
    job["options"] = o
    # настройки lftp (для FTP-варианта)
    lf = job.get("lftp") or {}
    job["lftp"] = {
        "parallel": max(1, _to_int(lf.get("parallel"), 4)),
        "pget": max(1, _to_int(lf.get("pget"), 1)),
        "passive": bool(lf.get("passive", True)),
        # буфер передач, КиБ (xfer:buffer-size); 1024 — по бенчмарку
        # мелких файлов, 0 — дефолт lftp (64 КБ)
        "buffer": max(0, _to_int(lf.get("buffer"), 1024)),
        # только новые файлы (mirror --only-newer); по умолчанию да
        "only_newer": bool(lf.get("only_newer", True)),
        # продолжать незавершённые передачи (mirror --continue);
        # по умолчанию нет
        "continue": bool(lf.get("continue", False)),
    }
    job["enabled"] = bool(job.get("enabled", True))
    return job


def validate_job(job):
    errs = []
    name = (job.get("name") or "").strip()
    if not name:
        errs.append("Укажите имя задания")
    for j in CONFIG.jobs:
        if j.get("id") != job.get("id") and \
                (j.get("name") or "").strip().lower() == name.lower():
            errs.append("Задание с таким именем уже существует")
            break
    # --- источник ---
    src = job.get("source") or {}
    if not isinstance(src, dict):
        src = {"type": "local", "path": str(src or "")}
    stype = src.get("type")
    if stype == "local":
        if not src.get("path"):
            errs.append("Укажите каталог источника")
        elif not str(src.get("path")).startswith("/"):
            errs.append("Источник (Linux) должен быть абсолютным путём")
    elif stype == "smb":
        if not src.get("path"):
            errs.append("Укажите адрес SMB-шары источника (//сервер/шара)")
        if not src.get("user"):
            errs.append("Укажите пользователя SMB (источник)")
    elif stype == "ssh":
        if not src.get("host"):
            errs.append("Укажите хост Windows (источник, SSH)")
        if not src.get("user"):
            errs.append("Укажите пользователя SSH (источник)")
        if not src.get("path"):
            errs.append("Укажите каталог на Windows (источник)")
    elif stype == "rsyncd":
        if not src.get("host"):
            errs.append("Укажите хост rsyncd (источник)")
        if not src.get("module"):
            errs.append("Укажите модуль rsyncd (источник, из rsyncd.conf)")
    elif stype == "ftp":
        if not src.get("host"):
            errs.append("Укажите хост FTP-сервера (источник)")
    else:
        errs.append("Неизвестный тип источника")

    # --- место хранения (цель) ---
    dest = job.get("destination") or {}
    t = dest.get("type")
    if t == "smb":
        if not dest.get("path"):
            errs.append("Укажите адрес SMB-шары (//сервер/шара)")
        if not dest.get("user"):
            errs.append("Укажите пользователя SMB")
    elif t == "ssh":
        if not dest.get("host"):
            errs.append("Укажите хост Windows (SSH)")
        if not dest.get("user"):
            errs.append("Укажите пользователя SSH")
        if not dest.get("path"):
            errs.append("Укажите каталог на Windows (например C:\\Backup)")
    elif t == "local":
        if not dest.get("path"):
            errs.append("Укажите локальный каталог")
    elif t == "rsyncd":
        if not dest.get("host"):
            errs.append("Укажите хост rsyncd (цель)")
        if not dest.get("module"):
            errs.append("Укажите модуль rsyncd (цель, из rsyncd.conf)")
    elif t == "ftp":
        if not dest.get("host"):
            errs.append("Укажите хост FTP-сервера (цель)")
    else:
        errs.append("Неизвестный тип цели")

    if stype == "ssh" and t == "ssh":
        errs.append("Одновременно удалённый источник и удалённая цель (SSH → SSH) "
                    "невозможны: rsync поддерживает только один удалённый конец. "
                    "Используйте SMB или локальный каталог для одного из концов")
    # FTP (lftp) может работать только с локальным каталогом или
    # другим FTP-сервером — SMB и SSH lftp не поддерживаются
    if (stype == "ftp" and t not in ("local", "ftp")) or \
       (t == "ftp" and stype not in ("local", "ftp")):
        errs.append("FTP (lftp) копирует только между локальным каталогом "
                    "и FTP-сервером (SMB и SSH не поддерживаются)")
    if job.get("mode") not in ("incremental", "full", "mirror"):
        errs.append("Неизвестный режим резервного копирования")
    st = job.get("schedule") or {}
    if st.get("kind") not in ("manual", "interval", "daily", "weekly"):
        errs.append("Неизвестный тип расписания")
    if st.get("kind") in ("daily", "weekly") and \
            not re.match(r"^([01]?\d|2[0-3]):[0-5]\d$", st.get("time") or ""):
        errs.append("Время расписания в формате ЧЧ:ММ")
    if st.get("kind") == "interval" and \
            not (1 <= _to_int(st.get("minutes"), 0) <= 525600):
        errs.append("Интервал: от 1 до 525600 минут")
    return errs


# --------------------------------------------------------------------------
# Просмоторы для API
# --------------------------------------------------------------------------

def status_info():
    rsync = None
    try:
        rsync = subprocess.run(["rsync", "--version"], capture_output=True,
                               text=True, timeout=10).stdout.splitlines()[0]
    except Exception:
        pass
    lftp = None
    try:
        lftp = subprocess.run(["lftp", "--version"], capture_output=True,
                              text=True, timeout=10).stdout.splitlines()[0]
    except Exception:
        pass
    return {
        "version": APP_VERSION,
        "rsync": rsync,
        "lftp": lftp,
        "python": sys.version.split()[0],
        "uptime": int(time.time() - START_TIME),
        "data_dir": str(DATA_DIR),
        "auth": bool(CONFIG.data.get("password_hash")
                     or CONFIG.data.get("auth_token")),
        "jobs": len(CONFIG.jobs),
        "mount_sudo": bool(SUDO),
        "fusermount": _fusermount_bin(),
    }


def jobs_view():
    now = time.monotonic()
    with FTP_PROGRESS_LOCK:
        # скорость и ETA считаются при каждом чтении (см. progress_view)
        prog_map = {k: progress_view(v, now) for k, v in FTP_PROGRESS.items()}
    out = []
    for j in CONFIG.jobs:
        st = STATE.get(j["id"])
        if j["id"] in prog_map:
            # живой прогресс FTP-копирования (только во время прогона)
            st = dict(st)
            st["progress"] = prog_map[j["id"]]
        out.append({**j, "state": st})
    return out


def snapshots_view(job_id):
    job = CONFIG.find_job(job_id)
    if not job:
        return {"error": "Задание не найдено"}
    dest = job["destination"]
    snap_pf = None
    try:
        if dest.get("type") == "smb":
            share, sub = parse_smb(dest["path"])
            mp = mount_smb(share, dest.get("user", ""),
                           dest.get("password", ""), dest.get("vers", ""),
                           job_id + "-dst")
            d = LocalDest(mp / sub if sub else mp)
        elif dest.get("type") == "ssh":
            d = SshDest(dest)
        elif dest.get("type") == "rsyncd":
            pw = (dest.get("password") or "").strip()
            if pw:
                snap_pf = DATA_DIR / "creds" / f"{job_id}-snapshots.rsync-pass"
                snap_pf.parent.mkdir(parents=True, exist_ok=True)
                snap_pf.write_text(pw, encoding="utf-8")
                os.chmod(snap_pf, 0o600)
            d = RsyncdDest(dest, snap_pf)
        else:
            d = LocalDest(Path(dest["path"]).expanduser())
        job_rel = sanitize_name(job["name"])
        out = []
        for n in d.listdir(job_rel):
            if SNAP_RE.match(n):
                out.append({"name": n, "size": d.size(f"{job_rel}/{n}")})
        out.sort(key=lambda x: x["name"], reverse=True)
        return {"snapshots": out}
    except Exception as e:
        return {"error": str(e)}
    finally:
        if snap_pf:
            try:
                snap_pf.unlink()
            except OSError:
                pass


# --------------------------------------------------------------------------
# HTTP API
# --------------------------------------------------------------------------

class Api(BaseHTTPRequestHandler):
    server_version = "backupd/" + APP_VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def handle_one_request(self):
        self._t0 = time.time()
        super().handle_one_request()

    def _send(self, code, obj, ctype="application/json; charset=utf-8"):
        body = obj if isinstance(obj, (bytes, bytearray)) \
            else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return
        dur = int((time.time() - self._t0) * 1000)
        ip = self.client_address[0] if self.client_address else "?"
        if code >= 500:
            clog("ERROR", f"HTTP {self.command} {self.path} от {ip} "
                  f"-> {code} ({dur} мс)")
        elif code >= 400:
            clog("WARN", f"HTTP {self.command} {self.path} от {ip} "
                  f"-> {code} ({dur} мс)")
        else:
            clog("DEBUG", f"HTTP {self.command} {self.path} от {ip} "
                  f"-> {code} ({dur} мс)")

    def _bearer(self):
        got = self.headers.get("Authorization") or ""
        return got[7:] if got.startswith("Bearer ") else got

    def _auth_ok(self):
        """Доступ разрешён, если пароль/токен не заданы либо предъявлен
        валидный токен сессии (POST /api/login) или старый статический токен."""
        data = CONFIG.data
        pwd_hash = data.get("password_hash") or ""
        static = data.get("auth_token") or ""
        if not pwd_hash and not static:
            return True
        got = self._bearer()
        if not got:
            return False
        if static and hmac.compare_digest(got, static):
            return True
        exp = SESSIONS.get(got)
        return bool(exp and exp > time.time())

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            n = 0
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw or b"{}")
        except Exception:
            return {}

    # -- GET --------------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?")[0]
        query = self.path.split("?")[1] if "?" in self.path else ""

        # Сам интерфейс всегда доступен — экран входа показывает GUI,
        # а данные защищены токеном сессии.
        if path in ("/", "/index.html"):
            if not (WEB_DIR / "index.html").exists():
                return self._send(500, {"error": "web/index.html не найден"})
            return self._send(200,
                              (WEB_DIR / "index.html").read_bytes(),
                              "text/html; charset=utf-8")
        if path == "/api/auth":
            # Публичный: позволяет интерфейсу решить, показывать ли
            # экран входа (без токена — только факт включения пароля)
            return self._send(200, {
                "auth": bool(CONFIG.data.get("password_hash")
                             or CONFIG.data.get("auth_token")),
                "logged_in": self._auth_ok(),
            })
        if not self._auth_ok():
            return self._send(401, {"error": "Требуется авторизация"})
        if path == "/api/status":
            return self._send(200, status_info())
        if path == "/api/notify":
            nt = CONFIG.data.get("notify") or {}
            return self._send(200, {"notify": {
                "enabled": bool(nt.get("enabled")),
                "url": nt.get("url") or "https://ntfy.sh",
                "topic": nt.get("topic") or ""}})
        if path == "/api/jobs":
            return self._send(200, {"jobs": jobs_view()})
        if path == "/api/history":
            return self._send(200, {"history": STATE.data["history"]})
        m = re.match(r"^/api/jobs/([\w-]+)/log$", path)
        if m:
            tail = 400
            if query:
                q = parse_qs(query)
                tail = max(1, _to_int(q.get("tail", ["400"])[0], 400))
            return self._send(200, {"log": job_log(m.group(1)).tail(tail)})
        m = re.match(r"^/api/jobs/([\w-]+)/snapshots$", path)
        if m:
            return self._send(200, snapshots_view(m.group(1)))
        return self._send(404, {"error": "Не найдено"})

    # -- POST -------------------------------------------------------------

    def do_POST(self):
        path = self.path.split("?")[0]
        # Вход, выход и (при выключенной авторизации) установка пароля
        # доступны без токена
        if path not in ("/api/login", "/api/logout") and not self._auth_ok():
            return self._send(401, {"error": "Требуется авторизация"})
        body = self._body()
        if not isinstance(body, dict):
            body = {}

        # --- авторизация ---

        if path == "/api/login":
            stored = CONFIG.data.get("password_hash") or ""
            if stored and check_password(str(body.get("password") or ""), stored):
                now = time.time()
                for t in [t for t, e in SESSIONS.items() if e < now]:
                    del SESSIONS[t]
                tok = uuid.uuid4().hex
                SESSIONS[tok] = now + SESSION_TTL
                clog("INFO", "Вход в интерфейс по паролю")
                return self._send(200, {"token": tok,
                                        "expires_in": SESSION_TTL})
            clog("WARN", "Неудачная попытка входа по паролю")
            return self._send(401, {"error": "Неверный пароль"})

        if path == "/api/logout":
            SESSIONS.pop(self._bearer(), None)
            clog("INFO", "Выход из интерфейса")
            return self._send(200, {"ok": True})

        if path == "/api/password":
            pwd = str(body.get("password") or "")
            if len(pwd) < 4:
                return self._send(400, {"error": "Пароль должен быть "
                                                 "не короче 4 символов"})
            CONFIG.data["password_hash"] = hash_password(pwd)
            CONFIG.save()
            clog("INFO", "Пароль доступа к интерфейсу установлен/изменён")
            return self._send(200, {"auth": True})

        if path == "/api/password/clear":
            CONFIG.data["password_hash"] = ""
            CONFIG.save()
            clog("INFO", "Авторизация интерфейса отключена")
            return self._send(200, {"auth": False})

        # --- push-уведомления (ntfy) ---

        if path == "/api/notify":
            url = str(body.get("url") or "").strip() or "https://ntfy.sh"
            topic = str(body.get("topic") or "").strip()
            if not (url.startswith("http://") or url.startswith("https://")):
                return self._send(400, {"error": "Адрес сервера ntfy должен "
                    "начинаться с http:// или https://"})
            if not re.fullmatch(r"[A-Za-z0-9/_.-]{1,64}", topic):
                return self._send(400, {"error": "Топик: 1–64 символа — "
                    "латинские буквы, цифры, дефис, точка, подчёркивание, "
                    "косая черта"})
            nt = CONFIG.data.setdefault("notify", {})
            nt["url"] = url
            nt["topic"] = topic
            nt["enabled"] = bool(body.get("enabled"))
            CONFIG.save()
            clog("INFO", "Настройки push-уведомлений (ntfy) сохранены "
                  f"(включены: {nt['enabled']}, сервер: {url})")
            return self._send(200, {"notify": {
                "enabled": nt["enabled"], "url": url, "topic": topic}})

        if path == "/api/notify/test":
            nt = CONFIG.data.get("notify") or {}
            url = (nt.get("url") or "https://ntfy.sh").strip()
            topic = (nt.get("topic") or "").strip()
            if not topic:
                return self._send(400, {"error": "Сначала задайте топик"})
            ok, err = _ntfy_post(
                url, topic,
                "Тестовое сообщение от backupd: сюда будут приходить "
                "уведомления о начале и завершении заданий.",
                title="Тест backupd", tag="🔔", timeout=15)
            if ok:
                clog("INFO", "Тестовое push-уведомление отправлено (ntfy)")
                return self._send(200, {"ok": True})
            clog("WARN", f"Тестовое push-уведомление не отправлено: {err}")
            return self._send(502, {"error": "Не удалось отправить: " + err})

        if path == "/api/jobs":
            job = normalize_job(dict(body))
            job["id"] = uuid.uuid4().hex[:12]
            errs = validate_job(job)
            if errs:
                return self._send(400, {"error": "; ".join(errs)})
            CONFIG.upsert_job(job)
            nr = compute_next_run(job, datetime.now(), None)
            if nr and nr.timestamp() < time.time():
                nr = datetime.now() + timedelta(seconds=60)
            STATE.update(job["id"], next_run=nr.timestamp() if nr else None)
            return self._send(200, {"job": job})

        m = re.match(r"^/api/jobs/([\w-]+)/run$", path)
        if m:
            # разовые переопределения lftp-опций для прогона
            # (кнопка «Продолжить»: continue + only_newer)
            ov = body.get("lftp")
            ov = ({k: ov[k] for k in
                   ("parallel", "pget", "passive", "buffer",
                    "only_newer", "continue") if k in ov}
                   if isinstance(ov, dict) else None)
            r = run_job(m.group(1), dry=bool(body.get("dry")),
                        lftp_overrides=ov)
            return self._send(200 if "error" not in r else 409, r)

        m = re.match(r"^/api/jobs/([\w-]+)/stop$", path)
        if m:
            return self._send(200, stop_job(m.group(1)))

        m = re.match(r"^/api/jobs/([\w-]+)/toggle$", path)
        if m:
            job = CONFIG.find_job(m.group(1))
            if not job:
                return self._send(404, {"error": "Не найдено"})
            job["enabled"] = not job.get("enabled", True)
            CONFIG.save()
            return self._send(200, {"job": job})

        if path == "/api/config":
            token = str(body.get("token") or "")
            CONFIG.data["auth_token"] = token
            CONFIG.save()
            return self._send(200, {"auth": bool(token)})
        if path == "/api/config/generate":
            token = uuid.uuid4().hex
            CONFIG.data["auth_token"] = token
            CONFIG.save()
            return self._send(200, {"token": token, "auth": True})

        return self._send(404, {"error": "Не найдено"})

    # -- PUT --------------------------------------------------------------

    def do_PUT(self):
        if not self._auth_ok():
            return self._send(401, {"error": "Требуется авторизация"})
        path = self.path.split("?")[0]
        m = re.match(r"^/api/jobs/([\w-]+)$", path)
        if m:
            job = CONFIG.find_job(m.group(1))
            if not job:
                return self._send(404, {"error": "Не найдено"})
            if STATE.get(m.group(1)).get("running"):
                return self._send(409,
                                  {"error": "Задание выполняется, "
                                            "измените настройки позже"})
            body = self._body()
            if not isinstance(body, dict):
                return self._send(400, {"error": "Некорректный формат задания"})
            body["id"] = m.group(1)
            job = normalize_job(body)
            errs = validate_job(job)
            if errs:
                return self._send(400, {"error": "; ".join(errs)})
            CONFIG.upsert_job(job)
            st = STATE.get(job["id"])
            nr = compute_next_run(job, datetime.now(), st.get("last_run"))
            if nr and nr.timestamp() < time.time() - 5:
                nr = datetime.now() + timedelta(seconds=60)
            STATE.update(job["id"], next_run=nr.timestamp() if nr else None)
            return self._send(200, {"job": job})
        return self._send(404, {"error": "Не найдено"})

    # -- DELETE -----------------------------------------------------------

    def do_DELETE(self):
        if not self._auth_ok():
            return self._send(401, {"error": "Требуется авторизация"})
        path = self.path.split("?")[0]
        m = re.match(r"^/api/jobs/([\w-]+)$", path)
        if m:
            job = CONFIG.find_job(m.group(1))
            if not job:
                return self._send(404, {"error": "Не найдено"})
            if STATE.get(m.group(1)).get("running"):
                return self._send(409, {"error": "Задание сейчас выполняется"})
            for mid in (m.group(1) + "-src", m.group(1) + "-dst"):
                try:
                    unmount_smb(mid)
                except Exception:
                    pass
            CONFIG.remove_job(m.group(1))
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "Не найдено"})


# --------------------------------------------------------------------------

def main():
    global DATA_DIR, CONFIG, STATE, VERBOSE, SUDO
    ap = argparse.ArgumentParser(
        description="Сервер резервного копирования на базе rsync "
                    "(источник и цель: Linux или Windows)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="адрес для прослушивания (по умолчанию 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8420,
                    help="порт (по умолчанию 8420)")
    ap.add_argument("--data-dir", default=str(BASE_DIR / "data"),
                    help="каталог для конфигурации, журналов, монтирования")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="расширенное логирование в консоль и в журнал "
                         "заданий (детали FTP-подключения: предпроверка "
                         "и протокол lftp; операции mirror и "
                         "dry-run-команды: без ключей выключены "
                         "(lftp запускается с --verbose=2 для процента прогресса в GUI, "
                         "строки отфильтровываются сервером; dry-run — "
                         "--verbose=0), -v — директории, -vv — и "
                         "файлы); -vv — максимальная детализация")
    ap.add_argument("--use-sudo", action="store_true",
                    help="выполнять mount/umount SMB-шар через sudo "
                         "(запуск сервера без root-прав)")
    args = ap.parse_args()
    VERBOSE = min(args.verbose, 2)
    SUDO = ["sudo"] if args.use_sudo else []

    # абсолютный путь: команды mount/umount (в т.ч. через sudo)
    # должны видеть ту же точку монтирования независимо от cwd
    DATA_DIR = Path(args.data_dir).expanduser().resolve()
    for sub in ("logs", "mounts", "reports"):
        (DATA_DIR / sub).mkdir(parents=True, exist_ok=True)
    CONFIG = Config(DATA_DIR / "config.json")
    STATE = State(DATA_DIR / "state.json")
    init_next_runs()

    clog("INFO", f"Запуск backupd {APP_VERSION} (PID {os.getpid()}, "
          f"Python {sys.version.split()[0]})")
    clog("INFO", f"Слушаю: http://{args.host}:{args.port}/")
    clog("INFO", f"Каталог данных: {DATA_DIR}")
    clog("INFO", f"Авторизация по паролю: "
          f"{'вкл' if CONFIG.data.get('password_hash') else 'выкл'}")
    clog("INFO", f"Монтирование SMB через sudo: {'вкл' if args.use_sudo else 'выкл'}")
    clog("INFO", f"Заданий в конфигурации: {len(CONFIG.jobs)}")
    rsync_bin = shutil.which("rsync")
    if rsync_bin:
        try:
            ver = subprocess.run(["rsync", "--version"], capture_output=True,
                                 text=True, timeout=10).stdout.splitlines()[0]
            clog("INFO", f"rsync: {rsync_bin} — {ver}")
        except Exception:
            clog("INFO", f"rsync: {rsync_bin}")
    else:
        clog("ERROR", "rsync не найден в PATH")
    lftp_bin = shutil.which("lftp")
    if lftp_bin:
        try:
            ver = subprocess.run(["lftp", "--version"], capture_output=True,
                                 text=True, timeout=10).stdout.splitlines()[0]
            clog("INFO", f"lftp: {lftp_bin} — {ver}")
        except Exception:
            clog("INFO", f"lftp: {lftp_bin}")
    else:
        clog("WARN", "lftp не найден в PATH — FTP-задания (lftp mirror) "
                     "не будут работать; установите его (apt install lftp / "
                     "dnf install lftp)")
    fm_bin = _fusermount_bin()
    if fm_bin:
        clog("INFO", f"Отключение SMB-шар: {fm_bin} "
                     f"({shutil.which(fm_bin)}), резервно — umount")
    else:
        clog("WARN", "fusermount/fusermount3 не найдены в PATH — установите "
                     "пакет fuse/fuse3 (например: apt install fuse3 / "
                     "dnf install fuse3); SMB-шары будут отключаться "
                     "только через umount (нужны root/sudo)")

    httpd = ThreadingHTTPServer((args.host, args.port), Api)
    threading.Thread(target=scheduler_loop, daemon=True).start()
    clog("INFO", "HTTP-сервер запущен, ожидают запросов")
    print(f"backupd {APP_VERSION} запущен: http://{args.host}:{args.port}/")
    print(f"Каталог данных: {DATA_DIR}")
    if not rsync_bin:
        print("ПРЕДУПРЕЖДЕНИЕ: rsync не найден в PATH — установите его "
              "(apt install rsync / dnf install rsync)")
    # SIGTERM (например, от systemd) — так же, как Ctrl+C
    def _term(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _term)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановка...")
        clog("INFO", "Остановка по сигналу (Ctrl+C / SIGTERM)")
        for entry in sorted((DATA_DIR / "mounts").iterdir()):
            if entry.is_dir() and entry.name.endswith(("-src", "-dst")):
                clog("INFO", f"Отключаю смонтированную SMB-шару: {entry.name}")
                try:
                    unmount_smb(entry.name)
                except Exception:
                    clog("WARN", f"Не удалось отключить {entry.name}")


if __name__ == "__main__":
    main()
