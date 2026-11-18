# backupd — rsync-based file backup server

[Русская версия — README.md](README.md)

A backup server for a machine: **source and copy destination** — directories
on Linux or Windows (local, over SMB, over SSH, or via the rsync daemon
rsyncd).
Works on the [rsnapshot](https://rsnapshot.org) principle: incremental
snapshots via `rsync --link-dest` (hard links), retention policies,
scheduling.

```
┌─────────────────┐        SMB (CIFS) or SSH+rsync        ┌──────────────────┐
│  Linux server   │ ──────────────────────────────────────▶ │  Windows        │
│  /var/data      │   backupd (this project, rsync inside) │  D:\Backup\...  │
│  /home          │                                         │  (share / disk) │
└─────────────────┘                                         └──────────────────┘
         HTML interface: http://127.0.0.1:8420/
```

Any combination of ends is possible (each — Linux or Windows):

| Source → Destination | Linux | Windows (SMB) | Windows (SSH) | rsyncd | FTP (lftp) |
|---|---|---|---|---|---|
| **Linux** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Windows (SMB)** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Windows (SSH)** | ✅ | ✅ | ❌ | ✅ | ❌ |
| **Windows (VSS)** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **rsyncd** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **FTP (lftp)** | ✅ | ❌ | ❌ | ❌ | ✅ |

Limitations:

- rsync supports only **one** SSH end — a "SSH → SSH" copy in a single run
  is not possible (use SMB, rsyncd or a local directory for one of the
  ends).
- With an **rsyncd** destination snapshots are always full copies:
  `--link-dest` (hard links) is unavailable — the daemon machine's path to
  the previous snapshot is unknown to the client.
- **FTP (lftp)** copies only between a local directory and an FTP server
  (SMB, SSH and rsyncd are not supported). No snapshots are made — there
  is always one current copy (mode "Mirror").
- **Windows (VSS)**: the source is a shadow copy of a Windows volume:
  `vssadmin create shadow` is run over SSH, and rsync copies files from
  the snapshot's mount point — this also copies files that are open for
  writing, correctly. The SSH user must be a local Windows
  administrator (VSS requires admin rights); an SSH key is required.
  The destination may only be a local directory of the server or an SMB
  share. The shadow copy is deleted automatically after the run.

## Features

- **Copy modes** (configured in the HTML interface):
  - *Incremental* — snapshots with hard links (`--link-dest`), they do not
    take double the space; a full copy every N days;
  - *Full* — every snapshot is an independent copy;
  - *Mirror* — one current copy (optionally with pruning of extra files).
- **Sources and destinations**: Windows SMB share (recommended),
  SSH + rsync (DeltaRSync), Windows shadow copy (VSS over SSH — correct
  copy of files open for writing), rsync daemon (rsyncd, rsync://
  protocol, port 873), FTP server (lftp client, one current copy), local
  Linux directory
  (testing) — for both ends.
- **SSH end**: key-based authentication only (no password prompt);
  optionally — the full path to the remote rsync (the "Path to rsync.exe
  on Windows" field, passed as `--rsync-path`, e.g. when a stray
  `rsync.cmd` sits in System32).
- **Scheduling**: manual, every N minutes, daily at HH:MM, weekly.
- **Retention**: last N snapshots + 1 per day/week/month over N periods
  (old snapshots are removed automatically).
- **Options**: excludes, compression, checksums, rate limit, dry run
  (test run), stopping a run.
- **Log** of each job and run history; after a run, the row under the
  job keeps the stats: total files on the source and how many were
  copied.
- **Password authentication for the interface** (optional, can be disabled;
  the password is stored as an scrypt hash).
- **Push notifications (ntfy)** about the start and finish of each job —
  on Android, Linux or Windows (public ntfy.sh or your own server in the
  local network).
- **Bilingual interface**: Russian and English (System tab → Interface
  language; the choice is stored in `config.json`).

## Installation on Linux (source server)

```bash
# dependencies
apt install rsync cifs-utils        # Debian/Ubuntu
# or: dnf install rsync cifs-utils # RHEL/Rocky/Alma
# optional, FTP variant only:
#   apt install lftp  /  dnf install lftp

# download the project, e.g. to /opt/backupd
cd /opt/backupd
python3 backupd.py --port 8420 --data-dir /var/lib/backupd
```

Interface: `http://SERVER-IP:8420/` (by default it listens on 127.0.0.1 only).

### Extended console logging

By default the server prints only the basic startup banner. The `-v` /
`--verbose` flags enable detailed console output (useful when running in a
terminal and when debugging; with systemd use `journalctl -u backupd -f`):

```bash
python3 backupd.py -v    # key events
python3 backupd.py -vv   # + maximum detail
```

What is logged to the console:

| Level | `-v` | `-vv` | What is logged |
|---|---|---|---|
| `INFO` | ✅ | ✅ | start/stop, job start and finish, scheduled runs, SMB mount/unmount, errors |
| `JOB` | ✅ | ✅ | **the whole log of each job** — rsync commands, rsync output, snapshot sizes, errors |
| `WARN` | ✅ | ✅ | HTTP requests with 4xx codes (with IP and duration) |
| `ERROR` | ✅ | ✅ | HTTP 5xx, rsync/mount/SMB errors, unhandled exceptions (with traceback) |
| `DEBUG` | — | ✅ | all HTTP requests (2xx), saving configuration/state, remote SSH commands, next-run calculation |

Shutdown (Ctrl+C or SIGTERM from systemd) is clean: the server waits for the
current HTTP request to finish and unmounts all mounted SMB shares.

### Running as a service (systemd)

A ready-made file — `backupd.service` in the repository root:
`cp backupd.service /etc/systemd/system/ && systemctl daemon-reload &&
systemctl enable --now backupd`. Contents:

```ini
[Unit]
Description=backupd - rsync backup server (Linux -> Windows)
After=network-online.target

[Service]
# the -v flag — detailed output to the journal (journalctl -u backupd -f)
ExecStart=/usr/bin/python3 /opt/backupd/backupd.py --port 8420 --data-dir /var/lib/backupd -v
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now backupd
```

> The service runs as root — that is required for `mount -t cifs`
> (SMB destinations). If root is not needed, see "Running without root"
> below.

### Running without root (mounting via sudo)

By default backupd calls `mount -t cifs ...` itself — that requires
root privileges. To run the server as a regular user, add the
`--use-sudo` flag: mount/umount/fusermount will be executed via `sudo`:

```bash
python3 backupd.py --port 8420 --data-dir /var/lib/backupd --use-sudo
```

In that case the server user must be allowed to run mount/umount
without a password prompt. `/etc/sudoers.d/backupd` (user `backupd`,
file mode 0440):

```
backupd ALL=(root) NOPASSWD: /bin/mount, /bin/umount, /usr/bin/fusermount, /usr/bin/fusermount3
```

> **fusermount / fusermount3.** To unmount an SMB share backupd uses
> `fusermount -u` (or `fusermount3 -u` if only the newer variant is
> installed on the system), then falls back to `umount`. If neither
> utility is found, a warning is written to the log and to the console
> at startup (with `-v`): "install the fuse/fuse3 package (apt install
> fuse3 / dnf install fuse3)". The selected utility is shown in the
> "System" tab ("SMB unmount").

The flag is shown in the "System" tab ("SMB mounting") and logged to the
console at startup (with `-v`).

### Accessing the interface from a browser

By default the interface is reachable from the server itself only
(127.0.0.1). For browser access use an SSH tunnel (secure):

```bash
ssh -L 8420:127.0.0.1:8420 user@linux-server
# then open http://localhost:8420/
```

If you need direct access, run with `--host 0.0.0.0` and **make sure**
to set an access password ("System" tab → "Set / change password").

## Windows setup (storage destination)

### Option 1. Shared folder (SMB) — recommended

1. On Windows create a folder, e.g. `D:\Backup`.
2. Right click → **Properties → Sharing → Advanced sharing**:
   - "Share this folder…", share name: `backup`;
   - **Permissions** — grant access to the needed user
     (e.g. a local `backupuser` with a password).
3. Firewall: allow "File and Printer Sharing (SMB-In)" for your subnet.
4. In backupd create a job: *Destination type* → "Windows — shared folder
   (SMB)", address `//WINDOWS_NAME_OR_IP/backup`, user and password.

Check from Linux:

```bash
mount -t cifs -o username=backupuser //192.168.1.50/backup /mnt/test
```

> **Mount diagnostics.** Before running `mount -t cifs` the server
> automatically checks for the `mount` program, `sudo` (with
> `--use-sudo`) and `mount.cifs` (the `cifs-utils` package), and for the
> SMB server being reachable over TCP (port 445, or 139 for `vers=1.x`).
> On a mount error the job log receives the full command, the original
> `mount` output and the probable cause in plain words: wrong password
> (NT_STATUS_LOGON_FAILURE), access denied, wrong share name,
> unsupported protocol version (vers), server unreachable, etc.
> See the "Log" tab in the web interface.

### Option 2. SSH + rsync (DeltaRSync)

1. On Windows enable **OpenSSH Server**:
   Settings → Apps → Optional features → "OpenSSH Server" (install,
   start the service).
2. Install [DeltaRSync](https://www.aitmail.com/deltarsync.html)
   (or cwRsync) so that `rsync.exe` is in the system PATH
   (check: `where rsync` in cmd).
3. Create a Windows user and a `C:\Backup` directory.
4. On Linux:

```bash
ssh-keygen -t ed25519          # if you have no key
ssh-copy-id backupuser@192.168.1.50   # or manually:
# copy ~/.ssh/id_ed25519.pub to %USERPROFILE%\.ssh\authorized_keys
# on Windows (grant read access to .ssh only to that user!)
rsync --version -e ssh backupuser@192.168.1.50:  # connection test
```

5. In backupd: *Destination type* → "Windows — SSH + rsync", host, user,
   directory `C:\Backup`.

### Option 3. Windows (VSS) — source

Copying **from** Windows, where files open for writing are also copied
correctly (their state at the snapshot moment). Requirements — as in
Option 2 (OpenSSH Server + rsync in PATH + key), plus:

1. The SSH user must be a **local Windows administrator** (creating
   shadow copies requires admin rights).
2. The Volume Shadow Copy (VSS) service is enabled (it is on standard
   Windows editions; check: `vssadmin list writers` in cmd as
   administrator).

In backupd: *Source type* → "Windows — shadow copy (VSS over SSH)",
host, user, a directory like `D:\Data` (the drive letter is the volume
that will be snapshotted). The destination is a local directory of the
server or an SMB share. The shadow copy is created before the run and
deleted automatically afterwards (in any outcome).

If a stray `rsync.cmd` sits in System32 while rsync itself is installed
elsewhere, give the full path to `rsync.exe` in the "Path to rsync.exe
on Windows" field (passed to rsync as `--rsync-path`).

## Option: rsync daemon (rsyncd)

Instead of SMB or SSH you can use the daemon built into rsync
(`rsync://` protocol, port **873**) — it works both as a source
and as a destination (on Linux and on Windows).

1. On the daemon machine create a config (example module `bk` for a
   **destination**, write allowed):

   ```ini
   # /etc/rsyncd.conf
   [bk]
   path = /backup
   comment = backup module
   read only = no
   list = yes
   auth users = backup
   secrets file = /etc/rsyncd.secrets
   ```

   `secrets file` — lines of `user:password`, file mode 600:

   ```
   backup:Parol123
   ```

   For a **destination** `read only = no` is mandatory (otherwise rsyncd
   will refuse writes). Without `auth users` access is anonymous
   (then no password is needed in backupd).

2. Start the daemon:

   ```bash
   rsync --daemon --config=/etc/rsyncd.conf   # or via systemd:
   systemctl enable --now rsyncd
   ```

3. Firewall: allow incoming TCP **port 873** (on Windows — "Firewall" →
   Inbound rules → port 873).

4. In backupd: *Type* → "rsyncd (rsync daemon)", host, port (default 873),
   module (as in the config), optionally a subpath inside the module, and
   credentials.

rsyncd specifics:

- The rsyncd protocol **does not encrypt** the transfer (unlike SSH) —
  use it only in a trusted network.
- With an rsyncd destination `--link-dest` is unavailable: snapshots are
  always full copies (the job log reflects this).
- The rsyncd password never appears in commands or logs: rsync reads it
  only from a temporary `--password-file` (mode 600) that is removed
  immediately after the run.
- Before copying the server checks the daemon's TCP availability
  (port 873) and writes the reason for any refusal to the job log.

## Option: FTP (lftp mirror)

If the source (or the destination) is an FTP server, copying can be done
with the [lftp](https://lftp.yar.ru/) utility (the `mirror` command)
instead of rsync. In the interface: *Source/destination type* → "FTP
server (lftp client)", host, port (default 21), user, password, directory
on the FTP server (empty field — the FTP server root, `/`).

FTP-variant specifics:

- Snapshots and retention **do not apply** — there is always **one
  current copy** in a `mirror` subdirectory (the job mode is forced to
  "Mirror", the mode selector in the interface is locked).
- lftp works only with a local directory and another FTP server:
  FTP + SMB/SSH/rsyncd combinations are rejected when creating a job.
- The lftp settings are in the "lftp settings" block of the job form:
  - *Parallel streams* — how many files are copied simultaneously
    (`mirror --parallel=N`, default 4);
  - *Streams per file (pget)* — 1 = off, >1 — each file is copied with
    several connections (`mirror --use-pget-n=N`);
  - *Transfer buffer, KiB* — `xfer:buffer-size`; default 1024
    (1 MiB) — the result of a small-file benchmark (see below), 0 —
    lftp's default (64 KiB);
  - *Only newer files* — `mirror --only-newer` (enabled by default):
    only files that changed on the source side after they were copied
    are copied; turn it off if you need to recreate on the destination
    files that are "older" than the local ones;
  - *Resume incomplete* — resume by list comparison (off by default):
    during copying a list of all source files and a list of copied files
    are built (local destination — a fresh scan of the destination
    directory, FTP destination — a map persisted between runs in
    `data/ftp_state/<id>.json`). If a copy is incomplete the lists are
    compared, and files missing on the destination (or differing in size
    — truncated on an abort) are copied again, in full. Copying goes by
    direct FTP transfers (ftplib) in parallel streams ("Parallel
    streams"), the `mirror` command is not used; a truncated file is
    copied from the start, not resumed (REST). This is what the ⏩
    "Continue" button does (a one-off run without "Only newer files",
    the rest of the job options are kept); with the checkbox enabled
    this algorithm is used by all runs of the job (incl. scheduled ones)
    — a re-run copies only the files that appeared on the source /
    changed size;
  - *Passive mode* — `ftp:passive-mode` (enabled by default; disable it
    if a firewall blocks incoming data connections).
- **Cyrillic (and any non-ASCII) file names** are copied correctly: lftp
  is launched in the system's UTF-8 locale (C.UTF-8 / C.utf8, or any
  other available UTF-8 locale — detected automatically on the first
  FTP run). This is mandatory: under `LC_ALL=C` lftp replaces non-ASCII
  characters in file names with "?" when sending FTP commands
  (RETR/DELE), the server answers 550, and such files are never copied
  (verified: lftp 4.9.2 + FileZilla Server 1.12.6).
- **Small-file optimization** (lftp 4.9.2 benchmark,
  `mirror --parallel=4`, an FTP server with ~300,000 small files,
  5,000+ directories; 90 s per configuration, 2 rounds):

  | Configuration | Round 1 (files/s) | Round 2 (files/s) | Result |
  |---|---|---|---|
  | baseline (as shipped) | 82 | 65 | — |
  | `--verbose=0` | 81 | 36 | no effect (the bottleneck is not output) |
  | `xfer:clobber true` | 78 | 60 | no effect (mirror already removes old files itself) |
  | `xfer:buffer-size 1 MiB` | **84** | **68** | consistently slightly faster — became the default |
  | `--parallel=8` | 47 | — | noticeably slower — the server does not scale with streams |

  Conclusion: with small files the bottleneck is the per-file protocol
  overhead (data connection + a LIST per directory), not throughput;
  client-side tuning gives only ~2–5 %. lftp 4.9.2 by default writes
  files straight to the target name (`xfer:use-temp-file no`) — no
  temporary file + rename is added.
- The rate limit is set by the common "Rate limit, KiB/s" field
  (converted to `net:limit-rate`, bytes/s).
- Excludes (`--exclude-glob`) work as they do for rsync.
- The password never appears on the command line or in the log: lftp is
  launched from a script in a temporary file `data/creds/<id>.lftp-script`
  (mode 600, removed after the run); in the log the password in the URL
  is masked (`***`). The job log records the full command with all
  options (without the password), and a copy of the script
  **without the password** is kept permanently in
  `data/scripts/<id>.lftp-script` (rewritten by every run) — for
  diagnostics.
- The FTP protocol **does not encrypt** the transfer (including
  passwords) — use it only in a trusted network. Encryption (FTPS/SSL)
  is explicitly disabled: `set ftp:ssl-allow no` in the lftp script —
  the connection is always unencrypted.
- Remote file permissions are not preserved
  (`set mirror:set-permissions no` in the lftp script): if the server
  does not support permission-change commands (CHMOD/MFF), lftp 4.9.x
  with verbose output treats it as an error and exits with a non-zero
  code.
- If the source is a local directory and the destination is FTP, the
  source is passed to lftp as a full `file://` URL: with a "bare" local
  path and an `ftp://` destination lftp 4.9.x does not connect to the
  server itself ("mirror: Not connected").
- **Copy progress** during an FTP job run is shown in the GUI: a bar,
  "N / M files", **transfer speed** (MiB/s, average over the run) and an
  **ETA** (the maximum of two estimates — by remaining bytes and by
  remaining files; with many small files the bottleneck is the per-file
  overhead, not bytes). The denominator source is browsed **once**:
  local — a single `os.walk` pass, FTP — one extra connection and a
  `LIST` over the directories (no file transfers; limits of 100,000
  directories, 1,000,000 files, 1800 s — protection against
  abnormally large sources). The scan runs **in parallel with the
  copying** and does not delay the start of the run: while the total is
  being counted the GUI shows the number of copied files and the note
  "total is being determined…", then the bar with a percentage, the
  speed and the ETA appear. The line "Source (total for progress): …"
  (or the reason the scan failed) is appended to the job log after the
  run finishes. The percentage itself is computed from the
  "Finished transfer" lines of the already-streamed lftp output — no
  extra requests to the server and no polling. The FTP scan uses the
  same data mode as the mirror itself (the job's `passive` setting),
  and on failure one retry is made (like lftp's reconnects). If the
  preview fails, the GUI shows only the number of copied files (without
  a percentage), and the job log records the full reason (preview limit,
  control- or data-connection timeout, etc.). Progress lives in memory
  only (it is not written to `state.json`) and is cleared after the job
  finishes.
- **Extended FTP logging** is enabled by the service's startup flags; the
  detail level of `mirror` operations depends on the flag:
  - **without `-v`** — detailed file and directory operations, planned
    dry-run commands and connection details are not written to the job
    log (quiet). lftp is launched not with `--verbose=0` but with
    `--verbose=2`: the "Transferring/Finished transfer" lines from that
    output are used for the GUI progress percentage and are filtered out
    of the job log by the server. A dry run is with `--verbose=0`:
    lftp prints the planned commands regardless of the level, the server
    filters them out;
  - **`-v`** — the log receives only directory operations
    ("Mirroring directory", "Making directory", "Finished mirror",
    "Removing old directory"), dry-run commands with directories
    ("mkdir …", "rm -r …"), pre-check details and the lftp connection
    protocol;
  - **`-vv`** — all detailed operations, including file ones
    ("Transferring file", "Finished transfer", "Removing old file"), and
    all dry-run commands ("get -O …", "chmod -f …", "rm …").

  The basic lines (command, options, errors, summary, result) are always
  written.
- Before copying the server checks the connection to each FTP server
  step by step. With `-v`/`-vv` the job log receives: the IP address
  (DNS resolution), the TCP connection time, the server's welcome banner
  (220); when unreachable — the reason for the refusal (the error is
  still recorded without `-v`).
- With `-v`/`-vv` the FTP connection phase is logged in detail: lftp runs
  with its own log enabled (`log:enabled`, `log:level 9`, `log:show-time`),
  and the excerpt of the protocol up to the start of file transfers (all
  parallel connections, login, passive mode, initial directory listings)
  together with the phase duration goes to the job log. In the protocol
  the password is masked (`***`); lftp itself writes `PASS XXXX` to its
  own log. The temporary lftp log file (`data/creds/<id>.lftp-log`) is
  created only with `-v`/`-vv` and removed after the run.
- `lftp` is not required for the other variants: if it is missing the
  server starts with a console warning and FTP jobs are rejected with a
  clear error. Install: `apt install lftp` (Debian/Ubuntu) or
  `dnf install lftp` (RHEL/Rocky/Alma).
- Stopping a run with the "Stop" button is **not** an error: the job
  status is "stopped" (an amber badge in the list and history), and the
  report says "Copy errors: none". If a transfer was in progress at the
  moment of stop, the job log receives the list of files whose transfer
  was interrupted (the line "Transfers interrupted: N …" + up to 50
  names) — such files on the destination may be truncated. The ⏩
  "Continue" button (or a run with the "Resume incomplete" option)
  compares the "source − copied" lists and copies the missing files
  without mirror: a truncated file is absent from the "copied" list (or
  has a different size), so it is copied again in full — truncations are
  repaired without any dependence on mtime or `--only-newer`.

## How copies are created

For a job `test` with the source `/var/data` on a Windows disk there
will be:

```
D:\Backup\test\
├── 20261005_020000\      <- snapshot (full, first)
├── 20261006_020000\      <- snapshot (incremental: changed files
│                             copied, the rest — hard links)
├── 20261007_020000\
└── ...
```

- Every snapshot is an **independent** copy: you can open any past day
  and restore files without touching the rest.
- The size of an incremental snapshot ≈ only the data delta.
- By the retention policy (e.g. last 7 snapshots + 7 days / 4 weeks /
  6 months) old snapshots are removed automatically.
- Every `full_every_days` days (default 7) a snapshot is made full —
  protection against accumulated errors and faster restores.

## Run report

After **every** job finish (a normal run, a dry run, success or error) a
record is appended to `data/reports/report.txt`:

```
============================================================
Job: test
Run: normal | mode: incremental
Start: 2026-11-07 02:00:00
Finish: 2026-11-07 02:04:12
Duration: 252.3 s
Files copied: 137
Size of copied files: 412.7 MiB
Average speed: 1.7 MiB/s
Copy errors: none
============================================================
```

The statistics (file count, size, speed) are taken from
`rsync --stats`; on an error before/instead of copying the "Copy
errors" field receives the error text (e.g. an SMB mount error or the
rsync exit code with its messages). The job log gets a line
"Report: <path to file>" about the record.

## Push notifications (ntfy)

About the start and the finish of **every** job (success, error, stop and
a dry run) you can receive push notifications on your device:
**Android** — the "ntfy" app (Play Store / F-Droid), **Linux** — ntfy
desktop (or any script subscribed to the topic), **Windows** — "ntfy for
Windows".

The server needs no SDKs — it sends a single HTTP POST to
`<server>/<topic>` (stdlib). The ntfy server can be:

- the public `https://ntfy.sh` — the device connects via the internet
  (works even if the device is outside the local network);
- your own in the local network, e.g.
  `http://192.168.1.100:2000` (Docker: `ntfy/ntfy`, port 2000) — then
  the notifications stay inside the LAN.

Configuration — "System" tab → "Push notifications (ntfy)": server URL,
topic (generated randomly), on/off and a "Send test" button. In the ntfy
app subscribe to the same server and topic.

Message contents (in Russian):

- **Start**: "Начало: <job name>" + the lines "Источник: …" and "Цель: …";
- **Success**: "Завершено: <name>" + "copied N files, X · T s" (✅);
- **Stop**: "Остановлено: <name>" + duration (⏸️) — not an error;
- **Error**: "Ошибка: <name>" + the error text, priority *urgent* (❌).

Notifications are sent **asynchronously** after the job log and the
report are written: an ntfy-server failure or no internet does not affect
the copies or the report. The messages contain no passwords (the end
labels are password-free). The topic is like a password: whoever knows it
can read the notifications, so use a random topic and do not publish it.

Non-ASCII characters in the message **Title** and **Tag** headers are
sent as RFC 2047 encoded-words (`=?UTF-8?B?…?=`), which ntfy decodes
natively — Cyrillic and emoji display correctly on the device
(percent-encoding in headers is not decoded by ntfy and would appear
literally).

## Files and data

| Path | Purpose |
|---|---|
| `backupd.py` | the server (startup, scheduling, HTTP API) |
| `web/index.html` | the HTML interface |
| `backupd.service` | the ready-made systemd unit (see "Running as a service") |
| `data/config.json` | jobs and the access-password hash |
| `data/state.json` | statuses, next run, history |
| `data/logs/<id>.log` | the job log |
| `data/mounts/<id>` | SMB mount point |
| `data/creds/` | temporary rsyncd password files and lftp scripts (removed after the run) |
| `data/reports/report.txt` | the text report (a record after every run) |

## REST API (for integrations)

All requests are JSON. If a password is set, protected requests require
the `Authorization: Bearer <token>` header; the token is issued at login:

```bash
TOK=$(curl -s -X POST localhost:8420/api/login \
       -d '{"password": "…"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -H "Authorization: Bearer $TOK" localhost:8420/api/jobs
```

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/login` | `{"password": "…"}` — login, issues a session token (12 h) |
| POST | `/api/logout` | end the current session |
| GET | `/api/auth` | public: is a password set and is the request authorized |
| POST | `/api/password` | `{"password": "…"}` — set/change the password (min 4 chars) |
| POST | `/api/password/clear` | disable authentication |
| GET | `/api/notify` | push-notification (ntfy) settings |
| POST | `/api/notify` | `{"enabled", "url", "topic"}` — save the ntfy settings |
| POST | `/api/notify/test` | send a test push notification |
| GET | `/api/status` | server status, rsync and lftp versions |
| GET | `/api/jobs` | list of jobs with statuses |
| POST | `/api/jobs` | create a job |
| PUT | `/api/jobs/<id>` | modify a job |
| DELETE | `/api/jobs/<id>` | delete a job |
| POST | `/api/jobs/<id>/run` | start a run (`{"dry": true}` — test) |
| POST | `/api/jobs/<id>/stop` | stop the current run |
| POST | `/api/jobs/<id>/toggle` | enable/disable a job |
| GET | `/api/jobs/<id>/log?tail=N` | tail of the job log |
| GET | `/api/jobs/<id>/snapshots` | list of snapshots |
| GET | `/api/history` | run history |

The old static token (`auth_token` in `config.json`) is still accepted as
a `Bearer` token for backward compatibility, but the interface no longer
offers managing it.

## Security

- By default the interface listens on **127.0.0.1 only** — it is not
  visible from outside.
- For external access set a password ("System" tab → "Set / change
  password"). The password is stored in `config.json` only as an scrypt
  hash; a session lives 12 hours and is issued at login (`/api/login`).
  Authentication can be disabled with the "Disable authentication"
  button.
- SMB passwords are stored in `config.json` (mode 644 by default —
  restrict it: `chmod 600 data/config.json`); the mount credentials file
  is created with mode 600 and removed immediately after mounting.
- SSH destinations use key authentication (no passwords stored).
- The rsyncd password is never passed on the command line: rsync reads
  it only from a temporary `--password-file` (mode 600, created in
  `data/creds/` and removed immediately after the run).
- The FTP (lftp) password is never passed on the command line: lftp is
  launched from a script in a temporary file `data/creds/<id>.lftp-script`
  (mode 600, removed immediately after the run), and the password in the
  URL is masked in the log. Note: the FTP protocol sends passwords in
  clear text — trusted networks only.

## License

MIT — see the [LICENSE](LICENSE) file.
