#!/usr/bin/env python3
"""fdw-hub 控制程式

子指令：
  tunnel  依 config.yaml 建立並維持 SSH 通道（常駐）
  apply   依 config.yaml 重建外部資料表、view、本地帳號，並產生 dbhub.toml
  check   只檢查設定檔，列出連線路徑，不做任何變更
"""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

import yaml

CONFIG_PATH = os.environ.get("HUB_CONFIG", "/app/config.yaml")
SSH_SRC = os.environ.get("HUB_SSH_SRC", "/ssh-src")
GENERATED_DIR = os.environ.get("HUB_GENERATED_DIR", "/generated")
HUB_HOST = os.environ.get("HUB_HOST", "hub")
HUB_PORT = int(os.environ.get("HUB_INTERNAL_PORT", "5432"))
HUB_DB = "hub"
TUNNEL_HOST = os.environ.get("HUB_TUNNEL_HOST", "tunnel")
PORT_BASE = 20000
ASKPASS_PATH = os.path.expanduser("~/.ssh/askpass.sh")

# 加密的帳密檔（AES-128-CBC，前 16 bytes 是 IV，整體 Base64）。
# 金鑰由 dbhub.ps1 init 隨機產生在 ssh/hub.key，與 SSH 金鑰一起掛進容器。
SECRETS_PATH = os.environ.get("HUB_SECRETS", "/app/.env.enc")
SECRET_KEY_PATH = os.path.join(SSH_SRC, "hub.key")

TAG = "managed-by-db-hub"
TAG_UPSTREAM = TAG + ":upstream"
TAG_VIEWS = TAG + ":views"

NAME_RE = re.compile(r"^[a-z_][a-z0-9_]*$")
BASTION_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SETTING_RE = re.compile(r"^[a-z_][a-z0-9_.]*$")
RESERVED_SCHEMAS = {"public", "information_schema"}
DEFAULT_PORTS = {"postgres": 5432, "mariadb": 3306}

DEFAULT_ROLE_SETTINGS = {
    "default_transaction_read_only": "on",
    "statement_timeout": "30s",
    "idle_in_transaction_session_timeout": "60s",
    "log_statement": "all",
}


# ---------------------------------------------------------------- 共用工具

def log(msg):
    print(f"[hubctl] {msg}", flush=True)


def die(msg):
    log(f"錯誤：{msg}")
    sys.exit(1)


_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env(value):
    """把 config.yaml 裡的 ${VAR} 換成 .env 的值。"""
    if isinstance(value, str):
        def repl(m):
            name = m.group(1)
            if name not in os.environ:
                die(f"config.yaml 用到環境變數 {name}，但 .env 裡沒有設定")
            return os.environ[name]
        return _ENV_RE.sub(repl, value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def yaml_scalar(v):
    """YAML 會把 on/yes 讀成布林值，這裡轉回 PostgreSQL / SSH 認得的字串。"""
    if v is True:
        return "on"
    if v is False:
        return "off"
    return str(v)


def need_name(kind, name):
    if not isinstance(name, str) or not NAME_RE.match(name):
        die(f"{kind}名稱「{name}」不合法：只能用小寫英文、數字、底線，且不能以數字開頭")
    if name.startswith("pg_"):
        die(f"{kind}名稱「{name}」不能以 pg_ 開頭")


def port_of(u):
    return int(u.get("port") or DEFAULT_PORTS[u["type"]])


# ---------------------------------------------------------------- 設定檔

def load_secrets():
    """把 .env.enc 解密後的變數放進 os.environ。已存在的環境變數優先，不覆蓋。"""
    if not os.path.isfile(SECRETS_PATH):
        return
    if not os.path.isfile(SECRET_KEY_PATH):
        die(f"有 {SECRETS_PATH} 但找不到金鑰 ssh/hub.key")
    import base64
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    try:
        with open(SECRET_KEY_PATH, encoding="ascii") as f:
            key = bytes.fromhex(f.read().strip())
        with open(SECRETS_PATH, encoding="ascii") as f:
            raw = base64.b64decode(f.read().strip())
        dec = Cipher(algorithms.AES(key), modes.CBC(raw[:16])).decryptor()
        plain = dec.update(raw[16:]) + dec.finalize()
        plain = plain[:-plain[-1]]                      # 去掉 PKCS7 padding
        data = json.loads(plain.decode("utf-8"))
    except Exception as e:
        die(f"無法解密 {SECRETS_PATH}（{type(e).__name__}），金鑰是否對應？")
    n = 0
    for k, v in data.items():
        if k not in os.environ:
            os.environ[k] = str(v)
            n += 1
    log(f"已從 .env.enc 載入 {n} 個變數")


def load_config():
    load_secrets()
    if not os.path.isfile(CONFIG_PATH):
        die(f"找不到設定檔 {CONFIG_PATH}")
    with open(CONFIG_PATH, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    cfg = expand_env(raw)
    for key in ("ssh", "bastions", "upstreams", "views", "roles"):
        cfg[key] = cfg.get(key) or {}
    validate(cfg)
    return cfg


def validate(cfg):
    # 跳板機
    for name, b in cfg["bastions"].items():
        if not BASTION_RE.match(str(name)):
            die(f"跳板機名稱「{name}」不合法")
        for field in ("host", "user"):
            if not b.get(field):
                die(f"跳板機 {name} 缺少 {field}")
        if not b.get("key") and not b.get("password"):
            die(f"跳板機 {name} 要指定 key（金鑰檔名）或 password（密碼）其中一個")
        if b.get("key") and b.get("password"):
            die(f"跳板機 {name} 不能同時指定 key 與 password")
        if b.get("password") and b.get("jump"):
            die(f"跳板機 {name} 用密碼認證時不能再指定 jump（多段跳板只支援金鑰）")
        if b.get("jump") and b["jump"] not in cfg["bastions"]:
            die(f"跳板機 {name} 的 jump 指向不存在的 {b['jump']}")

    # 上游
    all_locals = {}
    for name, u in cfg["upstreams"].items():
        need_name("上游", name)
        t = str(u.get("type", "")).lower()
        if t == "mysql":
            t = "mariadb"
        if t not in DEFAULT_PORTS:
            die(f"上游 {name} 的 type 必須是 postgres 或 mariadb")
        u["type"] = t
        for field in ("host", "database", "user", "password"):
            if not u.get(field):
                die(f"上游 {name} 缺少 {field}")
        if u.get("via") and u["via"] not in cfg["bastions"]:
            die(f"上游 {name} 的 via 指向不存在的跳板機 {u['via']}")
        for k in (u.get("server_options") or {}):
            if not SETTING_RE.match(str(k)):
                die(f"上游 {name} 的 server_options「{k}」名稱不合法")

        imps = u.get("import") or [{"remote": "public" if t == "postgres" else u["database"]}]
        parsed = []
        for imp in imps:
            if isinstance(imp, str):
                imp = {"remote": imp}
            if not imp.get("remote"):
                die(f"上游 {name} 的 import 缺少 remote")
            local = imp.get("local") or (name if len(imps) == 1 else None)
            if not local:
                die(f"上游 {name} 匯入多個 schema 時，每一項都要寫 local")
            need_name("schema ", local)
            if local in RESERVED_SCHEMAS:
                die(f"不能使用 {local} 當作 schema 名稱")
            if local in all_locals:
                die(f"schema {local} 重複（{all_locals[local]} 與 {name}）")
            all_locals[local] = name
            parsed.append({"remote": str(imp["remote"]), "local": local,
                           "tables": [str(x) for x in (imp.get("tables") or [])]})
        u["_imports"] = parsed
    cfg["_upstream_schemas"] = all_locals

    # view
    view_schemas = []
    for full in cfg["views"]:
        parts = str(full).split(".")
        if len(parts) != 2:
            die(f"view「{full}」要寫成 schema.名稱")
        need_name("view schema ", parts[0])
        need_name("view ", parts[1])
        if parts[0] in RESERVED_SCHEMAS:
            die(f"不能把 view 放在 {parts[0]}")
        if parts[0] in all_locals:
            die(f"view schema {parts[0]} 和上游匯入的 schema 撞名")
        if parts[0] not in view_schemas:
            view_schemas.append(parts[0])
    cfg["_view_schemas"] = view_schemas

    # 本地帳號
    for name, r in cfg["roles"].items():
        need_name("帳號", name)
        if name == "postgres":
            die("不能把 postgres 當作小帳號")
        if not r.get("password"):
            die(f"帳號 {name} 缺少 password")
        g = r.get("grant") or {}
        for t in g.get("tables") or []:
            if len(str(t).split(".")) != 2:
                die(f"帳號 {name} 的 grant.tables「{t}」要寫成 schema.表名")
        for k in (r.get("settings") or {}):
            if not SETTING_RE.match(str(k)):
                die(f"帳號 {name} 的設定「{k}」名稱不合法")

    m = cfg.get("mcp")
    if m and m.get("role") not in cfg["roles"]:
        die(f"mcp.role 指向不存在的帳號 {m.get('role')}")


def endpoints(cfg):
    """每個上游在集線器眼中的連線位址。經跳板機的依序分配 tunnel:20000、20001…"""
    ep, i = {}, 0
    for name, u in cfg["upstreams"].items():
        if u.get("via"):
            ep[name] = (TUNNEL_HOST, PORT_BASE + i)
            i += 1
        else:
            ep[name] = (u["host"], port_of(u))
    return ep


# ---------------------------------------------------------------- tunnel

def prepare_ssh(cfg):
    home = os.path.expanduser("~/.ssh")
    os.makedirs(home, mode=0o700, exist_ok=True)
    strict = yaml_scalar(cfg["ssh"].get("strict_host_key_checking", "yes"))
    strict = {"on": "yes", "off": "no"}.get(strict, strict)
    if strict not in ("yes", "accept-new", "no"):
        die("ssh.strict_host_key_checking 只能是 yes、accept-new 或 no")

    kh_src = os.path.join(SSH_SRC, "known_hosts")
    kh_dst = os.path.join(home, "known_hosts")
    if os.path.isfile(kh_src):
        shutil.copyfile(kh_src, kh_dst)
        os.chmod(kh_dst, 0o644)
    elif strict == "yes":
        die("缺少 ssh/known_hosts。請用 ssh-keyscan 產生，或暫時把 strict_host_key_checking 設為 accept-new")

    # 密碼認證用。ssh 執行它取得密碼，密碼由 cmd_tunnel 以環境變數逐一傳入
    with open(ASKPASS_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write('#!/bin/sh\nprintf %s "$HUBCTL_SSH_PASSWORD"\n')
    os.chmod(ASKPASS_PATH, 0o700)

    # 個別 Host 放在 Host * 前面：ssh_config 對同一項目取第一個出現的值
    lines = []
    for name, b in cfg["bastions"].items():
        lines += [f"Host {name}",
                  f"  HostName {b['host']}",
                  f"  Port {int(b.get('port') or 22)}",
                  f"  User {b['user']}"]
        if b.get("key"):
            key_src = os.path.join(SSH_SRC, b["key"])
            if not os.path.isfile(key_src):
                die(f"找不到跳板機 {name} 的金鑰 ssh/{b['key']}")
            key_dst = os.path.join(home, f"key_{name}")
            shutil.copyfile(key_src, key_dst)
            os.chmod(key_dst, 0o600)
            lines += [f"  IdentityFile {key_dst}",
                      "  IdentitiesOnly yes",
                      "  PasswordAuthentication no",
                      "  BatchMode yes"]
        else:
            lines += ["  PubkeyAuthentication no",
                      "  PreferredAuthentications password,keyboard-interactive",
                      "  NumberOfPasswordPrompts 1",
                      "  BatchMode no"]
        if b.get("jump"):
            lines.append(f"  ProxyJump {b['jump']}")
        lines.append("")
    lines += ["Host *",
              f"  StrictHostKeyChecking {strict}",
              f"  UserKnownHostsFile {kh_dst}",
              "  ServerAliveInterval 30",
              "  ServerAliveCountMax 3",
              ""]
    with open(os.path.join(home, "config"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.chmod(os.path.join(home, "config"), 0o600)


def cmd_tunnel():
    cfg = load_config()
    ep = endpoints(cfg)
    groups = {}
    for name, u in cfg["upstreams"].items():
        b = u.get("via")
        if not b:
            continue
        lport = ep[name][1]
        groups.setdefault(b, []).append(f"0.0.0.0:{lport}:{u['host']}:{port_of(u)}")
        log(f"{name}: tunnel:{lport} → [{b}] → {u['host']}:{port_of(u)}")

    if not groups:
        log("沒有需要 SSH 通道的上游，待命中")
        while True:
            time.sleep(3600)

    prepare_ssh(cfg)
    procs = {}

    def start(b):
        args = ["autossh", "-M", "0", "-N", "-o", "ExitOnForwardFailure=yes"]
        for fwd in groups[b]:
            args += ["-L", fwd]
        args.append(b)
        env = {**os.environ, "AUTOSSH_GATETIME": "0"}
        pw = cfg["bastions"][b].get("password")
        if pw:
            # SSH_ASKPASS_REQUIRE=force 讓 ssh 不需要 tty 也會呼叫 askpass（OpenSSH 8.4+）
            env["HUBCTL_SSH_PASSWORD"] = str(pw)
            env["SSH_ASKPASS"] = ASKPASS_PATH
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = env.get("DISPLAY", ":0")
        procs[b] = subprocess.Popen(args, env=env)
        log(f"啟動通道 {b}（{'密碼' if pw else '金鑰'}）")

    def shutdown(*_):
        for p in procs.values():
            p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    for b in groups:
        start(b)
    while True:
        time.sleep(5)
        for b, p in list(procs.items()):
            if p.poll() is not None:
                log(f"通道 {b} 結束（代碼 {p.returncode}），10 秒後重試")
                time.sleep(10)
                start(b)


# ---------------------------------------------------------------- apply

def wait_for_tunnels(cfg, ep, timeout=90):
    pending = {n: ep[n] for n, u in cfg["upstreams"].items() if u.get("via")}
    deadline = time.time() + timeout
    while pending and time.time() < deadline:
        for n, (h, p) in list(pending.items()):
            try:
                socket.create_connection((h, p), timeout=3).close()
                log(f"通道就緒：{n}（{h}:{p}）")
                pending.pop(n)
            except OSError:
                pass
        if pending:
            time.sleep(3)
    for n in pending:
        log(f"警告：{n} 的通道在 {timeout} 秒內沒有就緒，稍後可能會失敗")


def connect_hub(psycopg):
    pw = os.environ.get("HUB_ADMIN_PASSWORD")
    if not pw:
        die(".env 缺少 HUB_ADMIN_PASSWORD")
    last = None
    for _ in range(30):
        try:
            return psycopg.connect(host=HUB_HOST, port=HUB_PORT, dbname=HUB_DB,
                                   user="postgres", password=pw, autocommit=True)
        except psycopg.OperationalError as e:
            last = e
            time.sleep(2)
    die(f"連不上集線器：{last}")


def short_err(e):
    return str(e).strip().splitlines()[0] if str(e).strip() else repr(e)


def write_dbhub_toml(cfg):
    m = cfg["mcp"]
    role = m["role"]
    pw = cfg["roles"][role]["password"]

    def q(s):
        return json.dumps(str(s), ensure_ascii=False)

    lines = [
        "# 由 hubctl apply 自動產生，請勿手動修改，改 config.yaml 的 mcp 區塊",
        "[[sources]]",
        'id = "company"',
        f"description = {q(m.get('description') or '公司資料（唯讀）')}",
        'type = "postgres"',
        f"host = {q(HUB_HOST)}",
        f"port = {HUB_PORT}",
        f"database = {q(HUB_DB)}",
        f"user = {q(role)}",
        f"password = {q(pw)}",
        'sslmode = "disable"',
    ]
    if m.get("search_path"):
        lines.append(f"search_path = {q(m['search_path'])}")
    lines += [
        f"query_timeout = {int(m.get('query_timeout') or 30)}",
        "",
        "[[tools]]",
        'name = "execute_sql"',
        'source = "company"',
        "readonly = true",
        f"max_rows = {int(m.get('max_rows') or 200)}",
        "",
        "[[tools]]",
        'name = "search_objects"',
        'source = "company"',
        "",
    ]
    os.makedirs(GENERATED_DIR, exist_ok=True)
    path = os.path.join(GENERATED_DIR, "dbhub.toml")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.chmod(path, 0o644)
    log(f"已產生 {path}（帳號 {role}）")


def cmd_apply():
    import psycopg
    from psycopg import sql

    I, L = sql.Identifier, sql.Literal
    cfg = load_config()
    ep = endpoints(cfg)
    wait_for_tunnels(cfg, ep)
    conn = connect_hub(psycopg)
    warnings = []

    def opts(d):
        return sql.SQL(", ").join(
            sql.SQL("{} {}").format(I(str(k)), L(yaml_scalar(v))) for k, v in d.items())

    # ---- 目前狀態
    with conn.cursor() as cur:
        cur.execute("""SELECT n.nspname, coalesce(d.description, '')
                         FROM pg_namespace n
                         LEFT JOIN pg_description d ON d.objoid = n.oid
                          AND d.classoid = 'pg_namespace'::regclass AND d.objsubid = 0""")
        schemas = dict(cur.fetchall())
        cur.execute("""SELECT s.srvname, coalesce(d.description, '')
                         FROM pg_foreign_server s
                         LEFT JOIN pg_description d ON d.objoid = s.oid
                          AND d.classoid = 'pg_foreign_server'::regclass""")
        servers = dict(cur.fetchall())
        cur.execute("""SELECT r.rolname, coalesce(d.description, '')
                         FROM pg_roles r
                         LEFT JOIN pg_shdescription d ON d.objoid = r.oid
                          AND d.classoid = 'pg_authid'::regclass""")
        roles_now = dict(cur.fetchall())

    def managed(desc):
        return desc.startswith(TAG)

    # ---- 安全檢查：不碰不是本工具建立的物件
    for s in list(cfg["_upstream_schemas"]) + cfg["_view_schemas"]:
        if s in schemas and not managed(schemas[s]):
            die(f"schema {s} 已存在，但不是本工具建立的。請在 config.yaml 換個名稱，或自行處理後再執行")
    for srv in cfg["upstreams"]:
        if srv in servers and not managed(servers[srv]):
            die(f"FOREIGN SERVER {srv} 已存在，但不是本工具建立的")
    for rn in cfg["roles"]:
        if rn in roles_now and not managed(roles_now[rn]):
            die(f"帳號 {rn} 已存在，但不是本工具建立的")

    with conn.transaction():
        cur = conn.cursor()
        cur.execute("SET LOCAL lock_timeout = '30s'")
        cur.execute("CREATE EXTENSION IF NOT EXISTS postgres_fdw")
        if any(u["type"] == "mariadb" for u in cfg["upstreams"].values()):
            cur.execute("CREATE EXTENSION IF NOT EXISTS mysql_fdw")
        cur.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        cur.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(I(HUB_DB)))

        # ---- 清掉 view schema（稍後重建）與已從設定移除的上游
        for s, desc in schemas.items():
            if managed(desc) and (desc == TAG_VIEWS or s not in cfg["_upstream_schemas"]):
                cur.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(I(s)))
        for srv, desc in servers.items():
            if managed(desc) and srv not in cfg["upstreams"]:
                cur.execute(sql.SQL("DROP SERVER IF EXISTS {} CASCADE").format(I(srv)))
                log(f"已移除上游 {srv}")

        # ---- 上游：每個獨立存檔點，失敗就保留舊版本
        for name, u in cfg["upstreams"].items():
            host, port = ep[name]
            locals_ = [imp["local"] for imp in u["_imports"]]
            try:
                with conn.transaction():
                    cur.execute(sql.SQL("DROP SERVER IF EXISTS {} CASCADE").format(I(name)))
                    for s in locals_:
                        cur.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(I(s)))

                    extra = dict(u.get("server_options") or {})
                    if u["type"] == "postgres":
                        o = {"host": host, "port": port, "dbname": u["database"], **extra}
                        o["updatable"] = "false"          # 強制唯讀，不讓設定檔覆蓋
                        fdw, um = "postgres_fdw", {"user": u["user"], "password": u["password"]}
                    else:
                        o = {"host": host, "port": port, **extra}
                        fdw, um = "mysql_fdw", {"username": u["user"], "password": u["password"]}

                    cur.execute(sql.SQL("CREATE SERVER {} FOREIGN DATA WRAPPER {} OPTIONS ({})")
                                .format(I(name), I(fdw), opts(o)))
                    cur.execute(sql.SQL("COMMENT ON SERVER {} IS {}").format(I(name), L(TAG)))
                    cur.execute(sql.SQL("CREATE USER MAPPING FOR PUBLIC SERVER {} OPTIONS ({})")
                                .format(I(name), opts(um)))

                    for imp in u["_imports"]:
                        cur.execute(sql.SQL("CREATE SCHEMA {}").format(I(imp["local"])))
                        cur.execute(sql.SQL("COMMENT ON SCHEMA {} IS {}")
                                    .format(I(imp["local"]), L(f"{TAG_UPSTREAM}:{name}")))
                        limit = sql.SQL("")
                        if imp["tables"]:
                            limit = sql.SQL(" LIMIT TO ({})").format(
                                sql.SQL(", ").join(I(t) for t in imp["tables"]))
                        cur.execute(sql.SQL("IMPORT FOREIGN SCHEMA {}{} FROM SERVER {} INTO {}")
                                    .format(I(imp["remote"]), limit, I(name), I(imp["local"])))

                    cur.execute("""SELECT count(*) FROM information_schema.foreign_tables
                                    WHERE foreign_table_schema = ANY(%s)""", [locals_])
                    n = cur.fetchone()[0]
                log(f"上游 {name}：匯入 {n} 張表 → {', '.join(locals_)}")
                if n == 0:
                    warnings.append(f"上游 {name} 沒有匯入任何表，請確認 import 的 remote / tables")
            except psycopg.Error as e:
                warnings.append(f"上游 {name} 失敗，保留上一次成功的版本：{short_err(e)}")

        # ---- view
        for s in cfg["_view_schemas"]:
            cur.execute(sql.SQL("CREATE SCHEMA {}").format(I(s)))
            cur.execute(sql.SQL("COMMENT ON SCHEMA {} IS {}").format(I(s), L(TAG_VIEWS)))
        for full, body in cfg["views"].items():
            s, v = str(full).split(".")
            try:
                with conn.transaction():
                    cur.execute(sql.SQL("CREATE VIEW {}.{} AS ").format(I(s), I(v))
                                + sql.SQL(str(body).strip().rstrip(";")))
                log(f"view {full}：完成")
            except psycopg.Error as e:
                warnings.append(f"view {full} 失敗：{short_err(e)}")

        # ---- 本地帳號
        cur.execute("""SELECT n.nspname FROM pg_namespace n
                         JOIN pg_description d ON d.objoid = n.oid
                          AND d.classoid = 'pg_namespace'::regclass AND d.objsubid = 0
                        WHERE d.description LIKE %s""", [TAG + "%"])
        managed_schemas = [r[0] for r in cur.fetchall()]

        for rn, r in cfg["roles"].items():
            if rn not in roles_now:
                cur.execute(sql.SQL("CREATE ROLE {}").format(I(rn)))
            cur.execute(sql.SQL(
                "ALTER ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS INHERIT CONNECTION LIMIT {} PASSWORD {}")
                .format(I(rn), L(int(r.get("connection_limit") or -1)), L(str(r["password"]))))
            cur.execute(sql.SQL("COMMENT ON ROLE {} IS {}").format(I(rn), L(TAG)))
            cur.execute(sql.SQL("ALTER ROLE {} RESET ALL").format(I(rn)))
            settings = {**DEFAULT_ROLE_SETTINGS, **(r.get("settings") or {})}
            for k, v in settings.items():
                cur.execute(sql.SQL("ALTER ROLE {} SET {} = {}")
                            .format(I(rn), sql.SQL(k), L(yaml_scalar(v))))
            cur.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(I(HUB_DB), I(rn)))

            # 先收回所有受管理 schema 的權限，再依設定重新授權
            for s in managed_schemas:
                cur.execute(sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM {}").format(I(s), I(rn)))
                cur.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(I(s), I(rn)))

            g = r.get("grant") or {}
            for s in g.get("schemas") or []:
                try:
                    with conn.transaction():
                        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(I(s), I(rn)))
                        cur.execute(sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}")
                                    .format(I(s), I(rn)))
                except psycopg.Error as e:
                    warnings.append(f"帳號 {rn} 授權 schema {s} 失敗：{short_err(e)}")
            for t in g.get("tables") or []:
                s, tb = str(t).split(".")
                try:
                    with conn.transaction():
                        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(I(s), I(rn)))
                        cur.execute(sql.SQL("GRANT SELECT ON {}.{} TO {}").format(I(s), I(tb), I(rn)))
                except psycopg.Error as e:
                    warnings.append(f"帳號 {rn} 授權 {t} 失敗：{short_err(e)}")
            log(f"帳號 {rn}：完成")

        for rn, desc in roles_now.items():
            if managed(desc) and rn not in cfg["roles"]:
                cur.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(I(rn)))
                warnings.append(f"帳號 {rn} 已從設定移除，已停用登入（未刪除）")

    conn.close()
    if cfg.get("mcp"):
        write_dbhub_toml(cfg)

    if warnings:
        log("====== 完成，但有以下警告 ======")
        for w in warnings:
            log(f"  ⚠ {w}")
    else:
        log("====== 全部完成 ======")


# ---------------------------------------------------------------- check

def cmd_check():
    cfg = load_config()
    ep = endpoints(cfg)
    log("設定檔格式正確。連線路徑：")
    for name, u in cfg["upstreams"].items():
        h, p = ep[name]
        via = f" → [{u['via']}] → {u['host']}:{port_of(u)}" if u.get("via") else "（直連）"
        locals_ = ", ".join(i["local"] for i in u["_imports"])
        log(f"  {name}（{u['type']}）: {h}:{p}{via}  →  schema {locals_}")
    for full in cfg["views"]:
        log(f"  view {full}")
    for rn, r in cfg["roles"].items():
        g = r.get("grant") or {}
        log(f"  帳號 {rn}: schemas={g.get('schemas') or []} tables={g.get('tables') or []}")
    if cfg.get("mcp"):
        log(f"  DBHub 使用帳號 {cfg['mcp']['role']}")


if __name__ == "__main__":
    commands = {"tunnel": cmd_tunnel, "apply": cmd_apply, "check": cmd_check}
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd not in commands:
        print(__doc__)
        sys.exit(2)
    commands[cmd]()
