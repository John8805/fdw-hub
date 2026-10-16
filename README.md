# fdw-hub：唯讀資料庫集線器

把多台 PostgreSQL / MariaDB（經 SSH 跳板機才連得到的 RDS）整合成**一個**本地 PostgreSQL，
再用唯讀小帳號控管權限，最前面接 [Bytebase DBHub](https://github.com/bytebase/dbhub) 讓 AI 工具用 MCP 查詢。

```
DBeaver ──────────────────────────────┐
                                      ▼
AI 工具 ─ MCP ─► dbhub ─► hub（PostgreSQL，ai_reader 唯讀）
                            │  postgres_fdw / mysql_fdw
                            ▼
                         tunnel（autossh）── SSH ──► 跳板機 ──► RDS
```

## 與官方 DBHub 的差異

官方 DBHub 是這套系統的最外層，image 固定為 `bytebase/dbhub:1.2.3`，原始碼未修改。
本 repo 提供它前面的集線器、SSH 通道與設定工具。

| 面向 | 官方 DBHub | fdw-hub |
|---|---|---|
| 連線方式 | 每個來源一條連線字串 | `tunnel` 容器用 autossh 常駐維持 SSH 通道，內網 RDS 可達 |
| 多資料庫 | 每個來源各自設定 | 合成 hub 裡的單一資料庫，每個上游一個 schema |
| 跨庫查詢 | 各來源獨立 | 單一 SQL 可 JOIN 不同庫，PostgreSQL 與 MariaDB 可混用 |
| 上游帳密 | 寫在 DBHub 設定檔的連線字串 | 只存在 hub 的外部伺服器設定，加密檔 `.env.enc` 保管；DBHub 只持有 `ai_reader` |
| 唯讀保護 | DBHub 的 `readonly` | 四層：DBHub、session 預設唯讀、`ai_reader` 僅 SELECT、外部表禁寫（postgres_fdw） |
| 設定方式 | 手寫 `dbhub.toml` | 單一 `config.yaml`，`apply` 重建外部表並產生 toml |

## 需求

- Docker Desktop
- Windows PowerShell 5.1 以上（`dbhub.ps1` 在 Windows PowerShell 5.1 驗證過，其他平台未測試）
- OpenSSH client（`ssh-keyscan`）
- 對跳板機的存取權：自己的 SSH 私鑰（無 passphrase）或密碼；對 RDS 的帳號密碼

## 快速開始

在 repo 根目錄執行。

1. 建立設定檔

   ```powershell
   Copy-Item .env.example .env
   Copy-Item config.example.yaml config.yaml
   ```

   編輯 `config.yaml`：跳板機、上游資料庫、小帳號。

2. 放入 SSH 私鑰並登錄主機指紋

   把私鑰複製到 `ssh\`，檔名對應 `config.yaml` 裡的 `key`。每台跳板機各掃一次指紋：

   ```powershell
   ssh-keyscan jump-a.example.com | Out-File -Append -Encoding ascii ssh\known_hosts
   ```

   非 22 埠加 `-p 埠號`。

3. 寫入帳密

   `config.yaml` 裡每個 `${變數}` 與 `HUB_ADMIN_PASSWORD` 各執行一次：

   ```powershell
   .\dbhub.ps1 set
   ```

   依提示輸入變數名稱與值（值不回顯）。第一次執行會自動產生加密金鑰 `ssh\hub.key`。

4. 套用並啟動

   ```powershell
   .\dbhub.ps1 apply
   ```

   完成後 log 會列出每個上游匯入的表數。

5. 連線

   | 用途 | 位址 |
   |---|---|
   | DBeaver | PostgreSQL，`localhost:5433`，資料庫 `hub`，帳號 `ai_reader` |
   | Claude Code | `claude mcp add --transport http dbhub http://localhost:8080/mcp` |
   | DBHub 測試介面 | `http://localhost:8080` |

   埠號以 `.env` 為準。

## 日常操作

一律透過 `dbhub.ps1`。直接執行 `docker compose` 會缺少 `HUB_ADMIN_PASSWORD`，hub 無法啟動。

| 指令 | 作用 |
|---|---|
| `.\dbhub.ps1 apply` | 改完 `config.yaml` 後執行：驗證設定、重啟通道、重建外部表、重建 DBHub |
| `.\dbhub.ps1 check` | 只驗證設定檔，列出每個上游的連線路徑 |
| `.\dbhub.ps1 set` | 新增或修改一個帳密變數 |
| `.\dbhub.ps1 show` | 列出已存的變數，**會顯示明文**，看完請清除畫面 |
| `.\dbhub.ps1 up` / `stop` | 啟動 / 停止全部服務 |
| `.\dbhub.ps1 logs tunnel` | 其餘參數原樣轉交 docker compose |

## 新增一個上游

1. `config.yaml` 的 `upstreams` 複製一段，改 `database`（同台機器共用 `via` 與帳密變數）
2. 新的 schema 名稱加進 `roles.ai_reader.grant.schemas`、`roles.ai_reader.settings.search_path`、`mcp.search_path`
3. 新的 `${變數}` 用 `set` 寫入
4. 新的跳板機先 `ssh-keyscan`
5. `.\dbhub.ps1 apply`

`apply` 每次完整重建外部表，上游新增表或欄位時重跑即可同步。某個上游連不上時只有它失敗，並保留上一次成功的版本。

## 查詢時要知道的

- 查詢帶 schema 前綴（`shop_tx.games`）。不帶時依 `search_path` 解析，排第一的 schema 優先。
- `search_objects` 列不出外部表，改查 `information_schema.foreign_tables`。
- 資料即時，hub 沒有快取，每次查詢都會到 RDS 取資料。
- WHERE 寫成單純的欄位比較才會推到遠端執行。大表先下 `explain verbose`，確認 `Remote SQL` 有帶 WHERE 再執行。
- 預設單次最多 200 列、12 秒逾時，可在 `mcp` 區塊調整。

## 安全模型

- 唯讀四層：DBHub `BEGIN READ ONLY`、`default_transaction_read_only = on`、`ai_reader` 只有 `USAGE` 與 `SELECT`、postgres_fdw 的 `updatable 'false'`（`hubctl.py` 強制，設定檔無法覆蓋）。
- 帳密存放：`.env.enc` 以 AES-128-CBC 加密，金鑰在 `ssh\hub.key`。這層保護擋住不經意的閱讀，取得這兩個檔案的人可以解密。兩者都已列入 `.gitignore`，不要提交。
- DBHub 的 HTTP 介面沒有登入驗證，預設只綁定 `127.0.0.1`，請維持。
- 上游帳號建議使用專用唯讀帳號，並在 RDS 端為該帳號設定 `statement_timeout`。

## 已知限制

- MariaDB 外部表沒有等同 `updatable 'false'` 的強制禁寫，寫入防護靠 `ai_reader` 的權限與上游帳號權限。
- 12 秒逾時由 hub 判定，是否一併取消 RDS 上的查詢尚未驗證。
- 帳號自設定移除時只會停用登入（`NOLOGIN`），不會刪除。

## 疑難排解

| 狀況 | 處理方式 |
|---|---|
| `getaddrinfo EAI_AGAIN hub` / `SOURCE_UNREACHABLE` | 容器長時間運行後內建 DNS 失效。三個服務一起重啟：`.\dbhub.ps1 restart` |
| 通道連不上 | `.\dbhub.ps1 logs tunnel`。確認私鑰無 passphrase、`known_hosts` 有該主機 |
| `password is required` | 上游 PostgreSQL 對該連線使用 trust 驗證。請上游改用 scram/md5 |
| `out of shared memory` | 匯入的表太多，調高 `docker-compose.yml` 的 `max_locks_per_transaction` |
| 查不到新加的表或欄位 | 重跑 `.\dbhub.ps1 apply` |
| 想看 AI 下了什麼 SQL | hub 的 PostgreSQL log 寫在 `logs\`，`log_statement = all` |

## 來源

容器使用官方發行的 [bytebase/dbhub](https://github.com/bytebase/dbhub) image，授權依該專案。
`hubctl.py` 取自最初取得的集線器專案，另加兩項修改：支援密碼認證的跳板機、啟動時解密 `.env.enc`。
本 repo 尚未附授權條款。
