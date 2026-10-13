# repo-guard

Git commit / push 前的資料外洩檢查 CLI。發現 Excel、報價、客戶資料、金鑰、個資等違規內容時阻擋並說明原因。

- 只用 Python 標準函式庫（3.11+），**唯讀**、**不連網**、不修改任何使用者檔案與 git 歷史。
- Windows（PowerShell）、macOS、Linux 皆可；支援中文檔名。

## 安裝

```powershell
# 在本專案目錄
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # macOS/Linux：source .venv/bin/activate
pip install -e .                    # 之後可用 repo-guard 指令
pip install -e ".[test]"            # 若要跑測試（加裝 pytest）
```

驗證：`repo-guard --version`

## 使用

| 指令 | 用途 |
|---|---|
| `repo-guard scan --staged` | 掃描已暫存的變更（讀的是 index 內容，不是工作目錄） |
| `repo-guard scan --pre-push <remote_name> <remote_url>` | 從 stdin 讀 Git pre-push 格式，只掃未推送的 commit |
| `repo-guard scan --all` | 掃描 `git ls-files -co --exclude-standard` 列出的檔案 |
| `repo-guard scan --history [--names-only]` | 掃描所有 commit 出現過的檔案；`--names-only` 只查檔名（R1、R3） |
| `repo-guard config --show` | 顯示合併後設定（關鍵字只顯示數量） |
| `repo-guard install-hooks [--force]` / `uninstall-hooks` | 安裝／移除 hook |

共用參數：`--format text|json|markdown`、`--report <path>`（另存一份報告）、`-C <目錄>`（在指定目錄執行）、`--with-gitleaks`。

結束碼：`0` 無 BLOCK；`1` 有 BLOCK；`2` 工具或設定錯誤（`install-hooks` 有 hook 因已存在他人 hook 而未安裝時也回 2）。

## Hook 安裝與移除

```powershell
cd 你的專案
repo-guard install-hooks
```

- 用 `git rev-parse --git-path hooks` 找目錄，所以支援 `core.hooksPath`。
- hook 內含標記 `# repo-guard-managed-hook v1`。
- 若已有**非本工具**的 hook：**不覆寫**，會顯示手動合併的方法（在你的 hook 加一行 `repo-guard scan --staged || exit $?`；pre-push 用 `repo-guard scan --pre-push "$@" || exit $?`）。
- `--force`：先備份為 `<name>.bak-YYYYMMDD-HHMMSS` 再寫入。
- 移除：`repo-guard uninstall-hooks`，只刪除含標記的 hook，其他不動（備份檔也不動，需要請自行還原）。
- hook 找不到 `repo-guard` 時會先試安裝時所用的 Python（`python -m repo_guard`）；兩者都找不到會在 stderr 警告並放行（不擋住你的工作流程）。`git commit --no-verify` 可略過 hook，這是 git 本身的行為。

## 規則

| ID | 等級 | 內容 |
|---|---|---|
| R1 | BLOCK（`.pdf` 為 WARN） | 禁止副檔名：xlsx xlsm xls csv db sqlite sqlite3 accdb mdb dwg dxf rvt rfa bak pst zip 7z rar |
| R2 | BLOCK | 檔案大小超過門檻（預設 5 MB） |
| R3 | BLOCK | 機密檔名：`.env`、`.env.*`（不含 `.env.example`）、`id_rsa`、`*.pem`、`*.key`、`*.p12`、`*.pfx`、`credentials*.json`、`service-account*.json` |
| R4 | BLOCK | 秘密字串：私鑰區塊、AWS Access Key ID、GitHub token、Hugging Face token、Slack token、通用 `api_key/secret/token/password = 值（≥16 字元）` |
| R5-ID | BLOCK | 台灣身分證字號（通過檢查碼才回報） |
| R5-PHONE | WARN | 台灣手機 09 開頭 10 碼 |
| R5-EMAIL | WARN | Email（預設關閉） |
| R6 | BLOCK | 自訂關鍵字（客戶名、案名、廠商名；不分大小寫） |
| R6-CFG | WARN | 含關鍵字清單的設定檔位於 repo 內且未被 `.gitignore` 排除 |

規則定義與每條的來源／理由集中在 [repo_guard/rules.py](repo_guard/rules.py)。

### 遮罩

輸出（text／json／markdown 與 `--report`）都不會出現完整秘密：秘密只顯示前 4 字元加 `***`；身分證顯示 `A******89`；關鍵字顯示 `[關鍵字 #n]`（檔名含關鍵字時也會遮罩）。

## 設定

優先序：**repo > 全域 > 預設**。`repo-guard config --show` 可檢視結果。

### 全域：`~/.repo-guard/config.toml`（Windows：`C:\Users\<你>\.repo-guard\config.toml`）

```toml
max_file_size_mb = 5
pdf_level = "WARN"            # 或 "BLOCK"
keywords = ["客戶甲公司", "某某大樓案", "乙廠商"]   # 只能放在這裡

[rules]
R5-EMAIL = true               # 開啟 Email 檢查
R5-PHONE = false              # 關閉手機檢查

[[allowlist]]
path = "docs/sample/*.csv"
rule = "R1"
reason = "公開範例資料"
```

### repo：`<repo 根目錄>/.repo-guard.toml`（可 commit）

只能放規則開關、大小門檻、`pdf_level` 與 allowlist。**出現 `keywords` 欄位會報錯（結束碼 2）**。

```toml
[[allowlist]]
path = "tests/fixtures/*.xlsx"
rule = "R1"
reason = "測試用假資料"
```

allowlist 規則：

- 每筆都必須有 `path`、`rule`、`reason`；缺任何一項（尤其是原因）視為設定錯誤，結束碼 2。
- `path` 是 glob：`*` 不跨目錄、`**` 可跨目錄；不含 `/` 的樣式比對任意層的檔名；區分大小寫。
- `rule` 可用 `R1`…`R6`、`R5-ID` 等；`R5` 涵蓋 `R5-*`。
- 被放行的項目不計入 BLOCK/WARN，但會在摘要與 JSON 中列出筆數。

## 誤報處理

1. 看輸出中的「建議」，工具只提示、不動手。
2. 檔案確實不該進版控：`git restore --staged -- "<檔案>"`（新 repo 尚無任何 commit 時改用 `git rm --cached -- "<檔案>"`），並加到 `.gitignore`。
3. 確定是誤報：在 `.repo-guard.toml` 加 allowlist（要寫原因）。
4. 某條規則整體太吵：在 `[rules]` 關閉。

## 測試

```powershell
pytest
```

## 已知限制

- 無法辨識圖片、PDF、Office 檔（xlsx/docx 本質是 zip）內的文字；這類檔案只做檔名／大小檢查，內容掃描會標記為「跳過」。
- 已推送的歷史只能**偵測、不能清除**；本工具不會執行 `git filter-repo`、`git reset` 等歷史改寫。已推送的秘密請視為已外洩並撤銷。
- 合併 commit（merge commit）本身不掃描，只掃它所含的非合併 commit；僅在衝突解決時才新增的內容可能漏掉。
- 文字編碼僅依序嘗試 UTF-8、UTF-8 BOM、cp950（另支援帶 BOM 的 UTF-16）；其他編碼（如 Big5-HKSCS 特殊字、無 BOM 的 UTF-16）會被視為二進位或無法解碼而跳過。
- 超過 10 MB 的檔案不做內容掃描。
- R4 的 Hugging Face、Slack 長度為保守下限（官方未公布固定格式）；不認得的 token 格式不會被偵測，也沒有熵值偵測。通用賦值規則會略過全小寫識別字、`ALL_CAPS` 常數、變數引用與佔位字串，因此純小寫的真密碼可能漏報。
- 身分證只驗證一般 10 碼格式與檢查碼，不含新式外來人口統一證號；通過檢查碼的隨機字串仍有可能是巧合。
- 同一檔案同一規則最多列出 20 筆，其餘只計數。
- 關鍵字比對是子字串、不分大小寫，不做同義詞或簡繁轉換。
- `--with-gitleaks` 會先執行 `gitleaks version`：8.19.0 以上（或版本無法判斷）用 `git`／`dir` 子命令，更舊的版本用 `protect`／`detect`；新指令的旗標尚未在實機驗證。未安裝時只顯示提示。
- 檔名含換行字元的檔案無法由 `git cat-file --batch` 讀取，會被跳過。
