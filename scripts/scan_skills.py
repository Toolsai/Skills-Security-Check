#!/usr/bin/env python3
import argparse
import json
import os
import re
from datetime import datetime

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "coverage",
}

TEXT_EXTS = {
    ".md", ".py", ".js", ".ts", ".tsx", ".sh", ".ps1", ".json", ".yaml", ".yml",
    ".toml", ".txt", ".env", ".example", ".ini", ".conf", ".rb", ".go", ".java",
    ".html", ".css", ".xml", ".jsx", ".mjs", ".cjs",
}

ENV_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development", ".env.test",
    ".env.example", "config.json", "secrets.json",
}

# --- Improved Regex Rules based on Senior Security Engineer prompts ---

URL_REGEX = re.compile(r"https?://[^\s\)\]\"'<>]+", re.IGNORECASE)
IP_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# sensitive_behaviors
SENSITIVE_RULES = [
    # Credential/Key Access
    ("硬編碼憑證關鍵字 (API Key/Token/Secret)", re.compile(r"\b(api[_-]?key|secret|token|private[_-]?key|access[_-]?key|auth[_-]?token|bearer)\b", re.IGNORECASE), "credential_keyword"),
    ("存取環境變數 (Env Vars)", re.compile(r"\b(os\.environ|getenv|process\.env|dotenv|load_dotenv|os\.Getenv)\b", re.IGNORECASE), "credential_access"),
    
    # Wallet/Crypto
    ("加密貨幣錢包相關 (Wallet/Seed/Mnemonic)", re.compile(r"\b(wallet\.dat|keystore|mnemonic|seed phrase|private key|ledger|trezor|metamask)\b", re.IGNORECASE), "crypto_wallet"),
    ("以太坊/比特幣路徑", re.compile(r"(\.ethereum|\.bitcoin|\.gnupg)", re.IGNORECASE), "crypto_path"),
    
    # System/Cloud Credentials
    ("SSH 金鑰/設定存取", re.compile(r"(~/.ssh|\\.ssh|id_rsa|id_ed25519|authorized_keys|known_hosts)", re.IGNORECASE), "ssh_access"),
    ("AWS/Cloud 設定檔", re.compile(r"(\.aws/credentials|\.aws/config|\.config/gcloud|\.azure/)", re.IGNORECASE), "cloud_credentials"),
    ("瀏覽器機敏資料 (Cookies/Passwords)", re.compile(r"(Login Data|Chrome/User Data|Firefox/Profiles|Brave/User Data|Library/Application Support)", re.IGNORECASE), "browser_data"),
]

# executing remote or arbitrary code
EXEC_RULES = [
    ("疑似 C2/下載並執行 (curl|wget -> shell)", re.compile(r"(curl\s+.*\|\s*(bash|sh)|wget\s+.*\|\s*(bash|sh)|powershell\s+.*-c|Invoke-Expression|IEX\s|System\.Net\.WebClient\.DownloadString)", re.IGNORECASE), "download_exec"),
    ("執行任意系統指令 (Shell/Subprocess)", re.compile(r"\b(subprocess\.Popen|os\.system|popen|exec\(|spawn\(|child_process\.exec|Runtime\.getRuntime\(\)\.exec)\b", re.IGNORECASE), "shell_exec"),
    ("動態模組/代碼載入 (Eval/Import)", re.compile(r"\b(eval\(|exec\(|\_\_import\_\_|importlib|require\(.*\)|dlopen)\b", re.IGNORECASE), "dynamic_exec"),
]

# persistence or background tasks
BACKGROUND_RULES = [
    ("背景常駐/排程任務 (Persistence)", re.compile(r"\b(cron|crontab|@reboot|systemd|launchd\.plist|schtasks|windows\\currentversion\\run)\b", re.IGNORECASE), "persistence"),
]

# obfuscation or evasion
OBFUSCATION_RULES = [
    ("疑似混淆/編碼 (Base64/Hex/XOR)", re.compile(r"\b(base64|atob|btoa|fromCharCode|rot13|xor|unescape|decodeURIComponent|eval\(atob)\b", re.IGNORECASE), "obfuscation_encoding"),
    ("地區/時區規避偵測", re.compile(r"(timezone|Intl\.DateTimeFormat|locale|LANG=|getSystemDefault|user\.country)\b", re.IGNORECASE), "geo_evasion"),
    ("反除錯/反沙盒 (Sleep/UserInteraction)", re.compile(r"\b(sleep|delay|setTimeout|mousemove|click)\b", re.IGNORECASE), "anti_analysis"), # Broad, can be false positive
]

# Package Installation Commands (Supply Chain Risk)
# 這些指令會下載並執行第三方程式碼，需特別注意來源與版本鎖定
PACKAGE_INSTALL_RULES = [
    ("npm install 安裝 (Node.js)", re.compile(r"\b(npm\s+install|npm\s+i\s|npx\s)", re.IGNORECASE), "npm_install"),
    ("yarn add 安裝 (Node.js)", re.compile(r"\b(yarn\s+add|yarn\s+install)\b", re.IGNORECASE), "yarn_install"),
    ("pnpm add 安裝 (Node.js)", re.compile(r"\b(pnpm\s+add|pnpm\s+install)\b", re.IGNORECASE), "pnpm_install"),
    ("pip install 安裝 (Python)", re.compile(r"\b(pip\s+install|pip3\s+install|python\s+-m\s+pip)\b", re.IGNORECASE), "pip_install"),
    ("apt-get install 安裝 (Linux)", re.compile(r"\b(apt-get\s+install|apt\s+install)\b", re.IGNORECASE), "apt_install"),
    ("brew install 安裝 (macOS)", re.compile(r"\b(brew\s+install)\b", re.IGNORECASE), "brew_install"),
    ("gem install 安裝 (Ruby)", re.compile(r"\b(gem\s+install)\b", re.IGNORECASE), "gem_install"),
    ("go get/install 安裝 (Go)", re.compile(r"\b(go\s+get|go\s+install)\b", re.IGNORECASE), "go_install"),
]

def parse_skill_name(skill_dir):
    skill_md = os.path.join(skill_dir, "SKILL.md")
    if not os.path.exists(skill_md):
        return os.path.basename(skill_dir)

    try:
        with open(skill_md, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return os.path.basename(skill_dir)

    # Simple frontmatter parsing
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            frontmatter = parts[1]
            for line in frontmatter.splitlines():
                if line.strip().startswith("name:"):
                    return line.split(":", 1)[1].strip().strip('"').strip("'") or os.path.basename(skill_dir)
            # If no name line, maybe second line?
            # Fallback
            
    # Try Regex for Description
    return os.path.basename(skill_dir)


def iter_skill_dirs(root):
    skill_dirs = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=True):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "SKILL.md" in filenames:
            skill_dirs.append(dirpath)
    return sorted(set(skill_dirs))


def is_text_file(path):
    name = os.path.basename(path)
    if name in ENV_FILENAMES:
        return True
    _, ext = os.path.splitext(name)
    return ext.lower() in TEXT_EXTS


def scan_file(path, relpath, result):
    try:
        if os.path.getsize(path) > 2_000_000: # Increase limit slightly
            return
    except OSError:
        return

    if not is_text_file(path):
        return

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return

    if not content:
        return

    # Check .env existence clearly
    if os.path.basename(path) in ENV_FILENAMES:
        result["sensitive"].add(f"發現敏感設定檔：{relpath} (可能包含密鑰)")
        result["flags"].add("sensitive_files")

    # --- Match Rules ---
    
    # 1. Sensitive
    for label, pattern, flag in SENSITIVE_RULES:
        if pattern.search(content):
            result["sensitive"].add(f"{label}：{relpath}")
            result["flags"].add(flag)

    # 2. Exec
    for label, pattern, flag in EXEC_RULES:
        if pattern.search(content):
            result["sensitive"].add(f"{label}：{relpath}")
            result["flags"].add(flag)

    # 3. Background
    for label, pattern, flag in BACKGROUND_RULES:
        if pattern.search(content):
            result["sensitive"].add(f"{label}：{relpath}")
            result["flags"].add(flag)

    # 4. Obfuscation
    for label, pattern, flag in OBFUSCATION_RULES:
        if pattern.search(content):
            result["obfuscation"].add(f"{label}：{relpath}")
            result["flags"].add(flag)

    # 5. Package Install Commands (Supply Chain)
    for label, pattern, flag in PACKAGE_INSTALL_RULES:
        if pattern.search(content):
            result["package_installs"].add(f"{label}：{relpath}")
            result["flags"].add(flag)

    # 6. Network (URLs + IPs)
    for match in URL_REGEX.findall(content):
        result["network"].add(match)
    for match in IP_REGEX.findall(content):
        # Filter local IPs ideally, but listing all is safer for audit
        result["network"].add(match)

    result["files"] += 1


def determine_risk_level(flags, network_count):
    # High Risk
    if "download_exec" in flags: return "high"
    if "persistence" in flags: return "high"
    if "crypto_wallet" in flags: return "high" # Accessing wallet directly is very suspicious for a skill
    
    # Medium Risk
    if "shell_exec" in flags or "dynamic_exec" in flags: return "medium"
    if "ssh_access" in flags or "cloud_credentials" in flags: return "medium"
    if "browser_data" in flags: return "medium"
    if "obfuscation_encoding" in flags or "geo_evasion" in flags: return "medium"
    if network_count > 0: return "medium" # Any network activity warrants review
    
    return "low"


def build_reasoning(flags, network_items):
    reasons = []
    
    # High Priority Reasons
    if "download_exec" in flags:
        reasons.append("偵測到「下載並執行」或遠端腳本危險行為")
    if "persistence" in flags:
        reasons.append("偵測到系統駐留/開機啟動設定")
    if "crypto_wallet" in flags:
        reasons.append("偵測到加密貨幣錢包或私鑰存取路徑")

    # Medium Priority
    if "shell_exec" in flags:
        reasons.append("包含任意系統指令執行 (Shell/Subprocess)")
    if "dynamic_exec" in flags:
        reasons.append("使用動態代碼執行 (Eval/Import)")
    if "ssh_access" in flags or "cloud_credentials" in flags:
        reasons.append("嘗試讀取 SSH 金鑰或雲端憑證")
    if "browser_data" in flags:
        reasons.append("嘗試存取瀏覽器敏感資料")
    if "obfuscation_encoding" in flags:
        reasons.append("代碼包含混淆或編碼跡象 (Base64/Hex)")
    if "geo_evasion" in flags:
        reasons.append("包含地區/時區判斷邏輯 (可能為逃避偵測)")
    
    if len(network_items) > 0:
        domains = [u for u in network_items if 'http' in u]
        if len(domains) > 2:
            reasons.append(f"包含大量外部連線 ({len(domains)} 個)")
        else:
            reasons.append("包含外部網路連線")

    if not reasons:
        reasons.append("未偵測到明顯已知惡意特徵")
        
    return "； ".join(reasons)


def build_recommendation(risk_level):
    if risk_level == "high":
        return "⚠️ 高度危險：不建議在含真實憑證或資產的環境安裝！僅可在隔離 VM / 拋棄式沙盒中測試。"
    if risk_level == "medium":
        return "⚠️ 具可疑行為：建議僅在「隔離環境」或使用「小額測試錢包」進行測試，並檢查網路流量。"
    return "✅ 相對安全：目前未發現明顯惡意特徵，但仍建議遵循最小權限原則使用。"


def load_ai_audit(skill_dir):
    """Checks for and loads external AI audit findings."""
    # Priority 1: audit.json (Structured)
    json_path = os.path.join(skill_dir, "audit.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass

    # Priority 2: SECURITY_AUDIT.md (Markdown content)
    md_path = os.path.join(skill_dir, "SECURITY_AUDIT.md")
    if os.path.exists(md_path):
        try:
            with open(md_path, "r", encoding="utf-8") as f:
                content = f.read()
                return {
                    "summary": "AI Security Analyst Review",
                    "risk_level": "manual_review", # Special flag? or let UI decide
                    "ai_insights": content # Pass raw MD
                }
        except:
            pass
            
    return None


def parse_requirements(skill_dir):
    """Parses requirements.txt for Python dependencies."""
    req_path = os.path.join(skill_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return None
    
    deps = []
    try:
        with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    deps.append(line)
    except:
        return None
    return deps

def parse_package_json(skill_dir):
    """Parses package.json for Node.js dependencies."""
    pkg_path = os.path.join(skill_dir, "package.json")
    if not os.path.exists(pkg_path):
        return None
    
    deps = []
    try:
        with open(pkg_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            # Combine dependencies and devDependencies
            all_deps = {}
            if "dependencies" in data: all_deps.update(data["dependencies"])
            if "devDependencies" in data: all_deps.update(data["devDependencies"])
            
            for pkg, ver in all_deps.items():
                deps.append(f"{pkg} ({ver})")
    except:
        return None
    return deps

def generate_audit_prompt(skill_dir, root, result, sensitive_files, context_files=None):
    """Generates a detailed prompt for LLM security audit (Traditional Chinese)."""
    if context_files is None:
        context_files = ["SKILL.md", "README.md", "skill.json", "manifest.json"]
    
    skill_name = parse_skill_name(skill_dir)
    rel_path = os.path.relpath(skill_dir, root)
    
    # 1. File Tree
    tree_lines = []
    for dirpath, dirnames, filenames in os.walk(skill_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        level = dirpath.replace(skill_dir, '').count(os.sep)
        indent = ' ' * 4 * (level)
        if level > 0:
            tree_lines.append(f"{indent}{os.path.basename(dirpath)}/")
        subindent = ' ' * 4 * (level + 1)
        for f in filenames:
            tree_lines.append(f"{subindent}{f}")
    file_tree = "\n".join(tree_lines)

    # 2. Findings Summary
    findings_list = sorted(list(result["sensitive"]) + list(result["network"]) + list(result["obfuscation"]))
    findings_text = "\n".join([f"- {item}" for item in findings_list]) if findings_list else "- 未偵測到靜態異常"

    # 2.5 Supply Chain
    py_deps = parse_requirements(skill_dir)
    node_deps = parse_package_json(skill_dir)
    
    supply_chain_text = []
    if py_deps:
        supply_chain_text.append(f"### Python 依賴 (requirements.txt):\n" + "\n".join([f"- {d}" for d in py_deps]))
    if node_deps:
        supply_chain_text.append(f"### Node.js 依賴 (package.json):\n" + "\n".join([f"- {d}" for d in node_deps]))
        
    supply_chain_section = "\n\n".join(supply_chain_text) if supply_chain_text else "此 Skill 未偵測到明確的套件依賴文件。"

    # 3. Critical Content Gathering
    content_blocks = []
    
    # Collect Context Files
    for filename in context_files:
        path = os.path.join(skill_dir, filename)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content_blocks.append(f"### 📄 文件: {filename}\n```markdown\n{f.read()}\n```")
            except:
                pass
                
    # Collect Critical Files
    processed_critical = set()
    for rel_file in sensitive_files:
        base_name = os.path.basename(rel_file)
        if base_name in context_files: 
            continue
            
        full_path = os.path.join(root, rel_file)
        if os.path.exists(full_path) and full_path not in processed_critical:
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content_blocks.append(f"### ⚠️ 關鍵檔案 (偵測到風險): {rel_file}\n```python\n{f.read()}\n```")
                processed_critical.add(full_path)
            except:
                pass

    full_content = "\n\n".join(content_blocks)

    prompt = f"""
# 資安專家 AI 審查任務

請扮演一位資深資安工程師，針對以下 Skill 進行深度安全審查。
你的目標是識別潛在惡意代碼、供應鏈攻擊風險以及隱私洩露問題。

## 1. 專案基本資訊
- **名稱**: {skill_name}
- **路徑**: {rel_path}

## 2. 檔案結構 (File Tree)
```text
{file_tree}
```

## 3. 供應鏈依賴 (Supply Chain Dependencies)
請特別檢查以下外部套件是否存在已知惡意軟體或被濫用的歷史 (如 Typosquatting):
{supply_chain_section}

## 4. 靜態掃描發現的可疑熱點 (Scanner Findings)
以下是透過 Regex 腳本偵測到的可疑特徵，請重點檢查這些位置的上下文意圖：
{findings_text}

## 5. 專案核心與關鍵檔案內容 (Source Code)
以下包含專案的說明文件 (SKILL.md) 以及上述偵測到風險的關鍵程式碼。
請仔細閱讀程式邏輯，判斷是否存在「惡意意圖」或「隱藏邏輯漏洞」。

{full_content}

---

## 你的任務 (Output Format)
請根據以上資訊，分析此 Skill 是否安全。請回答：

1.  **功能總結**：它到底是做什麼的？代碼邏輯是否符合 SKILL.md 的描述？
2.  **供應鏈分析**：使用的外部庫是否合理？有無可疑或冷門的依賴項？
3.  **風險驗證**：靜態掃描到的「熱點」是惡意的嗎？還是正常功能？(例如：eval 用於計算機是低風險，用於執行外部腳本是高風險)
4.  **隱藏後門分析**：除了 regex 抓到的，你有看到其他奇怪邏輯嗎？(例如：特定條件下觸發、時間炸彈、寫死奇怪的變數)
5.  **最終判決**：
    *   🟢 **通過** (Safe)
    *   🟡 **警告** (Suspicious - 需人工覆核)
    *   🔴 **危險** (Malicious - 禁止安裝)

請給出簡短有力的結論 (繁體中文)。
"""
    return prompt


def scan_skill(skill_dir, root):
    # Ignore self (The scanner skill itself)
    if "skill-security-audit-dashboard" in skill_dir:
        return None

    result = {
        "sensitive": set(),
        "network": set(),
        "obfuscation": set(),
        "package_installs": set(),
        "flags": set(),
        "files": 0,
    }
    
    # Track which files triggered findings to include them in the prompt
    files_with_findings = set()

    for dirpath, dirnames, filenames in os.walk(skill_dir, followlinks=True):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            relpath = os.path.relpath(path, root)
            
            # Snapshot scan result before processing file
            len_before = len(result["sensitive"]) + len(result["network"]) + len(result["obfuscation"]) + len(result["package_installs"])
            
            scan_file(path, relpath, result)
            
            len_after = len(result["sensitive"]) + len(result["network"]) + len(result["obfuscation"]) + len(result["package_installs"])
            if len_after > len_before:
                files_with_findings.add(relpath)

    sensitive = sorted(list(result["sensitive"]))
    network = sorted(list(result["network"]))
    obfuscation = sorted(list(result["obfuscation"]))
    package_installs = sorted(list(result["package_installs"]))

    flags = result["flags"]
    risk = determine_risk_level(flags, len(network))

    summary_text = (
        f"功能分析：共掃描 {result['files']} 個檔案。偵測到 {len(sensitive)} 項敏感操作、"
        f"{len(network)} 個外部連線、{len(obfuscation)} 個潛在混淆指標、{len(package_installs)} 個套件安裝指令。"
    )
    
    # Generate Hybrid Audit Prompt
    prompt_content = generate_audit_prompt(skill_dir, root, result, files_with_findings)
    
    # Check for Existing AI Audit
    ai_audit = load_ai_audit(skill_dir)
    
    skill_data = {
        "skill": parse_skill_name(skill_dir),
        "path": os.path.relpath(skill_dir, root),
        "summary": summary_text,
        "sensitive_behaviors": sensitive,
        "network_activity": network,
        "obfuscation_signals": obfuscation,
        "package_installs": package_installs,
        "risk_level": risk,
        "reasoning": build_reasoning(flags, network),
        "recommendation": build_recommendation(risk),
        "audit_prompt": prompt_content,
        "ai_audit": ai_audit # Attach AI findings
    }
    
    # AI Override Logic: deeply merge useful fields if they exist
    if ai_audit:
        if isinstance(ai_audit, dict):
            # Override basic fields if provided in JSON
            if "summary" in ai_audit: skill_data["summary"] = ai_audit["summary"]
            if "risk_level" in ai_audit: skill_data["risk_level"] = ai_audit["risk_level"]
            if "reasoning" in ai_audit: skill_data["reasoning"] = ai_audit["reasoning"]
            if "recommendation" in ai_audit: skill_data["recommendation"] = ai_audit["recommendation"]
            
            # Merge lists if provided (AI might find more things or explain them better)
            # If AI provides these lists, we trust AI more? Or we union them? 
            # User wants AI view. Let's replacement if available, assuming AI is comprehensive.
            # Merge lists (Union of Scanner + AI) to ensure we don't hide new scanner findings
            # unless AI is strictly managing the list. But for safety, showing both is better.
            if "sensitive_behaviors" in ai_audit: 
                skill_data["sensitive_behaviors"] = sorted(list(set(skill_data["sensitive_behaviors"] + ai_audit["sensitive_behaviors"])))
            if "network_activity" in ai_audit: 
                skill_data["network_activity"] = sorted(list(set(skill_data["network_activity"] + ai_audit["network_activity"])))
            if "obfuscation_signals" in ai_audit: 
                skill_data["obfuscation_signals"] = sorted(list(set(skill_data["obfuscation_signals"] + ai_audit["obfuscation_signals"])))
    
    return skill_data


def generate_html(data, template_path, output_path):
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            template = f.read()
    except OSError as exc:
        raise SystemExit(f"Failed to read template: {exc}")

    data_json = json.dumps(data, ensure_ascii=False, indent=2)
    # Escape script tags
    data_json = data_json.replace("</", "<\\/")

    html = template.replace("__DATA_PLACEHOLDER__", data_json)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(description="Scan Skills and generate a security dashboard")
    parser.add_argument("--root", default=os.getcwd(), help="Root directory containing skills")
    # --out and --json are now optional/overridden by the new structure, but kept for compatibility or advanced use
    parser.add_argument("--out", help="Optional: Override output path") 
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    
    # Define Report Output Directory
    # Default: skill-security-audit-dashboard/reports/YYYYMMDD_HHMMSS/
    dashboard_skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if args.out:
        # If user explicitly specifies output, follow it (but still separate prompts? User asked for auto-folder)
        # To strictly follow user request: "Always create a timestamp folder inside the scan folder"
        # Let's pivot: Ignore --out or use it as base. 
        # Let's stick to the requested behavior as default.
        report_dir = os.path.dirname(os.path.abspath(args.out))
        html_path = os.path.abspath(args.out)
        json_path = os.path.splitext(html_path)[0] + ".json"
    else:
        report_dir = os.path.join(dashboard_skill_dir, "reports", timestamp)
        os.makedirs(report_dir, exist_ok=True)
        html_path = os.path.join(report_dir, "index.html")
        json_path = os.path.join(report_dir, "data.json")

    print(f"📂 Report Directory: {report_dir}")

    # Create Prompts Directory
    prompts_dir = os.path.join(report_dir, "prompts")
    os.makedirs(prompts_dir, exist_ok=True)

    skill_dirs = iter_skill_dirs(root)
    
    items = []
    for skill_dir in skill_dirs:
        item = scan_skill(skill_dir, root)
        if item is None:
            continue
            
        items.append(item)
        
        # Save prompt file
        skill_slug = re.sub(r'[^a-zA-Z0-9]', '_', item['skill'])
        prompt_filename = f"{skill_slug}_audit_prompt.txt"
        prompt_path = os.path.join(prompts_dir, prompt_filename)
        
        if "audit_prompt" in item:
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(item["audit_prompt"])
            # Remove prompt from item before JSON dump to keep data small
            del item["audit_prompt"] 
            
    # Compute Workspace Summary Stats
    total_skills = len(items)
    high_risk_count = len([i for i in items if i['risk_level'] == 'high'])
    med_risk_count = len([i for i in items if i['risk_level'] == 'medium'])
    low_risk_count = len([i for i in items if i['risk_level'] == 'low'])
    
    # Security Score: 100 - (High*20 + Med*5)
    score = 100 - (high_risk_count * 20 + med_risk_count * 5 + low_risk_count * 1)
    if score < 0: score = 0
    
    workspace_summary = {
        "total": total_skills,
        "high": high_risk_count,
        "medium": med_risk_count,
        "low": low_risk_count,
        "security_score": score,
    }

    data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "root": root,
        "workspace_summary": workspace_summary,
        "items": items,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    template_path = os.path.join(os.path.dirname(__file__), "..", "assets", "dashboard_template.html")
    template_path = os.path.abspath(template_path)
    generate_html(data, template_path, html_path)

    print(f"✅ Dashboard generated: {html_path}")
    print(f"✅ Audit Prompts generated in: {prompts_dir}")
    
    # Clickable Markdown Link for Agent/User
    print(f"\n[打開資安報告]({html_path})\n")
    
    # Auto-open in browser
    try:
        import webbrowser
        from urllib.parse import quote
        
        # Open file:// URL
        file_url = f"file://{quote(html_path)}"
        print(f"🚀 Opening report in browser...")
        webbrowser.open(file_url)
    except Exception as e:
        print(f"⚠️ Could not open browser automatically: {e}")
        print(f"🔗 Please open this link manually: file://{html_path}")


if __name__ == "__main__":
    main()
