"""规则注册表：sink、sanitizer、污点类别与规则版本。

RULE_VERSION 是缓存键的第三个因子：规则代码/规则表一旦变化就 bump，
旧清单整体失效，强制重扫。规则表用代码内常量表达（不读外部 YAML），
因此规则版本与分析器发布版本保持显式映射，避免"改了规则忘了 bump"。
"""
from __future__ import annotations

# 规则版本：任何 sink/sanitizer/传播语义的改动都必须递增。
# 语义化版本 MAJOR.MINOR.PATCH；缓存只比较完整字符串。
RULE_VERSION = "1.0.0"

# ---------------------------------------------------------------- 污点类别
# 一个污点值带类别位掩码；sanitizer 可以只清理某一类（basename 只防路径穿越，
# 不防命令注入），这是基线正则扫描做不到的精度。
TAINT_CMD = 1 << 0      # 命令注入（CWE-78）
TAINT_SQL = 1 << 1      # SQL 注入（CWE-89）
TAINT_PATH = 1 << 2     # 路径穿越（CWE-22）
TAINT_URL = 1 << 3      # SSRF（CWE-918）
TAINT_XML = 1 << 4      # XXE（CWE-611）
TAINT_ALL = (1 << 5) - 1

CATEGORY_OF_SINK = {
    "command_injection": TAINT_CMD,
    "sql_injection": TAINT_SQL,
    "path_traversal": TAINT_PATH,
    "ssrf": TAINT_URL,
    "xxe": TAINT_XML,
}

# ---------------------------------------------------------------- Sink 表
# rule_id -> (SARIF ruleId, CWE, 消息模板, 匹配方式)
# 所有 match 统一为 4 元素：
#   ("attr", 模块, 方法集合, 污点参数下标集合)
#   ("name", None, 函数名集合, 污点参数下标集合)
SINKS = [
    {
        "rule_id": "PY-CMD-001",
        "kind": "command_injection",
        "cwe": "CWE-78",
        "message": "外部可控数据流入 shell 执行函数，存在命令注入风险",
        "match": ("attr", "os", {"system", "popen", "exec"}, {0}),
    },
    {
        "rule_id": "PY-CMD-001",
        "kind": "command_injection",
        "cwe": "CWE-78",
        "message": "外部可控数据流入 subprocess(shell=True)，存在命令注入风险",
        "match": ("attr", "subprocess", {"run", "Popen", "call", "check_call", "check_output"}, {0}),
        "require_shell_true": True,
    },
    {
        "rule_id": "PY-SQL-001",
        "kind": "sql_injection",
        "cwe": "CWE-89",
        "message": "外部可控数据拼接进 SQL 语句",
        "match": ("name", None, {"execute", "executemany"}, {0}),
    },
    {
        "rule_id": "PY-PATH-001",
        "kind": "path_traversal",
        "cwe": "CWE-22",
        "message": "外部可控路径直接打开文件，存在路径穿越风险",
        "match": ("name", None, {"open"}, {0}),
    },
    {
        "rule_id": "PY-URL-001",
        "kind": "ssrf",
        "cwe": "CWE-918",
        "message": "外部可控 URL 直接发起网络请求，存在 SSRF 风险",
        "match": ("attr", "urllib.request", {"urlopen"}, {0}),
    },
    {
        "rule_id": "PY-URL-001",
        "kind": "ssrf",
        "cwe": "CWE-918",
        "message": "外部可控 URL 直接发起网络请求，存在 SSRF 风险",
        "match": ("attr", "requests", {"get", "post", "put", "delete", "request"}, {0}),
    },
    {
        "rule_id": "PY-XML-001",
        "kind": "xxe",
        "cwe": "CWE-611",
        "message": "外部可控数据进入 XML 解析器，存在 XXE 风险",
        "match": ("attr", "xml.etree.ElementTree", {"parse", "iterparse"}, {0}),
    },
    {
        "rule_id": "PY-XML-001",
        "kind": "xxe",
        "cwe": "CWE-611",
        "message": "外部可控数据进入 XML 解析器，存在 XXE 风险",
        "match": ("name", None, {"iterparse", "_expand_entities"}, {0}),
    },
]

# ---------------------------------------------------------------- Sanitizer 表
# 精确识别的、语义可证明的净化函数；净化类别为 None 表示净化所有类别。
# 启发式（按命名约定）的部分在 taint.py 中处理，并单独走"动态派发降级"通道。
SANITIZERS_EXACT = {
    # os.path.basename 只剥离目录段，只对路径穿越有效；拼进 shell 仍然可注入。
    ("os.path", "basename"): TAINT_PATH,
    # re.sub 的白名单式替换（模式里没有反向引用 \g<> / \1，替换目标为常量白名单类）
    # 在 taint.py 内进一步做模式检查，这里先登记函数本身。
    ("re", "sub"): "_re_sub_whitebox",
}

# 命名约定：命中这些名字特征的调用，若解析不到定义，按"疑似 sanitizer"降级处理。
SANITIZER_NAME_HINTS = ("sanitize", "sanitise", "allowlist", "whitelist",
                        "escape", "_clean", "clean_", "validate", "_only_")

# 入口函数命名约定（前缀）：这些函数的参数视为外部污点源。
ENTRY_PREFIXES = ("load_", "safe_load_", "handle_", "handler_", "view_")

# 硬编码密钥规则（基线含此条，语料里无样本，登记为扩展点并参与规则版本）。
HARDCODED_AK_PATTERN = r"_PROD_AK_\d+\s*="

# 标准库/常见第三方模块前缀：解析到这些模块的调用即使不是精确 sink/sanitizer，
# 也按"外部库普通函数"处理（默认干净），不触发动态派发降级。
LIBRARY_PREFIXES = (
    "os", "sys", "re", "json", "io", "ast", "hashlib", "collections", "itertools",
    "functools", "pathlib", "datetime", "time", "logging", "typing", "dataclasses",
    "enum", "abc", "copy", "math", "random", "string", "textwrap", "urllib",
    "http", "socket", "sqlite3", "xml", "html", "csv", "base64", "binascii",
    "subprocess", "threading", "multiprocessing", "tempfile", "shutil", "glob",
    "argparse", "configparser", "contextlib", "traceback", "inspect", "importlib",
    "requests", "lxml", "flask", "django", "pytest",
)


def is_library_module(module: str) -> bool:
    head = module.split(".")[0]
    return module.startswith(LIBRARY_PREFIXES) or head in LIBRARY_PREFIXES


# 污点保留型库函数：输出值的污点 = 入参污点的并集（净化交给 sanitizer 表判定）。
# 漏配这里会把 os.path.join 这类组合函数误判为"干净"，造成假阴性。
LIBRARY_PASSTHROUGH = {
    ("os.path", "join"),
    ("os.path", "abspath"),
    ("os.path", "normpath"),
    ("os.path", "relpath"),
    ("os.path", "expanduser"),
    ("os.path", "expandvars"),
    ("os.path", "split"),
    ("os.path", "splitext"),
    ("os.path", "dirname"),
    ("str", "format"),
    ("str", "join"),
    ("str", "replace"),
    ("str", "strip"),
    ("str", "lstrip"),
    ("str", "rstrip"),
    ("str", "lower"),
    ("str", "upper"),
    ("str", "split"),
    ("str", "encode"),
    ("bytes", "decode"),
}


def is_entry_function(name: str) -> bool:
    return name.startswith(ENTRY_PREFIXES)
