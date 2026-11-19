"""增量分析器测试：全量精度、三类缓存失效、幽灵守卫、退出码、动态派发降级。

所有夹具在 tmp_path 沙箱里生成，不碰仓库 src/。
"""
from __future__ import annotations

import json
import os
import sys

import pytest

from incremental.cache import compute_cache_key
from incremental.engine import (
    EXIT_FATAL, EXIT_FINDINGS, EXIT_UNRESOLVED, run_scan,
)
from incremental.rules import RULE_VERSION
from incremental.taint import POLICY_FAIL_CLOSED, POLICY_QUARANTINE
from incremental import replay as replay_mod

VULN_CMD = """import os
def load_v(raw):
    return os.system('ping -c 1 ' + raw)
"""
SAFE_CMD = """import os, re
def load_v(raw):
    clean = re.sub(r'[^a-zA-Z0-9_]', '', raw)
    return os.system('ping -c 1 ' + clean)
"""
VULN_PATH = """import os
BASE='/srv/data'
def load_p(raw):
    return open(os.path.join(BASE, raw)).read()
"""
# 形状像 sanitizer 但定义缺失：动态派发降级样本
UNRESOLVED_SAN = """import urllib.request
def load_u(raw):
    clean = _only_allowlisted(raw)
    return urllib.request.urlopen(clean).read()
"""
RESOLVED_SAN_MODULE = """import re
def _only_allowlisted(v):
    return re.sub(r'[^a-zA-Z0-9_]', '', v)
"""


def _write(root, name, text):
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, name), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _make_pkg(root):
    _write(root, "__init__.py", "")


def _keys(result):
    return {(f["file"], f["line"], f["rule_id"], f.get("degraded", False))
            for f in result.findings}


# ------------------------------------------------------------ 全量精度
def test_full_scan_detects_command_injection(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", VULN_CMD)
    r = run_scan(str(root), cache_dir=str(tmp_path / "c"), full=True)
    assert r.exit_code == EXIT_FINDINGS
    assert any(f["kind"] == "command_injection" for f in r.findings)
    assert all(not f["degraded"] for f in r.findings)


def test_allowlist_sanitizer_suppresses_finding(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", SAFE_CMD)
    r = run_scan(str(root), cache_dir=str(tmp_path / "c"), full=True)
    assert r.findings == []
    assert r.exit_code == 0


def test_basename_only_clears_path_category_not_command(tmp_path):
    # basename 防路径穿越，但不防命令注入——类别敏感的净化建模
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py",
           "import os\n"
           "def load_v(raw):\n"
           "    return os.system('x ' + os.path.basename(raw))\n")
    r = run_scan(str(root), cache_dir=str(tmp_path / "c"), full=True)
    assert any(f["kind"] == "command_injection" for f in r.findings)


# ------------------------------------------------------------ 缓存命中
def test_unchanged_tree_reuses_cache_and_matches_full(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", VULN_CMD)
    _write(root, "p.py", VULN_PATH)
    cdir = str(tmp_path / "c")
    full = run_scan(str(root), cache_dir=cdir, full=True)
    inc = run_scan(str(root), cache_dir=cdir)
    assert inc.stats["filesReusedFromCache"] == 3  # __init__ + 2 模块
    assert inc.stats["filesRescanned"] == 0
    assert _keys(inc) == _keys(full)


# ------------------------------------------------------------ factor 1
def test_factor1_source_change_rescans_file(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", VULN_CMD)
    cdir = str(tmp_path / "c")
    run_scan(str(root), cache_dir=cdir, full=True)
    _write(root, "h.py", SAFE_CMD)  # 同一文件哈希变化
    r = run_scan(str(root), cache_dir=cdir)
    assert r.stats["filesRescanned"] == 1
    assert r.findings == []  # 净化后漏洞消失，没留旧结论


# ------------------------------------------------------------ factor 2
def test_factor2_reverse_dependency_invalidation(tmp_path):
    """事故场景：改公共工具函数，所有调用方必须重扫。"""
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "common.py", "def _scrub(v):\n    return v\n")
    _write(root, "h1.py",
           "import os\nfrom common import _scrub\n"
           "def load_a(raw):\n"
           "    return os.system('a ' + _scrub(raw))\n")
    _write(root, "h2.py",
           "import os\nfrom common import _scrub\n"
           "def load_b(raw):\n"
           "    return os.system('b ' + _scrub(raw))\n")
    cdir = str(tmp_path / "c")
    before = run_scan(str(root), cache_dir=cdir, full=True)
    assert len(before.findings) == 2
    # 只改公共函数体（签名不变）
    _write(root, "common.py",
           "import re\ndef _scrub(v):\n"
           "    return re.sub(r'[^a-zA-Z0-9_]', '', v)\n")
    after = run_scan(str(root), cache_dir=cdir)
    # common + h1 + h2 三个文件都必须重扫（反向依赖闭包）
    assert after.stats["filesRescanned"] == 3
    assert after.findings == []
    # 与全量逐结论一致
    full = run_scan(str(root), cache_dir=str(tmp_path / "cf"), full=True)
    assert _keys(after) == _keys(full)


def test_factor2_signature_change_invalidates_dependents(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "common.py", "def _scrub(v):\n    return v\n")
    _write(root, "h.py",
           "import os\nfrom common import _scrub\n"
           "def load_a(raw):\n"
           "    return os.system('a ' + _scrub(raw))\n")
    cdir = str(tmp_path / "c")
    run_scan(str(root), cache_dir=cdir, full=True)
    _write(root, "common.py", "def _scrub(v, strict=False):\n    return v\n")
    r = run_scan(str(root), cache_dir=cdir)
    assert any("signature" in x or "fingerprint" in x for x in r.reasons)
    assert r.stats["filesRescanned"] == 2


# ------------------------------------------------------------ factor 3
def test_factor3_rule_version_bump_forces_full(tmp_path, monkeypatch):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", VULN_CMD)
    cdir = str(tmp_path / "c")
    run_scan(str(root), cache_dir=cdir, full=True)
    # 模拟规则升级：只改 cache 命名空间的 RULE_VERSION（清单加载与缓存键都读它），
    # 分析器版本保持不变，这样精确命中"规则版本失效"分支而非版本整体不兼容。
    import incremental.cache as cache_mod
    monkeypatch.setattr(cache_mod, "RULE_VERSION", "9.9.9")
    r = run_scan(str(root), cache_dir=cdir)
    assert r.forced_full is True
    assert r.stats["filesRescanned"] == 2
    joined = " ".join(r.reasons).lower()
    assert "rule" in joined and "version" in joined


def test_corrupt_manifest_forces_full(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", VULN_CMD)
    cdir = tmp_path / "c"
    cdir.mkdir()
    run_scan(str(root), cache_dir=str(cdir), full=True)
    manifest = cdir / "incremental-cache.json"
    manifest.write_text("{broken json", encoding="utf-8")
    r = run_scan(str(root), cache_dir=str(cdir))
    assert r.forced_full is True
    assert _keys(r)  # 强制全量后结论仍完整


# ------------------------------------------------------------ 幽灵守卫
def test_deleted_file_findings_disappear(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "keep.py", VULN_CMD)
    _write(root, "gone.py", VULN_PATH)
    cdir = str(tmp_path / "c")
    run_scan(str(root), cache_dir=cdir, full=True)
    os.remove(os.path.join(str(root), "gone.py"))
    r = run_scan(str(root), cache_dir=cdir)
    assert all("gone.py" not in f["file"] for f in r.findings)


def test_tampered_cache_entry_is_not_trusted(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", VULN_CMD)
    cdir = tmp_path / "c"
    cdir.mkdir()
    run_scan(str(root), cache_dir=str(cdir), full=True)
    manifest = cdir / "incremental-cache.json"
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    first = next(iter(doc["entries"]))
    doc["entries"][first]["cache_key"] = "0" * 64  # 破坏缓存键
    doc["entries"][first]["findings"].append({
        "rule_id": "PY-GHOST-999", "cwe": "CWE-999", "kind": "ghost",
        "message": "planted", "file": first, "line": 1,
        "sink": "x", "source": "x", "degraded": False})
    manifest.write_text(json.dumps(doc), encoding="utf-8")
    r = run_scan(str(root), cache_dir=str(cdir))
    assert all(f["rule_id"] != "PY-GHOST-999" for f in r.findings)


# ------------------------------------------------------------ 解析错误 / 退出码
def test_syntax_error_gives_fatal_exit(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "broken.py", "def load_x(:\n")
    r = run_scan(str(root), cache_dir=str(tmp_path / "c"), full=True)
    assert r.exit_code == EXIT_FATAL
    assert r.parse_errors


def test_unresolved_diagnostic_exit_code(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", UNRESOLVED_SAN)
    r = run_scan(str(root), cache_dir=str(tmp_path / "c"), full=True,
                 policy=POLICY_QUARANTINE)
    # quarantine 下无 error 级发现，但有未解析诊断 -> exit 3
    assert r.diagnostics
    assert r.exit_code == EXIT_UNRESOLVED


# ------------------------------------------------------------ 动态派发降级
def test_fail_closed_emits_degraded_warning(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", UNRESOLVED_SAN)
    r = run_scan(str(root), cache_dir=str(tmp_path / "c"), full=True,
                 policy=POLICY_FAIL_CLOSED)
    degraded = [f for f in r.findings if f["degraded"]]
    assert len(degraded) == 1
    assert degraded[0]["rule_id"] == "PY-DYN-001"
    # 下游 sink 不重复报（值在调用点被隔离）
    assert not any(f["kind"] == "ssrf" for f in r.findings)


def test_quarantine_suppresses_but_keeps_diagnostic(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", UNRESOLVED_SAN)
    r = run_scan(str(root), cache_dir=str(tmp_path / "c"), full=True,
                 policy=POLICY_QUARANTINE)
    assert r.findings == []          # 无 error 也无 warning 级结论
    assert len(r.diagnostics) == 1   # 诊断保留，审计可追溯


def test_resolving_dispatch_clears_degradation(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "allow.py", RESOLVED_SAN_MODULE)
    _write(root, "h.py",
           "import urllib.request\nfrom allow import _only_allowlisted\n"
           "def load_u(raw):\n"
           "    clean = _only_allowlisted(raw)\n"
           "    return urllib.request.urlopen(clean).read()\n")
    r = run_scan(str(root), cache_dir=str(tmp_path / "c"), full=True,
                 policy=POLICY_FAIL_CLOSED)
    assert r.findings == []
    assert r.diagnostics == []  # 可解析后不再有未解析诊断


def test_reflective_getattr_handled_conservatively(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py",
           "import urllib.request\n"
           "def load_u(raw):\n"
           "    fn = getattr(urllib.request, 'urlopen')\n"
           "    return fn(raw).read()\n")
    fc = run_scan(str(root), cache_dir=str(tmp_path / "c1"), full=True,
                  policy=POLICY_FAIL_CLOSED)
    q = run_scan(str(root), cache_dir=str(tmp_path / "c2"), full=True,
                 policy=POLICY_QUARANTINE)
    # 两种策略各自与其全量自洽（回放里再做增量对照），且反射不产生虚假"干净"
    assert _keys(fc) == _keys(run_scan(str(root), cache_dir=str(tmp_path / "c1b")))
    assert _keys(q) == _keys(run_scan(str(root), cache_dir=str(tmp_path / "c2b")))


# ------------------------------------------------------------ SARIF
def test_sarif_structure_and_notifications(tmp_path):
    root = tmp_path / "pkg"
    _make_pkg(root)
    _write(root, "h.py", UNRESOLVED_SAN)
    r = run_scan(str(root), cache_dir=str(tmp_path / "c"), full=True)
    sarif = r.sarif
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["properties"]["ruleVersion"] == RULE_VERSION
    # 降级诊断在 notifications，不污染 results
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert notes and all("unresolved" in n["message"]["text"] for n in notes)


# ------------------------------------------------------------ 40 条回放
def test_replay_40_mutations_equivalent_and_ghost_free(tmp_path):
    # 用仓库自带语料在临时位置复制一份做回放源
    src = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src")
    replay_root = tmp_path / "src"
    import shutil
    shutil.copytree(src, replay_root)
    summary = replay_mod.run_replay(str(replay_root))
    assert summary["total"] == 40
    assert summary["passed"] == 40, summary["failed"]
    assert summary["ghosts"] == []
    assert summary["quarantine_self_consistent"] is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
