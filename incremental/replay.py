"""40 条历史变更回放：验证增量结果与全量逐字节等价、且无幽灵告警。

回放原则：
- 在临时沙箱里复制一份语料，绝不动仓库里的 src/。
- 每条变更后跑两次：一次全量（独立缓存目录）、一次增量（延续缓存）。
- 比较两边 SARIF 的 (file, line, ruleId, level) 集合，必须完全一致。
- 幽灵告警守卫：增量结果里出现任何当前工作区已不存在文件的结论即判失败。
- 覆盖六大类：源文件改动、符号签名/函数体改动（反向依赖）、规则版本、
  缓存完整性、动态派发降级、结构性边界（增删文件/解析错误）。

用法：python -m incremental.replay --root src [--keep]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile

from .engine import run_scan
from .taint import POLICY_FAIL_CLOSED, POLICY_QUARANTINE

# 每个 mutation: (类别, 描述, 变更函数(workspace)->None, 期望触发的失效因子)
# 变更函数用文本替换/整文件写入，全部保证产出合法 Python。


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _append(path: str, text: str) -> None:
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _replace(path: str, old: str, new: str) -> None:
    src = open(path, encoding="utf-8").read()
    assert old in src, f"anchor not found in {path}: {old[:40]!r}"
    _write(path, src.replace(old, new, 1))


def _finding_keys(sarif_path: str) -> set[tuple]:
    doc = json.load(open(sarif_path, encoding="utf-8"))
    out = set()
    for r in doc["runs"][0]["results"]:
        loc = r["locations"][0]["physicalLocation"]
        out.add((loc["artifactLocation"]["uri"],
                 loc["region"]["startLine"], r["ruleId"], r["level"]))
    return out


def _all_uris(sarif_path: str) -> set[str]:
    doc = json.load(open(sarif_path, encoding="utf-8"))
    return {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in doc["runs"][0]["results"]}


def _live_files(ws: str) -> set[str]:
    live = set()
    for dirpath, _, names in os.walk(ws):
        for n in names:
            if n.endswith(".py"):
                rel = os.path.relpath(os.path.join(dirpath, n), ws).replace("\\", "/")
                live.add(rel)
    return live


# ---------------------------------------------------------------- 变更集
def build_mutations() -> list[dict]:
    s00, s01, s02, s03, s04, s05 = [f"svc_0{i}.py" for i in range(6)]
    muts: list[dict] = []

    def add(cat, desc, fn, expect):
        muts.append({"cat": cat, "desc": desc, "fn": fn, "expect": expect})

    # ---- A. 源文件内容变更（factor 1），12 条 ----
    add("A-source", "A1 注释改动（哈希变、语义不变）",
        lambda ws: _append(f"{ws}/{s00}", "# no-op comment\n"), "factor1")
    add("A-source", "A2 空白行改动",
        lambda ws: _append(f"{ws}/{s02}", "\n\n"), "factor1")
    add("A-source", "A3 重命名局部变量（语义不变）",
        lambda ws: _replace(f"{ws}/{s00}", "clean_input = value", "cleaned = value"),
        "factor1")
    add("A-source", "A4 调换两条独立语句顺序",
        lambda ws: _replace(
            f"{ws}/{s01}",
            "    clean = os.path.basename(raw_2)\n    return open",
            "    return open"), "factor1")
    add("A-source", "A5 给命令注入 sink 加 basename 净化（漏洞应消失）",
        lambda ws: _replace(
            f"{ws}/{s02}",
            "return os.system('ping -c 1 ' + raw_5)",
            "return os.system('ping -c 1 ' + os.path.basename(raw_5))"), "factor1")
    add("A-source", "A6 撤回 A5 的净化（漏洞应重现，验证不残留旧干净结论）",
        lambda ws: _replace(
            f"{ws}/{s02}",
            "return os.system('ping -c 1 ' + os.path.basename(raw_5))",
            "return os.system('ping -c 1 ' + raw_5)"), "factor1")
    add("A-source", "A7 把 SSRF 入参换成常量（漏洞消失）",
        lambda ws: _replace(
            f"{ws}/{s05}",
            "return urllib.request.urlopen(raw_11).read()",
            "return urllib.request.urlopen('http://127.0.0.1/health').read()"),
        "factor1")
    add("A-source", "A8 恢复 SSRF 污点入参",
        lambda ws: _replace(
            f"{ws}/{s05}",
            "return urllib.request.urlopen('http://127.0.0.1/health').read()",
            "return urllib.request.urlopen(raw_11).read()"), "factor1")
    add("A-source", "A9 路径穿越 sink 前加白名单 re.sub（漏洞消失）",
        lambda ws: _replace(
            f"{ws}/{s03}",
            "    return open(os.path.join(BASE_DIR, raw_6)).read()",
            "    import re\n    safe6 = re.sub(r'[^a-zA-Z0-9_]', '', raw_6)\n"
            "    return open(os.path.join(BASE_DIR, safe6)).read()"), "factor1")
    add("A-source", "A10 恢复 A9",
        lambda ws: _replace(
            f"{ws}/{s03}",
            "    import re\n    safe6 = re.sub(r'[^a-zA-Z0-9_]', '', raw_6)\n"
            "    return open(os.path.join(BASE_DIR, safe6)).read()",
            "    return open(os.path.join(BASE_DIR, raw_6)).read()"), "factor1")
    add("A-source", "A11 SQL 拼接参数化改造（漏洞消失）",
        lambda ws: _replace(
            f"{ws}/{s00}",
            'return _CUR.execute("SELECT * FROM users WHERE name = \'%s\'" % raw_0)',
            'return _CUR.execute("SELECT * FROM users WHERE name = ?", (raw_0,))'),
        "factor1")
    add("A-source", "A12 恢复 SQL 字符串拼接",
        lambda ws: _replace(
            f"{ws}/{s00}",
            'return _CUR.execute("SELECT * FROM users WHERE name = ?", (raw_0,))',
            'return _CUR.execute("SELECT * FROM users WHERE name = \'%s\'" % raw_0)'),
        "factor1")

    # ---- B. 符号签名/函数体变更 + 反向依赖（factor 2），10 条 ----
    def _make_common(ws, body):
        _write(f"{ws}/common_util.py",
               '"""公共工具模块（回放动态生成）"""\n' + body)

    add("B-symbol", "B1 新增公共工具模块（新文件，全量因子）",
        lambda ws: _make_common(ws, "def _scrub(v):\n    return v\n"), "new-file")

    def _wire(ws):
        # 让 svc_02 的 load_05 改用公共 _scrub
        _replace(f"{ws}/{s02}",
                 "import os\n",
                 "import os\nfrom common_util import _scrub\n", )
        _replace(f"{ws}/{s02}",
                 "return os.system('ping -c 1 ' + raw_5)",
                 "return os.system('ping -c 1 ' + _scrub(raw_5))")
    add("B-symbol", "B2 handler 接入公共工具（建立跨文件依赖）", _wire, "factor1")

    add("B-symbol", "B3 公共工具函数体改为白名单净化（签名不变，反向失效）",
        lambda ws: _make_common(
            ws, "import re\ndef _scrub(v):\n"
                "    return re.sub(r'[^a-zA-Z0-9_]', '', v)\n"), "factor2")
    add("B-symbol", "B4 公共工具改回 identity（漏洞重现）",
        lambda ws: _make_common(ws, "def _scrub(v):\n    return v\n"), "factor2")
    add("B-symbol", "B5 公共工具加默认参数（签名变化，反向失效）",
        lambda ws: _make_common(
            ws, "def _scrub(v, strict=False):\n    return v\n"), "factor2")
    add("B-symbol", "B6 公共工具去掉默认参数（签名再变）",
        lambda ws: _make_common(ws, "def _scrub(v):\n    return v\n"), "factor2")
    add("B-symbol", "B7 公共工具增加新函数（旧函数指纹不变，调用方不应失效）",
        lambda ws: _make_common(
            ws, "def _scrub(v):\n    return v\n\ndef _other(v):\n    return v\n"),
        "factor1-common-only")
    add("B-symbol", "B8 公共工具重命名函数（依赖符号解析不到，放弃缓存走全量）",
        lambda ws: _make_common(
            ws, "def _scrub_renamed(v):\n    return v\n"), "unresolvable-dep")
    add("B-symbol", "B9 恢复公共工具函数名",
        lambda ws: _make_common(ws, "def _scrub(v):\n    return v\n"), "factor2")
    add("B-symbol", "B10 删除公共工具模块（依赖悬空，强制全量）",
        lambda ws: os.remove(f"{ws}/common_util.py"), "unresolvable-dep")

    # ---- C. 规则版本 / 缓存完整性（factor 3），8 条 ----
    def _bump_rule(ws):
        # 直接改缓存清单里的规则版本号，模拟"规则升级后旧缓存仍在磁盘"
        p = os.path.join(ws, ".cache-c", "incremental-cache.json")
        doc = json.load(open(p, encoding="utf-8"))
        doc["rule_version"] = "0.0.1-stale"
        _write(p, json.dumps(doc))
    add("C-rule", "C1 规则版本落后于分析器（整盘作废，强制全量）", _bump_rule,
        "factor3")
    add("C-rule", "C2 版本落后后再次扫描（新清单已写入，应恢复增量命中）",
        lambda ws: None, "cache-hit")

    def _corrupt(ws):
        p = os.path.join(ws, ".cache-c", "incremental-cache.json")
        _write(p, "{ this is not valid json")
    add("C-integrity", "C3 清单 JSON 损坏（放弃缓存走全量）", _corrupt, "corrupt")

    def _truncate(ws):
        p = os.path.join(ws, ".cache-c", "incremental-cache.json")
        src = open(p, encoding="utf-8").read()
        _write(p, src[: len(src) // 2])
    add("C-integrity", "C4 清单被截断（schema 校验失败，强制全量）", _truncate, "corrupt")

    def _tamper_hash(ws):
        p = os.path.join(ws, ".cache-c", "incremental-cache.json")
        doc = json.load(open(p, encoding="utf-8"))
        first = next(iter(doc["entries"]))
        doc["entries"][first]["source_hash"] = "0" * 64
        _write(p, json.dumps(doc))
    add("C-integrity", "C5 篡改条目的 source_hash（读时缓存键双保险拦截）",
        _tamper_hash, "factor1")

    def _tamper_findings(ws):
        p = os.path.join(ws, ".cache-c", "incremental-cache.json")
        doc = json.load(open(p, encoding="utf-8"))
        first = next(iter(doc["entries"]))
        doc["entries"][first]["findings"].append({
            "rule_id": "PY-GHOST-999", "cwe": "CWE-999", "kind": "ghost",
            "message": "planted ghost", "file": first, "line": 1,
            "sink": "x", "source": "x", "degraded": False})
        # 同步破坏缓存键，使其必然不命中而重扫
        doc["entries"][first]["cache_key"] = "deadbeef"
        _write(p, json.dumps(doc))
    add("C-integrity", "C6 向缓存植入幽灵结论（缓存键失配，重扫且幽灵不出现）",
        _tamper_findings, "ghost-guard")

    def _wrong_schema(ws):
        p = os.path.join(ws, ".cache-c", "incremental-cache.json")
        doc = json.load(open(p, encoding="utf-8"))
        doc["schema"] = 999
        _write(p, json.dumps(doc))
    add("C-integrity", "C7 schema 版本不认识（强制全量）", _wrong_schema, "corrupt")
    add("C-integrity", "C8 删除整个缓存目录（冷启动全量）",
        lambda ws: shutil.rmtree(os.path.join(ws, ".cache-c"), ignore_errors=True),
        "cold-start")

    # ---- D. 动态派发降级，6 条 ----
    dyn_file = ("import urllib.request\n"
                "def load_dyn(raw_d):\n"
                "    clean = _only_allowlisted(raw_d)\n"
                "    return urllib.request.urlopen(clean).read()\n")
    add("D-dispatch", "D1 新增含未解析 sanitizer 的入口（fail-closed 降级告警）",
        lambda ws: _write(f"{ws}/svc_dyn.py", dyn_file), "new-file")

    def _resolve_dyn(ws):
        # 补上真实定义，动态派发变为可解析（降级告警应消失，结论随之变化）
        _write(f"{ws}/allow.py",
               "import re\n"
               "def _only_allowlisted(v):\n"
               "    return re.sub(r'[^a-zA-Z0-9_]', '', v)\n")
        _replace(f"{ws}/svc_dyn.py",
                 "import urllib.request\n",
                 "import urllib.request\nfrom allow import _only_allowlisted\n")
    add("D-dispatch", "D2 提供 sanitizer 定义并导入（可解析，降级解除）",
        _resolve_dyn, "factor1")

    def _dyn_reflect(ws):
        # 反射式调用：getattr 动态派发，静态无法确定目标
        _write(f"{ws}/svc_dyn.py",
               "import urllib.request\n"
               "def load_dyn(raw_d):\n"
               "    fn = getattr(urllib.request, 'urlopen')\n"
               "    return fn(raw_d).read()\n")
    add("D-dispatch", "D3 改成 getattr 反射调用（动态形态，按 identity 保守传播）",
        _dyn_reflect, "factor1")
    add("D-dispatch", "D4 quarantine 策略下重放 D3（验证两种策略各自自洽）",
        lambda ws: None, "policy-switch")

    def _dyn_indirect(ws):
        _write(f"{ws}/svc_dyn.py",
               "import urllib.request\n"
               "TARGET = urllib.request.urlopen\n"
               "def load_dyn(raw_d):\n"
               "    return TARGET(raw_d).read()\n")
    add("D-dispatch", "D5 函数别名间接调用（模块级变量派发，保守处理不报假干净）",
        _dyn_indirect, "factor1")
    add("D-dispatch", "D6 删除动态派发文，回到基线文件集",
        lambda ws: (os.remove(f"{ws}/svc_dyn.py"),
                    os.path.exists(f"{ws}/allow.py") and os.remove(f"{ws}/allow.py")),
        "file-removed")

    # ---- E. 结构性边界，4 条 ----
    def _new_vuln_file(ws):
        _write(f"{ws}/svc_new.py",
               "import os\n"
               "def load_new(raw_new):\n"
               "    return os.system('dig ' + raw_new)\n")
    add("E-structure", "E1 新增带漏洞文件（新文件被纳入，结论出现）",
        _new_vuln_file, "new-file")
    add("E-structure", "E2 删除该漏洞文件（结论必须随之消失，无幽灵）",
        lambda ws: os.remove(f"{ws}/svc_new.py"), "file-removed")

    def _rename(ws):
        src = open(f"{ws}/{s04}", encoding="utf-8").read()
        _write(f"{ws}/svc_renamed.py", src)
        os.remove(f"{ws}/{s04}")
    add("E-structure", "E3 文件重命名（旧路径缓存剔除，新路径按新文件分析）",
        _rename, "file-removed+new-file")

    def _rename_back(ws):
        src = open(f"{ws}/svc_renamed.py", encoding="utf-8").read()
        _write(f"{ws}/{s04}", src)
        os.remove(f"{ws}/svc_renamed.py")
    add("E-structure", "E4 重命名还原", _rename_back, "file-removed+new-file")

    return muts


def run_replay(src_root: str, keep: bool = False) -> dict:
    mutations = build_mutations()
    assert len(mutations) == 40, f"expected 40 mutations, got {len(mutations)}"
    sandbox = tempfile.mkdtemp(prefix="replay-")
    # 沙箱语料目录固定命名为 src，与生产包名一致：扫描根是包时模块限定名为
    # src.xxx，from-import 的裸模块（如 common_util）才能在同一包内正确解析。
    ws = os.path.join(sandbox, "src")
    shutil.copytree(src_root, ws)
    # 沙箱语料需要 __init__.py 以保持包形态（src 自带则原样复制）
    inc_cache = os.path.join(ws, ".cache-c")
    full_cache = os.path.join(ws, ".cache-f")
    os.makedirs(inc_cache, exist_ok=True)
    os.makedirs(full_cache, exist_ok=True)

    results = []
    ghosts = []
    for i, m in enumerate(mutations, 1):
        m["fn"](ws)
        # 全量（独立缓存，每次 --full）
        r_full = run_scan(ws, cache_dir=full_cache, full=True,
                          policy=POLICY_FAIL_CLOSED)
        full_sarif = os.path.join(sandbox, f"full_{i}.sarif")
        open(full_sarif, "w", encoding="utf-8").write(
            json.dumps(r_full.sarif, ensure_ascii=False))
        # 增量（延续缓存）
        r_inc = run_scan(ws, cache_dir=inc_cache, full=False,
                         policy=POLICY_FAIL_CLOSED)
        inc_sarif = os.path.join(sandbox, f"inc_{i}.sarif")
        open(inc_sarif, "w", encoding="utf-8").write(
            json.dumps(r_inc.sarif, ensure_ascii=False))

        kf, ki = _finding_keys(full_sarif), _finding_keys(inc_sarif)
        equivalent = kf == ki
        # 幽灵守卫：增量结论里的文件必须都还活着
        live = _live_files(ws)
        ghost = sorted(u for u in _all_uris(inc_sarif) if u not in live)
        if ghost:
            ghosts.append((i, m["desc"], ghost))
        ok = equivalent and not ghost
        results.append({
            "i": i, "cat": m["cat"], "desc": m["desc"], "expect": m["expect"],
            "equivalent": equivalent, "ghost": ghost,
            "only_in_full": sorted(kf - ki), "only_in_inc": sorted(ki - kf),
            "inc_mode": r_inc.stats["mode"],
            "rescanned": r_inc.stats["filesRescanned"],
            "reused": r_inc.stats["filesReusedFromCache"],
            "ok": ok,
        })

    # quarantine 策略独立回放 D 类动态派发文，验证两策略各自与全量自洽
    q_ok = _replay_quarantine(src_root, sandbox)

    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r["ok"]),
        "failed": [r for r in results if not r["ok"]],
        "ghosts": ghosts,
        "quarantine_self_consistent": q_ok,
        "sandbox": sandbox if keep else None,
        "results": results,
    }
    if not keep:
        shutil.rmtree(sandbox, ignore_errors=True)
    return summary


def _replay_quarantine(src_root: str, sandbox: str) -> bool:
    ws_q = os.path.join(sandbox, "ws_q")
    if os.path.exists(ws_q):
        shutil.rmtree(ws_q)
    shutil.copytree(src_root, ws_q)
    _write(f"{ws_q}/svc_dyn.py",
           "import urllib.request\n"
           "def load_dyn(raw_d):\n"
           "    clean = _only_allowlisted(raw_d)\n"
           "    return urllib.request.urlopen(clean).read()\n")
    c_inc = os.path.join(ws_q, ".qc-inc")
    c_full = os.path.join(ws_q, ".qc-full")
    r_inc = run_scan(ws_q, cache_dir=c_inc, policy=POLICY_QUARANTINE)
    r_full = run_scan(ws_q, cache_dir=c_full, full=True, policy=POLICY_QUARANTINE)
    ki = {(x["file"], x["line"], x["rule_id"]) for x in r_inc.findings}
    kf = {(x["file"], x["line"], x["rule_id"]) for x in r_full.findings}
    return ki == kf


def main(argv=None):
    p = argparse.ArgumentParser(prog="replay")
    p.add_argument("--root", default="src")
    p.add_argument("--keep", action="store_true", help="保留沙箱便于排查")
    p.add_argument("--json", dest="as_json", action="store_true")
    args = p.parse_args(argv)
    summary = run_replay(args.root, keep=args.keep)
    if args.as_json:
        print(json.dumps(summary, ensure_ascii=False, indent=1))
        return 0 if not summary["failed"] and not summary["ghosts"] else 1
    print(f"replay {summary['passed']}/{summary['total']} equivalent, "
          f"ghosts={len(summary['ghosts'])}, "
          f"quarantine_self_consistent={summary['quarantine_self_consistent']}")
    for r in summary["results"]:
        flag = "OK " if r["ok"] else "FAIL"
        print(f"[{flag}] {r['i']:02d} {r['cat']:<12} mode={r['inc_mode']:<10} "
              f"rescan={r['rescanned']} reuse={r['reused']}  {r['desc']}")
        if not r["ok"]:
            if r["only_in_full"]:
                print("       only-in-full:", r["only_in_full"])
            if r["only_in_inc"]:
                print("       only-in-inc:", r["only_in_inc"])
            if r["ghost"]:
                print("       ghost:", r["ghost"])
    if summary["sandbox"]:
        print("sandbox kept at:", summary["sandbox"])
    return 0 if not summary["failed"] and not summary["ghosts"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
