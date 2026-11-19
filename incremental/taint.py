"""过程内污点传播 + 跨项目函数摘要解析 + 动态派发降级。

策略总览：
- 入口函数（rules.ENTRY_PREFIXES）的全部参数初始化为全类别污点，逐语句传播。
- 项目内函数调用递归求值（带调用栈环检测 + 记忆化），因此公共工具函数的
  净化/透传语义能被精确建模，而不是把所有调用都当 identity。
- 解析不到的调用（动态派发、未导入名字、反射）走 UNRESOLVED 降级通道，
  具体策略见 analyze_file 的 policy 参数与 docs/incremental-analyzer.md。
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional

from .rules import (
    CATEGORY_OF_SINK,
    LIBRARY_PASSTHROUGH,
    SANITIZER_NAME_HINTS,
    TAINT_ALL,
    TAINT_PATH,
    is_entry_function,
    is_library_module,
    SINKS,
)
from .symbols import FileModel, FunctionModel, SymbolTable

# 降级策略：
#   fail-closed（默认）：疑似 sanitizer 解析失败 -> 产生降级告警，宁枉毋纵
#   quarantine：         疑似 sanitizer 解析失败 -> 抑制告警仅留诊断，换取精度
POLICY_FAIL_CLOSED = "fail-closed"
POLICY_QUARANTINE = "quarantine"

DEGRADED_RULE_ID = "PY-DYN-001"

# 不传播污点的内建/常见纯函数
SAFE_BUILTINS = {
    "len", "int", "float", "bool", "abs", "hash", "repr", "isinstance",
    "issubclass", "dict", "list", "tuple", "set", "frozenset", "range",
    "enumerate", "zip", "sorted", "min", "max", "sum", "any", "all",
    "getattr",  # getattr 结果按基对象处理，这里默认干净，由 Attribute 分支兜底
}
# 透传污点的内建（结果污点 = 参数污点并集）
PASSTHROUGH_BUILTINS = {"str", "bytes", "format", "chr", "ord", "strip",
                        "lstrip", "rstrip", "lower", "upper", "join"}


@dataclass
class Finding:
    rule_id: str
    cwe: str
    kind: str
    message: str
    file: str
    line: int
    sink: str
    source: str
    degraded: bool = False

    def key(self) -> tuple:
        return (self.file, self.line, self.rule_id)


@dataclass
class Diagnostic:
    file: str
    line: int
    dotted: str
    reason: str
    sanitizer_shaped: bool
    policy: str


@dataclass
class _CallDep:
    module: str
    symbol: str
    fp: str           # 调用点解析到的函数指纹（分析时刻快照）


class _Analyzer:
    def __init__(self, symbols: SymbolTable, file: FileModel, policy: str):
        self.symbols = symbols
        self.file = file
        self.policy = policy
        self.findings: list[Finding] = []
        self.diagnostics: list[Diagnostic] = []
        self.deps: dict[tuple[str, str], str] = {}
        self._ret_memo: dict[tuple, int] = {}
        self.stack: set[tuple[str, str]] = set()
        # 符号解析上下文栈：分析跨文件被调函数时，函数体内的 import/名字
        # 必须按"定义所在文件"解析，而不是调用方文件（否则 common.py 里的
        # re.sub 在 h_a 的上下文中会解析失败、sanitizer 失效）。
        self._ctx_stack: list[FileModel] = [file]
        self.current_source = "?"
        # 已产出的发现/诊断按 sink 身份去重，避免递归/多入口重复追加
        self._finding_seen: set[tuple] = set()
        self._diag_seen: set[tuple] = set()

    @property
    def _ctx(self) -> FileModel:
        return self._ctx_stack[-1]

    def _resolve(self, dotted: str):
        return self.symbols.resolve(self._ctx, dotted)

    # ---------------------------------------------------------- 收集助手
    def _add_finding(self, finding: Finding):
        key = finding.key()
        if key not in self._finding_seen:
            self._finding_seen.add(key)
            self.findings.append(finding)

    def _add_diagnostic(self, diag: Diagnostic):
        key = (diag.file, diag.line, diag.dotted)
        if key not in self._diag_seen:
            self._diag_seen.add(key)
            self.diagnostics.append(diag)

    # ---------------------------------------------------------- 表达式求值
    def eval(self, node: Optional[ast.AST], env: dict[str, int]) -> int:
        if node is None:
            return 0
        m = getattr(self, "_expr_" + type(node).__name__, None)
        if m is None:
            return self._expr_generic(node, env)
        return m(node, env)

    def _expr_generic(self, node: ast.AST, env: dict[str, int]) -> int:
        mask = 0
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.AST):
                mask |= self.eval(child, env)
        return mask

    def _expr_Constant(self, node, env):  # noqa: N802
        return 0

    def _expr_Name(self, node, env):  # noqa: N802
        return env.get(node.id, 0)

    def _expr_Attribute(self, node, env):  # noqa: N802
        return self.eval(node.value, env)  # 污点挂在对象上，属性名不引入污点

    def _expr_Subscript(self, node, env):  # noqa: N802
        return self.eval(node.value, env) | self.eval(node.slice, env)

    def _expr_Starred(self, node, env):  # noqa: N802
        return self.eval(node.value, env)

    def _expr_UnaryOp(self, node, env):  # noqa: N802
        return self.eval(node.operand, env)

    def _expr_BinOp(self, node, env):  # noqa: N802（含 % 格式化、字符串拼接）
        return self.eval(node.left, env) | self.eval(node.right, env)

    def _expr_BoolOp(self, node, env):  # noqa: N802
        mask = 0
        for v in node.values:
            mask |= self.eval(v, env)
        return mask

    def _expr_IfExp(self, node, env):  # noqa: N802
        return self.eval(node.body, env) | self.eval(node.orelse, env) | self.eval(node.test, env)

    def _expr_JoinedStr(self, node, env):  # noqa: N802（f-string）
        mask = 0
        for v in node.values:
            mask |= self.eval(v, env)
        return mask

    def _expr_FormattedValue(self, node, env):  # noqa: N802
        return self.eval(node.value, env)

    def _expr_List(self, node, env):  # noqa: N802
        return self._generic_seq(node.elts, env)

    _expr_Tuple = _expr_List
    _expr_Set = _expr_List

    def _generic_seq(self, elts, env):
        mask = 0
        for e in elts:
            mask |= self.eval(e, env)
        return mask

    def _expr_Dict(self, node, env):  # noqa: N802
        mask = 0
        for k in node.keys:
            mask |= self.eval(k, env)
        for v in node.values:
            mask |= self.eval(v, env)
        return mask

    def _expr_Lambda(self, node, env):  # noqa: N802
        return 0  # 定义不执行；调用点按普通 Call 处理

    # ---------------------------------------------------------- 调用表达式
    def _expr_Call(self, node, env):  # noqa: N802
        return self._eval_call(node, env)[0]

    def _eval_nested_in_func(self, node: ast.Call, env: dict[str, int]):
        """动态调用（f()(...)、obj.method()(...)、open(...).read()）的 func 子树
        里可能嵌套着真正的 sink 调用（如 open(os.path.join(x)).read()）。
        args 已在 _eval_call 入口求值过，这里补扫 func 链上的嵌套 Call。"""
        cur = node.func
        while isinstance(cur, ast.Attribute):
            cur = cur.value
        if isinstance(cur, ast.Call):
            self.eval(cur, env)

    def _dotted(self, node):
        """把 Call 的 func 还原成点号名字；非纯名字链（f()(...)、getattr(...)）返回 None。"""
        parts = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        return None

    def _has_shell_true(self, node) -> bool:
        return any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                   for kw in node.keywords)

    def _match_sink(self, node, dotted):
        if dotted is None or dotted == "<dynamic>":
            resolved = (None, None)
        else:
            resolved = self._resolve(dotted)
        for spec in SINKS:
            kind = spec["match"][0]
            if kind == "attr":
                _, mod, methods, _ = spec["match"]
                if not isinstance(node.func, ast.Attribute) or node.func.attr not in methods:
                    continue
                module, symbol = resolved
                if symbol != node.func.attr:
                    continue
                # 模块必须能对上。解析失败（项目对象方法，如游标 _CUR.execute）
                # 则让 name 类规则兜底，不在这里吞掉。
                if module is None or module != mod:
                    continue
                if spec.get("require_shell_true") and not self._has_shell_true(node):
                    continue
                return spec, module
            else:
                _, _, names, _ = spec["match"]
                if isinstance(node.func, ast.Name):
                    fname = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    fname = node.func.attr
                else:
                    continue
                if fname not in names:
                    continue
                if isinstance(node.func, ast.Attribute):
                    # 只有解析不到归属（项目对象，如游标 _CUR.execute）才用 name 兜底；
                    # 库模块属性各有 attr 规则负责。builtins 的属性形态（实际不存在，
                    # 但防御性处理）与库模块一样跳过，避免双重判定。
                    if resolved[0] is not None and resolved[0] != "builtins":
                        continue
                return spec, None
        return None

    def _eval_call(self, node: ast.Call, env: dict[str, int]):
        dotted = self._dotted(node)
        if dotted is None:
            # 动态形态：先扫 func 链上的嵌套 sink（open(...).read() 等），
            # 再按 identity 处理本层调用，不产生"未解析派发"误报。
            self._eval_nested_in_func(node, env)
            arg_masks = [self.eval(a, env) for a in node.args]
            return self._union(arg_masks), arg_masks
        arg_masks = [self.eval(a, env) for a in node.args]
        kw_masks = {kw.arg: self.eval(kw.value, env) for kw in node.keywords if kw.arg}

        # 1) Sink 判定
        sink = self._match_sink(node, dotted)
        if sink is not None:
            spec, module = sink
            kind = spec["kind"]
            tcat = CATEGORY_OF_SINK[kind]
            tainted_idx = spec["match"][3]
            hit = False
            for i, mask in enumerate(arg_masks):
                if i in tainted_idx and (mask & tcat):
                    hit = True
            if not hit and spec.get("require_shell_true"):
                hit = any(m & tcat for m in arg_masks)
            if hit:
                self._add_finding(Finding(
                    rule_id=spec["rule_id"], cwe=spec["cwe"], kind=kind,
                    message=spec["message"], file=self.file.relpath,
                    line=node.lineno, sink=dotted, source=self.current_source,
                ))
            return 0, arg_masks  # sink 的返回值不再参与传播

        # 2) 精确 sanitizer
        san = self._exact_sanitizer(node, dotted, arg_masks)
        if san is not None:
            return san, arg_masks

        # 3) 项目内函数（跨文件符号表解析）
        module = symbol = None
        if dotted != "<dynamic>":
            module, symbol = self._resolve(dotted)
            if module and symbol:
                fn = self.symbols.get_function(module, symbol)
                if fn is not None:
                    self.deps[(module, symbol)] = fn.fp
                    return self._call_project(fn, node, arg_masks, kw_masks)

        # 4) 已知外部库的普通调用：sink/sanitizer 已在前面截走，
        #    污点保留型函数按入参并集传播，其余库调用默认干净、不降级。
        if module and is_library_module(module):
            if (module, symbol) in LIBRARY_PASSTHROUGH:
                return self._union(arg_masks), arg_masks
            return 0, arg_masks

        # 5) 内建
        fname = dotted.split(".")[-1]
        if fname in SAFE_BUILTINS:
            return 0, arg_masks
        if fname in PASSTHROUGH_BUILTINS:
            return self._union(arg_masks) | (sum(kw_masks.values()) if kw_masks else 0), arg_masks

        # 6) 动态派发 / 未解析项目符号 —— 降级通道
        return self._unresolved(node, dotted, arg_masks), arg_masks

    def _exact_sanitizer(self, node, dotted, arg_masks) -> Optional[int]:
        module, symbol = self._resolve(dotted) if dotted != "<dynamic>" else (None, None)
        if module == "os.path" and symbol == "basename":
            # basename 只清理路径类别；其余类别原样保留
            return (arg_masks[0] if arg_masks else 0) & ~TAINT_PATH
        if module == "re" and symbol == "sub" and len(node.args) >= 3:
            pattern = node.args[0]
            repl = node.args[1]
            if (isinstance(pattern, ast.Constant) and isinstance(pattern.value, str)
                    and isinstance(repl, ast.Constant)):
                p = pattern.value
                allowlist = ("[^" in p) and ("\\g<" not in p) and not any(
                    isinstance(ch, ast.Name) for ch in ast.walk(repl))
                if allowlist:
                    return 0  # 白名单式替换：输出不携带任何污点类别
                # 黑名单式替换无法保证净化，污点透传
        return None

    def _run_in_definition_context(self, fn: FunctionModel, env: dict) -> int:
        """在函数定义所在文件的符号上下文中执行函数体。"""
        owner_rel = self.symbols.modules.get(fn.qualname.rsplit(".", 1)[0])
        owner_file = self.symbols.files.get(owner_rel) if owner_rel else None
        if owner_file is not None and owner_file is not self._ctx:
            self._ctx_stack.append(owner_file)
            try:
                return self._run_function(fn, env)
            finally:
                self._ctx_stack.pop()
        return self._run_function(fn, env)

    def _call_project(self, fn: FunctionModel, node, arg_masks, kw_masks):
        module = fn.qualname.rsplit(".", 1)[0]
        sub_env = self._bind_args(fn, node, arg_masks, kw_masks)
        cache_key = (fn.qualname, tuple(sorted(sub_env.items())))
        if cache_key in self._ret_memo:
            # 只复用返回掩码；函数体内的 sink/诊断在本次调用栈重新求值，
            # 避免跨入口上下文串号导致假阴性。
            self._run_in_definition_context(fn, dict(sub_env))
            return self._ret_memo[cache_key], arg_masks
        if (module, fn.name) in self.stack:
            # 递归环：本轮按 identity 近似，且不写 memo——
            # 否则脏的近似值会缓存住，后续正确结果永远进不来。
            return self._union(arg_masks), arg_masks
        self.stack.add((module, fn.name))
        ret = self._run_in_definition_context(fn, dict(sub_env))
        self.stack.discard((module, fn.name))
        self._ret_memo[cache_key] = ret
        return ret, arg_masks

    def _bind_args(self, fn: FunctionModel, node, arg_masks, kw_masks):
        env: dict[str, int] = {}
        params = fn.args
        for i, name in enumerate(params):
            if i < len(arg_masks):
                env[name] = arg_masks[i]
            elif name in kw_masks:
                env[name] = kw_masks[name]
            else:
                env[name] = 0
        # 多余位置参数（*args 场景）保守并入最后一个形参
        if len(arg_masks) > len(params) and params:
            env[params[-1]] |= self._union(arg_masks[len(params):])
        return env

    def _run_function(self, fn: FunctionModel, env):
        # 发现与诊断由 _add_* 全局去重，递归/多入口重复执行不会产生重复条目。
        saved_source = self.current_source
        self._walk_body(fn.node.body, env)
        self.current_source = saved_source
        return env.get("__return__", 0)

    # ---------------------------------------------------------- 语句传播
    def _walk_body(self, stmts, env):
        for stmt in stmts:
            self._stmt(stmt, env)

    def _stmt(self, stmt, env):
        m = getattr(self, "_stmt_" + type(stmt).__name__, None)
        if m is None:
            # 未知语句：保守遍历子表达式
            self._expr_generic(stmt, env)
            return
        m(stmt, env)

    def _stmt_Assign(self, stmt, env):  # noqa: N802
        mask = self.eval(stmt.value, env)
        for target in stmt.targets:
            self._assign(target, mask, env)

    def _stmt_AnnAssign(self, stmt, env):  # noqa: N802
        if stmt.value is not None:
            self._assign(stmt.target, self.eval(stmt.value, env), env)

    def _stmt_AugAssign(self, stmt, env):  # noqa: N802
        mask = self.eval(stmt.value, env) | self.eval(stmt.target, env)
        self._assign(stmt.target, mask, env)

    def _assign(self, target, mask, env):
        if isinstance(target, ast.Name):
            env[target.id] = mask
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = target.value if isinstance(target, ast.Attribute) else target.value
            if isinstance(base, ast.Name):
                env[base.id] = env.get(base.id, 0) | mask

    def _stmt_Return(self, stmt, env):  # noqa: N802
        env["__return__"] = env.get("__return__", 0) | self.eval(stmt.value, env)

    def _stmt_If(self, stmt, env):  # noqa: N802
        self.eval(stmt.test, env)
        import copy
        left = copy.deepcopy(env)
        right = copy.deepcopy(env)
        self._walk_body(stmt.body, left)
        self._walk_body(stmt.orelse, right)
        env.clear()
        env.update(self._merge_env(left, right))

    def _stmt_While(self, stmt, env):  # noqa: N802
        self.eval(stmt.test, env)
        self._walk_body(stmt.body, env)
        self._walk_body(stmt.orelse, env)

    def _stmt_For(self, stmt, env):  # noqa: N802
        iter_mask = self.eval(stmt.iter, env)
        if isinstance(stmt.target, ast.Name):
            env[stmt.target.id] = iter_mask
        self._walk_body(stmt.body, env)
        self._walk_body(stmt.orelse, env)

    def _stmt_Try(self, stmt, env):  # noqa: N802
        self._walk_body(stmt.body, env)
        for handler in stmt.handlers:
            self._walk_body(handler.body, env)
        self._walk_body(stmt.orelse, env)
        self._walk_body(stmt.finalbody, env)

    def _stmt_With(self, stmt, env):  # noqa: N802
        for item in stmt.items:
            self.eval(item.context_expr, env)
        self._walk_body(stmt.body, env)

    def _stmt_Expr(self, stmt, env):  # noqa: N802
        self.eval(stmt.value, env)

    def _stmt_Pass(self, stmt, env):  # noqa: N802
        pass

    _stmt_Break = _stmt_Pass
    _stmt_Continue = _stmt_Pass
    _stmt_Global = _stmt_Pass
    _stmt_Nonlocal = _stmt_Pass
    _stmt_Import = _stmt_Pass
    _stmt_ImportFrom = _stmt_Pass
    _stmt_Raise = _stmt_Pass

    def _stmt_FunctionDef(self, stmt, env):  # noqa: N802
        # 嵌套函数定义不执行；默认值表达式仍可能带污点
        for d in stmt.args.defaults + stmt.args.kw_defaults:
            if d is not None:
                self.eval(d, env)

    _stmt_AsyncFunctionDef = _stmt_FunctionDef

    def _stmt_Assert(self, stmt, env):  # noqa: N802
        self.eval(stmt.test, env)

    @staticmethod
    def _union(masks):
        out = 0
        for m in masks:
            out |= m
        return out

    @staticmethod
    def _merge_env(a, b):
        keys = set(a) | set(b)
        return {k: a.get(k, 0) | b.get(k, 0) for k in keys}

    # ---------------------------------------------------------- 降级
    def _unresolved(self, node, dotted, arg_masks):
        # 动态调用形态 f()(...)、obj.method()(...)：func 不是名字链。
        # 项目内不可解析的动态调用才需要降级；参数若带污点由外层调用的入参传播决定，
        # 这里默认干净，避免把库方法链式调用误报成"未解析派发"。
        if dotted == "<dynamic>":
            return 0
        fname = dotted.split(".")[-1]
        shaped = any(h in fname for h in SANITIZER_NAME_HINTS)
        self._add_diagnostic(Diagnostic(
            file=self.file.relpath, line=getattr(node, "lineno", 0),
            dotted=dotted, reason="unresolved-dispatch",
            sanitizer_shaped=shaped, policy=self.policy,
        ))
        if shaped and self.policy == POLICY_FAIL_CLOSED:
            # fail-closed（默认）：净化无法证明 -> 在调用点产生显式 warning（CI 可见、
            # 必须人工处置），并把该值隔离（污点不再向下游传播，避免同一数据源在
            # 调用点和下游 sink 双重报告）。这是"宁枉毋纵"——warning 即兜底结论，
            # 不会静默放行，也不会因为解析器能力不足而制造下游误报。
            taint = self._union(arg_masks)
            if taint:
                self._add_finding(Finding(
                    rule_id=DEGRADED_RULE_ID, cwe="CWE-20",
                    kind="unresolved_sanitizer",
                    message=(f"动态派发/未解析调用 {dotted} 命名疑似净化函数但定义无法解析，"
                             f"fail-closed 策略下产出降级告警并隔离该数据流"
                             f"（确认净化有效可切 quarantine）"),
                    file=self.file.relpath, line=node.lineno,
                    sink=dotted, source=self.current_source, degraded=True,
                ))
            return 0
        if shaped and self.policy == POLICY_QUARANTINE:
            # 隔离降级：信任命名约定、按"净化有效"返回干净掩码，仅保留诊断。
            # 这是唯一可能引入假阴性的路径（详见文档"动态派发降级"章节）。
            return 0
        # 非 sanitizer 形状的未解析调用：无论策略都按 identity 保守传播
        return self._union(arg_masks)


def find_entries(file: FileModel) -> list[FunctionModel]:
    return [fn for name, fn in file.functions.items() if is_entry_function(name)]


def analyze_file(symbols: SymbolTable, file: FileModel, policy: str,
                 _round: int = 0) -> dict:
    """分析单个文件。返回 findings/diagnostics/dependencies/entries。"""
    if file.parse_error:
        return {
            "file": file.relpath, "parse_error": file.parse_error,
            "findings": [], "diagnostics": [], "dependencies": [], "entries": [],
        }
    az = _Analyzer(symbols, file, policy)
    entries = find_entries(file)
    for fn in entries:
        env = {name: TAINT_ALL for name in fn.args}
        az.current_source = f"{fn.name}:{fn.args[0] if fn.args else '?'}"
        before = len(az.findings)
        az._walk_body(fn.node.body, env)
        # 入口自身无参数（罕见）：没有外部污点源，不产生注入类结论
        if not fn.args:
            del az.findings[before:]
    # 去重（同一 sink 行可能经多条路径重复命中）
    uniq: dict[tuple, Finding] = {}
    for f in az.findings:
        uniq.setdefault(f.key(), f)
    deps = [{"module": m, "symbol": s, "fp": fp} for (m, s), fp in sorted(az.deps.items())]
    return {
        "file": file.relpath,
        "parse_error": None,
        "findings": [f.__dict__ for f in uniq.values()],
        "diagnostics": [d.__dict__ for d in az.diagnostics],
        "dependencies": deps,
        "entries": [fn.name for fn in entries],
    }
