# 增量污点分析器设计说明

针对运单打印接口 CWE-78 事故的根因——**公共工具函数变更后，依赖它的 handler 没有
重扫、缓存保留旧结论**——本分析器用「文件哈希 + 符号表依赖 + 规则版本」三因子缓存
保证增量结论与全量逐结论一致，并以反向依赖闭包覆盖事故场景。

## 1. 总体结构

```
incremental/
  rules.py    规则注册表：sink/sanitizer、污点类别、规则版本 RULE_VERSION
  symbols.py  AST 解析、模块/函数指纹、跨文件符号解析（不执行项目代码）
  taint.py    过程内污点传播 + 跨项目函数摘要 + 动态派发降级
  cache.py    清单式缓存、缓存键、三类失效判定、反向依赖闭包
  sarif.py    SARIF 2.1.0 输出（结论与降级通知分通道）
  engine.py   全量/增量编排、CI 退出码
  replay.py   40 条历史变更回放
```

分析对象是 Python AST，全程不 import、不执行被扫描代码，因此没有 `json.py` 植马
这类导入副作用风险。入口函数（`load_*`/`safe_load_*`/`handle_*` 等）的参数被初始化为
全类别污点，按语句传播到 sink。

## 2. 缓存键包含哪些因子

每个文件一条缓存 entry，缓存键是下列因子拼接后的 sha256（见
`cache.compute_cache_key`），任一因子变化都会使该 entry 失效：

| 因子 | 取值 | 对应失效类别 |
| --- | --- | --- |
| `RULE_VERSION` | 规则表/sink/sanitizer/传播语义版本，改动规则必须 bump | 因子 3：规则版本 |
| `ANALYZER_VERSION` | 分析器实现版本，引擎代码变更的兜底因子 | 因子 3 |
| `source_hash` | 源文件全文 sha256 | 因子 1：源文件变化 |
| `root_relpath` | 文件在扫描根中的相对身份，防路径混淆/同名复活 | 完整性 |
| `dependencies` | 每个被调用项目符号的 `模块.符号@指纹 fp` 排序拼接 | 因子 2：符号签名 |
| `entry_set_hash` | 该文件入口函数名集合，防入口增删漏扫 | 完整性 |
| `policy` | 动态派发降级策略（fail-closed / quarantine） | 配置 |

其中符号指纹 `fp = sha256(sig_hash + body_hash)`：

- `sig_hash`：函数名 + 参数形状（位置参、`*args`、`**kwargs`、默认值、kwonly、装饰器）
- `body_hash`：去掉行号后的规范化函数体 AST

**签名没变但函数体变了（事故当天的情形）照样失效**，因为 `fp` 同时纳入两者。

命中判定是双保险：`invalidate_plan` 先逐因子比对，命中复用前 `engine` 还会重算一次
完整缓存键与 entry 里存的比对，不一致立即重扫，防止清单被局部篡改后读到脏结论。

## 3. 三类失效如何落地

1. **源文件变了（因子 1）**：重新哈希，`source_hash` 不等即标记重扫。
2. **被依赖符号签名/实现变了（因子 2）**：entry 里记录每个依赖符号的 `fp`，
   与当前符号表重算的指纹逐一比对；不一致即重扫。随后做**反向依赖闭包**：
   公共模块一改，所有把它写进 dependencies 的文件一起进入重扫集合，再对它们的
   调用方迭代到不动点。这正是事故里缺失的一环——`tests/test_incremental.py`
   的 `test_factor2_reverse_dependency_invalidation` 用两个 handler 依赖一个
   `_scrub` 的样本固化该行为。
3. **规则版本变了（因子 3）**：清单顶层 `rule_version` 与当前 `RULE_VERSION`
   不等，整盘作废、强制全量。

被删除文件的 entry 直接丢弃；结果集在输出前再过一次「幽灵守卫」，任何归属已不存在
文件的结论都会被剔除。

## 4. 哪类改动直接放弃缓存、走全量

- 规则版本或分析器版本变化（因子 3，整盘）。
- 清单 JSON 损坏、被截断、`schema` 无法识别、无法读取（完整性，整盘）。
- 冷启动（无清单）。
- entry 依赖的项目符号在当前符号表中**解析不到**（定义被删/改名/模块消失）：
  无法验证指纹，宁可放弃该 entry 全量重扫，也不沿用旧结论。
- 文件存在语法错误（`SyntaxError`）：该文件不产生结论、不复用缓存，并以退出码 2
  标记结果不完整。
- 扫描根身份变化、文件删除后同名复活（relpath 身份不可信）。
- 显式 `--full`。

## 5. 动态派发解析不出来时怎么降级

静态分析无法覆盖所有调用形态：`getattr(obj, name)(...)`、反射、未导入的名字、
函数别名间接调用等。解析器分三类处理（见 `taint._unresolved`）：

1. **库方法链式调用**（如 `open(...).read()`、`f()(...)`）：补扫 `func` 子树里的
   嵌套调用，本层按 identity 处理，不产生「未解析」噪声。
2. **命名疑似 sanitizer 但定义无法解析**（名字命中
   `sanitize/allowlist/whitelist/escape/clean/validate/_only_` 等特征）：
   - **fail-closed（默认）**：在调用点产出一条 `PY-DYN-001` 降级告警（warning 级，
     CI 可见、必须人工处置），并把该数据流隔离（污点不再向下游传播，避免同一数据源
     在调用点和下游 sink 双重报告）。**不静默放行**。
   - **quarantine（可选）**：信任命名约定，按「净化有效」返回干净掩码，只保留
     SARIF `toolExecutionNotifications` 诊断、不产生 result。
3. **非 sanitizer 形态的未解析调用**：两种策略都按 identity 保守传播污点，
   下游若流入 sink 仍正常报 error。

所有降级事件都写入 SARIF 的 `invocations[].toolExecutionNotifications`，与
`results` 分通道，不会被评估器或代码平台当成漏洞计入 precision。

### 降级会不会引入假阴性？

- **fail-closed 不会引入静默假阴性**：解析不到的疑似净化点一律显式告警，疑点可见、
  可追踪，不存在「污点被悄悄吞掉」。代价是可能多出需要人工确认的 warning。
- **quarantine 是唯一可能产生假阴性的路径**：它用「命名约定」替代「定义可证」，
  若一个名字像 sanitizer 的函数实际没有净化效果，污点会被错误地当作干净。
  因此 quarantine 只建议在高信噪比门禁、且配合诊断审计时使用；默认保持
  fail-closed。文档和 `--policy` 帮助文本都明确标注了这一权衡。

### 用什么样本验证降级路径

`tests/test_incremental.py` 与 `replay.py` 的 D 类变更专门覆盖：

- `UNRESOLVED_SAN`：`_only_allowlisted` 无定义——验证 fail-closed 产出恰好一条
  `PY-DYN-001` 且下游不重复报；quarantine 下零 result、保留一条诊断。
- 补上真实定义并 `from allow import _only_allowlisted` 后——验证降级解除、
  诊断归零（`test_resolving_dispatch_clears_degradation`）。
- `getattr(urllib.request, 'urlopen')` 反射样本——验证动态形态被保守处理、
  两种策略各自与全量自洽（`test_reflective_getattr_handled_conservatively`）。
- 模块级函数别名 `TARGET = urllib.request.urlopen; TARGET(...)`——验证不报假干净。
- 回放 D4 在 quarantine 策略下独立重放，确认策略切换后增量仍等于全量。

## 6. 精度对比（在仓库自带语料上）

| 方案 | 召回 | 精确率 | 说明 |
| --- | --- | --- | --- |
| 基线正则 `baseline/scan.py` | 100% | 58.3% | 12 条发现，5 个误报 |
| 本分析器 fail-closed | 100% | 77.8% | 7 真实漏洞全中 + 2 条降级 warning |
| 本分析器 quarantine | 100% | 100% | 7 真实漏洞，0 误报，降级仅入诊断 |

类别敏感的净化建模是精度来源：`os.path.basename` 只清除路径穿越类别，拼进 shell
仍报命令注入；白名单式 `re.sub(r"[^...]", "", x)` 才被认定为全类别净化。

## 7. SARIF 与 CI 退出码

输出 SARIF 2.1.0，安全结论在 `runs[].results`，降级/解析错误在
`toolExecutionNotifications`，扫描统计在 `tool.driver.properties.scanStats`。

| 退出码 | 含义 |
| --- | --- |
| 0 | 无安全发现、无未解析诊断 |
| 1 | 存在 error 级安全发现 |
| 2 | 解析错误等致命问题，结果不完整，不应放行 |
| 3 | 无 error 但存在未解析动态派发诊断（需人工确认） |
| 4 | 非预期的强制全量（缓存损坏/版本失效）且无发现，仅作观测信号；显式 `--full` 不触发 |

## 8. 用法

```bash
# 全量
python -m incremental.cli scan --root src --full --sarif out.sarif --uri-prefix src
# 增量（默认延续 <root>/.incremental-cache）
python -m incremental.cli scan --root src --sarif out.sarif --uri-prefix src --explain
# 切换降级策略
python -m incremental.cli scan --root src --policy quarantine --sarif out.sarif
# 40 条历史变更回放
python -m incremental.replay --root src
```

`--explain` 在 stderr 打印每个文件的缓存命中/失效原因，便于审计「为什么这次重扫」。
