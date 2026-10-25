"""Bounded intraprocedural evidence, not a proof of vulnerability.

No project imports or execution. Branches merge conservatively; unknown calls
propagate argument taint. Aliases, object fields and interprocedural flows are
not fully resolved. Findings retain this limitation explicitly.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class Flow:
    source: str
    line: int
    steps: tuple = ()
    sanitized_html: bool = False


def union(*groups):
    return list(dict.fromkeys(f for group in groups for f in group))[:4]


def merged(*envs):
    keys = set().union(*(env.keys() for env in envs))
    return {key: union(*(env.get(key, []) for env in envs)) for key in keys}


class Evidence:
    def __init__(self, content):
        self.content = content
        self.lines = content.splitlines()
        self.findings = []
        self.seen = set()
        self.steps = 0

    def emit(self, flows, line, column, sink, layer, rule_id, cwe, title, fix, html=False):
        for flow in flows:
            if html and flow.sanitized_html:
                continue
            key = (line, rule_id, flow.source, flow.line)
            if key in self.seen or len(self.findings) >= 1000:
                continue
            self.seen.add(key)
            self.findings.append(dict(line=line, column=column, layer=layer, rule=title,
                rule_id=rule_id, priority="高", confidence="AST 可见数据流（待复核）", cwe=cwe,
                snippet=self.lines[line - 1].strip()[:300],
                evidence=[f"L{flow.line}: 潜在外部输入 {flow.source}", *flow.steps,
                          f"L{line}: 到达 {sink}", "仅当前函数 / 文件的保守传播；未证明可利用性。"],
                recommendation=fix))

    def tick(self, depth):
        self.steps += 1
        if depth > 70 or self.steps > 60000:
            raise ValueError("AST 分析达到深度 / 节点上限；该文件的语法树分析不完整。")


class JavaScript(Evidence):
    FUNCTION = {"function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function_declaration", "generator_function"}
    SOURCE = re.compile(r"^(?:(?:window|document)\.)?location\.(?:search|hash|href)$|^document\.(?:cookie|referrer)$|^(?:req|request)\.(?:query|params|body)(?:\.|\[|$)|^(?:e|ev|event)\.data(?:\.|\[|$)|\.target\.value$")

    def __init__(self, content, suffix):
        super().__init__(content)
        from tree_sitter import Language, Parser
        if suffix in {".ts", ".tsx"}:
            import tree_sitter_typescript as grammar
            language = grammar.language_tsx() if suffix == ".tsx" else grammar.language_typescript()
        else:
            import tree_sitter_javascript as grammar
            language = grammar.language()
        self.parser = Parser(Language(language))
        self.raw = content.encode("utf-8")

    def text(self, node):
        return self.raw[node.start_byte:node.end_byte].decode("utf-8") if node else ""

    def field(self, node, name):
        return node.child_by_field_name(name)

    def analyze(self):
        tree = self.parser.parse(self.raw)
        self.expr(tree.root_node, {}, 0)
        notes = ["解析包含语法错误，AST 结果可能不完整。"] if tree.root_node.has_error else []
        if len(self.findings) >= 1000:
            notes.append("AST 证据达到单文件 1000 条上限，结果可能不完整。")
        return self.findings, notes

    def expr(self, node, env, depth):
        if node is None:
            return []
        self.tick(depth)
        kind = node.type
        line = node.start_point.row + 1
        column = len(self.raw[self.raw.rfind(b"\n", 0, node.start_byte) + 1:node.start_byte].decode("utf-8")) + 1
        text = self.text(node)
        if kind in {"string", "number", "true", "false", "null", "comment", "regex"}:
            return []
        if kind in {"member_expression", "subscript_expression"} and self.SOURCE.search(re.sub(r"\s+", "", text)):
            return [Flow(text[:120], line)]
        if kind == "identifier":
            return env.get(text, [])
        if kind in self.FUNCTION:
            inner = dict(env)
            params = self.field(node, "parameters") or self.field(node, "parameter")
            if params:
                stack = [params]
                while stack:
                    current = stack.pop()
                    if current.type == "identifier":
                        inner[self.text(current)] = []
                    stack.extend(current.named_children)
            self.expr(self.field(node, "body"), inner, depth + 1)
            return []
        if kind == "if_statement":
            self.expr(self.field(node, "condition"), env, depth + 1)
            left, right = dict(env), dict(env)
            self.expr(self.field(node, "consequence"), left, depth + 1)
            self.expr(self.field(node, "alternative"), right, depth + 1)
            env.clear()
            env.update(merged(left, right))
            return []
        if kind in {"for_statement", "for_in_statement", "while_statement", "do_statement", "switch_statement", "try_statement"}:
            before = dict(env)
            values = [self.expr(child, env, depth + 1) for child in node.named_children]
            combined = merged(before, env)
            env.clear()
            env.update(combined)
            return union(*values)
        if kind == "variable_declarator":
            value = self.expr(self.field(node, "value"), env, depth + 1)
            target = self.field(node, "name")
            if target and target.type == "identifier":
                env[self.text(target)] = [replace(f, steps=(*f.steps[-4:], f"L{line}: 赋值给 {self.text(target)}")) for f in value]
            return value
        if kind in {"assignment_expression", "augmented_assignment_expression"}:
            left = self.field(node, "left")
            value = self.expr(self.field(node, "right"), env, depth + 1)
            if kind == "augmented_assignment_expression":
                value = union(self.expr(left, env, depth + 1), value)
            target = self.text(left)
            if left and left.type == "identifier":
                env[target] = [replace(f, steps=(*f.steps[-4:], f"L{line}: 赋值给 {target}")) for f in value]
            elif re.search(r"\.(?:innerHTML|outerHTML)$|\[['\"](?:innerHTML|outerHTML)['\"]\]$", target):
                self.emit(value, line, column, target, 1, "JS-HTML-FLOW", "CWE-79", "外部输入到 HTML 写入", "使用 textContent；需要富文本时在最终 HTML 输出前采用可信净化器。", html=True)
            elif re.search(r"(?:^|\.)location(?:\.href)?$|\.(?:href|src|action)$", target):
                self.emit(value, line, column, target, 3, "JS-URL-FLOW", "CWE-79", "外部输入到 URL 属性 / 导航", "基于 URL 解析后的协议与业务允许域名进行校验；核查最终元素上下文。")
            return value
        if kind in {"call_expression", "new_expression"}:
            function = self.field(node, "function") or self.field(node, "constructor")
            name = re.sub(r"\s+", "", self.text(function))
            args = self.field(node, "arguments")
            arguments = list(args.named_children) if args else []
            values = [self.expr(child, env, depth + 1) for child in arguments]
            receiver = self.expr(self.field(function, "object"), env, depth + 1) if function else []
            combined = union(receiver, *values)
            if re.search(r"(?:localStorage|sessionStorage)\.(?:getItem|key)$", name):
                return [Flow(name, line)]
            if name in {"DOMPurify.sanitize", "sanitizeHtml"}:
                # A review signal remains in the regex layer. No universal sanitizer trust.
                return [replace(f, sanitized_html=True, steps=(*f.steps[-4:], f"L{line}: HTML 净化调用（配置和版本仍需复核）")) for f in combined]
            if name in {"eval", "Function", "window.eval"}:
                self.emit(combined, line, column, name, 8, "JS-CODE-FLOW", "CWE-95", "外部输入到动态代码执行", "避免动态执行外部字符串，改用显式分派或数据解析。")
            elif name in {"setTimeout", "setInterval"}:
                self.emit(values[0] if values else [], line, column, name, 8, "JS-TIMER-FLOW", "CWE-95", "外部输入到计时器参数", "传递函数回调，避免外部字符串作为执行内容。")
            elif name in {"window.open", "location.assign", "location.replace", "window.location.assign", "window.location.replace"}:
                self.emit(values[0] if values else [], line, column, name, 3, "JS-URL-FLOW", "CWE-79", "外部输入到浏览器导航", "校验解析后的协议、域名和具体导航上下文。")
            elif name in {"document.write", "document.writeln"} or name.endswith((".insertAdjacentHTML", ".setHTMLUnsafe")):
                selected = values[1] if name.endswith(".insertAdjacentHTML") and len(values) > 1 else combined
                self.emit(selected, line, column, name, 1, "JS-HTML-FLOW", "CWE-79", "外部输入到 HTML 插入", "采用安全文本 API，或在正确上下文进行最终净化。", html=True)
            return combined
        if kind == "jsx_attribute" and node.named_children and self.text(node.named_children[0]) == "dangerouslySetInnerHTML":
            value = union(*(self.expr(child, env, depth + 1) for child in node.named_children[1:]))
            self.emit(value, line, column, "dangerouslySetInnerHTML", 1, "JS-HTML-FLOW", "CWE-79", "外部输入到 React 原始 HTML", "优先使用普通 JSX 文本；富文本需要最终 HTML 净化。", html=True)
            return value
        return union(*(self.expr(child, env, depth + 1) for child in node.named_children))


class Python(Evidence):
    SOURCE = re.compile(r"^(?:request|req)\.(?:args|form|values|json|data|GET|POST|query_params|path_params)(?:\.|\[|$)|^sys\.argv(?:\[|$)")

    def name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self.name(node.value) + "." + node.attr
        return ""

    def analyze(self):
        tree = ast.parse(self.content)
        self.block(tree.body, {}, 0)
        return self.findings, (["AST 证据达到单文件 1000 条上限，结果可能不完整。"] if len(self.findings) >= 1000 else [])

    def expr(self, node, env, depth):
        if node is None:
            return []
        self.tick(depth)
        line = getattr(node, "lineno", 1)
        if isinstance(node, ast.Constant):
            return []
        if isinstance(node, ast.Name):
            return env.get(node.id, [])
        name = self.name(node)
        if name and self.SOURCE.search(name):
            return [Flow(name, line)]
        if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        if isinstance(node, ast.Call):
            name = self.name(node.func)
            args = [self.expr(arg, env, depth + 1) for arg in node.args]
            receiver = self.expr(node.func.value, env, depth + 1) if isinstance(node.func, ast.Attribute) else []
            values = union(receiver, *args, *(self.expr(k.value, env, depth + 1) for k in node.keywords))
            if name in {"input", "request.get_json", "request.get_data"}:
                return [Flow(name, line)]
            checks = []
            if name in {"eval", "exec"}:
                checks.append((8, "PY-CODE-FLOW", "CWE-95", "外部输入到动态执行", "移除 eval / exec，使用显式数据解析和允许操作列表。"))
            if name in {"os.system", "os.popen"} or (name.startswith("subprocess.") and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)):
                checks.append((16, "PY-SHELL-FLOW", "CWE-78", "外部输入到 Shell 命令", "使用参数数组和 shell=False；对每个参数做业务约束。"))
            if name.endswith((".execute", ".executemany", ".raw")):
                # Only the SQL expression (argument 0), not parameter values.
                values = args[0] if args else []
                checks.append((15, "PY-SQL-FLOW", "CWE-89", "外部输入到 SQL 语句构造", "使用数据库参数绑定，不拼接外部输入到 SQL 字符串。"))
            if name in {"open", "send_file", "flask.send_file"} or name.endswith((".read_text", ".read_bytes")):
                checks.append((17, "PY-PATH-FLOW", "CWE-22", "外部输入到文件路径", "解析规范路径后检查允许根目录；避免仅用字符串前缀校验。"))
            if name in {"requests.get", "requests.post", "requests.request", "httpx.get", "httpx.post", "urllib.request.urlopen", "urlopen"}:
                checks.append((18, "PY-SSRF-FLOW", "CWE-918", "外部输入到服务端请求", "限制协议、目标和重定向；结合网络出口限制与解析结果检查。"))
            if name in {"pickle.loads", "pickle.load", "marshal.loads", "yaml.unsafe_load", "yaml.load"}:
                if not (name == "yaml.load" and any(k.arg == "Loader" and self.name(k.value).endswith("SafeLoader") for k in node.keywords)):
                    checks.append((19, "PY-DESERIALIZE-FLOW", "CWE-502", "外部输入到反序列化", "使用安全数据格式与安全解析器，避免对不可信内容反序列化对象。"))
            if name in {"render_template_string", "flask.render_template_string", "mark_safe", "Markup"}:
                checks.append((14, "PY-TEMPLATE-FLOW", "CWE-79", "外部输入到模板 / 信任绕过", "固定模板源码，通过参数传入数据并保持上下文转义。"))
            for layer, rule_id, cwe, title, fix in checks:
                flows = args[0] if args else []
                keyword = "url" if layer == 18 else "file" if layer == 17 else ""
                if layer == 18 and name == "requests.request":
                    flows = args[1] if len(args) > 1 else []
                if keyword:
                    flows = union(flows, *(self.expr(k.value, env, depth + 1) for k in node.keywords if k.arg == keyword))
                if layer == 17 and name.endswith((".read_text", ".read_bytes")):
                    flows = receiver
                column = len(self.lines[line - 1].encode("utf-8")[:node.col_offset].decode("utf-8")) + 1
                self.emit(flows, line, column, name, layer, rule_id, cwe, title, fix)
            return values
        return union(*(self.expr(child, env, depth + 1) for child in ast.iter_child_nodes(node)))

    def block(self, statements, env, depth):
        for node in statements:
            self.tick(depth)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = dict(env)
                for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                    inner[arg.arg] = []
                self.block(node.body, inner, depth + 1)
            elif isinstance(node, ast.ClassDef):
                self.block(node.body, dict(env), depth + 1)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                values = self.expr(node.value, env, depth + 1)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        if isinstance(node, ast.AugAssign):
                            values = union(env.get(target.id, []), values)
                        env[target.id] = [replace(f, steps=(*f.steps[-4:], f"L{node.lineno}: 赋值给 {target.id}")) for f in values]
            elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)):
                for field in ("test", "iter"):
                    self.expr(getattr(node, field, None), env, depth + 1)
                original, branch = dict(env), dict(env)
                self.block(node.body, branch, depth + 1)
                self.block(getattr(node, "orelse", []), original, depth + 1)
                branches = [original, branch]
                for handler in getattr(node, "handlers", []):
                    other = dict(env)
                    self.block(handler.body, other, depth + 1)
                    branches.append(other)
                env.clear()
                env.update(merged(*branches))
                self.block(getattr(node, "finalbody", []), env, depth + 1)
            else:
                self.expr(node, env, depth + 1)


def analyze(content: str, suffix: str):
    engine = None
    try:
        if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            engine = JavaScript(content, suffix)
        elif suffix == ".py":
            engine = Python(content)
        else:
            return [], []
        return engine.analyze()
    except (SyntaxError, ValueError, RecursionError, MemoryError) as error:
        return (engine.findings if engine else []), [f"AST 分析不完整：{type(error).__name__}" + (f"：{error}" if isinstance(error, ValueError) else "")]
    except ImportError:
        return [], ["AST 依赖缺失，当前文件仅执行规则搜索。"]
