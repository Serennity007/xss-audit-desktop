# 检测与证据边界

本工具辅助人工代码审计，不给出“已经验证的漏洞”结论，也不承诺检出率。复核优先级与漏洞严重性不同。

## 有限 AST 数据流

- JavaScript / JSX 使用 Tree-sitter JavaScript，TypeScript / TSX 使用对应语法；Python 使用标准库 `ast`。
- 追踪部分常见浏览器、消息、请求与存储输入，经标识符赋值、字符串组合和未知函数参数传播，到 HTML、导航、动态执行等位置。
- Python 另覆盖部分 SQL 语句构造、`shell=True` / Shell API、文件路径、HTTP 客户端、反序列化与模板接口。
- 赋值为常量会清除该变量的已有传播记录；函数参数遮蔽外层同名变量；条件分支保守合并。循环只分析有限遍次。
- SQL 仅检查语句参数，不把参数绑定值本身当作 SQL 拼接；`shell=False` 的参数数组不按 Shell 字符串执行判定。
- 已知 HTML 净化调用降低 HTML 数据流优先级，仍保留净化器 / 输出位置的规则复核线索。它不证明净化配置正确，更不代表 URL 上下文安全。
- 输出来源行、部分赋值步骤与最终调用位置。单文件最多 1000 条 AST 证据；深度 / 节点预算、解析错误和依赖缺失会记录说明。

## 当前不完整的部分

不做完整跨文件 / 跨函数分析、导入别名解析、动态属性解析、对象字段敏感分析、精确控制流与运行时类型推断。不充分建模全部闭包、异步时序、框架生命周期与自定义包装器。根据语法和常见名字识别输入 / 函数，自定义同名对象可能造成误报。未知函数的参数传播也可能过于保守。

Vue / Svelte / Astro / MDX 等文件当前只进行规则搜索，未提取脚本区做 AST。Python 新语法的支持取决于所用 Python 版本；解析失败不会被视为安全。

## 凭据遮蔽

检查部分令牌前缀、`api_key` / `password` 等敏感变量赋值的字符串，跳过部分显式占位符。识别的值在显示、导出和发送给 AI 时替换为 `[REDACTED]`。不验证令牌是否有效，不自动撤销或轮换，也不能保证识别所有秘密。支持文件范围不包括 `.env`、二进制或压缩生成文件。

## 参考规范

- [Tree-sitter Python 绑定](https://github.com/tree-sitter/py-tree-sitter)
- [GitHub 仓库 ZIP archive API](https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-zip)
- [SARIF 2.1.0 规范](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)

`examples/demo-project/` 是合成测试项目，不代表真实漏洞报告或模型能力评测。
