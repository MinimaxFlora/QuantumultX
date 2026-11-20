# tools

改这份解析器不走手工编辑，全部用脚本重建，保证可复现、可比对。

## 准备

```bash
npm --prefix tools install    # 只依赖 acorn（解析注释用）
```

## 从上游重建

```bash
# 1. 取上游当前版本
curl -sL -o /tmp/upstream.js https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/resource-parser.js

# 2. 重建（注释剥离 → 换成本项目注释 → 链接与默认策略名替换 → 补一处类型跳转修补）
node tools/rebrand.js /tmp/upstream.js Scripts/resource-parser.js

# 3. 语法与等价性
node --check Scripts/resource-parser.js
node tools/gen-fixtures.js            # 生成测试语料到 tools/fixtures/
node tools/verify.js                  # 需先把上游存成 tools/orig.js、本项目版本存成 tools/new.js
```

`rebrand.js` 只做四件事，不碰任何解析逻辑：剥离上游注释（保留 BSD 许可声明）、按锚点插入本项目注释、
替换安装地址/反馈链接/通知配图/默认策略组名、修补「把链接填进错误资源类型」分支的 `Field[typec]` 异常。

## 等价性怎么验

`tools/verify.js` 用 `vm` 造一个 Quantumult X 运行时（`$resource` / `$environment` / `$done` / `$notify`），
把同一批语料分别喂给上游版与本项目版：

- A 口径（类型填对，16 份语料 × 6 个构建号 × 9 组参数）：`$done` 内容与通知必须逐字一致。
- B 口径（类型填错）：只要求本项目版不抛异常，并给出跳转通知。

品牌相关字符串在比对前统一归一化，所以任何非预期的逻辑差异都会直接暴露成 mismatch。
