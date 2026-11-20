# Quantumult X 资源解析器

把别家格式的节点订阅、分流规则、重写规则、Surge 模块翻译成 Quantumult X 的写法。装一次，之后所有资源引用都能用。

站点：<https://qx.tatalvpai.vip>

## 安装

在 Quantumult X 配置文件的 `[general]` 段落里加一行：

```ini
resource_parser_url = https://qx.tatalvpai.vip/Scripts/resource-parser.js
```

然后进「资源引用」，编辑要用的节点订阅 / 分流 / 重写，把「使用解析器」打开，下拉刷新。

若提示「没有自定义解析器」：长按首页右下角图标，点左侧刷新按钮更新资源，再从后台彻底退出 App 重进，直到资源页出现解析器说明。

## 带参数使用

参数写在订阅地址的 `#` 之后，多个用 `&` 连接：

```
https://你的订阅地址#emoji=1&udp=1&in=香港+台湾&rename=旧名@新名
```

特殊字符先 URL-Encode：`+` → `%2B`，空格 → `%20`，`@` → `%40`，`&` → `%26`，`,` → `%2C`。

全部参数见站点上的「参数速查」，也可以直接读 `Scripts/resource-parser.js` 顶部的注释。

## 支持的格式

- 节点：V2RayN、Shadowsocks / SSR / ShadowsocksD / SSD、VMess、VLESS（含 REALITY）、Trojan、Hysteria2、AnyTLS、HTTP(S)、SOCKS、Quantumult(X)、Surge、Clash、Shadowrocket、Loon、SIP008
- 规则：QX filter、Surge rule-set、Clash rule-provider、domain-set、JSON 规则集
- 重写：QX rewrite、Surge module、url-regex、Map Local、json-jq、Loon plugin

## 目录

```
Scripts/resource-parser.js   解析器本体，也是 QX 直接引用的文件
index.html                   站点首页（参数速查、常见问题）
img/                         通知配图与图标
Scripts/_headers 等          Pages 部署配置（_headers、_redirects、404.html、robots.txt）
```

`index.html`、`img/` 与 Pages 配置文件是站点源文件，部署方式是 Cloudflare Pages 直接上传（`wrangler pages deploy .`）。

## 说明

本解析器由 [KOP-XIAO](https://github.com/KOP-XIAO/QuantumultX) 的资源解析器改写而来，功能保持一致；注释、链接、默认策略组名（`Minimax`）均已替换为本项目自己的，代码逻辑未做改动。文件内嵌的 Base64 与 YAML 实现保留上游许可声明。

解析结果不对时请到 [Issues](https://github.com/MinimaxFlora/QuantumultX/issues) 反馈，附上订阅类型、链接参数和通知里的报错内容；不要把带 token 的完整订阅地址贴出来。
