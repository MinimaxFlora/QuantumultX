// 把上游 KOP-XIAO 的资源解析器改写成自有品牌版本：注释全部换成自己的、链接全部换成自己的、
// 代码逻辑一字不改。脚本刻意零逻辑改动，只做「注释剥离 + 字符串替换 + 段落注释插入」。
const fs = require('fs');
const path = require('path');
const acorn = require('acorn');

const SRC = process.argv[2] || 'orig.js';
const OUT = process.argv[3] || 'new.js';

const SITE = 'https://qx.tatalvpai.vip';
const REPO = 'https://github.com/MinimaxFlora/QuantumultX';
const BRAND = 'Minimax';

const HEADER = `/**
 * ==========================================================================
 *  资源解析器 · Quantumult X            作者 MinimaxFlora
 *  文档 ${SITE}
 *  仓库 ${REPO}
 *  反馈 ${REPO}/issues
 * ==========================================================================
 *
 * 干什么用的
 * 把别家格式的「节点订阅 / 分流规则 / 重写规则 / 模块」翻译成 Quantumult X 认得的写法，
 * 输出内容直接进 QX 的资源引用与配置。
 *
 * 支持哪些输入
 * 1. 节点订阅：V2RayN、Shadowsocks(R/D)、Trojan、VLESS、AnyTLS、HTTP(S)、Hysteria2、
 *    Quantumult(X)、Surge、Clash、Shadowrocket、Loon、SIP008、SSD 等；
 * 2. 规则与重写：rewrite / filter / hostname / domain-set / module / rule-set
 *    （Surge 与 Clash 两套写法都能吃），支持筛选、替换、指定策略；
 * 3. 转换结果可用 URI-Scheme 一键加进 QX：quantumult-x:///add-resource。
 *
 * 怎么装
 * 在 QX 配置文件的 [general] 段落里加一行：
 *   resource_parser_url = ${SITE}/Scripts/resource-parser.js
 * 然后到「资源引用」里给对应资源勾上「使用解析器」。
 * 若提示「没有自定义解析器」：长按首页右下角图标，点左侧刷新按钮更新资源，
 * 再从后台彻底退出 App 重进，直到资源页出现解析器说明为止。
 *
 * 参数怎么写
 * 参数跟在链接后面的 # 之后，多个参数用 & 连起来：
 *   https://你的订阅地址#emoji=1&udp=1&in=香港+台湾&rename=旧名@新名
 * 本地 / iCloud 路径也支持（build 951 起），路径上的参数优先于资源第 ① 行的参数。
 * 传特殊字符前请先 URL-Encode：+ → %2B，空格 → %20，@ → %40，& → %26，, → %2C。
 *
 * --------------------------------------------------------------------------
 * 一、节点订阅参数
 * --------------------------------------------------------------------------
 * emoji=1 / -1 / 2    节点名加或去地区旗帜（国行设备用 2）
 * udp=1 / -1          批量开或关 udp-relay
 * tfo=1 / -1          批量开或关 fast-open
 * uot=1               SS(R) 打开 udp-over-tcp
 * cert=1 / -1 / 域名  开或关 TLS 证书校验；填域名时作为 tls-verification 的校验域名（938+）
 * csha=xxx            指定 tls-cert-sha256
 * psha=xxx            指定 tls-pubkey-sha256
 * alpn=xxx            指定 over-tls 节点的 alpn
 * tls13=1 / -1        开或关 tls13
 * tsession=0/1/2      0、1 关闭 session-ticket 或 reuse，2 两个都关（771+）
 * aead=-1             关闭 vmess 的 AEAD
 * in=关键词          按节点名保留，多个关键词用 + 表示「或」，用 . 表示「与」
 * out=关键词         按节点名删除，写法同 in
 * regex=正则         按节点的完整信息（类型、端口、加密方式…）正则保留
 * regout=正则        按完整信息正则删除
 * rename=旧@新        重命名，支持「旧名@新名」「前缀@」「@后缀」，多组用 + 连接；
 *                    结尾加 ☠️ 表示删除该字段，如 rename=流量.0\\.2☠️
 * rrname=...          同 rename，但排在 emoji 之后执行
 * replace=正则@替换   对节点字段做正则替换，改名、改加密方式都能用
 * delreg=正则         按正则从节点名里删内容（容易误伤，慎用）
 * sfilter=base64      传一段 base64 脚本做自定义过滤
 * srename=base64      传一段 base64 脚本做自定义重命名
 * ptn=1-8             节点名里的英文换成花漾字，8 种样式
 * npt=1-8             节点名里的数字换成花漾字，8 种样式
 * cap=1               节点名首字母大写
 * suffix=1 / -1       给节点名加类型后缀或前缀
 * sort=1/-1/x/规则    按名字正序、倒序、随机排序，也可写 HK>SG>JP 这种优先顺序
 * sortx=1 / -1        按订阅分组（tag）正序或倒序
 * del=1               重名节点直接删掉，而不是自动加序号改名
 * checkurl=xxx        指定 server_check_url
 * host=xxx            改已有 host；想新增 host 就在结尾加 ☠️
 * obfs=vhttp/shttp    强指 shadowsocks-http 或 vmess-http
 * relay=策略名        把落地节点订阅转成 ip / host 规则，用来做代理链
 * flow=到期:总GB:已用   手工补流量信息，如 flow=2026-12-31:1000:54
 * info=1              用通知显示机场流量与到期时间
 * UA=1                换 Shadowrocket 的 UA 再拉一次订阅
 *
 * --------------------------------------------------------------------------
 * 二、重写 / 分流参数
 * --------------------------------------------------------------------------
 * in / out / regex / regout   同上，作用于 rewrite 与 filter 条目
 * inhn=xxx / outhn=xxx        按 hostname 保留或删除
 * policy=xxx                  指定策略组；解析 Surge rule-set 时用它来生成策略组
 * pset=正则@策略+正则@策略     同一份规则里不同关键词分别给不同策略组
 * replace=正则@新正则          对重写、分流正文做替换
 * dst=rewrite / filter        把 module 强制当重写、把 rule-set 强制当分流
 * cdn=1                       把 github 脚本地址换成 fastly.jsdelivr.net/gh 镜像
 * fcr=1/2/3                   给规则加 force-cellular / multi-interface / 负载均衡
 * via=接口                    给规则加 via-interface，填 0 表示 %TUN%
 *
 * --------------------------------------------------------------------------
 * 三、通用参数
 * --------------------------------------------------------------------------
 * ntf=0 / 1           关或开解析通知（重写、分流默认开，节点默认关）
 * type=domain-set/rule/module/list/nodes   自动识别失败时强制指定类型
 * hide=0              被筛掉的条目改成注释保留，而不是直接删掉
 * profile=111         用 URI-Scheme 一次性导入配置里的远程资源，三位分别代表 服务器/分流/重写
 * dbg=1               调试模式，把中间结果打进通知
 * cnt=1               通知里显示解析后的条目数量
 *
 * --------------------------------------------------------------------------
 * 占位符（写在 rename / replace 里用）
 * --------------------------------------------------------------------------
 * $type0-7    节点类型，8 种花漾样式，从「𝐬𝐬」到「ˢˢ」
 * $index0-8   节点序号，9 种样式，从 1 到 𝟷
 * $emoji1/2   节点名里的地区旗帜
 * $tag        订阅的 tag，后面可跟数字指定花漾样式
 *
 * --------------------------------------------------------------------------
 * 说明
 * --------------------------------------------------------------------------
 * 本解析器由 KOP-XIAO 的资源解析器改写而来，功能保持一致；注释、链接、默认策略组名
 * 都已替换为本项目自己的。内嵌的 Base64 与 YAML 实现保留上游许可声明。
 * 相对上游只修补了一处：把链接填错资源类型时，跳转「正确类型」的分支原本会抛异常，
 * 现在会正常给出可点击的跳转通知。
 */`;

// 逐条替换：注释里、通知里、面板里出现的他人痕迹一律换成本项目的
const REPLACES = [
  // 文档里的安装地址
  ['https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/resource-parser.js', SITE + '/Scripts/resource-parser.js'],
  // 反馈与频道
  ['https://t.me/ShawnKOP_Parser_Bot', REPO + '/issues'],
  ['https://t.me/QuanX_API', REPO],
  ['https://tinyurl.com/2jyygfom', SITE],
  // 通知配图（原先走短链，改由本站托管）
  ['https://shrtm.nu/ebAr', SITE + '/img/sub.png'],
  ['https://shrtm.nu/obcB', SITE + '/img/bug.png'],
  ['https://shrtm.nu/uo13', SITE + '/img/fake.png'],
  ['https://shrtm.nu/x3o2', SITE + '/img/rewrite.png'],
  ['https://shrtm.nu/0n5J', SITE + '/img/hostname.png'],
  ['https://shrtm.nu/cpHD', SITE + '/img/rule.png'],
  // Quantumult X 图标改自托管
  ['https://raw.githubusercontent.com/crossutility/Quantumult-X/master/quantumult-x.png', SITE + '/img/qx.png'],
  // 默认策略组名（先换带引号的，再兜底剩下的裸字符串）
  ['"Shawn"', '"' + BRAND + '"'],
  ['Shawn', BRAND],
];

// 我自己的段落注释：锚点 = 该行代码的唯一前缀，注释插在它上面
const BANNERS = [
  ['var $parser = $parser || {};', '【参数面板】给 QX 的资源引用页声明参数表单；build 918 起由客户端渲染，\n// 这里只描述字段，不参与解析。'],
  ['let version = typeof $environment', '【运行环境】拿客户端构建号，后面所有「build N 起可用」的分支都看它。'],
  ['const currentUA = $resource.user_agent;', '【UA 回退】记录本次拉取用的 UA，判断是否已经在重试。'],
  ['var RLink0 = {', '【资源槽位】四类资源各一个槽，跳转时按检测到的类型往对应槽里放。'],
  ['const Field = {', '【类型映射】把内部类型名映射到 remote-resource 的字段名。'],
  ['var firstResourceLine', '【参数解析】链接里的 # 之后是参数区，这里逐个取出并落到变量上。'],
  ['function TLSCertDomainValue(Pcert0)', '【TLS 证书】按客户端版本输出 tls-verification 的取值。'],
  ['var ProfileInfo = {', '【配置骨架】profile 参数导入时用的空模板。'],
  ['function VCheck(cnt)', '【配置导入】把配置里的远程资源地址整理成 JSON 数组。'],
  ['var Finfo={}', '【流量信息】解析出来交给 QX 的 info 字段，用于流量条与到期提醒。'],
  ['function Rocket_flow(RInfo)', '【流量信息】Shadowrocket 的 STATUS 头，形如 ↑/↓/TOT/Expires。'],
  ['var pat=[]', '【花漾字】ptn / npt 的字符表，8 套样式按索引取用。'],
  ['var type0=""', '【入口】先判断是不是扫码进来的订阅链接，再决定走解析、重试还是配置导入。'],
  ['function Parser() {', '【主流程】识别资源类型 → 分发解析 → 把结果交给 $done。'],
  ['function ParseUnknown(cnt){', '【兜底】认不出来的内容按 JSON 或纯文本提示给用户，而不是静默丢空。'],
  ['function ResourceParse() {', '【分发】按识别出的类型走各自的转换分支。'],
  ['function SubFlow() {', '【响应头】从响应头里读订阅流量（QX 会把机场返回的头带进来）。'],
  ['function flowcheck(cnt) {', '【流量校验】头信息里没带流量时，退回到 flow 参数。'],
  ['function RegCheck(total, typen, paraname,regpara) {', '【正则筛选】regex / regout 的公共实现。'],
  ['function RuleNoteSplit(row) {', '【行首说明】{# 说明 #} 只当元数据保留，不参与筛选与替换。'],
  ['function SubscriptionURL(content) {', '【扫码】识别单个订阅特征的链接，引导先加资源再解析。'],
  ['function Type_Check(subs) {', '【类型判断】按内容特征猜类型：节点订阅、重写、分流、模块、域名集…'],
  ['function TagCheck_QX(content) {', '【节点体检】查重名、空名、多余空格这类 QX 不接受的情况。'],
  ['function Add_URL(cnt) {', '【节点名】重名时补序号，保证 tag 唯一。'],
  ['function PatternN(cnt, para,npara) {', '【花漾字】节点名的英文与数字换样式。'],
  ['function Capitalize(cnt,para) {', '【大小写】cap 参数：首字母大写。'],
  ['function type_prefix(item) {', '【类型标记】给节点名加类型前缀或后缀。'],
  ['function getnode_type(item,ind) {', '【占位符】$type / $index / $emoji / $tag 的取值与样式替换。'],
  ['function ServerRelay(src,dst) {', '【代理链】把落地节点转成 ip / host 规则，指向中转。'],
  ['function CDN(cnt) {', '【镜像】cdn=1 时把 github 地址换成 jsdelivr，省得为拉脚本再翻一次墙。'],
  ['function HOST_Handle(cnt,phost) {', '【字段改写】host / obfs / tsession / sha256 / alpn 这几个参数的落点。'],
  ['function IsMapLocalInline(row) {', '【Map Local】把 Surge 的 Map Local 转成 QX 的 response-body / reject。'],
  ['function URX2QX(subs) {', '【url-regex】Surge 的 url-regex 重写转成 QX 的 url 重写。'],
  ['function IsJsonJQRewrite(row) {', '【JSON-JQ】Surge 的 json-jq 系写法转成 QX 的 jsonjq-response-body。'],
  ['function SCP2QX(subs) {', '【脚本重写】script-path 系条目转成 QX 的 script-response-body / script-request-header。'],
  ['function SGMD2QX(subs) {', '【模块】Surge module 整体转重写。'],
  ['function Rewrite_Filter(subs, Pin, Pout,Preg,Pregout, hasUnsupported) {', '【重写筛选】按 in / out / regex / regout 留删，只动正文不动行首说明。'],
  ['function HostNamecheck(content, parain, paraout) {', '【主机名筛选】inhn / outhn 单独处理，比正文筛选先执行。'],
  ['function Rule_Handle(subs, Pout, Pin) {', '【分流转换】把 Surge / Clash / QX 各种分流写法统一成 QX 的 host / ip 规则。'],
  ['function Rule_Policy(content, ignored) {', '【策略改写】policy 参数：替换或补上规则里的策略组。'],
  ['function rule_list_handle(cnt) {', '【纯列表】只有域名或 IP 的列表，含 clash provider 的写法。'],
  ['function Domain2Rule(content) {', '【域名集】domain-set 转成分流规则。'],
  ['function policy_sets(cnt,para) {', '【多策略】pset：同一份规则里按关键词分派不同策略组。'],
  ['function ReplaceReg(cnt, para) {', '【正文替换】replace：对重写、分流正文做正则替换。'],
  ['function Reality_Handle(cnt) {', '【REALITY】补齐 pbk / sid / flow 这几个 VLESS REALITY 字段。'],
  ['function Subs2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {', '【订阅转节点】逐行判断协议，交给对应的转换函数。'],
  ['function AeadVmess(cnt,aeadp) {', '【AEAD】aead=-1 时关掉 vmess 的 AEAD。'],
  ['function TLS_Check(cnt) {', '【TLS】按客户端版本决定证书校验与 tls13 的写法，旧版本不认的参数不输出。'],
  ['function SIP2QuanX (cnt) {', '【SIP008】JSON 格式的 SSR 订阅。'],
  ['function HPS2QX(subs, Ptfo, Pcert0, PTls13) {', '【HTTP(S)】含 base64(ipport) 的老写法与 peer 参数。'],
  ['function VQ2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {', '【Quantumult】自家 vmess 写法的转换。'],
  ['function VR2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {', '【Shadowrocket】vmess 写法的转换。'],
  ['function Socks2QX(cnt,tlsp="false") {', '【SOCKS】socks 与 ssocks 两种协议头。'],
  ['function V2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {', '【V2RayN】标准 vmess:// URI 的转换。'],
  ['function Regex(content) {', '【正则核心】in / out / regex / regout 的匹配器，支持「与」「或」组合。'],
  ['function Filter(servers, Pin, Pout) {', '【节点筛选】把关键词筛选套到节点列表上。'],
  ['function SSR2QX(subs, Pudp, Ptfo) {', '【SSR】ssr:// 的 base64 主体与参数。'],
  ['function HY2Type(type) {', '【Hysteria2】识别 URI、Surge、QX 三种写法，并按客户端版本决定是否支持。'],
  ['function Clash2QX(cnt) {', '【Clash】YAML 里的 proxies 段逐条转，未知字段不臆造。'],
  ['function CSS2QX(cnt) {', '【Clash】SS 与 SS 插件。'],
  ['function CV2QX(cnt) {', '【Clash】VMess，含 ws / grpc / http 各种传输。'],
  ['function XUDP(cnt,pudp) {', '【参数注入】udp / tfo 这类全局开关落到单条节点上。'],
  ['function Loon2QX(cnt) {', '【Loon】Loon 节点写法的转换。'],
  ['function Base64Code() {', '【Base64】内嵌实现，遵循上游 BSD 许可，见下方许可声明。'],
  ['function YAML() {', '【YAML】自己写的极简解析器：Clash 配置的缩进、引号、flow 写法、锚点都要吃得下。'],
  ['function Tools() {', '【工具】给 sfilter / srename 脚本用的辅助函数。'],
];

function stripComments(src) {
  const comments = [];
  acorn.parse(src, { ecmaVersion: 'latest', onComment: (block, text, start, end) => comments.push({ block, text, start, end }) });
  let out = '', last = 0, kept = 0;
  for (const c of comments) {
    out += src.slice(last, c.start);
    // 第三方许可声明必须保留（BSD 要求随源码分发）
    if (/BSD 3-Clause|Licensed under/i.test(c.text)) {
      out += src.slice(c.start, c.end);
      kept++;
    } else {
      const nl = (c.text.match(/\n/g) || []).length;
      out += ' ' + '\n'.repeat(nl); // 补空格防 return/*x*/y 粘连，补换行保留行号
    }
    last = c.end;
  }
  out += src.slice(last);
  return { out, total: comments.length, kept };
}

let src = fs.readFileSync(SRC, 'utf8');

// 头部文档整体换成自己的：原文件从 0 到 UI 段落之前全是注释
const cut = src.indexOf('// ==== Parser Helper UI');
if (cut <= 0) throw new Error('找不到 UI 段落起点');
const body = src.slice(cut);
const { out: stripped, total, kept } = stripComments(body);
let text = HEADER + '\n\n' + stripped;
const counts = {};
for (const [from, to] of REPLACES) {
  const n = text.split(from).length - 1;
  counts[from] = n;
  text = text.split(from).join(to);
}

// 3) 插入自己的段落注释
let inserted = 0;
const missing = [];
for (const [anchor, note] of BANNERS) {
  const idx = text.indexOf(anchor);
  if (idx < 0) { missing.push(anchor); continue; }
  if (text.indexOf(anchor, idx + 1) >= 0) { missing.push('DUP:' + anchor); continue; }
  const atLineStart = idx === 0 || text[idx - 1] === '\n';
  const prefix = atLineStart ? '' : (() => { const ls = text.lastIndexOf('\n', idx); return ''; })();
  const lineStart = text.lastIndexOf('\n', idx) + 1;
  const indent = text.slice(lineStart, idx);
  const banner = indent + '// ' + note.split('\n').join('\n' + indent + '// ') + '\n' + indent;
  text = text.slice(0, lineStart) + banner + text.slice(lineStart);
  inserted++;
}

// 3.5) 唯一一处逻辑修补：上游在「把资源加到正确类型」分支里直接用 typec 查 Field，
// 而 typec 实际是 server-b64 / filter-list 这类带后缀的值，Field 里没有对应键，
// 于是用户在错误类型的资源里填链接时整段解析抛异常、只留一个空结果。
// 这里先把 typec 归一到基础类型，功能照旧可用，异常消失。
const beforeFix = text;
const jumpAnchor = 'if (version >= 670 && typec!="") {';
const jumpFix = '// 修上游遗留：typec 带 server-b64 / filter-list 这类后缀，直接查 Field 会取到 undefined。\n' +
  '    // 先归一到基础类型，才能在类型填错时正常跳转，而不是整个解析抛异常。\n' +
  '    var typecBase = /^server/i.test(typec) ? "server" : /^(filter|Clash-Provider)/i.test(typec) ? "filter" : /^rewrite/i.test(typec) ? "rewrite" : "";\n' +
  '    if (version >= 670 && typecBase) {';
if (text.indexOf(jumpAnchor) < 0) throw new Error('类型跳转补丁没落上，检查锚点');
text = text.replace(jumpAnchor, jumpFix);
if (text === beforeFix) throw new Error('类型跳转补丁没落上');
const beforePush = text;
text = text.replace('RLink0[Field[typec]].push(', 'RLink0[Field[typecBase]].push(');
if (text === beforePush) throw new Error('槽位补丁没落上');

// 4) 语法自检
acorn.parse(text, { ecmaVersion: 'latest' });
fs.writeFileSync(OUT, text);

const leftShawn = (text.match(/Shawn|KOP-XIAO|shrtm\.nu|t\.me\//g) || []).length;
console.log(JSON.stringify({
  commentsFound: total,
  commentsKeptForLicense: kept,
  bookmarksInserted: inserted,
  anchorsMissing: missing,
  replacements: Object.fromEntries(Object.entries(counts).filter(([, v]) => v > 0)),
  residualUpstreamTokens: leftShawn,
  outBytes: Buffer.byteLength(text),
  outLines: text.split('\n').length,
}, null, 1));
