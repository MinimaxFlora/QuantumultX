/**
 * ==========================================================================
 *  资源解析器 · Quantumult X            作者 MinimaxFlora
 *  文档 https://qx.tatalvpai.vip
 *  仓库 https://github.com/MinimaxFlora/QuantumultX
 *  反馈 https://github.com/MinimaxFlora/QuantumultX/issues
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
 *   resource_parser_url = https://qx.tatalvpai.vip/Scripts/resource-parser.js
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
 *                    结尾加 ☠️ 表示删除该字段，如 rename=流量.0\.2☠️
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
 */

 
// 【参数面板】给 QX 的资源引用页声明参数表单；build 918 起由客户端渲染，
// // 这里只描述字段，不参与解析。
var $parser = $parser || {};

 
$parser.hashSchema = function () {
   
  function _emojiOptions() {
    return [
      { label: "添加",     value: "1"  },
      { label: "国行设备", value: "2"  },
      { label: "删除",     value: "-1" }
    ];
  }
  function _ptnOptions() {
    return [
      { label: "原样",         value: ""  },
      { label: "🅰 字母方块",   value: "1" },
      { label: "🄰 字母方块（实）", value: "2" },
      { label: "𝐀 加粗",        value: "3" },
      { label: "𝗮 加粗小写",    value: "4" },
      { label: "𝔸 双线",        value: "5" },
      { label: "𝕒 双线小写",    value: "6" },
      { label: "ᵃ 上标",        value: "7" },
      { label: "ᴬ 大写上标",    value: "8" }
    ];
  }
  function _nptOptions() {
    return [
      { label: "原样",         value: ""  },
      { label: "①",            value: "1" },
      { label: "❶",            value: "2" },
      { label: "⓵",            value: "3" },
      { label: "𝟙",            value: "4" },
      { label: "¹",            value: "5" },
      { label: "₁",            value: "6" },
      { label: "𝟏",            value: "7" },
      { label: "𝟷",            value: "8" }
    ];
  }

  if ($resource.type == "server") {  
    return {
    version: 1,
    sections: [
      { type: "group",
        title: "✈️ 订阅获取",
        items: [
          { type: "switch", key: "UA", label: "User-Agent 替换",
            onValue: "1", offValue: "" ,
            description: "开启该选项后，将会尝试使用 Shadowrocket 的 User-Agent 重新获取订阅内容"}
          ]
      },
      {
        type: "group",
        title: "🎲 筛选&排序",
        items: [
          { type: "tags",   key: "in",     label: "保留（in）",
            description: "按节点名关键字保留。每行一个关键字表示\"或\"；同行用 . 分隔表示\"与\"。例：另起一行填 香港、台湾 表示含其一即可；同一行填 香港.IPLC 表示同时含香港和 IPLC。",
            placeholder: "如：香港 / 香港.IPLC" },
          { type: "tags",   key: "out",    label: "删除（out）",
            description: "按节点名关键字删除。每行一个关键字表示\"或\"；同行用 . 分隔表示\"与\"。",
            placeholder: "如：BGP / BGP.试用" },
          { type: "text",   key: "regex",  label: "正则保留（regex）",
            description: "对节点完整信息正则匹配以保留节点", placeholder: "iplc" },
          { type: "text",   key: "regout", label: "正则删除（regout）",
            description: "对节点完整信息正则匹配以删除节点", placeholder: "" },
          { type: "text",   key: "sort", label: "节点排序（sort）",
            description: "对节点进行排序，参数是1(正序)/-1（逆序）/x（随机排序）/自定义规则（用>或者<连接）", placeholder: "🇭🇰>🇯🇵>🇺🇸" }
        ]
      },
      {
        type: "group",
        title: "⛰️ 参数调整",
        items: [
          { type: "select", key: "emoji", label: "Emoji 旗帜（🇨🇳🇭🇰🇺🇸...）",
            description: "添加/删除节点名地区旗帜", options: _emojiOptions() },
          { type: "text",   key: "replace", label: "正则替换节点信息（replace）",
            description: "替换节点信息（⚠️ 可匹配所有内容 ⚠️），regex1@str1+regex2@str2", placeholder: "" },
          { type: "switch", key: "udp",   label: "UDP Relay",
            onValue: "1", offValue: "-1" },
          { type: "switch", key: "tfo",   label: "Fast Open",
            onValue: "1", offValue: "-1" },
          { type: "switch", key: "cert",  label: "TLS 证书验证",
            description: "默认关闭", onValue: "1", offValue: "-1" },
          { type: "switch", key: "uot",   label: "UDP over TCP（仅 SS/SSR）",
            onValue: "1", offValue: "" },
          { type: "switch", key: "aead",  label: "VMess AEAD",
            description: "关闭 VMess AEAD", onValue: "", offValue: "-1" },
          { type: "text",   key: "alpn",  label: "ALPN",
            description: "over-tls 节点的 ALPN", placeholder: "h2" },
          { type: "text",   key: "host",  label: "Host",
            description: "修改已有 host；增加 host 请加 ☠️ 结尾",
            placeholder: "" },
          { type: "text",   key: "checkurl", label: "Check URL",
            description: "server_check_url 参数",
            placeholder: "http://...", keyboard: "url" }
        ]
      },
      {
        type: "group",
        title: "🎯 重命名",
        items: [
          { type: "text", key: "rename",  label: "节点重命名（Rename）",
            description: "格式：旧名@新名 / 前缀@ / @后缀；多组用 + 连接；删除字段用 ☠️ 结尾",
            placeholder: "香港@HK+@[1X]" },
          { type: "text", key: "rrname",  label: "节点重命名（emoji 保持在前）",
            description: "在 emoji 之后再次重命名", placeholder: "" },
          { type: "select", key: "ptn", label: "字母样式（ptn）",
            description: "将节点名英文替换成花式样式 🅰/🄰/𝐀/𝗮/𝔸/𝕒/ᵃ/ᴬ ",
            options: _ptnOptions() },
          { type: "select", key: "npt", label: "数字样式（npt）",
            description: "将节点名数字替换成花式样式 ①/❶/⓵/𝟙/¹/₁/𝟏/𝟷",
            options: _nptOptions() }
        ]
      },
      {
        type: "group",
        title: "🤖 其他参数",
        items: [
          { type: "select", key: "ntf",  label: "解析通知",
            options: [
              { label: "默认",          value: "" },
              { label: "关闭",          value: "0"},
              { label: "打开",          value: "1"}
            ] },
          { type: "switch", key: "info", label: "流量信息",
            onValue: "1", offValue: "", description: "通知的形式推送“订阅用量”以及“到期时间”等信息"},
          { type: "text",   key: "flow", label: "流量参数",
            description: "格式：到期时间:总流量GB:已用GB（如 2026-12-31:1000:54）",
            placeholder: "2026-12-31:1000:54" },
          { type: "select", key: "type", label: "强制类型",
            options: [
              { label: "自动",         value: ""           },
              { label: "Nodes",        value: "nodes"      },
              { label: "Rule",         value: "rule"       },
              { label: "Module",       value: "module"     },
              { label: "List",         value: "list"       },
              { label: "Domain Set",   value: "domain-set" }
            ] }
        ]
      }
    ]
  };
} else if ($resource.type == "filter") {  
  return {
    version: 1,
    sections: [
      {
        type: "group",
        title: "🔀 Filter 「分流」",
        description: "仅对 rewrite_remote / filter_remote 生效",
        items: [
          { type: "tags", key: "in",  label: "保留分流规则「in」",
            description: "按关键字保留 filter。每行一个关键字（多行之间为\"或\"关系）。",
            placeholder: "如：weibo" },
          { type: "tags", key: "out",  label: "禁用分流/重写「out」",
            description: "按关键字保留 filter。每行一个关键字（多行之间为\"或\"关系）。",
            placeholder: "如：weibo" },
          { type: "text", key: "policy", label: "单策略组指定「policy」",
            description: "rule-set 生成策略组的名字（默认 Minimax）",
            placeholder: "Minimax" },
          { type: "text", key: "pset",   label: "多策略组指定「pset」",
            description: "regex1@policy1+regex2@policy2" },
          { type: "text", key: "regex",   label: "正则保留「regex」",
            description: "正则匹配保留指定内容" },
          { type: "text", key: "regout",   label: "正则删除「regout」",
            description: "正则匹配删除指定内容" },
          { type: "text", key: "replace",   label: "正则替换「replace」",
            description: "regex@new_regex 正则替换指定内容" }
        ]
      },
      {
        type : "group",
        title: "🔗 代理链相关设置「Relay」",
        items : [
          { type: "text", key: "via",    label: "via-interface「规则订阅」",
             description: "0 : via-interface=%TUN%, 设置代理链时，规则分流需使用此参数，请在策略偏好将策略组指定为 落地策略组/节点\n" ,
             placeholder: "填写 0 即可" 
          },
          { type: "text",   key: "relay", label: "代理链 Relay「节点订阅」",
            description: "将（落地）节点的订阅转换为 ip/host 规则，指向 中转策略组/节点。\n ⚠️ 设置 代理链条Relay 时，请确保关闭改订阅首页的「策略偏好」设置 \n\n ⚠️ 以上两项不应该在同一条引用中同时设置 ⚠️" ,
            placeholder: "⚠️ 此处请填写你的 中转策略组/节点名" },
           
        ]
      },
      {
        type: "group",
        title: "🤖 其他参数",
        items: [
          { type: "select", key: "ntf",  label: "解析通知",
            options: [
              { label: "默认",          value: "" },
              { label: "关闭",          value: "0"},
              { label: "打开",          value: "1"}
            ] },
          { type: "select", key: "type", label: "强制类型",
            options: [
              { label: "自动",         value: ""           },
              { label: "Nodes",        value: "nodes"      },
              { label: "Rule",         value: "rule"       },
              { label: "Module",       value: "module"     },
              { label: "List",         value: "list"       },
              { label: "Domain Set",   value: "domain-set" }
            ] },
          { type: "switch", key: "cdn",  label: "GitHub CDN 加速",
            onValue: "1", offValue: "" },
          { type: "select", key: "dst", label: "转换目标「dst」",
            options: [
              { label: "默认（不转换）", value: ""        },
              { label: "Rewrite",        value: "rewrite" },
              { label: "Filter",         value: "filter"  }
            ] },
          { type: "select", key: "fcr",  label: "网络接口指定「fcr」",
            options: [
              { label: "默认",            value: ""  },
              { label: "强制蜂窝数据",    value: "1" },
              { label: "混合接口",        value: "2" },
              { label: "负载均衡",        value: "3" }
            ] , description:"强制指定 “强制蜂窝数据/混合接口/负载均衡 等”" }
        ]
      }
    ]
  };
} else {  
  return {
    version: 1,
    sections: [
      {
        type: "group",
        title: "🫆 Rewrite 「重写」",
        description: "仅对 rewrite_remote / filter_remote 生效",
        items: [
          { type: "tags", key: "in",  label: "保留分流/重写「in」",
            description: "按关键字保留 rewrite/filter。每行一个关键字（多行之间为\"或\"关系）。",
            placeholder: "如：weibo" },
          { type: "tags", key: "out",  label: "禁用分流/重写「out」",
            description: "按关键字保留 rewrite/filter。每行一个关键字（多行之间为\"或\"关系）。",
            placeholder: "如：weibo" },
          { type: "tags", key: "inhn",  label: "保留主机名「inhn」",
            description: "按关键字保留相关主机名hostname。每行一个关键字（多行之间为\"或\"关系）。",
            placeholder: "如：weibo" },
          { type: "tags", key: "outhn", label: "删除主机名「outhn」",
            description: "按关键字删除相关主机名hostname。每行一个关键字（多行之间为\"或\"关系）。",
            placeholder: "如：tb_price" },
          { type: "text", key: "regex",   label: "正则保留「regex」",
            description: "正则匹配保留指定内容" },
          { type: "text", key: "regout",   label: "正则删除「regout」",
            description: "正则匹配删除指定内容" },
          { type: "text", key: "replace",   label: "正则替换「replace」",
            description: "regex@new_regex 正则替换指定内容" }
        ]
      },
      {
        type: "group",
        title: "🤖 其他参数",
        items: [
          { type: "select", key: "ntf",  label: "解析通知",
            options: [
              { label: "默认",          value: "" },
              { label: "关闭",          value: "0"},
              { label: "打开",          value: "1"}
            ] },
          { type: "select", key: "type", label: "强制类型",
            options: [
              { label: "自动",         value: ""           },
              { label: "Nodes",        value: "nodes"      },
              { label: "Rule",         value: "rule"       },
              { label: "Module",       value: "module"     },
              { label: "List",         value: "list"       },
              { label: "Domain Set",   value: "domain-set" }
            ] },
          { type: "switch", key: "cdn",  label: "GitHub CDN 加速",
            onValue: "1", offValue: "" },
          { type: "select", key: "dst", label: "转换目标「dst」",
            options: [
              { label: "默认（不转换）", value: ""        },
              { label: "Rewrite",        value: "rewrite" },
              { label: "Filter",         value: "filter"  }
            ] }
        ]
      }
    ]
  };
}
};

 
$parser.hashToUI = function (hash) {
  if (!hash) return { version: 1, sections: [] };

  var schema = $parser.hashSchema();
  var allItems = {};
  schema.sections.forEach(function (g) {
    g.items.forEach(function (it) { allItems[it.key] = it; });
  });

  var pairs = hash.split("&");
  var values = {};
  var dynamicItems = [];

  pairs.forEach(function (p) {
    if (!p) return;
    var eq = p.indexOf("=");
    var k = eq === -1 ? p : p.substring(0, eq);
    var v = eq === -1 ? "" : p.substring(eq + 1);

    if (allItems[k]) {
      values[k] = v;
    } else {
      dynamicItems.push({
        type: "text",
        key: k,
        label: k,
        value: v
      });
    }
  });

  var sections = [];

  schema.sections.forEach(function (g) {
    var items = [];
    g.items.forEach(function (it) {
      if (!(it.key in values)) return;

      var clone = JSON.parse(JSON.stringify(it));
      var raw = values[it.key];

      if (it.type === "switch") {
        clone.value = (raw === it.onValue);
      } else if (it.type === "tags") {
        clone.value = raw.split("+").filter(Boolean);
      } else {
        clone.value = raw;
      }

      items.push(clone);
    });

    if (items.length) {
      sections.push({
        type: "group",
        title: g.title,
        items: items
      });
    }
  });

  if (dynamicItems.length) {
    sections.push({
      type: "group",
      title: "自定义参数",
      items: dynamicItems
    });
  }

  return {
    version: 1,
    sections: sections
  };
};


 
$parser.uiToHash = function (values) {
  var schema = $parser.hashSchema();
  var allItems = {};
  schema.sections.forEach(function (g) {
    g.items.forEach(function (it) { allItems[it.key] = it; });
  });

  var parts = [];

  Object.keys(values).forEach(function (k) {
    var v = values[k];
    var meta = allItems[k];
    var serialized;

    if (meta) {
      if (meta.type === "switch") {
        serialized = v ? meta.onValue : meta.offValue;
      } else if (meta.type === "tags") {
        serialized = (v || []).join("+");
      } else {
        serialized = String(v);
      }
    } else {
       
      serialized = String(v);
    }

    parts.push(k + "=" + serialized);
  });

  return parts.join("&");
};

 



 


 
// 【运行环境】拿客户端构建号，后面所有「build N 起可用」的分支都看它。
let version = typeof $environment != "undefined" ? Number($environment.version.split("build")[1]): 0  

const UA_Retry= "Shadowrocket/3218 CFNetwork/3860.600.12 Darwin/25.5.0 iPhone18,1"
// 【UA 回退】记录本次拉取用的 UA，判断是否已经在重试。
const currentUA = $resource.user_agent;
const inRetry = currentUA && currentUA.length > 0;

const result = {
       
       
      content: "",
       
  };

 
 



let [link0, content0, subinfo] = [$resource.link, $resource.content, $resource.info]

let Perror = 0  


const ADDRes = `quantumult-x:///add-resource?remote-resource=url-encoded-json`
// 【资源槽位】四类资源各一个槽，跳转时按检测到的类型往对应槽里放。
var RLink0 = {
  "filter_remote": [],
  "rewrite_remote": [],
  "server_remote": [],
}
// 【类型映射】把内部类型名映射到 remote-resource 的字段名。
const Field = {
  "filter" : "filter_remote",
  "rewrite": "rewrite_remote",
  "server" : "server_remote"
}  

const subtag = typeof $resource.tag != "undefined" ? $resource.tag : "";
 
content0 = content0.indexOf("DOCTYPE html") != -1 && link0.indexOf("github.com") != -1 && content0.split("\n").map(RuleNoteBody).join("\n").indexOf("DOCTYPE html") != -1 ? ToRaw(content0) : content0 ;
 
content0 = link0.indexOf("nsloon.com/openloon/import?plugin=") != -1 ? ToLink(link0) : content0 ;
 


 
// 【参数解析】链接里的 # 之后是参数区，这里逐个取出并落到变量上。
var firstResourceLine = content0.split("\n")[0].trim();
var para = /^https?:\/\//.test(link0) || (version >= 951 && link0.indexOf("#") != -1) ? link0 :
  (/^#[ \t]*[a-z][\w-]*=/i.test(firstResourceLine) ? firstResourceLine : "");
var para1 = para.slice(para.indexOf("#") + 1).replace(/\$type/g,"node_type_para_prefix").replace(/\$emoji/g,"node_emoji_flag_prefix").replace(/\$tag/g,"node_tag_prefix").replace(/\$index/g,"node_index_prefix")  
var mark0 = para.indexOf("#") != -1 ? true : false;  
var UARetry = mark0 && /(?:^|&)UA=1(?:&|$)/.test(para1) ? 1 : 0;
var Pinfo = mark0 && para1.indexOf("info=") != -1 ? para1.split("info=")[1].split("&")[0] : 0;
var ntf_flow = 0;
 
const Base64 = new Base64Code();
const escapeRegExp = str => str.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');  
var link1 = link0.split("#")[0]
const qxpng = "https://qx.tatalvpai.vip/img/qx.png"  
const subinfo_link = { "open-url": "https://github.com/MinimaxFlora/QuantumultX", "media-url": "https://qx.tatalvpai.vip/img/sub.png" };
const subinfo_link1 = { "open-url": link1, "media-url": "https://qx.tatalvpai.vip/img/fake.png" }  
const rwrite_link = { "open-url": link1, "media-url": "https://qx.tatalvpai.vip/img/rewrite.png" }  
const rwhost_link = { "open-url": link1, "media-url": "https://qx.tatalvpai.vip/img/hostname.png" }  
const rule_link = { "open-url": link1, "media-url": "https://qx.tatalvpai.vip/img/rule.png" }  
const nan_link = { "open-url": link1, "media-url": qxpng }  
const bug_link = { "open-url": "https://github.com/MinimaxFlora/QuantumultX/issues", "media-url": "https://qx.tatalvpai.vip/img/bug.png" }  
const sub_link = { "open-url": link1, "media-url": "https://qx.tatalvpai.vip/img/sub.png" }  
const update_link = {"open-url" : "https://apps.apple.com/us/app/quantumult-x/id1443988620", "media-url": qxpng}
const plink0 = {"open-url" : link0, "media-url": qxpng}  

if(version == 0) { $notify("⚠️ 请更新 Quantumult X 至最新商店版本\n","🚦 当前版本可能无法正常使用部分功能","\n👉 点击跳转商店链接更新",update_link) }



SubFlow()  


 
var Pin0 = mark0 && para1.indexOf("in=") != -1 ? (para1.split("in=")[1].split("&")[0].split("+")).map(decodeURIComponent) : null;
var Pout0 = mark0 && (para.indexOf("#out=") != -1 || para.indexOf("&out=") != -1)? ((para.indexOf("#out=")!=-1? para.split("#out="): para.split("&out="))[1].split("&")[0].split("+")).map(decodeURIComponent) : null;
var Psfilter = mark0 && para1.indexOf("sfilter=") != -1 ? Base64.decode(para1.split("sfilter=")[1].split("&")[0]) : null;  
var Preg = mark0 && para1.indexOf("regex=") != -1 ? decodeURIComponent(para1.split("regex=")[1].split("&")[0]).replace(/\，/g,",") : null;  
var Pregout = mark0 && para1.indexOf("regout=") != -1 ? decodeURIComponent(para1.split("regout=")[1].split("&")[0]).replace(/\，/g,",") : null;  
var Pregdel = mark0 && para1.indexOf("delreg=") != -1 ? decodeURIComponent(para1.split("delreg=")[1].split("&")[0]).replace(/\，/g,",") : null;  
var Phin0 = mark0 && para1.indexOf("inhn=") != -1 ? (para1.split("inhn=")[1].split("&")[0].split("+")).map(decodeURIComponent) : null;  
var Phout0 = mark0 && para1.indexOf("outhn=") != -1 ? (para1.split("outhn=")[1].split("&")[0].split("+")).map(decodeURIComponent) : null;  
var Preplace = mark0 && para1.indexOf("replace=") != -1 ? para1.split("replace=")[1].split("&")[0] : null;  
var Pemoji = mark0 && para1.indexOf("emoji=") != -1 ? para1.split("emoji=")[1].split("&")[0] : null;
var Pdbg = mark0 && para1.indexOf("dbg=") != -1 ? para1.split("dbg=")[1].split("&")[0] : null;
var Pudp0 = mark0 && para1.indexOf("udp=") != -1 ? para1.split("udp=")[1].split("&")[0] : 0;
var Ptfo0 = mark0 && para1.indexOf("tfo=") != -1 ? para1.split("tfo=")[1].split("&")[0] : 0;
 
var Prname = mark0 && /(^|\&)rename=/.test(para1) ? para1.split(/(^|\&)rename\=/)[2].split("&")[0].split("+") : null;
var Psrename = mark0 && para1.indexOf("srename=") != -1 ? Base64.decode(para1.split("srename=")[1].split("&")[0]) : null;  
var Prrname = mark0 && para1.indexOf("rrname=") != -1 ? para1.split("rrname=")[1].split("&")[0].split("+") : null;
var Psuffix = mark0 && para1.indexOf("suffix=") != -1 ? para1.split("suffix=")[1].split("&")[0] : 0;
var Ppolicy = mark0 && para1.indexOf("policy=") != -1 ? decodeURIComponent(para1.split("policy=")[1].split("&")[0]) : "Minimax";
var Ppolicyset = mark0 && para1.indexOf("pset=") != -1 ? decodeURIComponent(para1.split("pset=")[1].split("&")[0]) : "";
var PcertMatch = mark0 ? para1.match(/(?:^|\&)(?:cert|tls-verification)=([^&]*)/) : null;
var Pcert0 = PcertMatch ? PcertMatch[1] : 0;
var Psort0 = mark0 && para1.indexOf("sort=") != -1 ? para1.split("sort=")[1].split("&")[0] : 0;
var PsortX = mark0 && para1.indexOf("sortx=") != -1 ? para1.split("sortx=")[1].split("&")[0] : 0;
var PTls13 = mark0 && para1.indexOf("tls13=") != -1 ? para1.split("tls13=")[1].split("&")[0] : 0;
var Pntf0 = mark0 && para1.indexOf("ntf=") != -1 ? para1.split("ntf=")[1].split("&")[0] : 2;
var Phide = mark0 && para1.indexOf("hide=") != -1 ? para1.split("hide=")[1].split("&")[0] : 1;
var Pb64 = mark0 && para1.indexOf("b64=") != -1 ? para1.split("b64=")[1].split("&")[0] : 0;
var emojino = ["0️⃣", "1⃣️", "2⃣️", "3⃣️", "4⃣️", "5⃣️", "6⃣️", "7⃣️", "8⃣️", "9⃣️", "🔟"]
var pfi = mark0 &&Pin0 ? "in=" + Pin0.join(", ") + ",  " : ""
var pfo = mark0 &&Pout0 ? "out=" + Pout0.join(", ") : ""
var pfihn = mark0 &&Phin0 ? "inhn=" + Phin0.join(", ") + ",  " : ""
var pfohn = mark0 &&Phout0 ? "outhn=" + Phout0.join(", ") : ""
var Pcnt =  mark0 &&para1.indexOf("cnt=") != -1 ? para1.split("cnt=")[1].split("&")[0] : 0;
var Pcap = mark0 &&para1.indexOf("cap=") != -1 ? para1.split("cap=")[1].split("&")[0] : "";
var Pptn = mark0 &&para1.indexOf("ptn=") != -1 ? para1.split("ptn=")[1].split("&")[0] : "";  
var Pnptn = mark0 &&para1.indexOf("npt=") != -1 ? para1.split("npt=")[1].split("&")[0] : "";  
var Pcdn = mark0 &&para1.indexOf("cdn=") != -1 ? para1.split("cdn=")[1].split("&")[0] : "";
let [flow, exptime, errornode, total] = "";
var Pdel = mark0 && para1.indexOf("del=") != -1 ? para1.split("del=")[1].split("&")[0] : 0;  
var typeU = mark0 && para1.indexOf("type=") != -1 ? para1.split("type=")[1].split("&")[0] : "";
var Pfcr = mark0 && para1.indexOf("fcr=") != -1 ? para1.split("fcr=")[1].split("&")[0] : "";  
var Pvia = mark0 && para1.indexOf("via=") != -1 ? para1.split("via=")[1].split("&")[0] : "";  
var Paead = mark0 && para1.indexOf("aead=") != -1 ? para1.split("aead=")[1].split("&")[0] : "";  
var Phost = mark0 && ( para.indexOf("#host=") != -1 || para.indexOf("&host=") != -1) ? (para.indexOf("#host=")!=-1? para.split("#host="): para.split("&host="))[1].split("&")[0] : "";  
var Pcsha256 = mark0 && para1.indexOf("csha=") != -1 && version >= 646? para1.split("csha=")[1].split("&")[0] : "";  
var Ppsha256 = mark0 && para1.indexOf("psha=") != -1 && version >= 646? para1.split("psha=")[1].split("&")[0] : "";  
var typeQ = $resource.type? $resource.type:"unsupported"    
var PRelay =mark0 && para1.indexOf("relay=") != -1 ? decodeURIComponent(para1.split("relay=")[1].split("&")[0]) : "";  
var PUOT = mark0 && para1.indexOf("uot=") != -1 && version >= 665? para1.split("uot=")[1].split("&")[0] : "";  
var PcheckU = mark0 && para1.indexOf("checkurl=") != -1 ? decodeURIComponent(para1.split("checkurl=")[1].split("&")[0]) : "";  
typeQ = PRelay!=""? "server":typeQ
var typec=""  
var Pflow=mark0 && para1.indexOf("flow=") != -1 ? para1.split("flow=")[1].split("&")[0] : 0;  
var PProfile = mark0 && para1.indexOf("profile=") != -1 ? para1.split("profile=")[1].split("&")[0] : 0;  
var Palpn = mark0 && para1.indexOf("alpn=") != -1 && version >= 712? para1.split("alpn=")[1].split("&")[0] : "";  
var Pobfs = mark0 && para1.indexOf("obfs=") != -1 && version >= 770? para1.split("obfs=")[1].split("&")[0] : "";  
var Psession =  mark0 && para1.indexOf("tsession=") != -1 && version >= 771? para1.split("tsession=")[1].split("&")[0] : ""; 
 
var Pmix = version>=844? 1 : 0  
var Pjsonjq = version>=845? 0 : 1  

 
 
// 【TLS 证书】按客户端版本输出 tls-verification 的取值。
function TLSCertDomainValue(Pcert0) {
  var raw = Pcert0 === undefined || Pcert0 === null ? "" : String(Pcert0).trim();
  if (raw === "") return "";
  try { raw = decodeURIComponent(raw); } catch (e) {}
  raw = raw.trim();
  var low = raw.toLowerCase();
  if (low === "1" || low === "true") return "true";
  if (low === "-1" || low === "0" || low === "false") return "false";
  if (version >= 938 && /^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}$/.test(raw)) {
    return raw;
  }
  return "";
}

function TLSCertParam(Pcert0, fallback) {
  var cert = TLSCertDomainValue(Pcert0);
  var value = cert !== "" ? cert : fallback;
  return value === "" || value === undefined || value === null ? "" : "tls-verification=" + value;
}

var PNS=0  
var NSList=["当前订阅内，不支持以下节点 ↘️ \n"]  
var HY2Supported = Number.isInteger(version) && version >= 965
var HY2Skipped = Object.create(null)

var RegoutList= [] ; 
 
var ADDres = `quantumult-x:///add-resource?remote-resource=url-encoded-json`
var RLink = `{
  "server_remote": [
    sremoteposition
  ],
  "filter_remote": [
    fremoteposition
  ],
  "rewrite_remote": [
    rremoteposition
  ]
}`

// 【配置骨架】profile 参数导入时用的空模板。
var ProfileInfo = {
  "server":"",
  "filter":"",
  "rewrite":""
}

// 【配置导入】把配置里的远程资源地址整理成 JSON 数组。
function VCheck(cnt) {
  cnts=cnt.split("\n").filter(Boolean).map(item=>item.trim()).filter(item => /^http/.test(item)).map(item=>"\""+item+"\"")
  cnts=cnts.join(",\n")
   
  return  cnts
  }

function Profile_Handle() {
  let a = content0
  PProfile= PProfile==1? "001":PProfile
  PProfile= PProfile==8? "010": PProfile
  PProfile= PProfile==9? "011": PProfile
  srm = a.split("[server_remote]")[1] && String(PProfile)[0]=="1"? VCheck(a.split("[server_remote]")[1].split("[")[0]) : ""
  frm = a.split("[filter_remote]")[1] && String(PProfile)[1]=="1"? VCheck(a.split("[filter_remote]")[1].split("[")[0]) : ""
  rrm = a.split("[rewrite_remote]")[1] && String(PProfile)[2]=="1"? VCheck(a.split("[rewrite_remote]")[1].split("[")[0]) : ""
  RLink=RLink.replace("sremoteposition",srm).replace("fremoteposition",frm).replace("rremoteposition",rrm)
  ADDres=ADDres.replace("url-encoded-json",encodeURIComponent(RLink))
}

 
 
 
// 【流量信息】解析出来交给 QX 的 info 字段，用于流量条与到期提醒。
var Finfo={}
if (Pflow!=0) {
  Pflow = Pflow.split(":")
  var Bdate=Date.parse(new Date(Pflow[0]))/1000
  var Btotal=Pflow[1]? Pflow[1]*1024*1024*1024 : 0
  var Bused=Pflow[2]? Pflow[2]*1024*1024*1024 : 0
  var Bremain=Btotal !=0 ? Btotal-Bused : 1
  var BJson={bytes_used: Bused, bytes_remaining: Bremain, expire_date: Bdate}
   
  Finfo = BJson
}

 
 
 
// 【流量信息】Shadowrocket 的 STATUS 头，形如 ↑/↓/TOT/Expires。
function Rocket_flow(RInfo) {
  var Rinfo=RInfo.replace(/ /g, "").toLowerCase()
  var BJson={}
  try {
    var Pdate = Rinfo.split("expires:")[1].split(",")[0].replace(/[^\x00-\x7F]/g, '').trim() 
    var Ptotal = Number(Rinfo.split("tot:")[1].split("gb")[0])  
    var Pupload = Number(Rinfo.split("↑:")[1].split("gb")[0])  
    var Pdown = Number(Rinfo.split("↓:")[1].split("gb")[0])  
    var Bdate = Math.floor(Date.parse(Pdate)/1000)? Math.floor(Date.parse(Pdate)/1000): Math.floor(Date.parse("2046-10-10")/1000) 
    var Btotal=Ptotal? Ptotal*1024*1024*1024 : 0
    var Bused=Pupload? (Pupload+Pdown)*1024*1024*1024 : 0
    var Bremain=Btotal !=0 ? Btotal-Bused : 1
    BJson={bytes_used: Bused, bytes_remaining: Bremain, expire_date: Bdate}
    Finfo = BJson
  } catch (error) {
    console.log(error)
  }
}

 
// 【花漾字】ptn / npt 的字符表，8 套样式按索引取用。
var pat=[]
pat[0] = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","k","r","s","t","u","v","w","x","y","z"]
pat[1] = ["🅰","🅱","🅲","🅳","🅴","🅵","🅶","🅷","🅸","🅹","🅺","🅻","🅼","🅽","🅾","🅿","🅺","🆁","🆂","🆃","🆄","🆅","🆆","🆇","🆈","🆉"]
pat[2] = ["🄰","🄱","🄲","🄳","🄴","🄵","🄶","🄷","🄸","🄹","🄺","🄻","🄼","🄽","🄾","🄿","🄺","🅁","🅂","🅃","🅄","🅅","🅆","🅇","🅈","🅉"]
pat[3] = ["𝐀","𝐁","𝐂","𝐃","𝐄","𝐅","𝐆","𝐇","𝐈","𝐉","𝐊","𝐋","𝐌","𝐍","𝐎","𝐏","𝐊","𝐑","𝐒","𝐓","𝐔","𝐕","𝐖","𝐗","𝐘","𝐙"]
pat[4] = ["𝗮","𝗯","𝗰","𝗱","𝗲","𝗳","𝗴","𝗵","i","𝗷","𝗸","𝗹","𝗺","𝗻","𝗼","𝗽","𝗸","𝗿","𝘀","𝐭","𝘂","𝘃","𝘄","𝘅","𝘆","𝘇"]
pat[5] = ["𝔸","𝔹","ℂ","𝔻","𝔼","𝔽","𝔾","ℍ","𝕀","𝕁","𝕂","𝕃","𝕄","ℕ","𝕆","ℙ","𝕂","ℝ","𝕊","𝕋","𝕌","𝕍","𝕎","𝕏","𝕐","ℤ"]
pat[6] = ["𝕒","𝕓","𝕔","𝕕","𝕖","𝕗","𝕘","𝕙","𝕚","𝕛","𝕜","𝕝","𝕞","𝕟","𝕠","𝕡","𝕜","𝕣","𝕤","𝕥","𝕦","𝕧","𝕨","𝕩","𝕪","𝕫"]
pat[7] = ["ᵃ","ᵇ","ᶜ","ᵈ","ᵉ","ᶠ","ᵍ","ʰ","ⁱ","ʲ","ᵏ","ˡ","ᵐ","ⁿ","ᵒ","ᵖ","ᵒ⃒","ʳ","ˢ","ᵗ","ᵘ","ᵛ","ʷ","ˣ","ʸ","ᙆ"]
pat[8] = ["ᴬ","ᴮ","ᒼ","ᴰ","ᴱ","ᶠ","ᴳ","ᴴ","ᴵ","ᴶ","ᴷ","ᴸ","ᴹ","ᴺ","ᴼ","ᴾ","ᴼ̴","ᴿ","ˢ","ᵀ","ᵁ","ᵛ","ᵂ","ˣ","ʸ","ᙆ"]

 
var patn=[]
patn[0] = ["0","1","2","3","4","5","6","7","8","9"]
patn[1] = [ '⓪', '①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧', '⑨' ]
patn[2] = [ '⓪', '❶', '❷', '❸', '❹', '❺', '❻', '❼', '❽', '❾' ]
patn[3] = [ '⓪', '⓵', '⓶', '⓷', '⓸', '⓹', '⓺', '⓼', '⓻', '⓽' ]
patn[4] = [ '𝟘', '𝟙', '𝟚', '𝟛', '𝟜', '𝟝', '𝟞', '𝟟', '𝟠', '𝟡' ]
patn[5] = [ '⁰', '¹', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹' ]
patn[6] = [ '₀', '₁', '₂', '₃', '₄', '₅', '₆', '₇', '₈', '₉' ]
patn[7] = ["𝟎","𝟏","𝟐","𝟑","𝟒","𝟓","𝟔","𝟳","𝟖","𝟗"]
patn[8] = ["𝟶","𝟷","𝟸","𝟹","𝟺","𝟻","𝟼","𝟽","𝟾","𝟿"]


 
function numToEmoji10(n) {
    if (n == 10) {
      return emojino[10]+" ➠ ";
    } else {
      return String(n).split('').map(d => emojino[d] || d).join('')+" ➠ ";
    }
};


 
const getValue = (fn, defaultVaule) => {
  try {
    return fn();
  } catch (error) {
    return defaultVaule;
  }
};

// 【入口】先判断是不是扫码进来的订阅链接，再决定走解析、重试还是配置导入。
var type0=""
 
var flag = 1
var subscriptionURL = SubscriptionURL(content0)

 
if (subscriptionURL) {
  type0 = "sub-http"
  $done({content: ResourceParse()})
 
} else if (UARetry && !inRetry && version>920) {
  $notify("⚠️ 将尝试使用其他 UA, 重新获取订阅内容","⚠️ 如仍旧无有效内容，请自行与节点提供商联系","⚠️ 本次尝试使用 User-Agent 为 ⬇️\n\n"+UA_Retry)
  $done({retry: {user_agent: "Shadowrocket/3218 CFNetwork/3860.600.12 Darwin/25.5.0 iPhone18,1"}})
} else {
  if (typeof($resource)!=="undefined" && PProfile == 0) {
  Parser()
  $done({ content: total, info: Finfo })
} else if (PProfile != 0) {
  try {
    Profile_Handle()
  } catch (err) {
    if(Perror == 0) {
      $notify("❌ 解析出现错误", "⚠️ 请点击通知，发送订阅链接进行反馈", err, bug_link);
    }
    }
  openlink = {"open-url": ADDres}
  $notify("⚠️请忽略报错提示, 点击此通知跳转", "添加配置中的有效远程资源👇 ["+ PProfile+"]", ADDres,openlink)
  total = ProfileInfo[typeQ]
  $done({content:total})
}
}

// 【主流程】识别资源类型 → 分发解析 → 把结果交给 $done。
function Parser() {
  type0 = Type_Check(content0);  
   
  if (type0 != "web" && type0 != "wrong-field" && type0 != "JS-0" && type0 != "wrong-link"){
    try {
       
      if (Pdbg){
        $notify(link0,type0,content0)
      }
      total = ResourceParse();
      
    } catch (err) {
      if(Perror == 0) {
      $notify("❌ 解析出现错误", "⚠️ 请点击通知，发送订阅链接进行反馈", err, bug_link);
    }
    }
  } else if (type0 == "wrong-field"){
    // 修上游遗留：typec 带 server-b64 / filter-list 这类后缀，直接查 Field 会取到 undefined。
    // 先归一到基础类型，才能在类型填错时正常跳转，而不是整个解析抛异常。
    var typecBase = /^server/i.test(typec) ? "server" : /^(filter|Clash-Provider)/i.test(typec) ? "filter" : /^rewrite/i.test(typec) ? "rewrite" : "";
    if (version >= 670 && typecBase) {  
      RLink0[Field[typecBase]].push($resource.link+", opt-parser=true, tag=下次添加资源🉑️长点❤️8⃣️")  
      var flink = ADDRes.replace(/url-encoded-json/,encodeURIComponent(JSON.stringify(RLink0)))
      const bug_linkx = { "open-url": flink, "media-url": "https://qx.tatalvpai.vip/img/bug.png" }  
    $notify( "⚠️ 请点击通知跳转尝试添加到正确类型中","❌ 检测类型["+typec+"]"+"与填入类型"+"["+typeQ+"]冲突", "如果跳转添加仍旧失败，请发送链接反馈解析器bot\n"+$resource.link, bug_linkx)
    } else { 
    $notify("❌ 检测类型「"+typec+" 」"+"与目标类型"+" 「"+typeQ+" 」冲突", "⚠️ 请自行检查链接内容，或点击通知发送链接进行反馈", $resource.link, bug_link)
    }
    total=""
  } else {
    total=""
  }
    $done({ content: total });
}


 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 


 




// 【兜底】认不出来的内容按 JSON 或纯文本提示给用户，而不是静默丢空。
function ParseUnknown(cnt){
  try {
    cnt = JSON.parse(cnt)
    if(cnt) {
      $notify("⚠️ 链接返回内容并非有效订阅"+ "⟦" + subtag + "⟧","⁉️ 请自行检查原始链接，返回内容 👇️👇️",JSON.stringify(cnt), bug_link)
    }
    
  } catch(err) {
    if (!/error|block|invalid|support/.test(cnt.toLowerCase())) {
    $notify("😭 未能识别订阅 " + "⟦" + subtag + "⟧ 的内容",  "⚠️ 将尝试直接导入Quantumult X \n 如认为是 BUG, 请点通知跳转并 [发送链接] 反馈", "订阅返回内容: 👇 \n"+cnt, bug_link);
  } else {
    $notify("💢 ⟦" + subtag + "⟧ 返回内容无效",  "😠 请自行检查订阅，不要跑来反馈", "订阅返回内容: 👇 \n"+cnt, plink0);
  }
}
}


// 【分发】按识别出的类型走各自的转换分支。
function ResourceParse() {
  var rewriteFailures = [];
   
  if (type0 == "Subs-B64Encode") {  
    if (Pdbg) {$notify("original content", "node-b64", content0)}
    total = Subs2QX(Base64.decode(content0), Pudp0, Ptfo0, Pcert0, PTls13);
  } else if (type0 == "Subs") {
     
    total = Subs2QX(content0, Pudp0, Ptfo0, Pcert0, PTls13);
  } else if (type0 == "QuanX" || type0 == "Clash" || type0 == "Surge") {
    total = Subs2QX(isQuanX(content0).join("\n"), Pudp0, Ptfo0, Pcert0, PTls13);
  } else if (type0 == "sgmodule") {  
     
    flag = 2 
     
    total = Rewrite_Filter(isQuanXRewrite(content0.split("\n"), rewriteFailures), Pin0, Pout0,Preg,Pregout, rewriteFailures.length > 0); 
    if (Preplace) { total = ReplaceReg(total, Preplace) }
    total = total.filter( (ele,pos)=>total.indexOf(ele) == pos);  
    if (Pcdn) {total = CDN(total)
    } else { total = total.join("\n")}
  } else if (type0 == "rewrite") {  
    flag = 2;
    total = Rewrite_Filter(isQuanXRewrite(content0.split("\n"), rewriteFailures), Pin0, Pout0,Preg,Pregout, rewriteFailures.length > 0);
    if (Preplace) { total = ReplaceReg(total, Preplace) }
     
    total = total.filter( (ele,pos)=>total.indexOf(ele) == pos);
    if (Pcdn) {total = CDN(total)
    } else {total = total.join("\n")}
  } else if (type0 == "Rule") {   
    flag = 3;
    total = Rule_Handle(content0.split("\n").map(item=>item.trim()).filter(Boolean), Pout0, Pin0).filter(Boolean);
    if (Preg && total.length!=0) {  
    total = total.map(Regex).filter(Boolean) 
    RegCheck(total, "分流引用", "regex", Preg)
  } 
    if (Pregout && total.length!=0) {  
    total = total.map(RegexOut).filter(Boolean)
    RegCheck(total, "分流引用", "regout", Pregout)
  }
    if (Preplace) { total = ReplaceReg(total, Preplace) }
    if (Ppolicyset) {total = policy_sets(total, Ppolicyset)}
       
    total = total.length<100? total.filter( (ele,pos)=>total.indexOf(ele) == pos) : total
    total = total.join("\n")
  } else if (content0.trim() == "") {
    $notify("‼️ 当前引用" + "⟦" + subtag + "⟧" + " 返回內容为空", "1️⃣ 请确认 APP 已经更新至最新版本 1.5.6", "2️⃣ 如确认链接有效，请打开资源解析器的「User-Agent 替换」选项重新获取链接内容 ", nan_link);
    flag = 0;
  } else if (type0 == "sub-http") {
    let url = subscriptionURL
    if (version && version < 670) {
      $notify("⚠️ 疑似节点订阅链接", "请在节点资源中添加订阅", "当前版本不支持点击通知添加资源，请更新 Quantumult X 后重试。")
    } else {
      let resource = {server_remote: [url.replace(/,/g, "%2C") + ", opt-parser=true, tag=扫码订阅-" + Date.now()]}
      let addURL = ADDRes.replace("url-encoded-json", encodeURIComponent(JSON.stringify(resource)))
      $notify("⚠️ 疑似节点订阅链接", "请点击此通知，跳转添加节点订阅", "该内容应通过节点资源添加；请在添加页面确认订阅地址。", {"open-url": addURL})
    }
    return ""  
  } else if (type0 == "unknown") {
    ParseUnknown(content0)
    flag = -1;
  } else if (type0 == "profile") {
    PProfile = "111"  
    Profile_Handle()
    openlink = {"open-url": ADDres}
    $notify("⚠️ 该链接为完整配置文件, 请点击此通知跳转", "添加配置中的有效远程资源👇 ["+ PProfile+"]", ADDres, openlink)
    flag = -1;
    total = ""
  } else if (type0 == "JS-0") {
    total = ""
  }

   
  if (flag == 1) {  
    total = isQuanX(total.filter(Boolean).join("\n"))
    if (Pinfo == 1 && ntf_flow == 0) {  
      flowcheck(total)
    }
    if (Pin0 || Pout0) { total = Filter(total, Pin0, Pout0) }  
    if (Preg) { total = total.map(Regex).filter(Boolean)   
      RegCheck(total, "节点订阅", "regex", Preg)} 
    if (Pregout) { total = total.map(RegexOut).filter(Boolean)   
      RegCheck(total, "节点订阅", "regout", Pregout)} 
    if (Psfilter) { total = FilterScript(total, Psfilter) }
    if (Prrname) {
      Prn = Prrname;
      total = total.map(Rename);
    }
     
    if (Pregdel) {
      delreg = Pregdel
      total = total.map(DelReg)
    }
     
    if (Psrename) { total = RenameScript(total, Psrename) }
    if (Preplace) {  
      total = ReplaceReg(total, Preplace)
    }
    if (Prname) {
      Prn = Prname;
      total = total.map(Rename);
      if(Pdbg==1) {$notify("rename","content",total)}
    }
     
    if (Pemoji) { total = emoji_handle(total, Pemoji); }
    if (total.length > 0){
      if (Psuffix==1 || Psuffix==-1) {total = Psuffix == 1? total.map(type_suffix):total.map(type_prefix)
      }
      total = total.map(type_handle).map(emoji_prefix_handle).map(tag_handle)  
      if (Psort0) {  
        total = QXSort(total, Psort0);
      }
      total = para1.indexOf("node_index_prefix")!=-1 ?index_handle(total):total  
       
      total = TagCheck_QX(total).join("\n")  
      if (PUOT==1) { total = total.split("\n").map(UOT).join("\n")}
      if (Pcnt == 1 && total!=undefined) {$notify("⟦" + subtag + "⟧"+"解析后最终返回内容" , "节点数量: " +total.split("\n").length, total)}
      total = PRelay==""? Base64.encode(total) : ServerRelay(total.split("\n"),PRelay)  
      if (PNS !=0) {
        if (version >913) {
          $notify("⚠️ 存在 QuantumultX 不支持类型 ➟ ⟦"+subtag+"⟧", "⚠️ 已忽略相关节点，共计 ➟ "+PNS+" 条", UnsupportedNodeDetails("Tuic/Wireguard"))
        } else {
          $notify("⚠️ 存在 QuantumultX 不支持类型 ➟ ⟦"+subtag+"⟧", "⚠️ 已忽略相关节点，共计 ➟ "+PNS+" 条", UnsupportedNodeDetails("Tuic/Anytls"))
        }
      }
      if(Pflow==1) {
         
        $done({ content: total, info: {bytes_used: 3073741824, bytes_remaining: 2147483648, expire_date: 1854193966}});
       
      } else { $done({ content: total });}
    } else {  
      if(Perror == 0) {
      if (PNS !=0) {  
        if (version >913) {
          $notify("⚠️ QuantumultX 不支持该订阅内的任何节点➟ ⟦"+subtag+"⟧", "⚠️ 已忽略共计 ➟ "+PNS+" 条不支持节点，剩余 0️⃣ 条", UnsupportedNodeDetails("Tuic/Wireguard"))
        } else {
          $notify("⚠️ QuantumultX 不支持该订阅内的任何节点➟ ⟦"+subtag+"⟧", "⚠️ 已忽略共计 ➟ "+PNS+" 条不支持节点，剩余 0️⃣ 条", UnsupportedNodeDetails("Tuic/Anytls"))
        }
        
      } else {  
        $notify("❓❓ 该订阅 ➟ "+ "⟦" + subtag + "⟧ 解析后无有效节点", "⚠️⚠️ 解析后 Quantumult-X 支持节点数为 0️⃣ 条", "🚥🚥 请自行检查相关参数、确认节点类型, 或者点击通知跳转并发送链接反馈", bug_link)
      } 
    }
      total = errornode
      $done({ content: errornode })
    }
  } else if (flag == 0){  
    total = errornode
    $done({ content: errornode })
  } else if (flag == -1){  
    total = typeQ == "filter" || typeQ == "rewrite" ? content0.split("\n").map(RuleNoteOutput).join("\n") : content0
    $done({ content: total })
  } 
   
  if (flag == 2 || flag == 3) { total = total.split("\n").map(RuleNoteOutput).join("\n") }
  if (Pcnt == 1 && flag !=1 && total!=undefined) {$notify("解析后最终返回内容" , "总数量： " +total.split("\n").length, total)}
  return total
  
}

 
// 【响应头】从响应头里读订阅流量（QX 会把机场返回的头带进来）。
function SubFlow() {
  if (Pinfo == 1 && subinfo) {
    var sinfo = subinfo.replace(/ /g, "").toLowerCase();
    var total = "总流量: " + (parseFloat(sinfo.split("total=")[1].split(",")[0]) / (1024 ** 3)).toFixed(2) + "GB";
    var usd = "已用流量: " + ((parseFloat(sinfo.indexOf("upload")!=-1?sinfo.split("upload=")[1].split(",")[0]:"0") + parseFloat(sinfo.split("download=")[1].split(",")[0])) / (1024 ** 3)).toFixed(2) + "GB"
    var left = "剩余流量: " + ((parseFloat(sinfo.split("total=")[1].split(",")[0]) / (1024 ** 3)) - ((parseFloat(sinfo.indexOf("upload")!=-1?sinfo.split("upload=")[1].split(",")[0]:"0") + parseFloat(sinfo.split("download=")[1].split(",")[0])) / (1024 ** 3))).toFixed(2) + "GB"
    if (sinfo.indexOf("expire=") != -1) {
      var epr = new Date(parseFloat(sinfo.split("expire=")[1].split(",")[0]) * 1000);
      var year = epr.getFullYear();   
      var mth = epr.getMonth() + 1 < 10 ? '0' + (epr.getMonth() + 1) : (epr.getMonth() + 1);   
      var day = epr.getDate() < 10 ? "0" + (epr.getDate()) : epr.getDate();
      epr = "过期时间: " + year + "-" + mth + "-" + day
    } else {
      epr = "";  
    }
    var message = total + "\n" + usd + ", " + left;
    ntf_flow = 1;
    $notify("流量信息: ⟦" + subtag + "⟧", epr, message, subinfo_link)
  }
 
 
 
}

 
// 【流量校验】头信息里没带流量时，退回到 flow 参数。
function flowcheck(cnt) {
    for (var i = 0; i < cnt.length; i++) {
        var item = cnt[i];
        var nl = item.slice(item.indexOf("tag"))
        var nm = nl.slice(nl.indexOf("=") + 1)
        if (item.indexOf("剩余流量") != -1) {
            flow = nm
        } else if (item.indexOf("期时间") != -1) {
            exptime = nm
        }
    }
  flow = flow? flow:"⚠️ 该订阅未返回任何流量信息"
  exptime = exptime? exptime:"⚠️ 该订阅未返回套餐时间信息"
    if (flow != "") { $notify("流量信息: ⟦" + subtag + "⟧", flow, exptime, subinfo_link1) }
}

 
// 【正则筛选】regex / regout 的公共实现。
function RegCheck(total, typen, paraname,regpara) {
  if(total.length == 0){ 
    $notify("‼️ " + typen + "  ➟ " + "⟦" + subtag + "⟧", "⛔️ 筛选正则: " + paraname + "=" + regpara, "⚠️ 筛选后剩余项为 0️⃣ , 请检查正则参数及原始链接", nan_link)
  }else if((typen != "节点订阅" && Pntf0 !=0) || (typen == "节点订阅" && Pntf0 ==1)){
    var nolist = total.length <= 10 ? emojino[total.length] : total.length
    $notify("🤖 " + typen + "  ➟ " + "⟦" + subtag + "⟧", "⛔️ 筛选正则: " + paraname + "=" + regpara, "⚠️ 筛选后剩余以下" + nolist + "个匹配项 \n ⨷ " + total.join("\n ⨷ "), sub_link)
  }
}
 
// 【行首说明】{# 说明 #} 只当元数据保留，不参与筛选与替换。
function RuleNoteSplit(row) {
  var match = row.match(/^([ \t]*\{#[^\r\n]*?#\}[ \t]*)([^\r\n]*)\r?$/);
  return match ? { note: match[1], body: match[2] } : { note: "", body: row };
}

function RuleNoteBody(row) {
  return RuleNoteSplit(row).body;
}

function RuleNoteJoin(note, body) {
  return body && body.trim() && body.trim() != "-" ? note + body : "";
}

function RuleNoteMap(row, transform) {
  var parts = RuleNoteSplit(row);
  return RuleNoteJoin(parts.note, transform(parts.body));
}

function RuleNoteOutput(row) {
  var parts = RuleNoteSplit(row);
  if (parts.note) { return RuleNoteJoin(version >= 950 ? parts.note : "", parts.body) }
  return /^[ \t]*\{#/.test(row) ? "" : row;  
}

 
 
// 【扫码】识别单个订阅特征的链接，引导先加资源再解析。
function SubscriptionURL(content) {
    if (!/^(server|uri|unsupported)$/i.test(typeQ)) { return "" }
    var url = content.trim()
    var wrapped = /^subs?:\/\//i.test(url)
    if (wrapped) {
      var encoded = url.replace(/^subs?:\/\//i, "").split("#")[0]
      if (!/^[a-z0-9+/_-]+={0,2}$/i.test(encoded)) { return "" }
      url = Base64.decode(encoded.replace(/-/g, "+").replace(/_/g, "/")).trim()
    }
    if (/[\s\x00-\x1f\x7f<>"\\]/.test(url)) { return "" }
    var parts = /^https?:\/\/([^/?#]+)(\/[^?#]*)?(\?[^#]*)?(#.*)?$/i.exec(url)
    if (!parts) { return "" }
     
    if (!/^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)+|\[[a-f0-9:.]+\])(?::\d{1,5})?$/i.test(parts[1])) { return "" }
    var path = parts[2] || "", query = parts[3] || ""
    var subscriptionPath = /(?:^|\/)(?:sub|subscribe|subscription|link)(?:[/.]|$)/i.test(path)
    var resourceFile = /\.(?:txt|list|yaml|yml|conf|json|snippet)$/i.test(path)
    var tokenPath = path.split("/").some(function (part) { return /^[a-z0-9_-]{16,}$/i.test(part) && /[a-z]/i.test(part) && /\d/.test(part) })
    var subscriptionQuery = /[?&](?:token|access_token|subscription|subscribe|sub|target)=[^&#]+/i.test(query) || /[?&](?:type|flag|format)=(?:quanx|quantumultx?|clash|surge|v2ray|sing-?box)(?:&|$)/i.test(query)
    return wrapped || subscriptionPath || resourceFile || tokenPath || subscriptionQuery ? url : ""
}

// 【类型判断】按内容特征猜类型：节点订阅、重写、分流、模块、域名集…
function Type_Check(subs) {
     
    if (typeQ != "server" && typeQ != "uri" && subs.indexOf("{#") != -1) { subs = subs.split("\n").map(RuleNoteBody).join("\n") }
    var type = "unknown"
    var RuleK = ["host,", "-suffix,", "domain,", "domain-regex,", "-keyword,", "ip-cidr,", "ip-cidr6,",  "geoip,", "user-agent,", "ip6-cidr,", "ip-asn", "and,", "or,", "not,"];
    var DomainK = ["domain-set,"]
    var QuanXK = ["shadowsocks=", "trojan=", "vmess=", "http=", "socks5=", "vless=","anytls="];
    var SurgeK = ["=ss,", "=vmess,", "=trojan,", "=http,", "=custom,", "=https,", "=shadowsocks", "=shadowsocksr", "=sock5", "=sock5-tls","=anytls"];
    var ClashK = ["proxies:","\"proxies\":"]
    var SubK = ["dm1lc3M", "c3NyOi8v", "CnNzOi8", "dHJvamFu", "c3M6Ly", "c3NkOi8v", "c2hhZG93", "aHR0cDovLw", "aHR0cHM6L", "CnRyb2phbjo", "aHR0cD0", "aHR0cCA","U1RBVFVT","dmxlc3M6"];
    var RewriteK = [" url 302", " url 307", " url reject", " url script", " url req", " url res", " url echo", " url-and-header 302", " url-and-header 307", " url-and-header reject", " url-and-header script", " url-and-header req", " url-and-header res", " url-and-header echo", " url jsonjq"]  
    var JsonJQK = [" response-body-json-jq ", " request-body-json-jq ", " response-body-json-del ", " response-body-json-replace ", " http-response-jq ", " http-request-jq "]  
     
    var SubK2 = ["ss://", "vmess://", "ssr://", "trojan://", "ssd://", "\nhttps://", "\nhttp://","socks://","ssocks://","vless://","anytls://","wireguard://","wg://","tuic://","hysteria2://","hy2://"];
    var ModuleK = ["[Script]", "[Rule]", "[URL Rewrite]", "[Body Rewrite]", "[Map Local]", "\nhttp-r", "script-path"]
    var QXProfile = ["[filter_local]","[filter_remote]","[server_local]","[server_remote]"]
    var html = "DOCTYPE html"
    var subi = subs.replace(/ /g, "")
    const RuleCheck = (item) => subi.toLowerCase().indexOf(item) != -1;
    const NodeCheck = (item) => subi.toLowerCase().indexOf(item.toLowerCase()) != -1;
    const NodeCheck1 = (item) => subi.toLowerCase().indexOf(item.toLowerCase()) != -1;  
    const NodeCheck2 = (item) => subi.toLowerCase().indexOf(item.toLowerCase()) != -1;  
    const RewriteCheck = (item) => subs.indexOf(item) != -1 ;  
    const JsonJQCheck = (item) => (" " + subs.toLowerCase().replace(/\s+/g," ") + " ").indexOf(item) != -1;
    const ProfileCheck = (item) => subs.indexOf(item) != -1;  
    var subsn = subs.split("\n")
    var allowHY2 = ["server", "uri", "unsupported"].indexOf(String(typeQ).toLowerCase()) != -1
    var hy2Clash = allowHY2 && HY2ClashSnippet(subs)
    var hy2Lines = allowHY2 && subsn.some(HY2LineKind)
    var hy2Decoded
    if ( (subs.indexOf(html) != -1 || subs.indexOf("doctype html") != -1) && link0.indexOf("github.com" == -1)) {
      $notify("‼️ 该链接返回为无效网页内容"+ " ➟ " + "⟦" + subtag + "⟧", "⁉️ 点通知跳转以确认链接是否失效\n"+link0, "返回内容如下⬇️：\n"+subs, nan_link);
      type = "web";
    } else if (typeU == "nodes" && typeQ=="server") {  
      type = (typeQ == "unsupported" || typeQ =="server")? "Subs":"wrong-field"
    } else if (hy2Clash || ClashK.some(NodeCheck) || typeU == "clash"){  
      type = (hy2Clash || typeQ == "unsupported" || typeQ =="server")? "Clash":"wrong-field";
      typec = "server"
      content0 = Clash2QX(hy2Clash || subs)
    } else if ( (((ModuleK.some(RewriteCheck) || subsn.some(IsMapLocalInline) || para1.indexOf("dst=rewrite") != -1) && (para1.indexOf("dst=filter") == -1) && subs.indexOf("[Proxy]") == -1) || typeU == "module") && typeU != "nodes" && typeU != "rule" && typeQ !="filter") {  
      typec="rewrite"
      type = (typeQ == "unsupported" || typeQ =="rewrite")? "sgmodule" : "wrong-field"
    } else if ((/(^hostname|\nhostname)\s*\=/.test(subi) || RewriteK.some(RewriteCheck) || JsonJQK.some(JsonJQCheck))  && para1.indexOf("dst=filter")==-1 && subi.indexOf("securehostname") == -1 && !/module|nodes|rule/.test(typeU) && !(RuleK.some(RuleCheck) && typeQ == "filter") && !(typeQ!= "rewrite" && QXProfile.some(ProfileCheck))) {
       
      typec = "rewrite"
      type = (typeQ == "unsupported" || typeQ =="rewrite")? "rewrite":"wrong-field"  
    } else if (((RuleK.some(RuleCheck) && subs.indexOf(html) == -1 ) || (typeQ == "filter" && subsn.some(function (row) { return /^[a-z][\w-]*\s*,/i.test(row.trim()) })) || typeU == "rule" || para1.indexOf("dst=filter")!=-1) && typeU != "nodes" && !hy2Lines && !(typeQ == "server" && (QuanXK.some(NodeCheck) || SurgeK.some(NodeCheck))) ) {
       
       
      typec = "filter"
      type = (typeQ == "unsupported" || typeQ =="filter")? "Rule":"wrong-field";
    } else if (typeU == "domain-set") { 
      typec = "filter-domain-set"
      type = (typeQ == "unsupported" || typeQ =="filter")? "Rule":"wrong-field";
      content0 = Domain2Rule(content0)  
    } else if (typeQ == "filter" && subs.indexOf("payload:")==-1) {  
      typec = "filter-list"
      type = (typeQ == "unsupported" || typeQ =="filter")? "Rule":"wrong-field";
      content0 = content0.split("\n").map(rule_list_handle).join("\n")
    } else if (typeQ == "filter" && subs.indexOf("payload:")!=-1) {  
      typec = "Clash-Provider"
      type = (typeQ == "unsupported" || typeQ =="filter")? "Rule":"wrong-field";
    } else if (subsn.length >= 1 && SubK2.some(NodeCheck2) && !/\[(Proxy|filter_local)\]/.test(subs)) {  
      typec = "server-uri"
      type= (typeQ == "unsupported" || typeQ =="server" || typeQ =="uri") ? "Subs":"wrong-field"
    } else if ((subi.indexOf("tag=") != -1 && QuanXK.some(NodeCheck) && !/\[(Proxy|filter_local)\]/.test(subs)) || typeU =="list") {
      typec = "server-quanx"
      type = (typeQ == "unsupported" || typeQ =="server" || typeQ =="uri")? "Subs":"wrong-field"  
    } else if (subs.indexOf("[Proxy]") != -1) {
      typec= "server-surge"
      type = (typeQ == "unsupported" || typeQ =="server" || typeQ =="uri")? "Surge":"wrong-field";  
      content0 = Surge2QX(content0).join("\n");
    } else if (hy2Lines) {
      typec = "server"
      type = "Subs"
    } else if ((SurgeK.some(NodeCheck)  && !/\[(Proxy|filter_local)\]/.test(subs)) || typeU == "list") {
      typec="server-surge"
      type = (typeQ == "unsupported" || typeQ =="server" || typeQ =="uri")? "Subs":"wrong-field"  
    } else if (subs.indexOf("[server_local]") != -1 && QuanXK.some(NodeCheck)) {
       
      typec="server-quanx"
      type = (typeQ == "unsupported" || typeQ =="server"|| typeQ =="uri")? "Subs":"wrong-field"
    } else if (subs.indexOf("server") !=-1 && subs.indexOf("server_port") !=-1) {  
       
      typec= "server-sip008"
      type = (typeQ == "unsupported" || typeQ =="server")? "Subs":"wrong-field"
      content0 = SIP2QuanX(content0)
    } else if (allowHY2 && (hy2Decoded = HY2DecodeSubscription(subs))) {
      typec = "server-b64"
      type = "Subs"
      content0 = hy2Decoded
    } else if (SubK.some(NodeCheck1)) {   
      typec="server-b64"
      type = (typeQ == "unsupported" || typeQ =="server")? "Subs-B64Encode":"wrong-field"
      if (content0.split("\n").length >= 2) {  
        let tmp = content0.split("\n")[1]
        if (Pdbg) {$notify("local", "node", "\ntmp:\n"+tmp)}
        if (SubK.some((item) => tmp.toLowerCase().indexOf(item.toLowerCase()) != -1))
        content0 = tmp
      }
    } else if (QXProfile.every(ProfileCheck)) {
      typec = "profile"
      type = "profile"   
    }else if (/\.js/.test(link0)) {  
      Perror = 1 ;  
      $notify("⚠️ 你导入的链接内容为 JS 脚本","🚥 脚本内未有重写规则，无法解析使用", " 请⚠️不要⚠️跑来解析器🤖️反馈 \n"+link0)
      type = "JS-0"
    } else if (typeQ =="server" && subs.length>100) {  
      typec="server-b64-unknown"
      type = (typeQ == "unsupported" || typeQ =="server")? "Subs-B64Encode":"wrong-field"
    } else if(subs == "wrong-link") {
      type="wrong-link"
    }
     
   
  if(typeU == "X"){
    $notify("该链接判定类型",type+" : " +typec, subs)
  }
   
    return type
}

 
// 【节点体检】查重名、空名、多余空格这类 QX 不接受的情况。
function TagCheck_QX(content) {
  typefix = {"shadowsocks":["𝐬𝐬","𝐒𝐒","🅢🅢","🆂🆂","ⓢⓢ","🅂🅂","SS"],"shadowsocksr":["𝐬𝐬𝐫","𝐒𝐒𝐑","🅢🅢🅡","🆂🆂🆁","ⓢⓢⓡ","🅂🅂🅁","SSR"],
    "vmess":["𝐯𝐦𝐞𝐬𝐬","𝐕𝐌𝐄𝐒𝐒","🅥🅜🅔🅢🅢","🆅🅼🅴🆂🆂","ⓥⓜⓔⓢⓢ","🅅🄼🄴🅂🅂","VMESS"],"trojan":["𝐭𝐫𝐨𝐣𝐚𝐧","𝐓𝐑𝐎𝐉𝐀𝐍","🅣🅡🅞🅙🅐🅝","🆃🆁🅾🅹🅰🅽","ⓣⓡⓞⓙⓐⓝ","🅃🅁🄾🄹🄰🄽","TROJAN"],
    "http":["𝐡𝐭𝐭𝐩","𝐇𝐓𝐓𝐏","🅗🅣🅣🅟","🅷🆃🆃🅿","ⓗⓣⓣⓟ","🄷🅃🅃🄿","HTTP"],"socks5":["𝐬𝐨𝗰𝗸𝐬","𝐒𝐎𝐂𝐊𝐒","🅢🅞🅒🅚🅢","🆂🅾🅲🅺🆂","ⓢⓄⒸⓀⓢ","🅂🄾🄲🄺🅂","SOCKS"],
    "vless":["𝐯𝐥𝐞𝐬𝐬","𝐕𝐋𝐄𝐒𝐒","🅥🅛🅔🅢🅢","🆅🅻🅴🆂🆂","ⓥⓛⓔⓢⓢ","🅅🄻🄴🅂🅂","VLESS"],"anytls":["𝐚𝐧𝐲𝐭𝐥𝐬","𝐀𝐍𝐘𝐓𝐋𝐒","🅐🅝🅨🅣🅛🅢","🅰🅽🆈🆃🅻🆂","ⓐⓝⓨⓣⓛⓢ","🄰🄽🅈🅃🄻🅂","𝖠𝖭𝖸𝖳𝖫𝖲"]
  }  
  typefix.hysteria2 = ["HY2","HY2","HY2","HY2","HY2","HY2","HY2"]
  console.log(content)
    var Olist = content.map(item =>item.trim()) 
     
    var [Nlist, nmlist] = [ [], [] ]
    var [nulllist,duplist] = [ [], [] ];  
    var no=0 ;
    for (var i = 0; i < Olist.length; i++) {
        var item = Olist[i] ? Olist[i] : ""
        typefix["shadowsocks"]=item.indexOf("ssr-protocol")!=-1? typefix["shadowsocksr"] : typefix["shadowsocks"]
        if (item.replace(/ /gm, "").indexOf("tag=") != -1) {
            var hy2Tag = HY2LineKind(item) == "quanx"
            var tagAt = hy2Tag ? item.search(/,\s*tag=/) : -1
            var nl = tagAt < 0 ? item.slice(item.indexOf("tag")) : item.slice(tagAt + 1).trim()
            var nm = nl.slice(nl.indexOf("=") + 1)
            if (nm == "") {  
                tp = typefix[item.split("=")[0].trim()][3]
                nm = tp + " | " + item.split("=")[1].split(",")[0].split(":")[0]
                item = item.split("tag")[0] + "tag=" + nm.replace("shadowsocks", "ss")
                nulllist.push(nm.replace("shadowsocks", "ss"))
            }
            var ni = 0
            while (nmlist.indexOf(nm) != -1) {  
               
                nm = ni==0? nm+ NoReplace(ni+1):nm.split(" ").slice(0,nm.split(" ").length-2).join(" ") + NoReplace(ni+1)
                item = Pdel != 1 ? (tagAt < 0 ? item.split("tag")[0] : item.slice(0, tagAt) + ", ") + "tag=" + nm : ""
                ni = ni + 1
            }
            if (ni != 0) { duplist.push(nm) }
            nmlist.push(nm)
          if (Pcap) { 
            item = Capitalize(item,Pcap)
            console.log(item)
          }
          if (Pptn || Pnptn) { 
            item = Pattern(item,Pptn,Pnptn)
            console.log(item)
          }
            ni = 0
            if (item) {
            Nlist.push(item)
          }
        } 
    }  
     
    if (PcheckU != "") {
      Nlist = Nlist.map(Add_URL)
    }
    if (nulllist.length >= 1) {
        no = nulllist.length <= 10 ? emojino[nulllist.length] : nulllist.length;
        $notify("⚠️ 引用" + "⟦" + subtag + "⟧" + " 内有" + no + "个空节点名 ", "✅ 已将节点“类型+IP”设为节点名", " ⨁ " + nulllist.join("\n ⨁ "), nan_link)
    }
    if (duplist.length >= 1) {
        no = duplist.length <= 10 ? emojino[duplist.length] : duplist.length;
      if (Pdel!=1 && Pntf0 != 0){
        $notify("⚠️ 引用" + "⟦" + subtag + "⟧" + " 内有" + no + "个名字重复的节点 ", "✅ 已添加数字区分, 删除请添加参数 del=1:", " ⨁ " + duplist.join("\n ⨁ "), nan_link)
      } else if (Pdel ==1 && Pntf0 != 0) {
        $notify("⚠️ 引用" + "⟦" + subtag + "⟧" + " 内有" + no + "个名字重复的节点 ", "❌️ 已全部删除，如需保留请去除参数 del=1:", " ⨁ " + duplist.join("\n ⨁ "), nan_link)
      }
    }
    return Nlist
}

 
// 【节点名】重名时补序号，保证 tag 唯一。
function Add_URL(cnt) {
  if (cnt) {
    cnt = cnt +", server_check_url="+PcheckU
  }
  return cnt
}

 
function NoReplace(cnt) {
  if(cnt){
    for (var i=0;i<10;i++) {
      cnt = cnt.toString().replace(new RegExp(patn[0][i], "gmi"),patn[5][i])
    }
    return " " + cnt + " "
  }
}


 
// 【花漾字】节点名的英文与数字换样式。
function PatternN(cnt, para,npara) {
  if(cnt){
    if(para!=""){ 
      for (var i=0;i<26;i++) {
        cnt = cnt.toLowerCase()
        cnt = cnt.replace(new RegExp(pat[0][i], "gmi"),pat[para][i])
      }
    }
    if(npara!=""){  
      for (var i=0;i<10;i++) {
        cnt = cnt.replace(new RegExp(patn[0][i], "gmi"),patn[npara][i])
      }
    }
    console.log(cnt)
    return cnt
  }
}


function Pattern(cnt,para,npara) {
  if (para != "" || npara != "") {
    cnt = cnt.split("tag=")[0] +"tag="+ PatternN(cnt.split("tag=")[1],para,npara)
  }
  return cnt 
}


 
// 【大小写】cap 参数：首字母大写。
function Capitalize(cnt,para) {
  if (para == 1) {
    cnt = cnt.split("tag=")[0] +"tag="+ cnt.split("tag=")[1].toUpperCase()
  } else if (para == -1) {
    cnt = cnt.split("tag=")[0] +"tag="+ cnt.split("tag=")[1].toLowerCase()
  } else if (para == 0) {
    cnt =cnt.split("tag=")[0] +"tag="+titleCase(cnt.split("tag=")[1])
  }
  return cnt
}

function titleCase(str) {
  var newStr = str.split(" ");
  for(var i = 0; i<newStr.length; i++){
    newStr[i] = newStr[i].slice(0,1).toUpperCase() + newStr[i].slice(1).toLowerCase();
  }    return newStr.join(" ");
}


 
// 【类型标记】给节点名加类型前缀或后缀。
function type_prefix(item) {
  if(item.trim()!="") {
    typefix = {"shadowsocks":"「𝐬𝐬」","vmess":"「𝐯𝐦𝐞𝐬𝐬」","trojan":"「𝐭𝐫𝐨𝐣𝐚𝐧」","http":"「𝐡𝐭𝐭𝐩」","socks5":"「𝐬𝐨𝗰𝗸𝐬」","vless":"「𝐯𝐥𝐞𝐬𝐬」","anytls":"「𝐚𝐧𝐲𝐭𝐥𝐬」"}
    typefix["shadowsocks"]=item.indexOf("ssr-protocol")!=-1? "「𝐬𝐬𝐫」" : "「𝐬𝐬」"
    tp = HY2LineKind(item) == "quanx" ? "「𝐡𝐲𝟐」" : typefix[item.split("=")[0].trim()]
    return [[item.split("tag=")[0]+
      "tag=", tp, item.split("tag=")[1]].join(" ")].join(" ")
  }
}
function type_suffix(item) {
  if(item.trim()!=""){
    typefix={"shadowsocks":"「𝐬𝐬」","vmess":"「𝐯𝐦𝐞𝐬𝐬」","trojan":"「𝐭𝐫𝐨𝐣𝐚𝐧」","http":"「𝐡𝐭𝐭𝐩」","vless":"「𝐯𝐥𝐞𝐬𝐬」","anytls":"「𝐚𝐧𝐲𝐭𝐥𝐬」"}
    typefix["shadowsocks"]=item.indexOf("ssr-protocol")!=-1? "「𝐬𝐬𝐫」" : "「𝐬𝐬」"
    tp = HY2LineKind(item) == "quanx" ? "「𝐡𝐲𝟐」" : typefix[item.split("=")[0].trim()]
    return [item, tp].join(" ")
  }
}

 
// 【占位符】$type / $index / $emoji / $tag 的取值与样式替换。
function getnode_type(item,ind) {
    if (HY2LineKind(item) == "quanx") return ["𝐡𝐲𝟐","𝐇𝐘𝟐","🅗🅨❷","🅷🆈2","ⓗⓨ②","🄷🅈2","𝕙𝕪𝟚","ʰʸ²","HY2"][ind]
  if(item.trim()!="" && item.indexOf("tag=")!=-1) {
    ind = !/^(0|1|2|3|4|5|6|7)$/.test(ind) ? 8 : ind
    typefix = {"shadowsocks":["𝐬𝐬","𝐒𝐒","🅢🅢","🆂🆂","ⓢⓢ","🅂🅂","𝕊𝕊","ˢˢ","SS"],
      "shadowsocksr":["𝐬𝐬𝐫","𝐒𝐒𝐑","🅢🅢🅡","🆂🆂🆁","ⓢⓢⓡ","🅂🅂🅁","𝕊𝕊ℝ","ˢˢʳ","SSR"],
      "vmess":["𝐯𝐦𝐞𝐬𝐬","𝐕𝐌𝐄𝐒𝐒","🅥🅜🅔🅢🅢","🆅🅼🅴🆂🆂","ⓥⓜⓔⓢⓢ","🅅🄼🄴🅂🅂","𝕍𝕞𝕖𝕤𝕤","ᵛᵐᵉˢˢ","VMESS"],
      "trojan":["𝐭𝐫𝐨𝐣𝐚𝐧","𝐓𝐑𝐎𝐉𝐀𝐍","🅣🅡🅞🅙🅐🅝","🆃🆁🅾🅹🅰🅽","ⓣⓡⓞⓙⓐⓝ","🅃🅁🄾🄹🄰🄽","𝕋𝕣𝕠𝕛𝕒𝕟","ᵀʳᵒʲᵃⁿ","TROJAN"],
      "http":["𝐡𝐭𝐭𝐩","𝐇𝐓𝐓𝐏","🅗🅣🅣🅟","🅷🆃🆃🅿","ⓗⓣⓣⓟ","🄷🅃🅃🄿","𝕙𝕥𝕥𝕡","ʰᵗᵗᵖ","HTTP"],
      "socks5":["𝐬𝐨𝗰𝗸𝐬","𝐒𝐎𝐂𝐊𝐒","🅢🅞🅒🅚🅢","🆂🅾🅲🅺🆂","ⓢⓞⓒⓚⓢ","🅂🄾🄲🄺🅂","𝕤𝕠𝕔𝕜𝕤","ˢᵒᶜᵏˢ","SOCKS"],
      "vless":["𝐯𝐥𝐞𝐬𝐬","𝐕𝐋𝐄𝐒𝐒","🅥🅛🅔🅢🅢","🆅🅻🅴🆂🆂","ⓥⓛⓔⓢⓢ","🅅🄻🄴🅂🅂","𝕍𝕝𝕖𝕤𝕤","ᵛˡᵉˢˢ","VLESS"],
      "anytls":["𝐚𝐧𝐲𝐭𝐥𝐬","𝐀𝐍𝐘𝐓𝐋𝐒","🅐🅝🅨🅣🅛🅢","🅰🅽🆈🆃🅻🆂","ⓐⓝⓨⓣⓛⓢ","🄰🄽🅈🅃🄻🅂","𝔸𝕟𝕪𝕥𝕝𝕤","ᴬⁿʸᵗˡˢ","𝖠𝖭𝖸𝖳𝖫𝖲"]
    }
    typefix["shadowsocks"]=item.indexOf("ssr-protocol")!=-1? typefix["shadowsocksr"] : typefix["shadowsocks"]
    tp = typefix[item.split("=")[0].trim()][ind]
    return tp
  }
}


 
function type_handle(item) {
  if(item.indexOf("node_type_para_prefix")!=-1) {
    item = item.replace(/node_type_para_prefix(\d{0,1})/g,getnode_type(item,item.split("node_type_para_prefix")[1][0]))
  }
  return item
}

 
function index_handle(item) {
  items = item.map(item=>item.trim()).filter(Boolean)
  let b=Array.from(new Array(items.length),(val,index)=>index+1);
   
  for (var i=0; i< items.length;i++){
     
    if (items[i].indexOf("node_index_prefix") != -1) {  
    ind = items[i].split("node_index_prefix")[1][0]
    ind = !/^(0|1|2|3|4|5|6|7|8)$/.test(ind) ? 0 : ind
    console.log("handle index"+ind)
    items[i] = items[i].replace(/node_index_prefix(\d{0,1})/g,PatternN((i+1).toString(),"",ind))
  }
  }
  console.log(items)
  return items
}


 
function emoji_prefix_handle(item) {
  if(item.indexOf("node_emoji_flag_prefix")!=-1) {
    item = item.replace(/node_emoji_flag_prefix\d{0,1}/g,getnode_emoji(item,item.split("node_emoji_flag_prefix")[1][0]))
     
  }
  return item
}

 
function getnode_emoji(item,ind){
  ind = !/^(1|2)$/.test(ind) ? 2 : ind
  if(item.indexOf("tag=")!=-1) {
    return get_emoji(ind,item.split("tag=")[1])[1]
  }
}




 
function tag_handle(item) {
  if(item.indexOf("node_tag_prefix")!=-1) {
     
     
    ptnn = /\d/.test(item.split("node_tag_prefix")[1][0])? item.split("node_tag_prefix")[1][0]:""
    nptnn = /\d/.test(item.split("node_tag_prefix")[1][1])? item.split("node_tag_prefix")[1][1]:""
     
    item = item.replace(/node_tag_prefix\d{0,2}/g,PatternN(subtag,ptnn,nptnn))
  }
  return item
}

 
function URI_TAG(cnt0,tag0) {
  cnt0 = cnt0.split("tag=")[0] + "tag=" + tag0
  return cnt0
}

 
// 【代理链】把落地节点转成 ip / host 规则，指向中转。
function ServerRelay(src,dst) {
  var rsts=[]
  for (var i=0; i<src.length; i++) {
    serverA = src[i].indexOf("-host")==-1? src[i].split("=")[1].split(":")[0].trim() : src[i].split("-host")[1].split("=")[1].split(",")[0].trim()
    type = /^[a-z]/.test(serverA) || /[a-z]$/.test(serverA)? "host":"ip"
    rst = type == "ip"? "ip-cidr,"+serverA+"/32,"+dst : "host-suffix,"+serverA+","+dst 
    rsts.push(rst)
  }
  return rsts.join("\n")
  
}

 
function rawtest(cnt) {
  var Preg0 = RegExp(".*js-file-line\".*?\<\/td\>", "i")
  if (Preg0.test(cnt)) {
    return cnt.replace(/(.*js-file-line\"\>)(.*?)(\<\/td\>)/g,"$2").replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").trim()
  }
}

function ToRaw(cnt) {
  cnt = cnt.split("\n").map(rawtest).filter(Boolean).join("\n")
  var rawlink = link0.replace("github.com","raw.githubusercontent.com").replace("/blob","")
  if (cnt) {
    $notify( "⚠️⚠️ 将尝试解析该资源" + "⟦" + subtag + "⟧" , "🚥 请正确使用GitHub的 raw 链接" , "❌ 你的链接："+link0+"\n✅ 正确链接："+rawlink, {"open-url":rawlink})
  } else if(content0.indexOf("gridcell")!=-1) {
    $notify( "⚠️⚠️ 解析该资源" + " ⟦" + subtag + "⟧ 失败" , "🚥 你的链接似乎是目录，而不是文件" , "❌ 你的链接："+link0, {"open-url":link0})
  }
  return cnt
}

function ToLink(link) {
  cnt = link.split("nsloon.com/openloon/import?plugin=")[1]
  if (cnt) {
    
    typ=$resource.type
    RLink0[Field[typ]].push(cnt+", opt-parser=true, tag=🉑️长点❤️8⃣️")  
    flink = ADDRes.replace(/url-encoded-json/,encodeURIComponent(JSON.stringify(RLink0)))
    $notify( "⚠️ 请点击通知跳转尝试添加正确链接" , "🚥 请正确使用原始链接" , "❌ 你的链接："+link0+"\n✅ 正确链接："+cnt, {"open-url":flink})
  } 
  return "wrong-link"
}

// 【镜像】cdn=1 时把 github 地址换成 jsdelivr，省得为拉脚本再翻一次墙。
function CDN(cnt) {
  console.log("CDN start")
  cnt = cnt.map(item => RuleNoteMap(item, body => body.replace(/https:\/\/raw.githubusercontent.com\/(.*?)\/(.*?)\/(.*)/gmi,"https://fastly.jsdelivr.net/gh/$1/$2@$3"))).join("\n")
  return cnt
}

 
// 【字段改写】host / obfs / tsession / sha256 / alpn 这几个参数的落点。
function HOST_Handle(cnt,phost) {
  phost="host="+phost+","
  if (phost.indexOf("☠️") == -1) {  
    cnt = cnt.replace(/host\s*\=(.*?)\,/,phost)
  } else {  
    phost=phost.split("☠️")[0]
    if (/-host\s*\=/.test(cnt)) { 
      cnt = cnt.replace(/host\s*\=(.*?)\,/,phost+", ")
    } else if (/over-tls\s*\=\s*true/.test(cnt)) {  
      cnt = cnt+", tls-"+phost
    } else if (/obfs\s*\=/.test(cnt)) {
      cnt = cnt + ", obfs-"+phost
    }
  }
  return cnt
}

 
function OBFS_Handle(cnt,pobfs) {
  if (pobfs == "shttp") {
    pobfs="obfs="+"shadowsocks-http"
  } else if (pobfs == "vhttp") {
    pobfs="obfs="+"vmess-http"
  } else { 
    pobfs="invalid"
  }
  if (/obfs\s*\=\s*http/.test(cnt) && pobfs!="invalid") {  
    cnt = cnt.replace(/obfs\s*\=\s*http/,pobfs)
  }
  return cnt
}

 
function Session_Handle(cnt,psession) {
  let st = ", tls-no-session-ticket=true"
  let sr = ", tls-no-session-reuse=true"
  if (psession == 0) {
    cnt =cnt + st
  } else if (psession == 1) {
     cnt =cnt + sr
  } else if (psession == 2){ 
    cnt =cnt + st + sr
  }
  return cnt
}

 
function SHA256_Handle(cnt,pcsha256,ppsha256) {
  if (cnt.indexOf("over-tls=true")!=-1 || cnt.indexOf("obfs=wss")!=-1) {
    cnt = cnt.replace(/tls-verification\s*\=\s*false(\s*)\,/,"")  
     
    cnt = pcsha256!=""? cnt.replace(/tag\s*\=/,"tls-cert-sha256="+pcsha256+", tag=") : cnt
    cnt = ppsha256!=""? cnt.replace(/tag\s*\=/,"tls-pubkey-sha256="+ppsha256+", tag=") : cnt
  }
  return cnt
}

 
function ALPN_Handle(cnt,palpn) {
  cnti = cnt.replace(/\s/gmi,"")  
  if (cnti.indexOf("obfs=over-tls") != -1 || cnti.indexOf("over-tls=true")!=-1) {
    cnt = cnt + ", tls-alpn="+palpn
  }
  return cnt
}

 
 
 
 
 
 
// 【Map Local】把 Surge 的 Map Local 转成 QX 的 response-body / reject。
function IsMapLocalInline(row) {
    var text = row.trim()
    return !/^(?:#|;|\/\/)/.test(text) && /^(?:"[^"]+"|\S+)\s+(?:data(?:-type)?|status-code|header)\s*=/i.test(text) && /\sdata-type\s*=\s*(?:"(?:text|tiny-gif)"|'(?:text|tiny-gif)'|text|tiny-gif)(?=\s|$)/i.test(text)
}

function MapLocalInline2QX(row, ignored) {
    function skip(reason) {
        if (ignored) { ignored.push({ rule: row, reason: reason }) }
        return ""
    }
    var rule = row.match(/^("[^"]+"|\S+)(\s+[\s\S]+)$/)
    if (!rule) { return skip("无法识别 URL 匹配表达式或参数部分") }
    var rest = rule[2], options = Object.create(null)
    while (rest.trim()) {
        var field = rest.match(/^\s+(data-type|data|status-code|header)\s*=\s*/i)
        if (!field) { return skip("含未知参数、行尾注释或参数格式错误") }
        var key = field[1].toLowerCase()
        if (options[key] !== undefined) { return skip("参数 " + key + " 重复") }
        rest = rest.slice(field[0].length)
        var quote = rest[0], end = 0, value = ""
        if (quote === '"' || quote === "'") {
             
            for (end = 1; end < rest.length; end++) {
                if (rest[end] === "\\") { end++; continue }
                if (rest[end] !== quote) { continue }
                if (key !== "data" || /^\s*$|^\s+(?:[a-z][\w-]*\s*=|#|;|\/\/)/i.test(rest.slice(end + 1))) { break }
            }
            if (end >= rest.length) { return skip("参数 " + key + " 的引号未闭合或边界无法识别") }
            value = rest.slice(1, end)
            end++
        } else {
            var token = rest.match(/^[^\s"'\\]+/)
            if (!token) { return skip("参数 " + key + " 缺少有效值") }
            value = token[0]
            end = value.length
        }
        options[key] = value
        rest = rest.slice(end)
        if (rest && !/^\s/.test(rest)) { return skip("参数之间缺少空白分隔") }
    }
    var tinyGif = /^tiny-gif$/i.test(options["data-type"] || "")
    if (!tinyGif && !/^text$/i.test(options["data-type"] || "")) { return skip("data-type 不是 text 或 tiny-gif，无法按内置正文转换") }
    if (!tinyGif && options.data === undefined) { return skip("缺少 data 正文参数") }
    var status = options["status-code"] === undefined ? "200" : options["status-code"]
    if (status !== "200") { return skip("指定状态码为 " + status + "，当前转换仅支持 200") }
    if (options.header !== undefined && !/^Content-Type\s*:\s*[\w.+-]+\/[\w.+-]+(?:\s*;\s*charset\s*=\s*[\w-]+)?\s*$/i.test(options.header)) { return skip("含额外响应头或无法识别的 Content-Type 参数") }
    if (tinyGif) {
        if (options.data !== undefined || (options.header !== undefined && !/^Content-Type\s*:\s*image\/gif\s*$/i.test(options.header))) { return skip("tiny-gif 含自定义正文或非 image/gif 响应头，无法用 reject-img 保留") }
        return rule[1] + " url reject-img"
    }
    var action = "", simpleJSON = options.header === undefined || /^Content-Type\s*:\s*application\/json(?:\s*;\s*charset\s*=\s*[\w-]+)?\s*$/i.test(options.header)
    if (/^[ \t]*$/.test(options.data)) {
        action = "reject-200"
    } else if (simpleJSON) {
        try {
            var body = JSON.parse(options.data)
            if (body && typeof body === "object" && Object.keys(body).length === 0) { action = Array.isArray(body) ? "reject-array" : "reject-dict" }
        } catch (err) {   }
    }
    if (action) { return rule[1] + " url " + action }
     
    if (/[\\$\x00-\x1f\x7f\u2028\u2029]/.test(options.data)) { return skip("正文含 $、反斜线或控制字符，无法保证原样替换") }
    if (options.data !== options.data.trim()) { return skip("非空正文的首尾空白无法保证保留") }
    if (/\s(?:response-body|url-and-header)\s/.test(options.data)) { return skip("正文含重写分隔符，可能被 QX 当作规则语法") }
    return rule[1] + " url response-body ^[\\s\\S]+$ response-body " + options.data
}

function Mock2QXReject(row, filename) {
    if (/dict/i.test(filename)) {
        return row.replace(/ /g, "").split("data=")[0].split("data-type=")[0] + " url " + "reject-dict"
    } else if (/array/i.test(filename)) {
        return row.replace(/ /g, "").split("data=")[0].split("data-type=")[0] + " url " + "reject-array"
    } else if (/(txt|html)/i.test(filename) || filename==null) {
        return row.replace(/ /g, "").split("data=")[0].split("data-type=")[0] + " url " + "reject-200"
    } else if (/(png|jpg|gif)/i.test(filename)) {
        return row.replace(/ /g, "").split("data=")[0].split("data-type=")[0] + " url " + "reject-img"
    } else {
        return row.replace(/ /g, "").split("data=")[0].split("data-type=")[0] + " url " + "reject"
    }
}

 
// 【url-regex】Surge 的 url-regex 重写转成 QX 的 url 重写。
function URX2QX(subs) {
    var nrw = []
    var rw = ""
    subs = subs.split("\n")
     
    var NoteK = ["//", "#", ";"];   
    for (var i = 0; i < subs.length; i++) {
        const notecheck = (item) => subs[i].indexOf(item) == 0
        if (!NoteK.some(notecheck)) {
        if (subs[i].slice(0, 9) == "URL-REGEX") {   
          if (subs[i].indexOf("REJECT") != -1 || subs[i].split(",").length == 2 ) {  
            if (subs[i].replace(/ /g, "").split(",REJECT")[0].split("GEX,")[1].slice(0,1) != "*") {  
            rw = subs[i].replace(/ /g, "").split(",REJECT")[0].split("GEX,")[1] + " url " + "reject-200"
            nrw.push(rw)
          }
          }
        } else if (subs[i].indexOf("data=") != -1 && subs.indexOf("[Map Local]") != -1){  
             
            let fn = subs[i].match(/data=.+\/(.+)"/) ? subs[i].match(/data=.+\/(.+)"/)[1] : null
            if ((!/header=".*content-type/i.test(subs[i]) && /blank/i.test(fn)) || fn==null) {
                rw = Mock2QXReject(subs[i], fn)
            } else {
                rw = subs[i].replace(/ /g, "").split("data=")[0].split("data-type=")[0].replace(/\"/g,"") + " url echo-response text/html echo-response " + subs[i].split("data=")[1].split(" ")[0].replace(/\"/g,"").replace(/ /g, "") 
                if (subs[i].indexOf("header=")!=-1) {
                    if (subs[i].indexOf("Content-Type:") !=-1) {
                        let tpe = subs[i].split("header=")[1].split("Content-Type:")[1].split(",")[0].replace(/\"/g,"")
                        rw = rw.replace(/text\/html/g,tpe)
                    }
                }
            }
            nrw.push(rw)
        } 
    }
    }
     
    return nrw
}

 










// 【JSON-JQ】Surge 的 json-jq 系写法转成 QX 的 jsonjq-response-body。
function IsJsonJQRewrite(row) {
  return /^\s*(?:http-(?:request|response)-jq(?:\s|$)|(?:"[^"]+"|'[^']+'|\S+)\s+(?:response-body-json-jq|request-body-json-jq|response-body-json-del|response-body-json-replace)(?:\s|$))/i.test(row);
}

function JsonJQRewrite2QX(row) {
  function stripOuterJQQuotes(str) {
    str = typeof str == "undefined" || str === null ? "" : String(str).trim();
    if (str.length > 1 && ((str[0] == "'" && str[str.length - 1] == "'") || (str[0] == "\"" && str[str.length - 1] == "\""))) {
      return str.slice(1, -1);
    }
    return str;
  }

  function quoteJQExpression(str) {
    return "'" + str.replace(/'/g, "\\'") + "'";
  }

  function normalizeJsonPattern(pattern) {
    pattern = stripOuterJQQuotes(pattern);
    if (/^\^?https?\??/i.test(pattern)) {
      return pattern;
    }
    return pattern;
  }

  function splitTopLevel(str, delimiter) {
    var parts = [];
    var buf = "";
    var quote = "";
    var escaped = false;
    var depth = 0;
    for (var i = 0; i < str.length; i++) {
      var ch = str[i];
      if (quote) {
        buf += ch;
        if (quote == "\"" && ch == "\\" && !escaped) {
          escaped = true;
          continue;
        }
        if (quote == "'" && ch == "'" && str[i + 1] == "'") {
          buf += str[++i];
          continue;
        }
        if (ch == quote && !escaped) {
          quote = "";
        }
        escaped = false;
      } else if (ch == "\"" || ch == "'") {
        quote = ch;
        buf += ch;
      } else if (ch == "[" || ch == "{" || ch == "(") {
        depth++;
        buf += ch;
      } else if (ch == "]" || ch == "}" || ch == ")") {
        depth--;
        buf += ch;
      } else if (ch == delimiter && depth == 0) {
        if (buf.trim() != "") {
          parts.push(buf.trim());
        }
        buf = "";
      } else {
        buf += ch;
      }
    }
    if (buf.trim() != "") {
      parts.push(buf.trim());
    }
    return parts;
  }

  function splitTopLevelCommaOrSemi(str) {
    var commaParts = splitTopLevel(str, ",");
    if (commaParts.length > 1) {
      return commaParts;
    }
    return splitTopLevel(str, ";");
  }

  function splitTopLevelWhitespace(str) {
    var parts = [];
    var buf = "";
    var quote = "";
    var escaped = false;
    var depth = 0;
    for (var i = 0; i < str.length; i++) {
      var ch = str[i];
      if (quote) {
        buf += ch;
        if (quote == "\"" && ch == "\\" && !escaped) {
          escaped = true;
          continue;
        }
        if (ch == quote && !escaped) {
          quote = "";
        }
        escaped = false;
      } else if (ch == "\"" || ch == "'") {
        quote = ch;
        buf += ch;
      } else if (ch == "[" || ch == "{" || ch == "(") {
        depth++;
        buf += ch;
      } else if (ch == "]" || ch == "}" || ch == ")") {
        depth--;
        buf += ch;
      } else if (/\s/.test(ch) && depth == 0) {
        if (buf.trim() != "") {
          parts.push(buf.trim());
        }
        buf = "";
      } else {
        buf += ch;
      }
    }
    if (buf.trim() != "") {
      parts.push(buf.trim());
    }
    return parts;
  }

  function findTopLevelOperator(str, ops) {
    var quote = "";
    var escaped = false;
    var depth = 0;
    for (var i = 0; i < str.length; i++) {
      var ch = str[i];
      if (quote) {
        if (quote == "\"" && ch == "\\" && !escaped) {
          escaped = true;
          continue;
        }
        if (ch == quote && !escaped) {
          quote = "";
        }
        escaped = false;
      } else if (ch == "\"" || ch == "'") {
        quote = ch;
      } else if (ch == "[" || ch == "{" || ch == "(") {
        depth++;
      } else if (ch == "]" || ch == "}" || ch == ")") {
        depth--;
      } else if (depth == 0) {
        for (var j = 0; j < ops.length; j++) {
          if (str.slice(i, i + ops[j].length) == ops[j]) {
            return { index: i, op: ops[j] };
          }
        }
      }
    }
    return null;
  }

  function normalizeJsonPath(path) {
    path = stripOuterJQQuotes(path);
    if (path.indexOf("$.") == 0) {
      return "." + path.slice(2);
    }
    if (path[0] != "." && path[0] != "[" && path.indexOf("getpath(") != 0) {
      return "." + path;
    }
    return path;
  }

  function pathToSegments(path) {
    path = stripOuterJQQuotes(path);
    if (path.indexOf("$.") == 0) {
      path = path.slice(2);
    } else if (path[0] == "$") {
      path = path.slice(1);
    }
    if (/^\[[\s\S]*\]$/.test(path)) {
      try {
        var arr = JSON.parse(path);
        return Array.isArray(arr) ? arr : null;
      } catch (err) {
        return null;
      }
    }
    path = path.replace(/\[['"]([^'"]+)['"]\]/g, ".$1").replace(/\[(\d+)\]/g, ".$1");
    if (path[0] == ".") {
      path = path.slice(1);
    }
    if (!/^[^.\s]+(\.[^.\s]+)*$/.test(path)) {
      return null;
    }
    return path.split(".").map(function(part) {
      return /^\d+$/.test(part) ? Number(part) : part;
    });
  }

  function canUseDirectJQPath(path) {
    return /^\.[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(path);
  }

  function jqValueLiteral(value) {
    value = stripOuterJQQuotes(value);
    if (value == "") {
      return "null";
    }
    if (/^(true|false|null)$/i.test(value) || /^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(value)) {
      return value.toLowerCase();
    }
    if (/^["\[{]/.test(value) || /^(if\s|\.|getpath\(|setpath\(|del\(|delpaths\()/.test(value)) {
      return value;
    }
    return JSON.stringify(value);
  }

  function buildDelJQ(payload) {
    payload = stripOuterJQQuotes(payload);
    if (/^(del|delpaths)\s*\(/.test(payload)) {
      return payload;
    }
    if (/^\[\s*\[/.test(payload)) {
      return "delpaths(" + payload + ")";
    }
    var paths = splitTopLevelCommaOrSemi(payload);
    if (paths.length == 1) {
      var ws = splitTopLevelWhitespace(payload);
      if (ws.length > 1) {
        paths = ws;
      }
    }
    paths = paths.map(function(path) {
      return normalizeJsonPath(path);
    }).filter(Boolean);
    if (paths.length == 0) {
      return "";
    }
    if (paths.every(canUseDirectJQPath)) {
      return "del(" + paths.join(", ") + ")";
    }
    var segments = paths.map(pathToSegments);
    if (segments.every(function(item) { return Array.isArray(item) })) {
      return "delpaths(" + JSON.stringify(segments) + ")";
    }
    return "del(" + paths.join(", ") + ")";
  }

  function parseReplacePair(item) {
    var found = findTopLevelOperator(item, ["=>", "="]);
    if (found) {
      return {
        path: item.slice(0, found.index).trim(),
        value: item.slice(found.index + found.op.length).trim()
      };
    }
    var parts = splitTopLevelWhitespace(item);
    if (parts.length >= 2) {
      return {
        path: parts[0],
        value: parts.slice(1).join(" ")
      };
    }
    return null;
  }

  function buildSafeSetpath(path, value) {
    var segments = pathToSegments(path);
    var literal = jqValueLiteral(value);
    if (!segments || segments.length == 0) {
      return normalizeJsonPath(path) + " = " + literal;
    }
    var parent = segments.slice(0, -1);
    var key = segments[segments.length - 1];
    var typeCheck = typeof key == "number" ? "type == \"array\" and has(" + key + ")" : "type == \"object\" and has(" + JSON.stringify(key) + ")";
    return "if (getpath(" + JSON.stringify(parent) + ")? | " + typeCheck + ") then setpath(" + JSON.stringify(segments) + "; " + literal + ") else . end";
  }

  function buildReplaceJQ(payload) {
    payload = stripOuterJQQuotes(payload);
    if (/^(if\s|setpath\(|getpath\(|reduce\s|map\(|walk\()/.test(payload)) {
      return payload;
    }
    try {
      var obj = JSON.parse(payload);
      if (obj && typeof obj == "object" && !Array.isArray(obj)) {
        return Object.keys(obj).map(function(key) {
          return buildSafeSetpath(key, JSON.stringify(obj[key]));
        }).join(" | ");
      }
    } catch (err) {}
    var items = splitTopLevelCommaOrSemi(payload);
    var expressions = [];
    for (var i = 0; i < items.length; i++) {
      var pair = parseReplacePair(items[i]);
      if (pair) {
        expressions.push(buildSafeSetpath(pair.path, pair.value));
      }
    }
    return expressions.join(" | ");
  }

   
  var surge = row.match(/^\s*http-(request|response)-jq\s+(\"[^\"]+\"|'[^']+'|\S+)\s+([\s\S]+?)\s*$/i);
  if (surge) {
    var surgePattern = normalizeJsonPattern(surge[2]);
    if (/^http-(?:request|response)(?:-jq)?$/i.test(surgePattern) || /\s|^["']/.test(surgePattern)) { return "" }
    var expression = surge[3].trim();
    if ((expression[0] == "'" || expression[0] == '"') && expression.slice(-1) != expression[0]) { return "" }
    row = surge[2] + " " + surge[1].toLowerCase() + "-body-json-jq " + expression;
  }
  var matched = row.match(/^\s*(\"[^\"]+\"|'[^']+'|\S+)\s+(response-body-json-jq|request-body-json-jq|response-body-json-del|response-body-json-replace)\s+([\s\S]+?)\s*$/i);
  if (!matched) { return "" }
  var pattern = normalizeJsonPattern(matched[1]);
  var action = matched[2].toLowerCase();
  var body = matched[3].trim();
  var type = action == "request-body-json-jq" ? "jsonjq-request-body" : "jsonjq-response-body";
  var jq = "";
  if (action == "response-body-json-del") {
    jq = buildDelJQ(body);
  } else if (action == "response-body-json-replace") {
    jq = buildReplaceJQ(body);
  } else {
    jq = stripOuterJQQuotes(body);
  }
  return jq ? pattern + " url " + type + " " + quoteJQExpression(jq) : "";
}

 
// 【脚本重写】script-path 系条目转成 QX 的 script-response-body / script-request-header。
function SCP2QX(subs) {
  var nrw = []
  var rw = ""
  var RewriteK = [" url 302", " url 307", " url reject", " url script", " url req", " url res", " url echo", " url-and-header 302", " url-and-header 307", " url-and-header reject", " url-and-header script", " url-and-header req", " url-and-header res", " url-and-header echo", " url jsonjq"]  
  var rawSubs = subs.split("\n").map(x => x.trim())
  subs = rawSubs.map(x => x.replace(/\s+/g," "))
   
  for (var i = 0; i < subs.length; i++) {
    try {
       
      subs[i] = subs[i].replace("^http","http")  
      if (subs[i].slice(0, 8) == "hostname") {
        hn = subs[i].replace(/\%.*\%/g, "").replace(/\:\d*/g,"")
        nrw.push(hn)
      }
      var SC = ["type=", ".js", "pattern=", "script-path="]
      var NoteK = ["//", "#", ";"];  
      const sccheck = (item) => subs[i].indexOf(item) != -1
      const notecheck = (item) => subs[i].indexOf(item) == 0
      const RewriteCheck = (item) => subs[i].indexOf(item) != -1 ;  
      if (!NoteK.some(notecheck) && !RewriteK.some(RewriteCheck)){
        if(Pdbg==1) {$notify("rewrite-check","",subs[i])}
        if (IsJsonJQRewrite(rawSubs[i])) {
          rw = JsonJQRewrite2QX(rawSubs[i])
          if (rw != "") {
            nrw.push(rw)
          }
        } else if (SC.every(sccheck)) {  
           
          ptn = subs[i].replace(/\s/gi,"").split("pattern=")[1].split(/\,[a-zA-Z]/)[0] 
          js = subs[i].replace(/\s/gi,"").split("script-path=")[1].split(",")[0]
          type = subs[i].replace(/\s/gi,"").split("type=")[1].split(",")[0].trim()
          subsi = subs[i].replace(/ /g,"").replace(/\=true/g,"=1")
          if (type == "http-response" && subsi.indexOf("requires-body=1") != -1) {
            type = "script-response-body "
          } else if (type == "http-response" && subsi.indexOf("requires-body=1") == -1) {
            type = "script-response-header "
          } else if (type == "http-request" && subsi.indexOf("requires-body=1") != -1) {
            type = "script-request-body "
          } else if (type == "http-request" && subsi.indexOf("requires-body=1") == -1) {
            type = "script-request-header "
          } else {type = "" }
          if (type != "") {
            rw = ptn + " url " + type + js
            nrw.push(rw)
          }
        } else if (/\d\s30(7|2)$/.test(subs[i])) {  
           
           
          rw = subs[i].split(" ")[0] + " url " + subs[i].split(" ")[2] + " " + subs[i].split(" ")[1].trim()
           
          nrw.push(rw)
        } else if (/\d\s\-\s30(2|7)\s/.test(subs[i])) {  
           
          rw = subs[i].replace(" - "," url ")
          nrw.push(rw)
        } else if(subs[i].split(" ")[2] == "header") {  
          var pget = subs[i].split(" ")[0].split(".com")[1]
          var pgetn = subs[i].split(" ")[1].split(".com")[1]
          rw = subs[i].split(" ")[0] + " url 302 " + subs[i].split(" ")[1]
           
          nrw.push(rw)
        } else if(subs[i].split(" ")[1] == "header-replace") {  
          console.log(subs[i])
          var pget = subs[i].split("header-replace")[1].split(":")[0].trim()
          var pgetn = subs[i].split("header-replace")[1].trim()
          rw = subs[i].split(" ")[0] + " url request-header " +"(.+\\r\\n)"+pget+":.+(\\r\\n) request-header " + "$1" + pgetn + "$2"
          nrw.push(rw)
        } else if(subs[i].indexOf(" _ reject") != -1) {  
          rw = subs[i].split(" ")[0] + " url reject-200"
          nrw.push(rw)
        } else if(subs[i].indexOf(" - reject") != -1 || subs[i].indexOf(" - REJECT") != -1) {  
          rw = subs[i].replace(" - ", " url ").toLowerCase()
          nrw.push(rw)
        } else if(subs[i].split(" ").length == 2 && (/\s(reject)$/.test(subs[i]) || /\s(reject\-)/.test(subs[i]))){  
          rw = subs[i].replace(" reject", " url reject")
          nrw.push(rw)
        } else if (subs[i].indexOf("script-path") != -1) {  
          type = subs[i].replace(/\s+/g," ").split(" ")[0]
          js = subs[i].split("script-path")[1].split("=")[1].split(",")[0]
          ptn = subs[i].replace(/\s+/g," ").split(" ")[1]
          subsi = subs[i].replace(/ /g,"").replace(/\=true/g,"=1")
          if (type == "http-response" && subsi.indexOf("requires-body=1") != -1) {
            type = "script-response-body "
          } else if (type == "http-response" && subsi.indexOf("requires-body=1") == -1) {
            type = "script-response-header "
          } else if (type == "http-request" && subsi.indexOf("requires-body=1") != -1) {
            type = "script-request-body "
          } else if (type == "http-request" && subsi.indexOf("requires-body=1") == -1) {
            type = "script-request-header "
          } else {type = "" }
          if (type != "") {
            rw = ptn + " url " + type + js
            nrw.push(rw)
          } 
        }
      } else if(RewriteK.some(RewriteCheck)) {
        nrw.push(subs[i])
      }
    } catch (err) {
      $notify("❌️解析此条时出现错误，已忽略",subs[i],err)
    }
  }
  return nrw
}

 
// 【模块】Surge module 整体转重写。
function SGMD2QX(subs) {
    var nrw0 = URX2QX(subs)
    var nrw1 = SCP2QX(subs)
    var nrwt = [...nrw0, ...nrw1]
    return nrwt
}

 
// 【重写筛选】按 in / out / regex / regout 留删，只动正文不动行首说明。
function Rewrite_Filter(subs, Pin, Pout,Preg,Pregout, hasUnsupported) {
    if (!subs.length && hasUnsupported) { return [] }  
    var Nlist = [];
    var noteK = ["//", "#", ";"];
    var hnc = 0;
    var dwrite = []
    var hostname = ""
     
    for (var i = 0; i < subs.length; i++) {
        var noteParts = RuleNoteSplit(subs[i].trim());
        subi = noteParts.body;
        var subii = subi.replace(/ /g, "")
        if (subi != "" && (subi.indexOf(" url ")!=-1 || subi.indexOf("host")!=-1 || /^(?:ip-cidr|ip6-cidr|geoip|ip-asn|user-agent)\s*,/i.test(subi) || subi.indexOf(" url-and-header ")!=-1 || /^hostname\=/.test(subii))) {
            const notecheck = (item) => subi.indexOf(item) == 0
            if (noteK.some(notecheck)) {  
                continue;
            } else if (hnc == 0 && subii.indexOf("hostname=") == 0) {  
                hostname = (Phin0 || Phout0 || Preg || Pregout) ? HostNamecheck(subi, Phin0, Phout0) : subi; 
            } else if (subii.indexOf("hostname=") != 0) {  
                var inflag = Rcheck(subi, Pin);
                var outflag = Rcheck(subi, Pout);
                if (outflag == 1 || inflag == 0) {
                    dwrite.push(RuleNoteJoin(noteParts.note, /^[a-z][\w-]*\s*,/i.test(subi) ? "-" + subi : subi.replace(" url "," - ").replace(" url-and-header "," - ")));  
                } else if (outflag == 0 && inflag != 0) {  
                    Nlist.push(RuleNoteJoin(noteParts.note, subi));
                } else if (outflag == 2 && inflag != 0) {  
                    Nlist.push(RuleNoteJoin(noteParts.note, subi));
                }
            }
        }
    }

    if (Pntf0 != 0) {
        nowrite = dwrite.length <= 10 ? emojino[dwrite.length] : dwrite.length
        no1write = Nlist.length <= 10 ? emojino[Nlist.length] : Nlist.length
        if (Pin0 && no1write != " 0️⃣ ") {  
          if (Pout!=0) {
            $notify("🤖 " + "重写引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 筛选参数: " + pfi + pfo, "☠️ 重写 rewrite 中保留以下" + no1write + "个匹配项:" + "\n ⨷ " + Nlist.join("\n ⨷ "), rwrite_link)
          }
        } else if (dwrite.length > 0) {
          if (Pout0!=0) {
            $notify("🤖 " + "重写引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 筛选参数: " + pfi + pfo, "☠️ 重写 rewrite 中已禁用以下" + nowrite + "个匹配项:" + "\n ⨷ " + dwrite.join("\n ⨷ "), rwrite_link)
          }
        }
    }

    if (Nlist.length == 0 ) { 
      if ((Pin0 || Pout0 || Phin0 || Phout0 || Pregout || Preg)) {
        $notify("🤖 " + "重写引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 筛选参数: " + pfi + pfo, "⚠️ 筛选后剩余rewrite规则数为 0️⃣ 条, 请检查参数及原始链接", nan_link) 
      } else {
        $notify("🤖 " + "重写引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 解析后 rewrite 规则数为 0️⃣ 条 " , "⚠️ 请检查参数及原始链接内容", nan_link) 
      
      }
    }
    if(Preg){ Nlist = Nlist.map(Regex).filter(Boolean)  
      RegCheck(Nlist, "重写引用", "regex", Preg) }
    if(Pregout){ Nlist = Nlist.map(RegexOut).filter(Boolean)  
      RegCheck(Nlist, "重写引用", "regout", Pregout) }
    if (hostname != "") { Nlist.push(hostname) }
    Nlist =Phide ==1? Nlist : [...dwrite,...Nlist]
     
    return Nlist
}

 
// 【主机名筛选】inhn / outhn 单独处理，比正文筛选先执行。
function HostNamecheck(content, parain, paraout) {
    var hname = content.replace(/ /g, "").split("=")[1].split(",");
    var nname = [];
    var dname = [];  
    for (var i = 0; i < hname.length; i++) {
        dd = hname[i]
        const excludehn = (item) => dd.indexOf(item) != -1;
        if (paraout && paraout != "") {  
            if (!paraout.some(excludehn)) {  
                if (parain && parain != "") {
                    if (parain.some(excludehn)) {  
                        nname.push(hname[i])
                    } else {
                        dname.push(hname[i])
                    }  
                } else { nname.push(hname[i]) }  
            } else { dname.push(hname[i]) }  
        } else if (parain && parain != "") {  
            if (parain.some(excludehn)) {  
                nname.push(hname[i])
            } else { dname.push(hname[i]) }
        } else {
            nname.push(hname[i])
        }
    }  
    if (Pntf0 != 0) {
        if (paraout || parain) {
            var noname = dname.length <= 10 ? emojino[dname.length] : dname.length
            var no1name = nname.length <= 10 ? emojino[nname.length] : nname.length
            if (parain && no1name != " 0️⃣ ") {
                $notify("🤖 " + "重写引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 筛选参数: " + pfihn + pfohn, "☠️ 主机名 hostname 中已保留以下" + no1name + "个匹配项:" + "\n ⨷ " + nname.join(","), rwhost_link)
            } else if (dname.length > 0) {
                $notify("🤖 " + "重写引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 筛选参数: " + pfihn + pfohn, "☠️ 主机名 hostname 中已删除以下" + noname + "个匹配项:" + "\n ⨷ " + dname.join(","), rwhost_link)
            }
        }
    }
    if (nname.length == 0) {
        $notify("🤖 " + "重写引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 筛选参数: " + pfihn + pfohn, "⚠️ 主机名 hostname 中剩余 0️⃣ 项, 请检查参数及原始链接", nan_link)
    }
    if(Preg){ nname = nname.map(Regex).filter(Boolean)
      RegCheck(nname, "主机名hostname","regex", Preg) }
    if(Pregout){ nname = nname.map(RegexOut).filter(Boolean)
      RegCheck(nname, "主机名hostname", "regout", Pregout) }
    hname = "hostname=" + nname.join(", ");
    return hname
}

 
function Rcheck(content, param) {
    name = content.toUpperCase()
    if (param) {
        var flag = 0;  
        const checkpara = (item) => name.indexOf(item.toUpperCase()) != -1;
        if (param.some(checkpara)) {
            flag = 1  
        }
        return flag
    } else {  
        return 2
    }  
}

 
// 【分流转换】把 Surge / Clash / QX 各种分流写法统一成 QX 的 host / ip 规则。
function Rule_Handle(subs, Pout, Pin) {
    cnt = subs  
    Tin = Pin;  
    Tout = Pout;  
    ply = Ppolicy;  
    var nlist = []
    var ignored = []
    var RuleK = ["//", "#", ";","[","^"];  
    var RuleK2 = ["host,", "-suffix,", "domain,", "-keyword,", "ip-cidr,", "ip-cidr6,",  "geoip,", "user-agent,", "ip6-cidr,", "ip-asn"];
     
    if (Tout != "" && Tout != null) {  
        var dlist = [];
        for (var i = 0; i < cnt.length; i++) {
            cc = cnt[i].replace(/^\s*\-\s/g,"").trim()
             
            const exclude = (item) => RuleNoteBody(cc).indexOf(item) != -1;  
            const RuleCheck = (item) => cc.toLowerCase().indexOf(item) != -1;  
            const CommentCheck = (item) => RuleNoteBody(cc).toLowerCase().indexOf(item) == 0;  
            if (Tout.some(exclude) && !RuleK.some(CommentCheck) ) {
               
                dlist.push(RuleNoteMap(Rule_Policy(cc, ignored), body => body ? "-" + body : ""))  
            } else if (!RuleK.some(CommentCheck) && cc ) {  
               
                dd = Rule_Policy(cc, ignored);
                if (Tin != "" && Tin != null) {
                    const include = (item) => RuleNoteBody(dd).indexOf(item) != -1;  
                    if (Tin.some(include)) {
                        nlist.push(dd);
                    }
                } else {
                    nlist.push(dd);
                }
            }  
        } 
        var no = dlist.length <= 10 ? emojino[dlist.length] : dlist.length
        if (dlist.length > 0) {
            if (Pntf0 != 0) { $notify("🤖 " + "分流引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 禁用: " + Tout, "☠️ 已禁用以下" + no + "条匹配规则:" + "\n ⨷ " + dlist.join("\n ⨷ "), rule_link) }
        } else { $notify("🤖 " + "分流引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 禁用: " + Tout, "⚠️ 未发现任何匹配项, 请检查参数或原始链接", nan_link) }
        if (Tin != "" && Tin != null) {   
            if (nlist.length > 0) {
                var noin0 = nlist.length <= 10 ? emojino[nlist.length] : nlist.length
                if (Pntf0 != 0) {
                    $notify("🤖 " + "分流引用  ➟ " + "⟦" + subtag + "⟧", "✅ 保留:" + Tin, "🎯 已保留以下 " + noin0 + "条匹配规则:" + "\n ⨁ " + nlist.join("\n ⨁ "), rule_link)
                }
            } else {
                $notify("🤖 " + "分流引用  ➟ " + "⟦" + subtag + "⟧", "✅ 保留:" + Tin + ",⛔️ 禁用: " + Tout, "⚠️ 筛选后剩余规则数为 0️⃣ 条, 请检查参数及原始链接", nan_link)
            }
        } else { 
            if (nlist.length == 0) {
                $notify("🤖 " + "分流引用  ➟ " + "⟦" + subtag + "⟧", "⛔️ 禁用: " + Tout, "⚠️ 筛选后剩余规则数为 0️⃣ 条, 请检查参数及原始链接", nan_link)
            }
        }
      nlist =Phide ==1? nlist : [...dlist,...nlist]
         
    } else if (Tin != "" && Tin != null) {  
        var dlist = [];
        for (var i = 0; i < cnt.length; i++) {
            cc = cnt[i].replace(/^\s*\-\s/g,"").trim()
            const RuleCheck = (item) => cc.indexOf(item) != -1;  
            const CommentCheck = (item) => RuleNoteBody(cc).toLowerCase().indexOf(item) == 0;  
            if (!RuleK.some(CommentCheck) && cc) {  
                dd = Rule_Policy(cc, ignored);
                const include = (item) => RuleNoteBody(dd).indexOf(item) != -1;  
                if (Tin.some(include)) {
                    nlist.push(dd);
                } else { dlist.push(RuleNoteMap(dd, body => body ? "-" + body : "")) }
            }
        }  
        if (nlist.length > 0) {
            var noin = nlist.length <= 10 ? emojino[nlist.length] : nlist.length
            if (Pntf0 != 0) {
                $notify("🤖 " + "分流引用  ➟ " + "⟦" + subtag + "⟧", "✅ 保留:" + Tin, "🎯 已保留以下 " + noin + "条匹配规则:" + "\n ⨁ " + nlist.join("\n ⨁ "), rule_link)
            }
        } else { $notify("🤖 " + "分流引用  ➟ " + "⟦" + subtag + "⟧", "✅ 保留:" + Tin, "⚠️ 筛选后剩余规则数为 0️⃣ 条, 请检查参数及原始链接", nan_link) }
      nlist =Phide ==1? nlist : [...dlist,...nlist]
       
    } else {   
      nlist = cnt.map(function (row) { return Rule_Policy(row, ignored) })
         
    }
  nlist = nlist.filter(item => item && item != "-")  
  nlist = Pfcr == 1? nlist.filter(Boolean).map(item => item+", force-cellular") : nlist.filter(Boolean)
  nlist = Pfcr == 2? nlist.filter(Boolean).map(item => item+", multi-interface") : nlist.filter(Boolean)
  nlist = Pfcr == 3? nlist.filter(Boolean).map(item => item+", multi-interface-balance") : nlist.filter(Boolean)

  if (Pvia!="") {
    nlist = Pvia ==0? nlist.filter(Boolean).map(item => item+", via-interface=%TUN%") : nlist.filter(Boolean).map(item => item+", via-interface="+Pvia)
  }

  nlist=nlist.map(item=>RuleNoteMap(item, body => body.replace(/:\d*\s*,/g,",").replace(/(\'|\")/g,"").replace(/(\-suffix|\-SUFFIX)\s*\,\s*\./g,"$1, ")))  
  NotifyUnsupportedRules(ignored)
   
  return nlist
}

// 【策略改写】policy 参数：替换或补上规则里的策略组。
function Rule_Policy(content, ignored) {  
    var noteParts = RuleNoteSplit(content);
    if (noteParts.note) {
        var failureStart = Array.isArray(ignored) ? ignored.length : 0;
        var converted = Rule_Policy(noteParts.body, ignored);
        if (Array.isArray(ignored)) {
            for (var n = failureStart; n < ignored.length; n++) { ignored[n].rule = RuleNoteJoin(noteParts.note, ignored[n].rule) }
        }
        return RuleNoteJoin(noteParts.note, converted);
    }
    function skip(reason) {
        if (Array.isArray(ignored) && /^[a-z][\w-]*\s*,/i.test(content.trim())) { ignored.push({rule: content, reason: reason}) }
        return "";
    }
    if (/^(?:AND|OR|NOT)\s*,/i.test(content.trim())) { return skip("逻辑组合规则无法直接转换，拆开会改变匹配条件") }
    if (/^URL-REGEX\s*,/i.test(content.trim())) { return skip("URL-REGEX 需要作为重写资源导入，不是 Quantumult X 分流语法") }
    var cnt = content.replace(/^\s*\-\s/g,"").replace(/REJECT-TINYGIF/gi,"reject").replace(/REJECT-DROP/gi,"reject").trim().split("//")[0].trim().split(",");
     
     
    cnt = cnt.map(function (part) { return part.trim() });
    if (/^(?:domain(?:-suffix|-keyword|-wildcard|-regex)?|host(?:-suffix|-keyword|-wildcard)?|ip-cidr6?|ip6-cidr|ip-asn|geoip|user-agent)$/i.test(cnt[0])) {
        cnt = cnt.slice(0, 2).concat(cnt.slice(2).filter(function (part) { return !/^(?:no-resolve|pre-matching|extended-matching)$/i.test(part) }));
        if (cnt[1]) { cnt[1] = cnt[1].replace(/^(["'])([\s\S]*)\1$/, "$2") }
    }
     
     
    if (/^domain-regex$/i.test(cnt[0].trim())) {
        var pattern = (cnt[1] || "").trim();
        if (!/^\^?(?:[a-z0-9_-]|\\\.|\.\*?)+\$?$/i.test(pattern)) {
            if (Array.isArray(ignored)) { return skip("DOMAIN-REGEX 含无法转换为 host-wildcard 的复杂或无效正则") }
            $notify("⚠️ DOMAIN-REGEX 无法转换为 Quantumult X 通配符规则", "已忽略该条复杂或无效正则，其余规则继续处理", content);
            return "";
        }
        var wildcard = pattern.replace(/^\^|\$$/g, "").replace(/\\\.|\.\*|\./g, token => token == "\\." ? "." : token == ".*" ? "*" : "?");
        cnt[0] = "host-wildcard";
        cnt[1] = ((pattern[0] == "^" ? "" : "*") + wildcard + (pattern.slice(-1) == "$" ? "" : "*")).replace(/\*+/g, "*");
    }
    var RuleK = ["//", "#", ";","[","/", "hostname","no-ipv6","no-system","<","{","}","]","^"];
    var RuleK1 = ["host", "host-suffix", "host-keyword", "host-wildcard", "domain", "domain-suffix", "domain-keyword", "domain-wildcard", "ip-cidr", "ip-cidr6", "geoip", "user-agent", "ip6-cidr", "ip-asn"];
    const RuleCheck = (item) => cnt[0].trim().toLowerCase().indexOf(item) == 0;  
    const RuleCheck1 = (item) => cnt[0].trim().toLowerCase() == item;  
    if (RuleK1.some(RuleCheck1) && !RuleK.some(RuleCheck) ) {
        if (!cnt[1] || (cnt.length > 2 && !cnt[2])) { return skip("分流缺少匹配内容或有效策略") }
        if (cnt.length == 3 && cnt.indexOf("no-resolve") == -1) {
            ply0 = Ppolicy != "Minimax" ? Ppolicy : cnt[2]
            nn = cnt[0] + ", " + cnt[1] + ", " + ply0
        } else if (cnt.length == 4 && cnt.indexOf("no-resolve") != -1) {  
          nn = cnt.join(",").replace(",no-resolve","")
        } else if (cnt.length == 2) {  
            ply0 = Ppolicy != "Minimax" ? Ppolicy : "Minimax"
            nn = cnt[1].trim() !=""? cnt[0] + ", " + cnt[1] + ", " + ply0 : ""
        } else if (cnt.length == 3 && cnt[2].indexOf("no-resolve") != -1) {
            ply0 = Ppolicy != "Minimax" ? Ppolicy : "Minimax"
            nn = cnt[0] + ", " + cnt[1] + ", " + ply0  
        } else if (cnt.length == 4 && cnt[3].indexOf("no-resolve") != -1) {
            ply0 = Ppolicy != "Minimax" ? Ppolicy : cnt[2]
            nn = cnt[0] + ", " + cnt[1] + ", " + ply0  
        } else if (!RuleK.some(RuleCheck) && content) {
             
            return skip("分流参数数量或附加参数无法识别，未擅自删除未知条件")
        } else { return "" }
        if (cnt[0].indexOf("URL-REGEX") != -1 || cnt[0].indexOf("PROCESS") != -1) {
            nn = ""
        } else { 
          nn = nn.replace(/^ip-cidr6/i, "ip6-cidr").replace(/^domain/i,"host")
        }
        return nn
    } else if (cnt.length == 1 && !RuleK.some(RuleCheck) && cnt[0]!="" && cnt[0].indexOf("payload:")==-1 && cnt[0].indexOf("=")==-1 && cnt[0].trim()!="https:") {  
       
      return rule_list_handle(cnt[0])
    } else { 
       
      return skip("当前解析器没有此分流类型的可靠转换") } 
}

 
// 【纯列表】只有域名或 IP 的列表，含 clash provider 的写法。
function rule_list_handle(cnt) {
  var noteParts = RuleNoteSplit(cnt);
  if (noteParts.note) { return RuleNoteJoin(noteParts.note, rule_list_handle(noteParts.body)) }
  if (/^[ \t]*\{#/.test(cnt)) { return "" }  
  var RuleK = ["//", "#", ";", "[", "!", "/"]
  const RuleCheck = (item) => cnt.trim().indexOf(item) == 0;  
  const nocheck = (item) => /^\d+$/.test(item)  
  cnt = cnt.split("#")[0].trim()  
  if (cnt.trim().indexOf(" ") == -1 && cnt.trim() != "" && !RuleK.some(RuleCheck)) {
    if (cnt.indexOf("::") != -1 && cnt.indexOf("/") != -1) {  
      cnt = "ip6-cidr, " + cnt
      cnt = Ppolicy == "Minimax" ? cnt + ", Minimax" : cnt + ", " + Ppolicy
    } else if (cnt.split("/").length == 2) { 
      cnt = "ip-cidr, " + cnt
      cnt = Ppolicy == "Minimax" ? cnt + ", Minimax" : cnt + ", " + Ppolicy
    } else if (cnt.split(".").length == 4 && cnt.split(".").every(nocheck)) {   
      cnt = "ip-cidr, " + cnt + "/32"
      cnt = Ppolicy == "Minimax" ? cnt + ", Minimax" : cnt + ", " + Ppolicy
    } else if (cnt.indexOf("payload:") == -1) {  
       
       

      if (!/^('|")/.test(cnt)) {  
        if (!/\*|\+/.test(cnt[0])) {
          cnt = cnt[0] == "." ? cnt.replace(".", "") : cnt
          cnt = "host-suffix, " + cnt
        } else {
          cnt = "host-wildcard, " + cnt
        }
      } else {  
        cnt = cnt.replace(/'|"/g, "").trim()

        if (/^\.|\*\./.test(cnt) || cnt.indexOf("*") != -1) {
           
           
          cnt = "host-wildcard, " + cnt.replace(/^\.|\*\./, "*.")
        } else {
          cnt = "host-suffix, " + cnt.replace(/^(\+\.)/, "") 
        }
      }
      cnt = Ppolicy == "Minimax" ? cnt + ", Minimax" : cnt + ", " + Ppolicy
    }
  }
  return cnt
}

 
// 【域名集】domain-set 转成分流规则。
function Domain2Rule(content) {
    var cnt = content.split("\n");
    var RuleK = ["//", "#", ";","["]
    var nlist = []
    for (var i = 0; i< cnt.length; i++) {
        var noteParts = RuleNoteSplit(cnt[i].trim());
        cc = noteParts.body;
        const RuleCheck = (item) => cc.indexOf(item) != -1;  
        if(!RuleK.some(RuleCheck) && cc) {
            if (cc[0] == "."){
                nlist.push(RuleNoteJoin(noteParts.note, "host-suffix, " + cc.slice(1 , cc.length)))
            } else {
                nlist.push(RuleNoteJoin(noteParts.note, "host, " + cc))
            }
        }
    }
    return nlist.join("\n")
}
 
// 【多策略】pset：同一份规则里按关键词分派不同策略组。
function policy_sets(cnt,para) {
  pcnt = para.split("+")
  cnt=cnt 
  for (i=0;i<pcnt.length;i++){
    console.log(pcnt[i])
    if (pcnt[i].indexOf("@")!=-1){
      cnt = cnt.map(item => filter_set(item, pcnt[i]))
    }
  }
  cnt=cnt.filter(Boolean) 
  return cnt
  console.log(cnt)
}

 
function filter_set(cnt,para){
  var noteParts = RuleNoteSplit(cnt);
  if (noteParts.note) { return RuleNoteJoin(noteParts.note, filter_set(noteParts.body, para)) }
  if (cnt){
    paras=[para.split("@")[0],para.slice(para.split("@")[0].length+"@".length)]
    console.log(para.split("@")[0].length+"@".length,paras)
    cnt = cnt.split(",")
    reg = RegExp(paras[0])
    console.log(paras,cnt)
    if(cnt.length == 3){
      if (reg.test(cnt[1]) || reg.test(cnt[2])) {
        cnt[2] = paras[1]
      }
    }
    return cnt.join(",")
  }
}


 
 
// 【正文替换】replace：对重写、分流正文做正则替换。
function ReplaceReg(cnt, para) {
    var cnt0 = cnt 
     
    var pp = para.replace(/\\\@/g,"atsymbol").replace(/\\\+/g,"plussymbol").split("+");
    for (var i = 0; i < pp.length; i++) {
        var p1 = decodeURIComponent(pp[i].split("@")[0]).replace(/atsymbol/g,"\@").replace(/plussymbol/g,"\\\+").replace(/\，/g,",");
        var p2 = decodeURIComponent(pp[i].split("@")[1]).replace(/atsymbol/g,"@").replace(/plussymbol/g,"+").replace(/\，/g,",");
        p1 = new RegExp(p1, "gmi");
        cnt0 = cnt0.map(item => flag == 2 || flag == 3 ? RuleNoteMap(item, body => body.replace(p1, p2)) : item.replace(p1, p2));
         
    }
   
    return cnt0 
}


 
function param(res,org,mbody) {
  if(mbody.indexOf(org)!=-1) {
    tmp=mbody.split(org)[1].split("&")[0].split("#")[0].replace(/\s/,"")
    tmp = tmp!=""? res+"="+tmp : ""
    return tmp
  }
  else return ""
}

 
// 【REALITY】补齐 pbk / sid / flow 这几个 VLESS REALITY 字段。
function Reality_Handle(cnt) {
 
  a1=param("reality-base64-pubkey","pbk=",cnt)
  a2=param("reality-hex-shortid","sid=",cnt)
  a3=(cnt.indexOf("flow=xtls-rprx-vision")!=-1 || cnt.indexOf("xtls=2")!=-1)? "vless-flow=xtls-rprx-vision": ""
  rnt=[a1,a2,a3].filter(Boolean).join(", ")
  return rnt
}


 
// 【订阅转节点】逐行判断协议，交给对应的转换函数。
function Subs2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {
  if (Pdbg) {$notify("subs", "node", subs)}
    var list0 = subs.split("\n");
    var QuanXK = ["shadowsocks=", "trojan=", "vmess=", "http=","socks5=", "vless=", "anytls="];
    var SurgeK = ["=ss,", "=vmess,", "=trojan,", "=http,", "=https,", "=custom,", "=socks5", "=socks5-tls","=anytls"];
    var LoonK = ["=Shadowsocks", "=ShadowsocksR", "=Trojan", "=VLESS","=AnyTLS"]
    var QXlist = [];
    var failedList = [];
    for (var i = 0; i < list0.length; i++) {
        var node = ""
        var hy2Kind = HY2LineKind(list0[i])
        if (hy2Kind) {
          node = HY2Convert(hy2Kind, list0[i])
          if (node) QXlist.push(node)
          continue
        }
         
        if (list0[i].trim().length > 3 && !/\;|\/|\#/.test(list0[i][0]) && list0[i].indexOf(" url ")==-1) {
            var type = list0[i].split("://")[0].trim()
            var listi = list0[i].replace(/ /g, "")
            var tag0 = list0[i].indexOf("tag=")!=-1 ? list0[i].split(/\&*(emoji|udp|tfo|cert|rename|replace)\=/)[0].split("tag=")[1] : ""
            list0[i] = (type=="ssr") ? list0[i].split(/#|,|，/)[0] : list0[i]  
            const NodeCheck = (item) => listi.toLowerCase().indexOf(item) != -1;
            const NodeCheck1 = (item) => listi.toLowerCase().indexOf(item) == 0;
            const NodeCheck2 = (item) => listi.indexOf(item) != -1;
            try {
              if (Pdbg) {$notify(i, type, list0[i])}
                if (type == "vmess" && (list0[i].indexOf("remark=") == -1 && list0[i].indexOf("remarks=") == -1) && !/(obfs|alterId|type|\@)\=/.test(list0[i])) {
                    var bnode = Base64.decode(list0[i].split("vmess://")[1])
                    if (bnode.indexOf("over-tls=") == -1) {  
                        node = V2QX(list0[i], Pudp, Ptfo, Pcert0, PTls13)
                    } else {  
                        node = VQ2QX(list0[i], Pudp, Ptfo, Pcert0, PTls13)
                    }
                  node = tag0 != "" ? URI_TAG(node, tag0) : node
                } else if (type == "vmess" && ( list0[i].indexOf("remark=") != -1 || list0[i].indexOf("remarks=") != -1 || /(obfs|alterId|type|\@)\=/.test(list0[i]))) {  
                    node = VR2QX(list0[i], Pudp, Ptfo, Pcert0, PTls13)
                    node = tag0 != "" ? URI_TAG(node, tag0) : node
                } else if (type == "socks" && list0[i].indexOf("remarks=") != -1) {  
                    node = S5R2QX(list0[i])
                    node = tag0 != "" ? URI_TAG(node, tag0) : node
                } else if (type == "ssocks" && list0[i].indexOf("remarks=") != -1) {  
                    node = S5R2QX(list0[i],tlsp="over-tls")
                    node = tag0 != "" ? URI_TAG(node, tag0) : node
                } else if (type == "socks" && list0[i].indexOf("remarks=") == -1) {  
                    node = Socks2QX(list0[i])
                    node = tag0 != "" ? URI_TAG(node, tag0) : node
                } else if (type == "ssr") {
                    node = SSR2QX(list0[i], Pudp, Ptfo)
                    node = tag0 != "" ? URI_TAG(node, tag0) : node
                } else if (type == "ss") {
                    node = SS2QX(list0[i], Pudp, Ptfo)
                    node = tag0 != "" ? URI_TAG(node, tag0) : node
                } else if (type == "ssd") {
                    node = SSD2QX(list0[i], Pudp, Ptfo)
                } else if (type == "trojan") {
                    node = TJ2QX(list0[i], Pudp, Ptfo, Pcert0, PTls13)
                    node = tag0 != "" ? URI_TAG(node, tag0) : node
                } else if ((type == "https" || type == "http") && list0[i].indexOf(",") == -1) {
                    if (listi.indexOf("@") != -1) {
                        node = HPS2QX(list0[i], Ptfo, Pcert0, PTls13)
                        node = tag0 != "" ? URI_TAG(node, tag0) : node
                    } else {  
                        var listh = Base64.decode(listi.split(type+"://")[1].split("#")[0].split("?")[0])
                        listh = list0[i].replace(listi.split(type+"://")[1].split("#")[0].split("?")[0],listh)  
                        node = HPS2QX(listh, Ptfo, Pcert0, PTls13)
                        node = tag0 != "" ? URI_TAG(node, tag0) : node
                    }
                } else if (type == "vless" && version<821) {
                  Perror = 1 ;  
                  $notify("⚠️ 你的 Quantumult X 版本暂未支持 Vless 节点","请更新app到最新版本",list0[i])
                } else if (type == "vless" ) {  
                  node=VL2QX(list0[i], Pudp, Ptfo, Pcert0, PTls13)
                } else if (type == "anytls") {  
                  if (version <914) {
                    Perror = 1 ;  
                    $notify("⚠️ 你的 Quantumult X 版本暂未支持 anytls 节点","请更新app到最新版本",list0[i])
                  } else {
                    node=Anytls2QX(list0[i],Pcert0)
                  }
                } else if (QuanXK.some(NodeCheck1)) {  
                    node = QX_TLS(isQuanX(list0[i])[0], Pcert0, PTls13)
                } else if (LoonK.some(NodeCheck2)) {  
                    node = Loon2QX(list0[i])
                } else if (SurgeK.some(NodeCheck) ) {  
                    node = QX_TLS(Surge2QX(list0[i])[0], Pcert0, PTls13)
                } else if ((type=="anytls" && version<914) || type=="tuic" || type=="wireguard"|| type=="wg") {
                  PNS=PNS+1 
                  NSList.push(numToEmoji10(PNS)+list0[i])
                } else if (/^STATUS\=/.test(listi)) {  
                   
                  Rocket_flow(listi)
                }
              if (Pdbg) {$notify(i, type, node)}
            } catch (e) {
                failedList.push(`<<<\nContent: ${list0[i]}\nError: ${e}`)
            }
            if (Paead != "") {node = AeadVmess(node,Paead)}  
            if (Phost != "") {node = HOST_Handle(node,Phost)}  
            if (Pobfs != "") {node = OBFS_Handle(node,Pobfs)}  
            if (Psession != "") { node = Session_Handle(node,Psession)}  
            if (Pcsha256 != "" || Ppsha256 != "") {
            node = SHA256_Handle(node,Pcsha256,Ppsha256)}  
            if (Palpn !="") { node = ALPN_Handle(node,Palpn)}  
            node = TLS_Check(node)
             
            if (node instanceof Array) {
                for (var j in node) {
                  node[j] = Pudp != 0 ? XUDP(node[j],Pudp) : node[j]
                  node[j] = Ptfo != 0 ? XTFO(node[j],Ptfo) : node[j]
                    QXlist.push(node[j])
                }
            } else if (node != ""  && node) {
              node = Pudp != 0 ? XUDP(node,Pudp) : node
              node = Ptfo != 0 ? XTFO(node,Ptfo) : node
                QXlist.push(node)
            }
        }
    }
    if (failedList.length > 0 && Pntf0 != 0) {
        $notify(`⚠️ 有 ${failedList.length} 条数据解析失败, 已忽略`, "出错内容👇", failedList.join("\n"));
    }
     
    return QXlist;
}

 
// 【AEAD】aead=-1 时关掉 vmess 的 AEAD。
function AeadVmess(cnt,aeadp) {
  let paead = aeadp == -1? "aead=false" : "aead=true" 
  if (/^vmess\s*\=/.test(cnt)) {
    if (/aead\s*\=/.test(cnt)) {
      cnt = cnt.replace(/aead\s*\=.*\,/,paead+",")
    } else {
      cnts = cnt.split(",")
      cnts.push(paead)
       
      cnt=cnts.join(", ")
    }

  }
  return cnt
}

 
// 【TLS】按客户端版本决定证书校验与 tls13 的写法，旧版本不认的参数不输出。
function TLS_Check(cnt) {
  cnt =cnt.indexOf("tls-cert-sha256")!=-1 || cnt.indexOf("tls-pubkey-sha256")!=-1 ? cnt.replace(/tls-verification\s*\=\s*false.*?\,/,"tls-verification=true,"): cnt  
  return cnt
}

 
function QX_TLS(cnt,Pcert0,PTls13) {
  cnt =cnt.replace(/tag\s*\=/gm,"tag=")  
  var cert0 = TLSCertParam(Pcert0, "false") + ", "
  var tls13 = PTls13 == 1? "tls13=true, " : ""
  if(cnt.indexOf("tls-verification") != -1){  
    cnt = TLSCertDomainValue(Pcert0) !== "" ? cnt.replace(RegExp("tls\-verification.*?\,", "gmi"), cert0): cnt
     
  } else if(cnt.indexOf("obfs=over-tls")!=-1 || /over\-tls\s*\=\s*true/.test(cnt) || cnt.indexOf("obfs=wss")!=-1){  
    cnt = cnt.replace(new RegExp("tag\s*\=", "gmi"), cert0+"tag=")
  }
  if (tls13 !="") {
  if(cnt.indexOf("tls13") != -1){
    cnt = cnt.replace(RegExp("tls13.*?\,", "gmi"), tls13)
  } else if(cnt.indexOf("obfs=over-tls")!=-1 || /over\-tls\s*\=\s*true/.test(cnt) || cnt.indexOf("obfs=wss")!=-1){
    cnt = cnt.replace(new RegExp("tag\s*\=", "gmi"), tls13+"tag=")
  }
  }
  if (!/^(shadowsocks|trojan|vmess|vless|anytls)/.test(cnt.trim())) {  
    udp =  "udp-relay=false, "
    if(cnt.indexOf("udp-relay") != -1){
      var cnt = cnt.replace(RegExp("udp\-relay.*?\,", "gmi"), udp)
    }else{
      var cnt = cnt.replace(new RegExp("tag\s*\=", "gmi"), udp+"tag=")
    }
  }
  return cnt
}

 
// 【SIP008】JSON 格式的 SSR 订阅。
function SIP2QuanX (cnt) {
  cnt = JSON.parse(cnt)
  ll =cnt.length
  nodes =[]
  for (i=0; i<ll; i++) {
    node = "shadowsocks= "
    cnti = cnt[i]
    ip = cnti.server + ":" + cnti.server_port
    mtd = "method=" + cnti.method
    pwd = "password=" + cnti.password
    obfs = cnti.plugin_opts? cnti.plugin_opts.replace(";", ", "):""
    tag = "tag="+cnti.remarks
    node = node +[ip,pwd, mtd, obfs, tag].filter(Boolean).join(", ")
    nodes.push(node)
  }
  return nodes.join("\n")
   
}

 
 
// 【HTTP(S)】含 base64(ipport) 的老写法与 peer 参数。
function HPS2QX(subs, Ptfo, Pcert0, PTls13) {
    var type = subs.indexOf("https://")!=-1? "https" : "http" 
    var server = subs.replace("https://", "").replace("http://", "").trim() 
    var nss = []
    if (server != "") {
      if (server.indexOf("@")!=-1) {
        var ipport = "http=" + server.split("@")[1].split("#")[0].split("/")[0].split("?")[0];
        var uname = "username=" + server.split(":")[0];
        var pwd = "password=" + server.split("@")[0].split(":")[1];
      } else {
        var ipport = server.split("#")[0].indexOf(":")==-1? "http=" + Base64.decode(server.split("#")[0].split("?")[0]) : "http=" + server.split("#")[0].split("?")[0];  
      }
        var tag = "tag=" + decodeURIComponent(server.split("#")[1]);
        var tls = type == "https"? "over-tls=true": "";
        var thost = subs.indexOf("peer=")!= -1? "tls-host=" + subs.split("peer=")[1].split("#")[0].split("&")[0] : ""  
        var cert = TLSCertParam(Pcert0, "false");
        var tfo = Ptfo == 1 ? "fast-open=true" : "fast-open=false";
        var tls13 = PTls13 == 1 ? "tls13=true" : "tls13=false";
        if (tls=="") {
          cert=""
          tls13=""
        }
        nss.push(ipport, uname, pwd, tls, thost, cert, tfo, tls13, tag)
    }
    var QX = nss.filter(Boolean).join(",");
    return QX
}

 
// 【Quantumult】自家 vmess 写法的转换。
function VQ2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {
  var server = String(Base64.decode(subs.replace("vmess://", "").trim()).split("\u0000")[0])
  var node = ""
  var ip = "vmess=" + server.split(",")[1].trim() + ":" + server.split(",")[2].trim() + ", " + "method=aes-128-gcm, " + "password=" + server.split(",")[4].split("\"")[1] + ", "
  var tag = "tag=" + server.split("=")[0]
  var tfo = subs.indexOf("tfo=1") != -1 ? "fast-open=true, " : "fast-open=false, "
  var udp = Pudp == 1 ? "udp-relay=false, " : "udp-relay=false, ";  
  node = ip + tfo + udp
  var obfs = ""
  if (server.indexOf("obfs=") == -1) {  
    obfs = server.indexOf("over-tls=true") != -1 ? "obfs=over-tls, " : ""  
    var host = server.indexOf("tls-host") != -1 ? "obfs-host=" + server.split("tls-host=")[1].split(",")[0] + ", " : ""
    obfs = obfs + host
  } else if (server.indexOf("obfs=ws") != -1) {
    obfs = server.indexOf("over-tls=true") != -1 ? "obfs=wss, " : "obfs=ws, "  
    var uri = server.indexOf("obfs-path=") != -1 ? "obfs-uri=" + server.split("obfs-path=")[1].split("\"")[1] + ", " : "obfs-uri=/, "
    obfs = obfs + uri
    var host = server.indexOf("obfs-header=") != -1 ? "obfs-host=" + server.split("obfs-header=\"Host:")[1].split("[")[0].trim() + ", " : ""
    obfs = obfs + host
  } else if (server.indexOf("obfs=http") != -1) {
    obfs = "obfs=http, "
    var uri = server.indexOf("obfs-path=") != -1 ? "obfs-uri=" + server.split("obfs-path=")[1].split("\"")[1] + ", " : "obfs-uri=/, "
    obfs = obfs + uri
    var host = server.indexOf("obfs-header=") != -1 ? "obfs-host=" + server.split("obfs-header=\"Host:")[1].split("[")[0].trim() + ", " : ""
    obfs = obfs + host
  }
  if (obfs.indexOf("obfs=over-tls") != -1 || obfs.indexOf("obfs=wss") != -1) {
    var cert = TLSCertParam(Pcert0, subs.indexOf("allowInsecure=1") != -1 ? "false" : "true") + ", "
    var tls13 = PTls13 == 1 ? "tls13=true, " : ""
    obfs = obfs + cert + tls13
  }
  node = node + obfs + tag
  return node
}


 
// 【Shadowrocket】vmess 写法的转换。
function VR2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {
  var server = String(Base64.decode(subs.replace("vmess://", "").split("?remark")[0].split("&remark")[0].split("?")[0]).trim()).split("\u0000")[0]
  if(Pdbg==1) {$notify("Shadowrocket-Vmess-URI","..",subs+"\n\n"+server)}
  if (server.indexOf("@")==-1 && subs.indexOf("@")!=-1) { server = subs.replace("vmess://", "").split("?")[0]}
  var node = ""
  var ip = "vmess=" + server.split("@")[1] + ", " + "method=aes-128-gcm, " 
  var pwd =  server.split("@")[0].split(":")[1]? "password=" + server.split("@")[0].split(":")[1] + ", " : "password=" + server.split("@")[0]+ ", "
  if (subs.indexOf("#")==-1) {
    tag = /remarks*=/.test(subs)? "tag=" + decodeURIComponent(subs.split(/remarks*=/)[1].split("&")[0]) : "tag="+server.split("@")[1]  
  } else {
    tag = "tag=" + subs.split("#")[1]
  }
  var tfo = subs.indexOf("tfo=1") != -1 ? "fast-open=true, " : "fast-open=false, "
  var udp = Pudp == 1 ? "udp-relay=false, " : "udp-relay=false, ";
  var pdrop = 0
  node = ip + pwd+ tfo + udp
  var obfs = subs.indexOf("obfs=")!=-1 ? subs.split("obfs=")[1].split("&")[0].trim() : "none"
  if (obfs == "none") {  
    obfs = subs.indexOf("tls=1") != -1 ? "obfs=over-tls, " : ""  
  } else if (obfs == "websocket" || obfs == "http") {
    obfs = obfs == "http" ? "obfs=http, " : "obfs=ws, "  
    obfs = subs.indexOf("tls=1") != -1 ? "obfs=wss, " : obfs  
    var ouri = subs.indexOf("&path=") != -1 ? decodeURIComponent(subs.split("&path=")[1].split("&")[0]) : "/"  
    obfs = obfs + "obfs-uri=" + ouri + ", "
    var host = subs.indexOf("&obfsParam=") != -1 ? decodeURIComponent(subs.split("&obfsParam=")[1].split("&")[0].split("\n")[0]).split("\n")[0].trim() : ""
    if (host.indexOf("\"Host\"")!=-1 && host.indexOf("{")!=-1) {
      host = JSON.parse(host)["Host"]
    }
    host = host!="{}" && host ? "obfs-host=" + host + ", " : ""
    obfs = obfs + host
   
   
  } else if (obfs=="grpc" || obfs =="h2") {
    Perror = 1  
    if (Pntf0!=0) {
    $notify( "⚠️ Quantumult X 暂不支持该类型节点", "已忽略以下 grpc|h2 vmess 节点",subs)
  }
    pdrop = 1
  } else {
    Perror = 1
    $notify( "⚠️ Quantumult X 暂不支持该类型节点", "已忽略以下 " + obfs + " vmess 节点",subs)
    pdrop = 1
  }
  if (obfs.indexOf("obfs=over-tls") != -1 || obfs.indexOf("obfs=wss") != -1) {
    var cert = TLSCertParam(Pcert0, subs.indexOf("allowInsecure=1") != -1 ? "false" : "true") + ", "
    var tls13 = PTls13 == 1 ? "tls13=true, " : ""
    obfs = obfs + cert + tls13
  }
  caead="aead=false, "
  if (subs.indexOf("alterId=") != -1) {
    caead = Number(subs.split("alterId=")[1].split("&")[0]) != 0 ? "aead=false, " : ""
  }
  node = pdrop==0? node + obfs +caead+ tag : ""
   
  return node
}

 
function S5R2QX(cnt,tlsp="false") {
  var listh = Base64.decode(cnt.split("socks://")[1].split("#")[0].split("?")[0])
  server=cnt.indexOf("#")!=-1? listh+"#"+cnt.split("?")[1] : listh+"?"+cnt.split("?")[1]
  var nss = []
  if (server != "") {
      var ipport = "socks5=" + server.split("@")[1].split("#")[0].split("/")[0];
      var uname = "username=" + server.split(":")[0];
      var pwd = "password=" + server.split("@")[0].split(":")[1];
      var tag = "tag=" + decodeURIComponent(server.split("remarks=")[1].split("&")[0]);
      var tls = tlsp=="false"? "":"over-tls=true"
      var cert = TLSCertParam(Pcert0, "false");
      cert = tls == ""? "":cert
      var tfo = Ptfo0 == 1 ? "fast-open=true" : "fast-open=false";
      nss.push(ipport, uname, pwd, tls, cert, tfo, tag)
  }
  var QX = nss.filter(Boolean).join(",");
  return QX
}
 
 
// 【SOCKS】socks 与 ssocks 两种协议头。
function Socks2QX(cnt,tlsp="false") {
  var listh = Base64.decode(cnt.split("socks://")[1].split("#")[0].split("?")[0])
  server=cnt.indexOf("#")!=-1? listh+"#"+cnt.split("?")[1] : listh+"?"+cnt.split("?")[1]
  var nss = []
  if (server != "") {
      var ipport = "socks5=" + server.split("@")[1].split("#")[0].split("/")[0];
      var uname = "username=" + server.split(":")[0];
      var pwd = "password=" + server.split("@")[0].split(":")[1];
      name = server.indexOf("#") != -1? server.split("#")[1] : ipport.split("=")[1].split(":")[0]
      var tag = "tag=" + decodeURIComponent(name.split("&")[0]);
      var tls = tlsp=="false"? "":"over-tls=true"
      var cert = TLSCertParam(Pcert0, "false");
      cert = tls == ""? "":cert
      var tfo = Ptfo0 == 1 ? "fast-open=true" : "fast-open=false";
      nss.push(ipport, uname, pwd, tls, cert, tfo, tag)
  }
  var QX = nss.filter(Boolean).join(",");
  return QX
}

 
// 【V2RayN】标准 vmess:// URI 的转换。
function V2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {
   
  var cert = Pcert0
  var tls13 = PTls13
  var server = String(Base64.decode(subs.replace("vmess://", "")).trim()).split("\u0000")[0];
  var nss = [];
  if (server != "") {
    ss = JSON.parse(server);
    if(Pdbg) {$notify("Vmess-URI","",JSON.stringify(ss))}
    ip = "vmess=" + ss.add + ":" + ss.port;
    pwd = "password=" + ss.id;
    mtd = "method=aes-128-gcm"
    try {
      tag = "tag=" + decodeURIComponent(ss.ps);
    } catch (e) {
      tag = "tag=" + ss.ps;
    }
    udp = Pudp == 1 ? "udp-relay=false" : "udp-relay=false";
    tfo = Ptfo == 1 ? "fast-open=true" : "fast-open=false";
    obfs = Fobfs(ss, cert, tls13);
    caead = ss.aid && ss.aid != "0" ? "aead=false" : "aead=true";  
    if (obfs == "" || obfs == undefined) {
      nss.push(ip, mtd, pwd, tfo, udp, caead, tag)
    } else if(obfs != "NOT-SUPPORTTED"){
      nss.push(ip, mtd, pwd, obfs, tfo, udp, caead, tag);
    } else if(obfs == "NOT-SUPPORTTED"){
      PNS=PNS+1
      NSList.push(numToEmoji10(PNS)+subs)
    }
    QX = nss.join(", ");
  }
  return QX
}

 
function Fobfs(jsonl, Pcert0, PTls13) {
  var obfsi = [];
  var cert = Pcert0;
  tcert = TLSCertParam(cert, "false");
  tls13 = PTls13 == 1 ? "tls13=true" : "tls13=false"
  if (jsonl.net == "ws" && jsonl.tls == "tls") {
    obfs0 = "obfs=wss, " + tcert + ", " + tls13 + ", ";
    uri0 = jsonl.path && jsonl.path != "" ? "obfs-uri=" + jsonl.path : "obfs-uri=/";
    uri0 = uri0.indexOf("uri=/")!=-1 ? uri0:uri0.replace("uri=","uri=/")
    host0 = jsonl.host && jsonl.host != "" ? "obfs-host=" + jsonl.host + ", " : "";
    obfsi.push(obfs0 + host0 + uri0)
    return obfsi.join(", ")
  } else if (jsonl.net == "ws") {
    obfs0 = "obfs=ws";
    uri0 = jsonl.path && jsonl.path != "" ? "obfs-uri=" + jsonl.path : "obfs-uri=/";
    uri0 = uri0.indexOf("uri=/")!=-1 ? uri0:uri0.replace("uri=","uri=/")
    host0 = jsonl.host && jsonl.host != "" ? "obfs-host=" + jsonl.host + ", " : "";
    obfsi.push(obfs0, host0 + uri0);
    return obfsi.join(", ")
  } else if (jsonl.tls == "tls" && (jsonl.net == "tcp" || jsonl.net == "none")) {  
    obfs0 = "obfs=over-tls, " + tcert + ", " + tls13;
    uri0 = jsonl.path && jsonl.path != "" ? "obfs-uri=" + jsonl.path : "";
    uri0 = uri0.indexOf("uri=/")!=-1 ? uri0:uri0.replace("uri=","uri=/")
    host0 = jsonl.host && jsonl.host != "" ? ", obfs-host=" + jsonl.host : "";
    obfsi.push(obfs0 + host0)
    return obfsi.join(", ")
  } else if ((jsonl.net == "tcp" || jsonl.net == "none") && jsonl.type == "http"){
    obfs0 = "obfs=http";
    uri0 = jsonl.path && jsonl.path != "" ? "obfs-uri=" + jsonl.path : "obfs-uri=/";
    uri0 = uri0.indexOf("uri=/")!=-1 ? uri0:uri0.replace("uri=","uri=/")
    host0 = jsonl.host && jsonl.host != "" ? "obfs-host=" + jsonl.host + ", " : "";
    obfsi.push(obfs0, host0 + uri0);
    return obfsi.join(", ")
  } else if (jsonl.net !="tcp" && jsonl.net !="none" &&  jsonl.net != undefined){  
    Perror = 1
    $notify("⚠️ Quantumult X 不支持该类型节点", "vmess + " + jsonl.net, JSON.stringify(jsonl))
    return "NOT-SUPPORTTED"
  } else if ((jsonl.net == "tcp" || jsonl.net == "none") && jsonl.type != undefined && jsonl.type != "none" && jsonl.type != "" && jsonl.type != "vmess") {
    return "NOT-SUPPORTTED"
  } else {return ""}
}

 
function Dot2(cnt) {
    cnt = cnt ? cnt.replace(/\\\./g, "这是个点") : ""
    return cnt
}

function ToDot(cnt) {
    cnt = cnt ? cnt.replace(/这是个点/g, ".") : ""
    return cnt
}

 
// 【正则核心】in / out / regex / regout 的匹配器，支持「与」「或」组合。
function Regex(content) {
    var Preg0 = RegExp(Preg, "i")
    cnt = flag == 2 || flag == 3 ? RuleNoteBody(content) : content
    if (Preg0.test(cnt)) {
        return content
    }
}

 
function RegexOut(content) {
  var Preg0 = RegExp(Pregout, "i")
  cnt = flag == 2 || flag == 3 ? RuleNoteBody(content) : content
  if (!Preg0.test(cnt)) {
    return content
  } else {
    RegoutList.push(cnt)
  }
}

 
function Scheck(content, param) {
    name = content.replace(/tag\s*\=/g,"tag=").split("tag=")[1].toUpperCase()
    param = param ? param.map(Dot2) : param  
    if (param) {
        var flag = 0;
        for (var i = 0; i < param.length; i++) {
            var params = param[i].split(".").map(ToDot);
            const checkpara = (item) => name.indexOf(item.toUpperCase()) != -1;
            if (params.every(checkpara)) {
                flag = 1
            }
        } 
        return flag
    } else {  
        return 2
    }
}

 
// 【节点筛选】把关键词筛选套到节点列表上。
function Filter(servers, Pin, Pout) {
    var Nlist = [];
    var Delist = [];
    var Nname = [];
    servers = servers.filter(Boolean)
    for (var i = 0; i < servers.length; i++) {
        if (Scheck(servers[i], Pin) != 0 && Scheck(servers[i], Pout) != 1) {
            Nlist.push(servers[i])
            Nname.push(servers[i].replace(/ /g, "").split("tag=")[1])
        } else { Delist.push(servers[i].replace(/ /g, "").split("tag=")[1]) }  
    } 
    var no = Delist.length <= 10 ? emojino[Delist.length] : Delist.length;
    var no1 = Nlist.length <= 10 ? emojino[Nlist.length] : Nlist.length;
    if (Pntf0 == 1 && Delist.length >= 1) { 
        if (Pin && no1 > 0) {  
            $notify("👥 引用" + "⟦" + subtag + "⟧" + " 开始节点筛选", "🕹 筛选关键字: " + pfi + pfo, "☠️ 已保留以下 " + no1 + "个节点\n" + Nname.join(", "), sub_link);
        } else if (Pout && no > 0) {
            $notify("👥 引用" + "⟦" + subtag + "⟧" + " 开始节点筛选", "🕹 筛选关键字: " + pfi + pfo, "☠️ 已删除以下 " + no + "个节点\n" + Delist.join(", "), sub_link);
        }
    } else if (no1 == 0 || no1 == null) {  
        $notify("‼️ ⟦" + subtag + "⟧" + "筛选后节点数为0️⃣", "⚠️ 请自行检查原始链接以及筛选参数", link0, sub_link);
    }
    return Nlist
}

function FilterScript(servers, script) {
    $notify("🤖 启用脚本进行筛选", "", script);
    try {
        const $ = Tools();
        eval(script);
         
        const nodes = Tools().getNodeInfo(servers);
        const IN = filter(nodes);
        const res = servers.filter((_, i) => IN[i]);
        if (res.length === 0) {
            $notify("‼️ ⟦" + subtag + "⟧" + "筛选后节点数为0️⃣", "⚠️ 请自行检查原始链接以及筛选参数", link0, sub_link);
        }
        return res;
    } catch (err) {
        $notify("❌ 脚本筛选出现错误", "", err);
        return servers;
    }
}

 
 
// 【SSR】ssr:// 的 base64 主体与参数。
function SSR2QX(subs, Pudp, Ptfo) {
    var nssr = []
    var cnt = Base64.decode(subs.split("ssr://")[1].replace(/-/g, "+").replace(/_/g, "/")).split("\u0000")[0]
    var obfshost = '';
    var oparam = '';
    if(Pdbg==1) {$notify("ssr","content",cnt)}
    if (cnt.split(":").length <= 8) {  
        type = "shadowsocks=";
        ip = cnt.split(":")[0] + ":" + cnt.split(":")[1];
        pwd = "password=" + Base64.decode(cnt.split("/?")[0].split(":")[5].replace(/-/g, "+").replace(/_/g, "/")).split("\u0000")[0];
        mtd = "method=" + cnt.split(":")[3];
        obfs =cnt.split(":")[4]!= "plain"? "obfs=" + cnt.split(":")[4] : "";  
        ssrp = cnt.split(":")[2] != "origin"? "ssr-protocol=" + cnt.split(":")[2] : "";  
        if (cnt.indexOf("obfsparam=") != -1 && obfs != "") {
            obfshost = cnt.split("obfsparam=")[1].split("&")[0] != "" ? "obfs-host=" + Base64.decode(cnt.split("obfsparam=")[1].split("&")[0].replace(/-/g, "+").replace(/_/g, "/")).split(",")[0].split("\u0000")[0] : ""
        }
        if (cnt.indexOf("protoparam=") != -1) {
            oparam = cnt.split("protoparam=")[1].split("&")[0] != "" ? "ssr-protocol-param=" + Base64.decode(cnt.split("protoparam=")[1].split("&")[0].replace(/-/g, "+").replace(/_/g, "/")).split(",")[0].split("\u0000")[0]  : ""
        }
        tag = "tag=" + (Base64.decode(cnt.split("remarks=")[1].split("&")[0].replace(/-/g, "+").replace(/_/g, "/"))).split("\u0000")[0]
        pudp = Pudp == 1 ? "udp-relay=true" : "udp-relay=false";
        ptfo = Ptfo == 1 ? "fast-open=true" : "fast-open=false";
        nssr.push(type + ip, pwd, mtd, obfs , obfshost, oparam, ssrp, pudp, ptfo, tag)
        QX = nssr.filter(Boolean).join(", ")
    } else { QX = "" }
    return QX;
}

 
// 【Hysteria2】识别 URI、Surge、QX 三种写法，并按客户端版本决定是否支持。
function HY2Type(type) {
  return typeof type == "string" && /^(?:hysteria2|hy2)$/i.test(type)
}

function HY2LineKind(row) {
  var line = row.trim()
  if (/^(?:hysteria2|hy2):\/\//i.test(line)) return "uri"
  if (/^(?:[a-z][\w+.-]*:\/\/|[#;\[])/i.test(line)) return ""
  if (/^[^=\r\n]+=\s*hysteria2\s*,\s*[^,\s]+\s*,/i.test(line)) return "surge"
  return /^hysteria2\s*=/i.test(line) ? "quanx" : ""
}

function HY2DecodeSubscription(content) {
  var compact = content.replace(/^\s*#[^\n]*\n/, "").replace(/\s/g, "")
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(compact)) return ""
  var rows = Base64.decode(compact, true).split("\n")
  if (!rows.some(HY2LineKind)) return ""
  return rows.map(row => HY2LineKind(row) ? row : row.replace(/&gt;/g, ">").replace(/&lt;/g, "<")).join("\n")
}

function HY2ClashSnippet(content) {
  var text = content.trim()
  if (!/\b(?:hysteria2|hy2)\b/i.test(text)) return ""
  if (/^[{\[]/.test(text)) {
    try {
      var input = JSON.parse(text)
      var nodes = Array.isArray(input) ? input : [input]
      if (nodes.some(node => node && HY2Type(node.type)) &&
          nodes.every(node => node && typeof node.type == "string")) {
        return JSON.stringify({proxies: nodes})
      }
    } catch (err) {}
  }
  return /^-\s*\{/.test(text) && /(?:[{,]\s*["']?type["']?\s*:\s*["']?(?:hysteria2|hy2)\b)/i.test(text)
    ? "proxies:\n" + text : ""
}

function HY2ClashOriginal(content) {
  if (!/\b(?:hysteria2|hy2)\b/i.test(content)) return null
  try {
    var input = content.trim()
    if (/^{/.test(input)) return JSON.parse(input).proxies || null
    var lines = input.split(/\r?\n/)
    var start = lines.findIndex(line => /^(?:proxies|"proxies"|'proxies')[ \t]*:/.test(line))
    if (start < 0) return null
    var values = lines.slice(start + 1)
    var end = values.findIndex(line => /^(?:[A-Za-z][\w-]*|["'][^"']+["'])[ \t]*:/.test(line))
    if (end >= 0) values = values.slice(0, end)
     
    if (values.some(line => /^-[ \t]/.test(line))) values = values.map(line => "  " + line)
    var yaml = new YAML()
    var nodes = yaml.parse([lines[start]].concat(values).join("\n")).proxies
    return yaml.errors.length || !Array.isArray(nodes) ? null : nodes
  } catch (err) {
    return null
  }
}

function UnsupportedNodeDetails(types) {
  var details = Object.keys(HY2Skipped).map(reason => "Hysteria2：" + reason + "（" + HY2Skipped[reason] + " 条）")
  return "⚠️ 此版本暂不支持 " + (HY2Supported ? "" : "Hysteria2/") + types +
    " 等类型, 以及 http-upgrade/xhttp/grpc/mkcp/h2” 等类型 vless\n\n" + NSList.concat(details).join("\n")
}

function HY2Skip(reason) {
  PNS++
  HY2Skipped[reason] = (HY2Skipped[reason] || 0) + 1
  return ""
}

function HY2Invalid(reason) {
   
  throw {hy2Reason: reason}
}

function HY2Bool(value, fallback) {
  if (value === undefined) return fallback
  if (value === true || value === 1 || typeof value == "string" && /^(?:1|true)$/i.test(value)) return true
  if (value === false || value === 0 || typeof value == "string" && /^(?:0|false)$/i.test(value)) return false
  HY2Invalid("布尔参数无效")
}

function HY2VerifyName(value) {
  if (value === undefined || value === "") return ""
  if (typeof value != "string" || !value.includes(".") || TLSCertDomainValue(value) != value) {
    HY2Invalid("TLS 校验域名无效")
  }
  return value
}

function HY2Pin(value) {
  if (value === undefined || value === "") return ""
  if (typeof value != "string" || !/^(?:[0-9a-f]{64}|(?:[0-9a-f]{2}:){31}[0-9a-f]{2})$/i.test(value)) {
    HY2Invalid("SHA-256 指纹格式无效")
  }
  return value.replace(/:/g, "").toLowerCase()
}

function HY2Fields(text, quoted) {
  var fields = Object.create(null)
  if (!text.trim()) return fields
  text.split(/,[ \t]*(?=[a-z][\w-]*[ \t]*=)/i).forEach(function (part) {
    var m = part.trim().match(/^([a-z][\w-]*)[ \t]*=([\s\S]*)$/i)
    if (!m || m[1].toLowerCase() in fields) HY2Invalid("节点字段无效或重复")
    var value = m[2].trim()
    if (quoted && /^["']/.test(value)) {
      if (value.length < 2 || value.slice(-1) != value[0]) HY2Invalid("字段引号不完整")
      value = value.slice(1, -1)
    }
    fields[m[1].toLowerCase()] = value
  })
  return fields
}

function HY2URI(line) {
  var match = line.match(/^(?:hysteria2|hy2):\/\/([^/?#\s]+)\/?(?:\?([^#]*))?(?:#(.*))?$/i)
  if (!match) HY2Invalid("URI 格式无效")
  var at = match[1].lastIndexOf("@")
  var address = match[1].slice(at + 1).match(/^(\[[0-9a-f:.]+\]|[^:\s]+)(?::(.+))?$/i)
  if (at < 1 || !address) HY2Invalid("缺少服务器或认证密码")
  var params = Object.create(null)
  var query = (match[2] || "").split("&").filter(Boolean)
  query.forEach(function (pair) {
    var pos = pair.indexOf("=")
    var key = decodeURIComponent((pos < 0 ? pair : pair.slice(0, pos)).replace(/\+/g, " ")).toLowerCase()
    var value = pos < 0 ? "" : decodeURIComponent(pair.slice(pos + 1).replace(/\+/g, " "))
    if (key in params) HY2Invalid("URI 参数重复")
    params[key] = value
  })
  if (params.ech || params.alpn && params.alpn != "h3") HY2Invalid("当前目标格式无法等价保留 URI 连接参数")
  if (params.insecure !== undefined && params.allowinsecure !== undefined &&
      HY2Bool(params.insecure) != HY2Bool(params.allowinsecure)) HY2Invalid("URI 证书校验开关冲突")
  var ports = address[2] || "443"
  return {
    host: address[1], port: ports.split(/[,-]/)[0], auth: decodeURIComponent(match[1].slice(0, at)),
    name: params.tag || decodeURIComponent(match[3] || ""), sni: params.sni || params.peer,
    verification: HY2Bool(params.insecure, HY2Bool(params.allowinsecure, false)) ? "false" : "true",
    certPin: params.pinsha256, udp: params.udp, obfs: params.obfs,
    key: params.obfs ? params["obfs-password"] || params["salamander-password"] : params["salamander-password"],
    ports: params["port-hopping"] || params.mport || (/[,-]/.test(ports) ? ports : undefined),
    interval: params["port-hopping-interval"] || params["hop-interval"],
    down: params["download-bandwidth"] || params.down
  }
}

function HY2Surge(line) {
  var m = line.match(/^([^=]+)=\s*hysteria2\s*,\s*([^,]+),\s*(\d+)\s*,\s*(.+)$/i)
  if (!m) HY2Invalid("Surge 节点字段无效")
  var p = HY2Fields(m[4], true)
  if (p["client-cert"] || p["ech-config"] || p["underlying-proxy"] || p.sni == "off" ||
      (p.alpn && p.alpn != "h3")) HY2Invalid("当前目标格式无法等价保留 Surge 连接参数")
  var pin = p["server-cert-fingerprint-sha256"]
  var verifyName = HY2VerifyName(p["server-cert-verify-name"])
  var skipVerify = HY2Bool(p["skip-cert-verify"], false)
  if (skipVerify && verifyName) HY2Invalid("Surge 证书校验开关与校验域名冲突")
  return {
    host: m[2].trim(), port: m[3], auth: p.password, name: m[1].trim(), sni: p.sni,
    verification: skipVerify ? "false" : verifyName || "true",
    certPin: pin, pinOnly: !!pin, udp: p["udp-relay"], key: p["salamander-password"],
    obfs: p["gecko-password"] ? "gecko" : undefined, ports: p["port-hopping"],
    interval: p["port-hopping-interval"], down: p["download-bandwidth"], check: p["test-url"]
  }
}

function HY2Clash(node) {
  if ((node["realm-opts"] && node["realm-opts"].enable) ||
      (node["ech-opts"] && node["ech-opts"].enable) || node["private-key"] ||
      node.certificate || node.ca || node["ca-str"] ||
      (node.alpn && String(node.alpn) != "h3")) HY2Invalid("当前目标格式无法等价保留 Clash 连接参数")
  var skipVerify = HY2Bool(node["skip-cert-verify"], false)
  return {
    host: node.server, port: node.port, auth: node.password, name: node.name, sni: node.sni,
    verification: HY2VerifyName(node["name-cert-verify"]) || (skipVerify ? "false" : "true"),
    certPin: node.fingerprint, pinOnly: !!node.fingerprint, udp: node.udp, obfs: node.obfs,
    key: node.obfs ? node["obfs-password"] : undefined,
    ports: node.ports, interval: node["hop-interval"], down: node.down
  }
}

function HY2QuanX(line) {
  var m = line.match(/^hysteria2\s*=\s*(\[[0-9a-f:.]+\]|[^:,\s]+):(\d+)\s*,\s*(.*)$/i)
  if (!m) HY2Invalid("原生 QuanX 地址或字段无效")
  var p = HY2Fields(m[3], false)
  return {
    host: m[1], port: m[2], auth: p.password, name: p.tag, sni: p["tls-host"],
    verification: p["tls-verification"], certPin: p["tls-cert-sha256"], keyPin: p["tls-pubkey-sha256"],
    udp: p["udp-relay"], key: p["salamander-password"], ports: p["port-hopping"],
    interval: p["port-hopping-interval"], down: p["download-bandwidth"], native: p
  }
}

function HY2Serialize(node) {
  function safeValue(value) {
    return typeof value == "string" && value.length > 0 && value.trim() == value &&
      !/[,;"'\\\x00-\x1f\x7f\u0085\u2028\u2029]|tag\s*=|node_(?:type|emoji|tag|index)_prefix/i.test(value)
  }
  function portNumber(value) {
    if (!/^\d{1,5}$/.test(value) || Number(value) < 1 || Number(value) > 65535) HY2Invalid("端口超出有效范围")
    return Number(value)
  }
  function hostname(value) {
    return typeof value == "string" && /^(?=.{1,253}$)[a-z0-9]+(?:[.-][a-z0-9]+)*\.?$/i.test(value)
  }
  var host = node.host
  if (!hostname(host)) {
    if (typeof host != "string" || !/^(?:\[[0-9a-f:.]+\]|[0-9a-f:.]+)$/i.test(host) || host.indexOf(":") < 0) {
      HY2Invalid("服务器地址无效")
    }
    host = "[" + host.replace(/^\[|\]$/g, "") + "]"
  }
  if (!safeValue(node.auth)) HY2Invalid("认证密码缺失或含 QuanX 无法安全表示的字符")
  if (node.sni !== undefined && !hostname(node.sni)) HY2Invalid("SNI 无效")
  var hopping = node.ports === undefined || node.ports === "" ? "" : String(node.ports).trim().split(/[,;/]/).map(function (item) {
    var range = item.trim().split("-").map(portNumber)
    if (range.length > 2 || range.length == 2 && range[0] > range[1]) HY2Invalid("端口跳跃范围无效")
    return range.join("-")
  }).join(",")
  var port = portNumber(node.port === undefined && hopping ? hopping.split(/[,-]/)[0] : node.port)
  var interval = node.interval
  if (interval !== undefined && (!hopping || !/^\d+$/.test(interval) || interval < 5 || interval > 3600)) {
    HY2Invalid("QuanX 端口跳跃仅支持 5–3600 秒的固定间隔")
  }
   
  var plainObfs = typeof node.obfs == "string" && /^(?:none|plain)$/i.test(node.obfs)
  if (plainObfs && node.key !== undefined && node.key !== "") HY2Invalid("无混淆设置与混淆密钥冲突")
  if (node.obfs && !plainObfs && node.obfs != "salamander") HY2Invalid("当前 Quantumult X 仅支持 Salamander 混淆")
  if (!plainObfs && (node.key !== undefined || node.obfs == "salamander")) {
    if (!safeValue(node.key) || encodeURIComponent(node.key).replace(/%[A-F0-9]{2}/g, "x").length < 4) {
      HY2Invalid("Salamander 密钥缺失、少于 4 字节或无法安全表示")
    }
  }
  var verification = node.verification
  if (verification !== undefined && !/^(?:true|false)$/i.test(verification)) verification = HY2VerifyName(verification)
  else if (verification !== undefined) verification = verification.toLowerCase()
  var certPin = HY2Pin(node.certPin)
  var keyPin = HY2Pin(node.keyPin)
   
  if (node.pinOnly || (verification == "false" && (certPin || keyPin))) {
    HY2Invalid("当前目标格式无法等价保留仅凭指纹验证的设置")
  }
  verification = (Pcert0 === 0 ? "" : TLSCertDomainValue(Pcert0)) || verification
  var certOverride = Pcsha256 && HY2Pin(decodeURIComponent(Pcsha256))
  var keyOverride = Ppsha256 && HY2Pin(decodeURIComponent(Ppsha256))
  if ((certPin && certOverride && certPin != certOverride) ||
      (keyPin && keyOverride && keyPin != keyOverride) ||
      (certPin && !keyPin && keyOverride)) HY2Invalid("资源参数与来源指纹冲突")
  certPin = certPin || certOverride
  keyPin = keyPin || keyOverride
  if (certPin || keyPin) {
    if (verification == "false") HY2Invalid("关闭证书验证会使 SHA-256 指纹失效")
    verification = verification || "true"
  }
  var udp = HY2Bool(node.udp, node.native ? undefined : true)
  if (Pudp0 == 1 || Pudp0 == -1) udp = Pudp0 == 1
  var mbps
  if (node.down !== undefined) {
    var rate = String(node.down).trim().match(/^(\d+(?:\.\d+)?)(?:\s*([KMGT]?)([bB])ps)?$/i)
    if (!rate) HY2Invalid("下载带宽格式无效")
    mbps = Number(rate[1]) * (rate[3] ? Math.pow(1000, " KMGT".indexOf(rate[2].toUpperCase() || " ") - 2) * (rate[3] == "B" ? 8 : 1) : 1)
    if (!Number.isFinite(mbps) || /e/i.test(String(mbps))) HY2Invalid("下载带宽超出可表示范围")
  }
  var fields = {
    password: node.auth, "tls-host": node.sni, "tls-verification": verification,
    "tls-cert-sha256": certPin, "tls-pubkey-sha256": keyPin, "udp-relay": udp,
    "salamander-password": plainObfs ? undefined : node.key, "download-bandwidth": mbps || undefined,
    "port-hopping": hopping, "port-hopping-interval": interval === undefined ? undefined : Number(interval),
    server_check_url: node.check
  }
  Object.keys(node.native || {}).forEach(function (key) {
    if (key == "tag" || Object.prototype.hasOwnProperty.call(fields, key) && key != "server_check_url") return
    if (!safeValue(node.native[key])) HY2Invalid("原生 QuanX 字段无法安全表示")
    Object.defineProperty(fields, key, {value: node.native[key], enumerable: true})
  })
  if (node.check !== undefined && !safeValue(node.check)) HY2Invalid("测试 URL 无法安全表示")
  var name = ClashNameFix(node.name).replace(/[\x00-\x1f\x7f\u0085\u2028\u2029]/g, " ").replace(/=/g, "＝").trim()
  fields.tag = name || "[hysteria2] " + host + ":" + port
  var entries = Object.keys(fields).filter(key => fields[key] !== undefined && fields[key] !== "")
  return "hysteria2=" + host + ":" + port + ", " + entries.map(key => key + "=" + fields[key]).join(", ")
}

function HY2Convert(kind, input) {
  if (!HY2Supported) return HY2Skip("需要 Quantumult X 1.9.0 build 965 或更新版本")
  try {
    var line = kind == "clash" ? "" : input.trim()
    return HY2Serialize(kind == "uri" ? HY2URI(line) : kind == "surge" ? HY2Surge(line) :
      kind == "quanx" ? HY2QuanX(line) : HY2Clash(input))
  } catch (err) {
    return HY2Skip(err.hy2Reason || "无法安全读取节点字段")
  }
}

 
 
 
 

function Anytls2QX(subs,Pcert0) {
  try {
    var Nanytls=[];
    var cnt=subs.split("anytls://")[1]
    type="anytls=";
    ip = cnt.split("@")[1].split("encry")[0].split("?")[0];
    pwd = cnt.split("@")[0]? "password=" + cnt.split("@")[0]:"";
    ptls="over-tls=true"
    pcert = TLSCertParam(Pcert0, cnt.indexOf("allowInsecure=0") != -1 ? "true" : "false");
    thost = cnt.indexOf("sni=") != -1? "tls-host="+cnt.split("sni=")[1].split(/&|#/)[0]:""
    thost = cnt.indexOf("peer=") != -1? "tls-host="+cnt.split("peer=")[1].split(/&|#/)[0]:thost
    pudp = Pudp0 == -1 ? "udp-relay=false" : "udp-relay=true"  
    tag = cnt.indexOf("#") != -1 ? "tag=" + decodeURIComponent(cnt.split("#").slice(-1)[0]) : "tag= [anytls]" + ip
     
    prlt= version>=914? Reality_Handle(cnt) : ""
    Nanytls.push(type + ip, pwd, ptls, pcert, pudp, thost, prlt, tag)
    QX= Nanytls.filter(Boolean).join(", ")
    return QX
  } catch (error) {
    console.log(error)
  }
}

 
 
 
 
 
 
 
function VL2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {
  var nvless = []
  var cnt = subs.split("vless://")[1]
  type = "vless=";
  mtd= "method=none"
  obfs=""
  thost=""
  if((cnt.indexOf("remarks=")==-1 && cnt.indexOf("remark=")==-1) && cnt.indexOf("@")!=-1) {  
  typeU = "URI"
  ip = cnt.split("@")[1].split("encry")[0].split("?")[0];
  pwd = cnt.split("@")[0]? "password=" + cnt.split("@")[0]:"";
  pcert = TLSCertParam(Pcert0, cnt.indexOf("allowInsecure=0") != -1 ? "true" : "false");
  thost = cnt.indexOf("sni=") != -1? "tls-host="+cnt.split("sni=")[1].split(/&|#/)[0]:""
  thost = cnt.indexOf("peer=") != -1? "tls-host="+cnt.split("peer=")[1].split(/&|#/)[0]:thost
  tag = cnt.indexOf("#") != -1 ? "tag=" + decodeURIComponent(cnt.split("#").slice(-1)[0]) : "tag= [vless]" + ip
  } else {  
    typeU = "SR-URI"
    b64part = Base64.decode(cnt.split("?")[0])
    ip = b64part.split("@")[1]
    pwd = "password=" + b64part.split("@")[0].split(":")[1]
    tag = cnt.indexOf("remarks=") != -1 ? "tag=" + decodeURIComponent(cnt.split("remarks=")[1].split("&")[0]) : "tag= [vless]" + ip
    tag = cnt.indexOf("remark=") != -1 ? "tag=" + decodeURIComponent(cnt.split("remark=")[1].split("&")[0]) : tag
  }
 
  puri = ""
 
  pudp = (Pudp == 1 || cnt.indexOf("udp=1")!=-1) ? "udp-relay=true" : "udp-relay=false";
  ptfo = (Ptfo == 1 || cnt.indexOf("tfo=1")!=-1)? "fast-open=true" : "fast-open=false";
   
  if (typeU == "SR-URI") { 
    if((cnt.indexOf("obfs=none")!=-1 || cnt.indexOf("obfs=")==-1) && cnt.indexOf("tls=1")==-1) {
       
      obfs = ""
    } else if((cnt.indexOf("obfs=none")!=-1 || cnt.indexOf("obfs=")==-1) && cnt.indexOf("tls=1")!=-1) {
      obfs = "obfs=over-tls"
    } else if(cnt.indexOf("obfs=http")!=-1) {
      obfs = "obfs=http"
    } else if(cnt.indexOf("obfs=websocket")!=-1) {
      obfs = cnt.indexOf("tls=1") != -1? "obfs=wss" : "obfs=ws"
    } else {  
      type="NS"
    }
  thost=cnt.indexOf("obfsParam=") == -1? thost : "obfs-host=" + decodeURIComponent(cnt.split("obfsParam=")[1].split("&")[0].split("#")[0]).replace(/\"|(Host\":)|\{|\}/g,"")
  thost=cnt.indexOf("sni=") == -1? thost : "obfs-host=" + decodeURIComponent(cnt.split("sni=")[1].split("&")[0].split("#")[0]).replace(/\"|(Host\":)|\{|\}/g,"")
  thost=cnt.indexOf("peer=") == -1? thost : "obfs-host=" + decodeURIComponent(cnt.split("peer=")[1].split("&")[0].split("#")[0]).replace(/\"|(Host\":)|\{|\}/g,"")

  puri = cnt.indexOf("path=") == -1? puri : "obfs-uri=" + decodeURIComponent(cnt.split("path=")[1].split("&")[0].split("#")[0])
  } else if (cnt.indexOf("&type=ws")!=-1 || cnt.indexOf("?type=ws")!=-1 || cnt.indexOf("type=http")!=-1 || cnt.indexOf("security=tls")!=-1 || cnt.indexOf("security=reality")!=-1) { 
    if(cnt.indexOf("type=http") != -1) {
      obfs="obfs=http"
    } else if (cnt.indexOf("type=ws") != -1) {
      obfs = cnt.indexOf("security=tls") != -1 || cnt.indexOf("security=reality")!=-1? "obfs=wss" : "obfs=ws" 
    } else if(cnt.indexOf("type=")==-1 || cnt.indexOf("type=tcp")!=-1) {
      obfs = "obfs=over-tls"
    } else if(cnt.indexOf("type=")!=-1 && cnt.indexOf("type=tcp")==-1) { 
    type="NS"
  }
    thost1=cnt.indexOf("&host=") == -1? thost : "obfs-host=" + decodeURIComponent(cnt.split("&host=")[1].split("&")[0].split("#")[0])
    thost2=cnt.indexOf("sni=") == -1? thost : "obfs-host=" + decodeURIComponent(cnt.split("sni=")[1].split("&")[0].split("#")[0]).replace(/\"|(Host\":)|\{|\}/g,"")
    thost = thost1.length >= thost2.length ? thost1 : thost2;
    puri = cnt.indexOf("&path=") == -1? puri : "obfs-uri=" + decodeURIComponent(cnt.split("&path=")[1].split("&")[0].split("#")[0])
  } 
if(obfs=="obfs=wss" || obfs=="obfs=over-tls"){
  ptls13 = PTls13 == 1 ? "tls13=true" : "tls13=false"
  pcert = TLSCertParam(Pcert0, cnt.indexOf("allowInsecure=0") != -1 ? "true" : "false");
} else {
  pcert=""
  ptls13=""
}
 
  prlt= version>=891? Reality_Handle(cnt) : ""
  nvless.push(type + ip, pwd, mtd, obfs, pcert, thost, puri, pudp, ptfo, prlt, tag)
  QX = type!="NS"? nvless.filter(Boolean).join(", ")  : ""
  if (type=="NS") {
    PNS=PNS+1
    NSList.push(numToEmoji10(PNS)+subs)
  }
  return QX
}

 
function TJ2QX(subs, Pudp, Ptfo, Pcert0, PTls13) {
    var ntrojan = []
    var cnt = subs.split("trojan://")[1]
    type = "trojan=";
    if (cnt.indexOf(":443") != -1) {
        ip = cnt.split("@")[1].split(":443")[0] + ":443";
    } else {
        ip = cnt.split("@")[1].split("?")[0].split("\n")[0].split("#")[0].trim();  
    }
    pwd = cnt.split("@")[0]? "password=" + decodeURIComponent(cnt.split("@")[0]):"";
    obfs = "over-tls=true";
    pcert = TLSCertParam(Pcert0, cnt.indexOf("allowInsecure=0") != -1 ? "true" : "false");
    thost = cnt.indexOf("sni=") != -1? "tls-host="+cnt.split("sni=")[1].split(/&|#/)[0]:""
    thost = cnt.indexOf("peer=") != -1? "tls-host="+cnt.split("peer=")[1].split(/&|#/)[0]:thost
    ptls13 = PTls13 == 1 ? "tls13=true" : "tls13=false"
    puri = ""
    pcert = TLSCertParam(Pcert0, cnt.indexOf("allowInsecure=0") != -1 ? "true" : "false");
    pudp = (Pudp == 1 || cnt.indexOf("udp=1")!=-1) ? "udp-relay=true" : "udp-relay=false";
    ptfo = (Ptfo == 1 || cnt.indexOf("tfo=1")!=-1)? "fast-open=true" : "fast-open=false";
     
    tag = cnt.indexOf("#") != -1 ? "tag=" + decodeURIComponent(cnt.split("#").slice(-1)[0]) : "tag= [trojan]" + ip
    if (cnt.indexOf("&plugin=obfs-local")!=-1) { 
    obfs = cnt.indexOf("obfs=websocket") != -1? "obfs=wss" : obfs 
    thost=cnt.indexOf("obfs-host=") == -1? thost : "obfs-host=" + decodeURIComponent(cnt.split("obfs-host=")[1].split(";")[0].split("#")[0])
    puri = cnt.indexOf("obfs-uri=") == -1? puri : "obfs-uri=" + decodeURIComponent(cnt.split("obfs-uri=")[1].split(";")[0].split("#")[0])
    } else if (cnt.indexOf("&type=ws")!=-1 || cnt.indexOf("?type=ws")!=-1) { 
      obfs = cnt.indexOf("security=tls") != -1? "obfs=wss" : obfs 
      thost=cnt.indexOf("&host=") == -1? thost : "obfs-host=" + decodeURIComponent(cnt.split("&host=")[1].split("&")[0].split("#")[0])
      puri = cnt.indexOf("&path=") == -1? puri : "obfs-uri=" + decodeURIComponent(cnt.split("&path=")[1].split("&")[0].split("#")[0])
    }
     
    prlt= version>=891? Reality_Handle(cnt) : ""
    ntrojan.push(type + ip, pwd, obfs, pcert, thost, puri, pudp, ptfo,prlt,tag)
    QX = ntrojan.filter(Boolean).join(", ");
     
    return QX;
}

function joinx(total,item) {
  return total+":"+item
}

 
function SS2QX(subs, Pudp, Ptfo) {
  var nssr = []
  var cnt = subs.split("ss://")[1]
  QX=""
  if (cnt.split(":").length <= 10) {  
    type = "shadowsocks=";
    let cntt = cnt.split("#")[0] 
     
    if (cntt.indexOf("@") != -1 && cntt.indexOf(":") != -1) { 
      ip = cnt.split("@")[1].split("#")[0].split("/")[0].split("?")[0];
      if(cntt.indexOf("%")==-1 || cntt.split("@")[0].indexOf(":")==-1){  
        pwdmtd = Base64.decode(cnt.split("@")[0].replace(/-/g, "+").replace(/_/g, "/").replace(/(%3D)|(\=)/g,"")).split("\u0000")[0].split(":")
      } else {
        pwdmtd = decodeURIComponent(cnt.split("@")[0]).split(":")
      }
    } else if (cntt.indexOf("?")==-1) {  
      var cnt0 = Base64.decode(cnt.split("#")[0].replace(/-/g, "+").replace(/_/g, "/").split("\u0000")[0]);
      ip = cnt0.split("@")[1].split("#")[0].split("/")[0];
      pwdmtd = cnt0.split("@")[0].split(":")
    } else if (cntt.indexOf("?") !=-1) {  
      var cnt0 = Base64.decode(cnt.split("#")[0].split("?")[0].replace(/-/g, "+").replace(/_/g, "/").split("\u0000")[0]);
      var cnt1 = Base64.decode(cnt.split("#")[0].split("?")[1].split("=")[1].replace(/-/g, "+").replace(/_/g, "/").split("\u0000")[0]);
      ip = cnt0.split("@")[1].split("#")[0].split("/")[0];
      pwdmtd = cnt0.split("@")[0].split(":")
    } 
    if(Pdbg) {$notify("dd","",pwdmtd)}
    mtd = "method=" + pwdmtd[0];
    pwdmtd.splice(0,1) 
    pwd = "password=" + pwdmtd.reduce(joinx);
    if (cntt.indexOf("v2ray-plugin")==-1 && cntt.indexOf("plugin=v2ray")==-1) {  
      obfs = cnt.split("obfs%3D")[1] != null ? ", obfs=" + cnt.split("obfs%3D")[1].split("%3B")[0].split("#")[0] : "";
      obfshost = cnt.split("obfs-host%3D")[1] != null ? ", obfs-host=" + decodeURIComponent(cnt.split("obfs-host%3D")[1].split("&")[0].split("#")[0]) : "";
    } else if (cnt1 != undefined){
      cnt1 = JSON.parse(cnt1)
      obfs= cnt1.tls? ", obfs=wss" : ", obfs=ws"
      obfshost = cnt1.host? ", obfs-host="+cnt1.host+", "+TLSCertParam(Pcert0, "false") : ""
    } else if (cntt.indexOf("v2ray-plugin")!=-1){
      cnt1 = decodeURIComponent(cntt.split("v2ray-plugin")[1])
      obfs= cnt1.indexOf("tls")!=-1? ", obfs=wss" : ", obfs=ws"
      obfshost = cnt1.indexOf("host=")!=-1? ", obfs-host="+cnt1.split("host=")[1].split(";")[0].split("#")[0].trim() : ""
      obfshost = obfshost != "obfs-host="? obfshost : ""
       
    } else if (cntt.indexOf("plugin=v2ray")!=-1) {
      cnt1 = decodeURIComponent(cntt.split("plugin=v2ray")[1])
      obfs= cnt1.indexOf("tls")!=-1? ", obfs=wss" : ", obfs=ws"
      obfshost = cnt1.indexOf("host=")!=-1? ", obfs-host="+cnt1.split("host=")[1].split(";")[0].split("#")[0].trim() : ""
      obfshost = obfshost != "obfs-host="? obfshost : ""
       

    }
    tag = decodeURIComponent(cnt.split("#")[1])!="undefined"? "tag=" + decodeURIComponent(cnt.split("#")[1]) : "tag=" + ip
    pudp = Pudp == 1 ? "udp-relay=true" : "udp-relay=false";
    ptfo = Ptfo == 1 ? "fast-open=true" : "fast-open=false";
    nssr.push(type + ip, pwd, mtd + obfs + obfshost, pudp, ptfo, tag)
    QX = nssr.join(", ")
    if(Pdbg==1) {$notify("SS","content",cnt+"\n"+QX)}
  }
  return QX;
}


 
function SSD2QX(subs, Pudp, Ptfo) {
    var j = 0
    var QX = []
    var cnt = JSON.parse(Base64.decode(subs.split("ssd://")[1]))
    var type = "shadowsocks=";
    var pwd = "password=" + cnt.password;
    var mtd = "method=" + cnt.encryption;
    var obfs = ""
    var obfshost = ""
    var port = cnt.port ? ":" + cnt.port : ""
    if (cnt.plugin_options) {
        obfs = cnt.plugin_options.split(";")[0] != null ? ", " + cnt.plugin_options.split(";")[0] : "";
        obfshost = cnt.plugin_options.split(";")[1] != null ? ", " + cnt.plugin_options.split(";")[1] : "";
    }
    pudp = Pudp == 1 ? "udp-relay=true" : "udp-relay=false";
    ptfo = Ptfo == 1 ? "fast-open=true" : "fast-open=false";
    for (var i in cnt.servers) {
        ip = cnt.servers[i].server;
        if (cnt.servers[i].plugin_options) {
            obfs = cnt.servers[i].plugin_options.split(";")[0] != null ? ", " + cnt.servers[i].plugin_options.split(";")[0] : "";
            obfshost = cnt.servers[i].plugin_options.split(";")[1] != null ? ", " + cnt.servers[i].plugin_options.split(";")[1] : "";
        }
        if (cnt.servers[i].encryption) {   
            mtd = "method=" + cnt.servers[i].encryption
        }
        if (cnt.servers[i].password) {   
            pwd = "password=" + cnt.servers[i].password
        }
        if (ip.indexOf(".") > 0) {  
            port = cnt.servers[i].port ? ":" + cnt.servers[i].port : port;
            tag = "tag=" + cnt.servers[i].remarks;
            QX[j] = type + ip + port + ", " + pwd + ", " + mtd + obfs + obfshost + ", " + pudp + ", " + ptfo + ", " + tag;
            var j = j + 1;
        }
    }
    return QX;
}

 







 
function QXFix(cntf) {
var cnti = cntf.replace(/\s*tag\s*\=/g,"tag=").replace("chacha20-poly","chacha20-ietf-poly")
try {
  function normalizeQXObfsUriValue(str) {
    var fieldK = "(password|method|udp-relay|udp-over-tcp|fast-open|obfs|obfs-host|obfs-uri|over-tls|tls-host|tls-verification|tls13|aead|tag|username|tls-alpn|server_check_url|tls-cert-sha256|tls-pubkey-sha256|reality-base64-pubkey|reality-hex-shortid|vless-flow)";
    return str.replace(new RegExp("(obfs-uri=)([\\s\\S]*?)(,\\s*" + fieldK + "=|$)", "g"), function(match, key, value, tail) {
      if (value.indexOf(",") == -1) {
        return key + value + tail;
      }
      var first = value.split(",")[0];
      var queryIndex = value.lastIndexOf("?");
      var query = queryIndex == -1 ? "" : value.slice(queryIndex);
      if (first.indexOf("?") != -1) {
        first = first.split("?")[0];
      }
      return key + first + query + tail;
    });
  }
  var hd = cnti.split(",tag=")[0]
  var tag = "tag="+cnti.split(",tag=")[1].split(",")[0].trim()
  var tail = cnti.split(tag+",")
  cnti = tail.length<=1?  cnti : String(hd + ","+tail[1].split("\r")[0] +"," + tag)
  cnti = normalizeQXObfsUriValue(cnti)
  cntis = cnti.split(",").filter(Boolean).map(item => item.trim())  
  tagfix = ""
  cntii = ""
  for (i in cntis) {
    if (cntis[i].indexOf("=") == -1 && cntis[i].trim() !="") {   
      tagfix += ","+cntis[i]
    } else {
      cntis[i].indexOf("tag=") != 0? cntii += cntis[i]+", ": cntii=cntii
    }
  }
  cntii = cntii+tag+tagfix
   
  return cntii
} catch (err) {
  if(Perror == 0) {
  $notify("❌ 解析出现错误,已忽略该条目", "⚠️ 请点击通知，发送订阅链接进行反馈", cntf+"\n"+ err, bug_link);
}
}
  return ""
}

 
function isQuanX(content) {
    var cnts = content.split("\n");
    var nlist = []
    for (var i = 0; i < cnts.length; i++) {
        var cnti = cnts[i];
        if (HY2Supported && HY2LineKind(cnti) == "quanx") {
            nlist.push(cnti.trim())
            continue
        }
        if (cnti.indexOf("=") != -1 && cnti.indexOf("tag") != -1) {
            var cnt = cnti.split("=")[0].trim()
            if (cnt == "http" || cnt == "shadowsocks" || cnt == "trojan" || cnt == "vmess" || cnt == "socks5" || cnt == "vless" ||  cnt == "anytls") {
                nlist.push(QXFix(cnti))
            }
        }
    }
   return nlist
}

 









function RewritePatternQuoteFix(cnti) {
  if (!cnti) { return cnti }
  function stripQuote(pattern) {
    if (pattern.length > 1 && pattern[0] == "\"" && pattern[pattern.length - 1] == "\"") {
      var unquoted = pattern.slice(1, -1).trim();
      if (/^\^?https?\??/i.test(unquoted)) {
        return unquoted;
      }
    }
    return pattern;
  }
  var marker = cnti.indexOf(" url-and-header ") != -1 ? " url-and-header " : " url ";
  var idx = cnti.indexOf(marker);
  if (idx == -1) { return cnti }
  var pattern = cnti.slice(0, idx).trim();
  var rest = cnti.slice(idx);
  if (marker == " url-and-header ") {
    var matched = pattern.match(/^(\"[^\"]+\")(\s+[\s\S]+)$/);
    if (matched) {
      return stripQuote(matched[1]) + matched[2] + rest;
    }
  }
  return stripQuote(pattern) + rest;
}

 
 
function NotifyUnsupportedRules(ignored) {
  if (!ignored.length) { return }
  var groups = [], byReason = Object.create(null), shown = 0, truncated = false
  function preview(text, limit) {
    if (text.length <= limit) { return text }
    truncated = true
    var end = limit - 1
    if (/[\uD800-\uDBFF]/.test(text[end - 1])) { end-- }
    return text.slice(0, end) + "…"
  }
  ignored.forEach(function (item) {
    var group = byReason[item.reason]
    if (!group) { group = { reason: item.reason, count: 0, rules: [], selected: [] }; byReason[item.reason] = group; groups.push(group) }
    group.count++
    if (group.rules.length < 10) { group.rules.push(item.rule) }
  })
  var visible = groups.slice(0, 5)
   
  for (var round = 0; round < 10 && shown < 10; round++) {
    for (var i = 0; i < visible.length && shown < 10; i++) {
      if (round < visible[i].rules.length) { visible[i].selected.push(visible[i].rules[round]); shown++ }
    }
  }
  var message = visible.map(function (group) {
    return "原因：" + preview(group.reason, 200) + "（共 " + group.count + " 条）\n" + group.selected.map(function (rule, i) { return (i + 1) + ". " + preview(rule, 240) }).join("\n")
  }).join("\n\n")
  if (shown < ignored.length) { message += "\n\n其余 " + (ignored.length - shown) + " 条未展开" + (groups.length > visible.length ? "，另有 " + (groups.length - visible.length) + " 组原因未展示" : "") + "。" }
  $notify("⚠️ 已忽略 " + ignored.length + " 条无法自动转换的规则 ➟ ⟦" + subtag + "⟧", "📋 点击通知查看详情（展示 " + shown + "/" + ignored.length + " 条）" + (truncated ? "，长内容已截断" : ""), message)
}

 
function isQuanXRewrite(content, failures) {
  var cnt = content.filter(Boolean)
  var cnt0=[]
  var ignoredEcho = failures || []
  var section = "", inComment = false, sectionInComment = false
  for (var i = 0; i< cnt.length; i++){
    if(cnt[i]){
      var cnti = cnt[i].trim()
      var originalRewrite = cnti
      var noteParts = RuleNoteSplit(cnti)
      cnti = noteParts.body
      if (!noteParts.note && /^\{#/.test(cnti)) { continue }  
      if (!cnti || /^(?:#|;|\/\/)/.test(cnti)) { continue }
       
      if (/^\/\*/.test(cnti)) { inComment = inComment || cnti.indexOf("*/", 2) == -1; continue }
      if (/^\*+\/(?:\s|$)/.test(cnti)) {
        if (sectionInComment) { section = "" }
        inComment = false; sectionInComment = false; continue
      }
      if (/^\[[^\]]+\]$/.test(cnti)) { section = cnti.toLowerCase(); sectionInComment = inComment; continue }
       
      var filterRule = /^[a-z][\w-]*\s*,/i.test(cnti) && (
        section == "[rule]" || section == "[filter_local]" ||
        /^(?:(?:host|domain)(?:-[\w-]+)?|ip-cidr6?|ip6-cidr|ip-asn|geoip|user-agent)\s*,\s*\S/i.test(cnti) ||
        /^(?:AND|OR|NOT)\s*,\s*\(/i.test(cnti)
      )
      var failureCount = ignoredEcho.length
       
       
      if (!/^(?:#|;|\/\/)/.test(cnti) && /\surl(?:-and-header)?\s+script-echo-response\s+resource-parser-response\.js(?:#[^\s]*)?$/i.test(cnti)) {
        ignoredEcho.push({ rule: originalRewrite, reason: "旧版本地辅助脚本引用已停用，解析器不能自动部署该文件" })
        continue
      }
       
      if (IsMapLocalInline(cnti)) {
        var inlineRewrite = MapLocalInline2QX(cnti, ignoredEcho)
        if (inlineRewrite) {
          cnt0.push(RuleNoteJoin(noteParts.note, RewritePatternQuoteFix(inlineRewrite)))
        }
        for (var n = failureCount; n < ignoredEcho.length; n++) { ignoredEcho[n].rule = originalRewrite }
        continue
      }
       
      if (IsJsonJQRewrite(cnti)) {
        if (version < 845) {
          ignoredEcho.push({ rule: originalRewrite, reason: "jsonjq 需要 Quantumult X build 845 或更新版本" })
          continue
        }
        cnti = JsonJQRewrite2QX(cnti)
        if (!cnti) { ignoredEcho.push({ rule: originalRewrite, reason: /^http-(?:request|response)-jq\s+http-(?:request|response)(?:-jq)?\s/i.test(originalRewrite) ? "jq 规则的 URL 位置多出 http-request/http-response 动作，源格式错误" : "jq 规则缺少有效 URL、表达式，或引号未闭合" }) }
      } else if (/\surl(?:-and-header)?\s+jsonjq-(?:request|response)-body\s/i.test(cnti)) {
        cnti = cnti.replace(/^\^http/, "http")
      } else if (filterRule && /^(?:AND|OR|NOT)\s*,/i.test(cnti)) {
        ignoredEcho.push({ rule: originalRewrite, reason: "逻辑组合规则无法直接转换，拆开会改变匹配条件" })
        continue
      } else if (cnti.indexOf("pattern")!=-1 && cnti.indexOf("type")!=-1 || cnti.indexOf("http-r")!=-1) {
        cnti=SGMD2QX(cnti)[0]? SGMD2QX(cnti)[0]:""
         
      }else if (!filterRule && (cnti.indexOf(" 302")!=-1 || cnti.indexOf(" 307")!=-1 || (/\s(_|-)\s(reject|REJECT)/.test(cnti)) || (/\sreject$/.test(cnti)) || (/\sreject-/.test(cnti))) && cnti.indexOf(" url ")==-1 && cnti.indexOf(" url-and-header ")==-1 ){
        cnti=SGMD2QX(cnti)[0]? SGMD2QX(cnti)[0]:""
         
      }else if(cnti.indexOf(" data=")!=-1){
        cnti = SGMD2QX("[Map Local]\n"+cnti)[0]? SGMD2QX("[Map Local]\n"+cnti)[0]:""
         
      }else if(cnti.indexOf("URL-REGEX")!=-1 || cnti.indexOf(" header")!=-1 || cnti.replace(/ /g,"").indexOf("hostname=")!=-1){
        cnti=SGMD2QX(cnti)[0]? SGMD2QX(cnti)[0]:""
      }else if (cnti.indexOf(" url ")!=-1 && cnti.indexOf(" simple-response ")==-1 && cnti.indexOf(" url = ")==-1){  
        cnti = cnti.replace("^http","http")  
        cnti= cnti.split(" ")[1] == "url" ? cnti : ""
      } else if (cnti.indexOf(" url-and-header ")!=-1 ){  
        cnti= cnti  
      } else if (filterRule) {
        if (Pmix==1) { cnti = Rule_Policy(cnti, ignoredEcho) }
        else { ignoredEcho.push({ rule: originalRewrite, reason: "重写资源混合分流需要 Quantumult X build 844 或更新版本" }); cnti = "" }
      } else {
        cnti=""
      }
      if (noteParts.note) {
        for (var n = failureCount; n < ignoredEcho.length; n++) { ignoredEcho[n].rule = originalRewrite }
      }
      if (!cnti && ignoredEcho.length == failureCount && (/^\[(?:rule|url rewrite|body rewrite|map local|script)\]$/.test(section) || /\sdata-type\s*=|^http-(?:request|response)(?:\s|$)/i.test(noteParts.body))) {
        ignoredEcho.push({ rule: originalRewrite, reason: "未识别到此条目的可靠 Quantumult X 转换语法" })
      }
      if (/\surl(?:-and-header)?\s+jsonjq-(?:request|response)-body\s/i.test(cnti) && version < 845) {
        ignoredEcho.push({ rule: originalRewrite, reason: "jsonjq 需要 Quantumult X build 845 或更新版本" })
        continue
      }
      if (cnti!="" && cnti.trim()[0]!="[" && cnti.indexOf("RULE-SET")==-1 && !/cronexp\=|type\=cron/.test(cnti.replace(/ /g,""))) {  
        if (!(/\;$/.test(cnti))) {  
         
        var echo = cnti.match(/\surl(?:-and-header)?\s+echo-response\s+\S[\s\S]*?\s+echo-response(?:\s+([\s\S]*))?$/i)
        var echoBody = echo ? (echo[1] || "").trim().replace(/^(['"])([\s\S]*)\1$/, "$2") : ""
        if (echo && (!echoBody || /^(?:\{[\s\S]*\}|\[[\s\S]*\]|<[\s\S]*>)$|^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(echoBody))) {
          var echoReason = !echoBody ? "echo-response 缺少本地正文文件名" : /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(echoBody) ? "echo-response 需要本机 Data 目录中的正文文件，不能直接引用 URL/URI" : "echo-response 不接受内联正文，需要本机 Data 目录中的正文文件"
          ignoredEcho.push({ rule: originalRewrite, reason: echoReason })
          continue
        }
        cnt0.push(RuleNoteJoin(noteParts.note, RewritePatternQuoteFix(cnti)))  
         
      }
      }
    }
  }
  NotifyUnsupportedRules(ignoredEcho)
   
  return cnt0
}



 
function QXSort(content, para) {
    var nlist = content; 
    if (para == 1) {
        return nlist.sort(ToTag)
    } else if (para == -1) {
        return nlist.sort(ToTagR)
    } else if(para == "x") {
        return shuffle(nlist)
    } else if(para == "0") {
        return nlist
    } else {
      return Sort_KWD (nlist,para)  
    }
}
 
function ToTag(elem1, elem2) {
    var tag1 = elem1.split("tag")[1].split("=")[1].trim()
    var tag2 = elem2.split("tag")[1].split("=")[1].trim()
    res = tag1 > tag2 ? 1 : -1
    return res
}
 
function ToTagR(elem1, elem2) {
    var tag1 = elem1.split("tag")[1].split("=")[1].trim()
    var tag2 = elem2.split("tag")[1].split("=")[1].trim()
    res = tag1 > tag2 ? -1 : 1
    return res
}
 
function shuffle(arr) {
    var input = arr;
    for (var i = input.length - 1; i >= 0; i--) {
        var randomIndex = Math.floor(Math.random() * (i + 1));
        var itemAtIndex = input[randomIndex];
        input[randomIndex] = input[i];
        input[i] = itemAtIndex;
    }
    return input;
}

 
function Sort_KWD (cnt,strs) {
  strlist = strs.indexOf("<") != -1 ? strs.split("<"):strs.split(">")
  regj = strlist.map(item => RegExp(item, "i"))
   
  dir = strs.indexOf("<") != -1 ? -1:1
  var arr =  new Array(strlist.length+1);    
  for(var i = 0;i < arr.length; i++){
    arr[i] = [];     
  }
  for (var i =0; i<cnt.length ; i++) {
    flag = 0
    for (var j=0; j<strlist.length ; j++){
      if(regj[j].test(cnt[i])) {
        arr[j].push(cnt[i])
        flag = 1
        break
      } 
    }
    if (flag != 1){
      arr[strlist.length].push(cnt[i]) }  
  }
   
  arr = PsortX == -1? arr.map(item => item.sort(ToTagR)):arr
  arr = PsortX == 1? arr.map(item => item.sort(ToTag)):arr
  newarr = MixArr(arr,dir)
  return newarr
}

function MixArr(cnt,dir){
  var cnt0=[]
  for (i=0; i<cnt.length-1; i++){
     
    cnt0 = dir ==1? cnt0.concat(cnt[i]):cnt0.concat(cnt[cnt.length-2-i])
  }
  cnt0 = dir ==1? cnt0.concat(cnt[cnt.length-1].sort(ToTag)):(cnt[cnt.length-1].sort(ToTagR)).concat(cnt0)
  return cnt0
}


 
function DelReg(content) {
    delreg = RegExp(delreg, "gmi")
    content=content.replace(/tag\s*\=\s*/,"tag=")
    cnt0 = content.split("tag=")[0]
    cnt1 = content.split("tag=")[1].split(",")[0]
    cnt2 = content.split("tag=")[1].split(",").length==1 ? "": content.split(cnt1)[1]
    cnt = cnt0 + "tag=" + cnt1.replace(delreg, "")+cnt2
    return cnt
}

 
function Rename(str) {
    var server = str;
    if (server.indexOf("tag=") != -1) {
        hd = server.split("tag=")[0]  
        name = server.split("tag=")[1].split(",")[0].trim()  
        tail = server.split("tag=")[1].split(",").length <=1 ? "" : server.split("tag=")[1].split(name)[1]
        for (var i = 0; i < Prn.length; i++) {
            nname = Prn[i].split("@")[1] ? decodeURIComponent(Prn[i].split("@")[1]) : Prn[i].split("@")[1];
            oname = Prn[i].split("@")[0] ? decodeURIComponent(Prn[i].split("@")[0]) : Prn[i].split("@")[0];
            if (oname && nname) {  
                var rn = escapeRegExp(oname)
                name = name.replace(new RegExp(rn, "gm"), nname)
            } else if (oname && nname == "") { 
                var nemoji = emoji_del(name)
                if ((Pemoji == 1 || Pemoji == 2) && Prname ) {  
                    name = oname + nemoji  
                } else { name = oname + name.trim() }
            } else if (nname && oname == "") { 
                name = name.trim() + nname
            } else if (oname && oname.indexOf("☠️") != -1) {  
                hh = Dot2(oname.slice(0, oname.length - 2)).split(".")  
                for (j = 0; j < hh.length; j++) {
                    var nn = escapeRegExp(ToDot(hh[j]))
                    var del = new RegExp(nn, "gm");
                    name = name.replace(del, "")
                }
            } else if (oname == "" && nname == "") {  
                name = name.replace(/@/g, "")
            } else {
                name = name
            }
            nserver = hd + "tag=" + name + tail
        }
      return nserver
    } else {
      return server
    }
}

function RenameScript(servers, script) {
    $notify("🤖 启用脚本进行重命名", "", script);
    try {
        const $ = Tools().rename;
         
        const nodes = Tools().getNodeInfo(servers);
        eval(script);
        const newNames = rename(nodes);
         
        return servers.map((s, i) => s.split("tag=")[0] + "tag=" + newNames[i]);
    } catch (err) {
        $notify("❌ 脚本重命名出现错误", "", err);
        return servers;
    }

}

 
function emoji_del(str) {
    return str.replace(/[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/g, "").trim(); 
}

 
function get_emoji(emojip, sname) {
   var Lmoji = { 
    "🏳️‍🌈": ["流量", "套餐", "剩余", "重置", "到期" , "时间", "应急", "过期", "Bandwidth", "expire", "Traffic", "traffic"],
    "🇴🇲": ["阿曼", " OM "],
    "🇦🇩": ["安道尔","安道爾", "Andorra"],
    "🇦🇴": ["安哥拉"],
    "🇦🇫": ["阿富汗"],
    "🇩🇿": ["阿尔及利亚","阿爾及利亞"],
    "🇫🇴": ["法羅群島","法罗群岛"],
    "🇧🇲": ["百慕大"],
    "🇦🇽": ["奧蘭群島", "奥兰群岛"],
    "🇦🇿": ["阿塞拜疆","Azerbaijan"],
    "🇦🇹": ["奥地利", "奧地利", "Austria", "维也纳"],
    "🇦🇺": ["AU", "Australia", "Sydney", "澳大利亚", "澳洲", "墨尔本", "悉尼" ,"土澳", "京澳","廣澳","滬澳","沪澳","广澳"],
    "🇧🇪": ["BE", "比利時","比利时","Belgium"],
    "🇧🇬": ["保加利亚", "保加利亞","Bulgaria"],
    "🇵🇰": ["巴基斯坦","Pakistan", "PAKISTAN"],
    "🇧🇭": ["巴林","Bahrain"],
    "🇵🇾": ["巴拉圭","Paraguay"],
    "🇧🇧": ["巴巴多斯"],
    "🇬🇶": ["赤道几内亚","赤道幾內亞"],
    "🇹🇱": ["东帝汶","東帝汶"],
    "🇰🇭": ["柬埔寨","Cambodia"],
    "🇿🇼": ["津巴布韦","津巴布韋"],
    "🇺🇦": ["烏克蘭","乌克兰","Ukraine"],
    "🇺🇿": ["乌兹别克斯坦", "烏茲別克斯坦","Uzbekistan"],
    "🇭🇷": ["克罗地亚","HR","克羅地亞", "Croatia"],
    "🇨🇦": ["CA", "Canada","CANADA", "CAN", "Waterloo", "加拿大", "蒙特利尔", "温哥华", "楓葉", "枫叶", "滑铁卢", "多伦多"],
    "🇨🇭": ["瑞士", "苏黎世", "Switzerland", "CH "],
    "🇳🇬": ["尼日利亚", "NG", "尼日利亞","拉各斯", "Nigeria"],
    "🇨🇿": ["Czechia", "捷克"],
    "🇸🇰": ["斯洛伐克", "SK" , "Slovakia"],
    "🇸🇮": ["斯洛文尼亚", "斯洛文尼亞", "Slovenia"],
    "🇦🇲": ["亚美尼亚", "亞美尼亞", "Armenia"],
    "🇷🇸": ["RS ","RS_", "塞尔维亚", "塞爾維亞", "Seville", "Sevilla"],
    "🇲🇩": ["摩爾多瓦"," MD-","摩尔多瓦", "Moldova"," MD "],
    "🇩🇪": ["DE ", "DE-", "DE_", "German", "GERMAN", "德国", "德國", "法兰克福","京德","滬德","廣德","沪德","广德"],
    "🇩🇰": ["DK","DNK","丹麦","丹麥", "Denmark"],
    "🇪🇸": ["ES", "西班牙", "Spain"],
    "🇪🇺": ["EU", "欧盟", "欧罗巴","欧洲", "European"],
    "🇫🇮": ["Finland", "芬兰","芬蘭","赫尔辛基"],
    "🇫🇷": ["FR", "France", "法国", "法國", "巴黎"],
    "🇷🇪": ["留尼汪", "留尼旺", "Réunion", "Reunion"],
    "🇨🇼": ["库拉索", "庫拉索", "Curaçao"],
    "🇬🇧": ["UK", "GB ", "England", "United Kingdom", "英国", "伦敦", "英", "Britain"],
    "🇲🇴": ["MO", "Macao","Macau", "MAC", "澳门", "澳門", "CTM"],
    "🇰🇿": ["哈萨克斯坦", "哈薩克斯坦", "Kazakhstan"],
    "🇱🇦": ["老挝","老挝", "Laos"],
    "🇭🇺": ["匈牙利", "Hungary"],
    "🇭🇳": ["洪都拉斯"],
    "🇱🇹": ["立陶宛", "Lithuania"],
    "🇱🇰": ["斯里兰卡", "斯里蘭卡", "Sri Lanka"],
    "🇧🇾": ["BY","白俄罗斯","白俄羅斯", "White Russia", "Republic of Belarus", "Belarus"],
    "🇷🇺": ["RU ","RU-", "RU_", "RUS", "Russia", "俄罗斯", "毛子", "俄国", "俄羅斯", "伯力", "莫斯科", "圣彼得堡", "西伯利亚", "新西伯利亚", "京俄", "杭俄","廣俄","滬俄","广俄","沪俄"],
    "🇸🇬": ["SG", "Singapore","SINGAPORE", "新加坡", "狮城", "獅城", "沪新", "京新", "泉新", "穗新", "深新", "杭新", "广新","廣新","滬新"],
    "🇺🇸": ["US", "USA", "America", "United States", "美国", "美", "京美", "波特兰", "达拉斯", "俄勒冈", "凤凰城", "费利蒙", "硅谷", "矽谷", "拉斯维加斯", "洛杉矶", "圣何塞", "圣荷西", "圣克拉拉", "西雅图", "芝加哥", "沪美", "哥伦布", "纽约"],
    "🇹🇼": ["TW", "Taiwan","TAIWAN", "台湾", "台北", "台中", "新北", "彰化", "CHT", "台", "HINET"],
    "🇮🇩": ["ID ","ID-", "IDN ", "Indonesia", "印尼", "印度尼西亚", "雅加达"],
    "🇮🇪": ["Ireland", "IRELAND", "IE ", "爱尔兰", "愛爾蘭", "都柏林"],
    "🇮🇱": ["Israel", "以色列"],
    "🇮🇳": ["India", "IND", "INDIA","印度", "孟买", "Mumbai","IN "],
    "🇮🇸": ["IS","ISL", "冰岛","冰島", "Iceland"],
    "🇰🇵": ["KP", "朝鲜", "North Korea","朝鮮"],
    "🇰🇷": ["KR", "Korea", "KOR", "韩国", "首尔", "韩", "韓","春川"],
    "🇬🇭": ["加纳", "Ghana", "迦納"],
    "🇱🇺": ["卢森堡", "盧森堡", "LU ", "Luxembourg"],
    "🇱🇻": ["Latvia", "Latvija", "拉脱维亚"],
    "🇧🇩": ["孟加拉", "Bengal"],
    "🇲🇽️": [" MEX", "MX", "墨西哥", "Mexico", "MEXICO"],
    "🇲🇾": [" MY", "MY-", "Malaysia","MALAYSIA", "马来西亚", "马来", "馬來", "大马", "大馬", "馬來西亞", "吉隆坡"],
    "🇲🇲": ["缅甸","緬甸"],
    "🇳🇮": ["尼加拉瓜"],
    "🇳🇱": [" NL","NL-", "Netherlands", "荷兰", "荷蘭", "尼德蘭", "阿姆斯特丹"],
    "🇵🇭": [" PH", "Philippines", "菲律宾", "菲律賓"],
    "🇷🇴": [" RO ", "罗马尼亚", "Rumania", "羅馬尼亞"],
    "🇸🇦": ["沙特", "利雅得", "Saudi Arabia", "Saudi"],
    "🇸🇪": ["SE", "Sweden","瑞典"],
    "🇹🇭": [" TH", "Thailand", "泰国", "泰國", "曼谷"],
    "🇹🇷": ["TR ","TR-", "TR_", "TUR", "Turkey", "土耳其", "伊斯坦布尔"],
    "🇻🇳": ["VN", "越南", "胡志明市", "Vietnam"],
    "🇮🇹": ["Italy", " IT ", "Nachash", "意大利", "米兰", "義大利"],
    "🇿🇦": ["South Africa", "南非", "Johannesburg"],
    "🇦🇪": ["United Arab Emirates", "阿联酋","AE ", "迪拜", "阿聯酋", "Dubai"],
    "🇧🇷": ["BR", "Brazil", "巴西", "圣保罗"],
    "🇯🇵": ["JP", "Japan","JAPAN", "日本", "东京", "大阪", "埼玉", "京日", "苏日", "沪日","上日", "穗日", "川日", "中日", "泉日", "杭日", "深日", "辽日", "广日", "Tokyo"],
    "🇦🇷": ["AR ", "Argentina", "阿根廷","AR-"],
    "🇳🇴": ["Norway", "挪威", "NO"],
    "🇵🇱": [" PL", "POL", "波兰","波蘭", "Poland"],
    "🇨🇱": ["智利","Chile","CHILE"],
    "🇳🇿": ["新西蘭","新西兰", "New Zealand"],
    "🇬🇷": ["希腊","希臘", "Greece"],
    "🇪🇬": ["埃及", "Egypt"],
    "🇮🇲": ["马恩岛","馬恩島", "Isle of Man", "Mannin"],
    "🇵🇹": ["葡萄牙", "Portugal"],
    "🇲🇳": ["蒙古", "Mongolia"],
    "🇵🇪": ["秘鲁","祕魯", "Peru"],
    "🇨🇴": ["哥伦比亚", "哥倫比亞", "Colombia"],
    "🇪🇪": ["爱沙尼亚", "愛沙尼亞", "Estonia"],
    "🇱🇾": ["利比亚","利比亞", "Libya"],
    "🇲🇰": ["马其顿","馬其頓", "Macedonia"],
    "🇲🇹": ["马耳他", "馬其他", "Malta"],
    "🇻🇪": ["委内瑞拉", "Venezuela"],
    "🇧🇦": ["波黑共和国","波黑", "Bosnia and Herzegovina"],
    "🇬🇪": ["格魯吉亞","格鲁吉亚", "Georgia"],
    "🇦🇱": ["阿爾巴尼亞","阿尔巴尼亚", "Albania"],
    "🇨🇾": ["CY","塞浦路斯", "Cyprus"],
    "🇨🇷": ["哥斯达黎加", "哥斯達尼加", "Costa Rica"],
    "🇹🇳": ["突尼斯", "Tunisia"],
    "🇻🇦": ["梵蒂冈","梵蒂岡"],
    "🇷🇼": ["卢旺达","盧旺達"],
    "🇵🇦": ["巴拿马","巴拿馬", "Panama"],
    "🇮🇷": ["伊朗", "Iran"],
    "🇯🇴": ["约旦", "約旦", "Jordan"],
    "🇺🇾": ["乌拉圭" , "烏拉圭", "Uruguay"],
    "🇰🇪": ["肯尼亚", "肯尼亞", "Kenya"],
    "🇰🇬": ["吉尔吉斯坦","吉尔吉斯斯坦", "Kyrghyzstan"],
    "🇳🇵": ["尼泊尔", "尼泊爾", "Nepal"],
    "🇽🇰": ["科索沃", "Kosovo"],
    "🇲🇦": ["摩洛哥", "Morocco"],
    "🇪🇨": ["厄瓜多尔", "厄瓜多爾", "EC", "Ecuador"],
    "🇲🇺": ["毛里求斯", "Mauritius"],
    "🇵🇷": ["波多黎各", "PR ","PR-", "Puerto Rico"],
    "🇬🇹": ["危地马拉", "危地馬拉", " GT "],
    "🇭🇰": ["HK", "Hongkong", "Hong Kong", "HongKong", "HONG KONG","香港", "深港", "沪港", "呼港", "HKT", "HKBN", "HGC", "WTT", "CMI", "穗港", "京港", "港"],
    "🇨🇳": ["CN", "China", "回国", "中国","中國", "江苏", "北京", "上海", "广州", "深圳", "杭州", "徐州", "青岛", "宁波", "镇江", "back"],
    "🇨🇺": ["古巴"],
    "🇸🇲": ["圣马力诺","聖馬利諾"],
    "🇰🇾": ["开曼群岛","開曼群島"],
    "🇫🇯": ["斐济","斐濟"],
    "🇬🇱": ["格陵兰","格陵蘭"],
    "🇬🇮": ["直布罗陀","直布羅陀"],
    "🇲🇪": ["黑山"],
    "🇱🇮": ["列支敦士登"],
    "🇬🇺": ["关岛","關島"],
    "🇦🇶": ["南极","南極"],
    "🇧🇹": ["不丹"], 
    "🇲🇻": ["马尔代夫", "馬爾代夫"],
    "🇮🇶": ["伊拉克"],
    "🇸🇨": ["塞舌尔","塞舌爾"],
    "🇶🇦": ["卡塔尔", "卡塔爾", " QA "],
    "🇸🇾": ["叙利亚", "敘利亞", " SY "],
    "🇱🇧": ["黎巴嫩","LB", "Lebanon"],
    "🇧🇳": ["文莱","汶萊", "BRN","Negara Brunei Darussalam"],
    "🇨🇻": ["佛得角"],
    "🇸🇷": ["苏里南","蘇里南"],
    "🇲🇨": ["摩纳哥","摩納哥"],
    "🇯🇲": ["牙买加","牙買加 "],
    "🌏": ["亚洲","Asia"],
    "🇹🇬": ["多哥"],
    "🇵🇸": ["巴勒斯坦"],
    "🇬🇫": ["法屬圭亞那","法属圭亚那"],
    "🇹🇹": ["特立尼达和多巴哥","特立尼達和多巴哥"]
  }
    str1 = JSON.stringify(Lmoji)
    aa = JSON.parse(str1)
    bb = JSON.parse(str1.replace(/🇹🇼/g, " 🇨🇳"))
    var cnt = emojip ==1? aa:bb;
    var flag = 0;
    for (var key in cnt) {
        dd = cnt[key]
        for (i in dd) {
            if (sname.indexOf(dd[i]) != -1) {
                flag = 1;
                nname = key + " " + sname.replace(/[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/g, "").trim();  
                return [nname,key]
            }
        }
    }
    if (flag == 0) { return ["🏴‍☠️ " + sname.replace(/[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/g, "").trim(), "🏴‍☠️"] }
}

 
function emoji_handle(servers, Pemoji) {
    var nlist = []
    var ser0 = servers

    for (var i = 0; i < ser0.length; i++) {
        if (ser0[i].indexOf("tag=") != -1) {
            var oname = ser0[i].split("tag=")[1].trim();
            var hd = ser0[i].split("tag=")[0];
            var nname = oname; 
             
            if (Pemoji == 1) {
                var nname = get_emoji(1, nname)[0]
            } else if (Pemoji == 2) {
                var nname = get_emoji(2, nname)[0]
            } else if (Pemoji == -1) {
                nname = emoji_del(oname);
            }
            var nserver = hd + "tag=" + nname.replace("  ", " ").trim()
            nlist.push(nserver)
        }
    }
    return nlist
}

 
function Surge2QX(conf) {
  var QXlist = conf.split("\n").map(function (row) {
    return HY2LineKind(row) == "surge" ? row : isSurge(row)
  }).filter(Boolean)
  var Nlist = []
  var node=""
  for (var i = 0; i < QXlist.length; i++) {
    var cnt = QXlist[i];
    if (HY2LineKind(cnt) == "surge") {
      var hy2 = HY2Convert("surge", cnt)
      if (hy2) Nlist.push(hy2)
      continue
    }
    if (cnt.split("=")[1].split(",")[0].indexOf("trojan") != -1) {
      node = Strojan2QX(cnt) 
    } else if (cnt.split("=")[1].split(",")[0].indexOf("http") != -1) {
      node = Shttp2QX(cnt)  
    } else if (cnt.split("=")[1].split(",")[0].indexOf("vmess") != -1) {
      node = SVmess2QX(cnt)  
    } else if (cnt.split("=")[1].split(",")[0].indexOf("ss") != -1) {
      node = SSS2QX(cnt)  
    } else if (cnt.split("=")[1].split(",")[0].indexOf("socks5") != -1) {
      node = SS52QX(cnt)  
    } else if (cnt.split("=")[1].split(",")[0].indexOf("custom") != -1) {
      node = SCT2QX(cnt)  
    } else if (cnt.split("=")[1].split(",")[0].indexOf("anytls") != -1 && version>913) {
      node = SATS2QX(cnt)  
    }
    node = Pudp0 != 0 ? XUDP(node,Pudp0) : node
    node = Ptfo0 != 0 ? XTFO(node,Ptfo0) : node
    if (cnt.indexOf("test-url") !=-1) {
      var checkurl = ", server_check_url" + cnt.split("test-url")[1].split(",")[0]
      node = node.replace(/\,(\s)*tag/, checkurl + ", tag")
    }
    Nlist.push(node)
  }
  return (Nlist)
}


 
 
function SCT2QX(content) {
    var cnt = content;
    var tag = "tag=" + cnt.split("=")[0].trim();
    var ipport = cnt.split(",")[1].trim() + ":" + cnt.split(",")[2].trim();
    var pmtd = "method=" + cnt.split(",")[3].trim();
    var pwd = "password=" + cnt.split(",")[4].trim();
    if (cnt.indexOf("obfs") != -1) {
        pobfs = "obfs=" + cnt.replace(/obfs-host/, "").split("obfs")[1].split(",")[0].split("=")[1]
    } else { pobfs = "" }
    var phost = cnt.indexOf("obfs-host") != -1 ? "obfs-host" + cnt.split("obfs-host")[1].split(",")[0].trim() : "";
    if (phost != "") {
        pobfs = pobfs + ", " + phost
    }
    var ptfo = paraCheck(cnt, "tfo") == "true" ? "fast-open=true" : "fast-open=false";
    var pudp = paraCheck(cnt, "udp-relay") == "true" ? "udp-relay=true" : "udp-relay=false";
    var nserver = pobfs != "" ? "shadowsocks= " + [ipport, pmtd, pwd, pobfs, ptfo, pudp, tag].join(", ") : "shadowsocks= " + [ipport, pmtd, pwd, ptfo, pudp, tag].join(", ");
    return nserver
}


 
function SSS2QX(content) {
    var cnt = content;
    var cnts=cnt.replace(" ","").replace("\"","")
    var tag = "tag=" + cnt.split("=")[0].trim();
    var ipport = cnt.split(",")[1].trim() + ":" + cnt.split(",")[2].trim();
    var pmtd = "method=" + cnt.split("encrypt-method")[1].split(",")[0].split("=")[1];
    var pwd = "password=" + cnts.split("password=")[1].split(",")[0].replace("\"","") 
    if (cnt.indexOf("obfs") != -1) {
        pobfs = "obfs=" + cnt.replace(/obfs-host/, "").split("obfs")[1].split(",")[0].split("=")[1]
    } else { pobfs = "" }
    var phost = cnt.indexOf("obfs-host") != -1 ? "obfs-host" + cnt.split("obfs-host")[1].split(",")[0].trim() : "";
    if (phost != "") {
        pobfs = pobfs + ", " + phost
    }
    var ptfo = paraCheck(cnt, "tfo") == "true" ? "fast-open=true" : "fast-open=false";
    var pudp = paraCheck(cnt, "udp-relay") == "true" ? "udp-relay=true" : "udp-relay=false";
    var nserver = pobfs != "" ? "shadowsocks= " + [ipport, pmtd, pwd, pobfs, ptfo, pudp, tag].join(", ") : "shadowsocks= " + [ipport, pmtd, pwd, ptfo, pudp, tag].join(", ");
    return nserver
}


 
function SVmess2QX(content) {
    var cnt = content;
    var tag = "tag=" + cnt.split("=")[0].trim();
    var ipport = cnt.split(",")[1].trim() + ":" + cnt.split(",")[2].trim();
    var puname = cnt.indexOf("username") != -1 ? "password=" + cnt.split("username")[1].split(",")[0].split("=")[1].trim() : "";
    var pmtd = "method=aes-128-gcm";
    var ptls13 = paraCheck(cnt, "tls13") == "true" ? "tls13=true" : "tls13=false";
    var pverify = TLSCertParam(Pcert0, cnt.replace(/ /g,"").indexOf("skip-cert-verify=false") != -1 ? "true" : "false");
    if (paraCheck(cnt.replace(/tls13/, ""), "tls") == "true" && paraCheck(cnt.replace(/ws-header/, ""), "ws") == "true") {
        pobfs = "obfs=wss" + ", " + ptls13 + ", " + pverify
    } else if (paraCheck(cnt.replace(/ws-header/, ""), "ws") == "true") {
        pobfs = "obfs=ws"
    } else if (paraCheck(cnt.replace(/tls13/, ""), "tls") != "false") {
        pobfs = "obfs=over-tls" + ", " + ptls13 + ", " + pverify
    } else if (paraCheck(cnt.replace(/ws-header/, ""), "ws") == "false") {
        pobfs = ""
    }
    var puri = paraCheck(cnt, "ws-path") != "false" ? "obfs-uri=" + cnt.split("ws-path")[1].split(",")[0].split("=")[1].trim() : "obfs-uri=/"
    var phost = cnt.indexOf("ws-headers") != -1 ? "obfs-host=" + cnt.split("ws-headers")[1].split(",")[0].split("=")[1].split(":")[1].trim() : "";
    if (pobfs.indexOf("ws" || "wss") != -1) {
        if (phost != "") {
            pobfs = pobfs + ", " + puri + ", " + phost
        } else { pobfs = pobfs + ", " + puri }
    }
    var ptfo = paraCheck(cnt, "tfo") == "true" ? "fast-open=true" : "fast-open=false";
    var nserver = pobfs != "" ? "vmess= " + [ipport, puname, pmtd, pobfs, ptfo, tag].join(", ") : "vmess= " + [ipport, puname, pmtd, ptfo, tag].join(", ");
    return nserver
}

 
function isSurge(content) {
  if (content.indexOf("=") != -1) {
    cnt = content.split("=")[1].split(",")[0].trim()
    if (cnt == "http" || cnt == "ss" || cnt == "trojan" || cnt == "vmess" || cnt == "custom" || cnt == "https" || cnt == "socks5"|| cnt == "socks5-tls"|| cnt == "anytls") {
        return content
    }
  }
}
 
function paraCheck(content, para) {
  content=content.replace(/ /g,"")
  if (content.indexOf(para+"=") == -1) {
    return "false"
  } else {
       
    return content.split(para+"=")[1].split(",")[0].trim()
  }
}
 
function Strojan2QX(content) {
  var cnt = content;
  var tag = "tag=" + cnt.split("=")[0].trim();
  var ipport = cnt.split(",")[1].trim() + ":" + cnt.split(",")[2].trim();
  var pwd = "password=" + cnt.split("password")[1].split(",")[0].split("=")[1].trim();
  var ptls = "over-tls=true";
  var ptfo = paraCheck(cnt, "tfo") == "true" ? "fast-open=true" : "fast-open=false";
  var pverify = TLSCertParam(Pcert0, cnt.replace(/ /g,"").indexOf("skip-cert-verify=false") != -1 ? "true" : "false");
  var phost = cnt.indexOf("sni")!=-1? "tls-host="+cnt.split("sni")[1].split(",")[0].split("=")[1]:""
  var ptls13 = paraCheck(cnt, "tls13") == "true" ? "tls13=true" : "tls13=false";
  var nserver = "trojan= " + [ipport, pwd, ptls, ptfo, ptls13, phost,pverify, tag].filter(Boolean).join(", ");
  return nserver
}

 
function SATS2QX(content) {
  try {
    var cnt = content;
    if (Pdbg==1) {$notify(cnt)}
    var tag = "tag=" + cnt.split("=")[0].trim();
    var ipport = cnt.split(",")[1].trim() + ":" + cnt.split(",")[2].trim();
    var pwd = "password=" + cnt.split("password")[1].split(",")[0].split("=")[1].trim();
    var ptls = "over-tls=true";
     
    var pverify = TLSCertParam(Pcert0, cnt.replace(/ /g,"").indexOf("skip-cert-verify=false") != -1 ? "true" : "false");
    var phost = cnt.indexOf("sni")!=-1? "tls-host="+cnt.split("sni")[1].split(",")[0].split("=")[1]:""
    pudp = Pudp0 == -1 ? "udp-relay=false" : "udp-relay=true"  
    var nserver = "anytls= " + [ipport, pwd, ptls, pverify, phost,pudp, tag].filter(Boolean).join(", ");
    return nserver
  } catch (error) {
    console.log("surge-anytls:"+error)
  }
}


 
function Shttp2QX(content) {
  var cnt = content;
  var tag = "tag=" + cnt.split("=")[0].trim();
  var ipport = cnt.split(",")[1].trim() + ":" + cnt.split(",")[2].trim();
  var puname = cnt.indexOf("username") != -1 ? "username=" + cnt.split("username")[1].split(",")[0].split("=")[1].trim() : "";
  var pwd = cnt.indexOf("password") != -1 ? "password=" + cnt.split("password")[1].split(",")[0].split("=")[1].trim() : "";
  var ptls = cnt.split("=")[1].split(",")[0].trim() == "https" ? "over-tls=true" : "over-tls=false";
  var ptfo = paraCheck(cnt, "tfo") == "true" ? "fast-open=true" : "fast-open=false";
  if (ptls == "over-tls=true") {
    var pverify = TLSCertParam(Pcert0, cnt.replace(/ /g,"").indexOf("skip-cert-verify=false") != -1 ? "true" : "false");
    var ptls13 = paraCheck(cnt, "tls13") == "true" ? "tls13=true" : "tls13=false";
    ptls = ptls + ", " + pverify + ", " + ptls13
  }
  var nserver = puname != "" ? "http= " + [ipport, puname, pwd, ptls, ptfo, tag].join(", ") : "http= " + [ipport, ptls, ptfo, tag].join(", ");
  return nserver
}

 
function SS52QX(content) {
  var cnt = content;
  var tag = "tag=" + cnt.split("=")[0].trim();
  var ipport = cnt.split(",")[1].trim() + ":" + cnt.split(",")[2].trim();
  var puname = cnt.indexOf("username") != -1 ? "username=" + cnt.split("username")[1].split(",")[0].split("=")[1].trim() : "";
  var pwd = cnt.indexOf("password") != -1 ? "password=" + cnt.split("password")[1].split(",")[0].split("=")[1].trim() : "";
  var ptls = cnt.split("=")[1].split(",")[0].trim() == "socks5-tls" ? "over-tls=true" : "over-tls=false";
  var ptfo = paraCheck(cnt, "tfo") == "true" ? "fast-open=true" : "fast-open=false";
  if (ptls == "over-tls=true") {
    var pverify = TLSCertParam(Pcert0, cnt.replace(/ /g,"").indexOf("skip-cert-verify=false") != -1 ? "true" : "false");
    var ptls13 = paraCheck(cnt, "tls13") == "true" ? "tls13=true" : "tls13=false";
    ptls = ptls + ", " + pverify + ", " + ptls13
  }
  var nserver = puname != "" ? "socks5= " + [ipport, puname, pwd, ptls, ptfo, tag].join(", ") : "socks5= " + [ipport, ptls, ptfo, tag].join(", ");
  return nserver
}

// 【Loon】Loon 节点写法的转换。
function Loon2QX(cnt) {
  var type = cnt.split("=")[1].split(",")[0].trim()
  var node = ""
  if (type == "Shadowsocks") {  
      node = LoonSS2QX(cnt)
  } else if (type == "ShadowsocksR") {  
      node = LoonSSR2QX(cnt)
  } else if (type == "Trojan") {  
      node = LoonTJ2QX(cnt)
  } else if (type == "VLESS") {  
    node = LoonVL2QX(cnt)
  } else if (type == "AnyTLS" && version > 913) {  
    node = LoonTLS2QX(cnt)
  }
  return node
}

 
 
function LoonTJ2QX(cnt) {
  var tag = "tag=" + cnt.split("=")[0].trim();
  var ipport = [cnt.split(",")[1].trim(), cnt.split(",")[2].trim()].join(":");
  var pwd = "password=" + cnt.split(",")[3].trim().replace(/^\"|\"$/g, "");
  var phost = cnt.indexOf("sni=") != -1 ? "tls-host=" + cnt.split("sni=")[1].split(",")[0].trim() : "";
  var pverify = TLSCertParam(Pcert0, cnt.replace(/ /g, "").indexOf("skip-cert-verify=false") != -1 ? "true" : "false");
  var pudp = paraCheck(cnt, "udp") == "true" ? "udp-relay=true" : "udp-relay=false";
  return "trojan=" + [ipport, pwd, "over-tls=true", pverify, phost, pudp, tag].filter(Boolean).join(", ");
}

 
function LoonSS2QX(cnt) {
  var node = "shadowsocks="
  var ip = [cnt.split(",")[1].trim(), cnt.split(",")[2].trim()].join(":")
  var mtd = "method=" + cnt.split(",")[3].trim()
  var pwd = "password=" + cnt.split(",")[4].trim().split("\"")[1]
  var obfs = cnt.split(",").length == 7 ? ", " + ["obfs=" + cnt.split(",")[5].trim(), "obfs-host=" + cnt.split(",")[6].trim()].join(",") : ""
  var tag = ", tag=" + cnt.split("=")[0].trim()
  node = node + [ip, mtd, pwd].join(", ") + obfs + tag
  return node
}

 
 
 
function LoonSSR2QX(cnt) {
  var node = "shadowsocks="
  var ip = [cnt.split(",")[1].trim(), cnt.split(",")[2].trim()].join(":")
  var mtd = "method=" + cnt.split(",")[3].trim()
  var pwd = "password=" + cnt.split(",")[4].trim().split("\"")[1]
  var ssrp = "ssr-protocol=" + cnt.split(",")[5].trim()
  var ssrpara = "ssr-protocol-param=" + cnt.split(",")[6].replace(/\{|\}/g, "").trim()
  var obfs = "obfs=" + cnt.split(",")[7].trim()
  var obfshost = "obfs-host=" + cnt.split(",")[8].replace(/\{|\}/g, "").trim()
  var tag = ", tag=" + cnt.split("=")[0].trim()
  node = node + [ip, mtd, pwd, ssrp, ssrpara, obfs, obfshost].join(", ") + tag
  return node
}

 
function param1(res,org,mbody) {
  mbodys=mbody.replace(/\s/g,"")
  if(mbodys.indexOf(org)!=-1) {
    tmp=mbodys.split(org)[1].split("=")[1].split(",")[0].replace(/\"/g,"")
    return res+"="+tmp
  }
  else return ""
}

 
 
 
 
function LoonVL2QX(cnt) {
  var tag = ", tag=" + cnt.split("=")[0].trim()
  cnt=cnt.replace(" ","")  
  var node = "vless="
  var ip = [cnt.split(",")[1].trim(), cnt.split(",")[2].trim()].join(":")
  var mtd = "method=none"
  var pwd = "password=" + cnt.split(",")[3].trim().split("\"")[1]
  if (cnt.indexOf("transport=tcp")!=-1) {
    obfs= cnt.indexOf("over-tls=true")=="-1"? "":"obfs=over-tls"
  } else if (cnt.indexOf("transport=http")!=-1) {
    obfs="obfs=http"
  } else if (cnt.indexOf("transport=ws")!=-1) {
    obfs= cnt.indexOf("over-tls=true")=="-1"? "obfs=ws":"obfs=wss"
  }
  vpath = cnt.indexOf("path=")==-1? "":"obfs-uri="+cnt.split("path=")[1].split(",")[0]
  if (cnt.indexOf("host=")!=-1) {
    obfshost="obfs-host="+cnt.split("host=")[1].split(",")[0]
  }  else if (cnt.indexOf("tls-name=")!=-1) {
    obfshost="obfs-host="+cnt.split("tls-name=")[1].split(",")[0]
  } else if (cnt.indexOf("sni=")!=-1) {
    obfshost="obfs-host="+cnt.split("sni=")[1].split(",")[0]
  }
  vflow=param1("vless-flow","flow",cnt)
  vpbk=param1("reality-base64-pubkey","public-key",cnt)
  vsid=param1("reality-hex-shortid","short-id",cnt)
  node = node + [ip, mtd, pwd, obfs, obfshost, vpath,vflow,vpbk,vsid].filter(Boolean).join(", ") + tag
  return node
}

 
 
function LoonTLS2QX(content) {
  try {
    var cnt = content;
    $notify("Loon","",cnt)
    if (Pdbg==1) {$notify(cnt)}
    var tag = "tag=" + cnt.split("=")[0].trim();
    var ipport = [cnt.split(",")[1].trim(), cnt.split(",")[2].trim()].join(":");
    var pwd = "password=" +  + cnt.split(",")[3].trim().split("\"")[1];
    var ptls = "over-tls=true";
    var phost = cnt.indexOf("sni")!=-1? "tls-host="+cnt.split("sni")[1].split(",")[0].split("=")[1]:""
    pudp = Pudp0 == -1 ? "udp-relay=false" : "udp-relay=true"  
    var pverify = TLSCertParam(Pcert0, cnt.replace(/ /g,"").indexOf("skip-cert-verify=false") != -1 ? "true" : "false");
    var nserver = "anytls= " + [ipport, pwd, ptls, pverify, phost,pudp, tag].filter(Boolean).join(", ");
    $notify("Loon","",nserver)
    return nserver
  } catch (error) {
    console.log("loon-anytls:"+error)
  }

}

 

 








function YAMLFix(cnt){
  function splitInlineYamlMapItems(str) {
    var parts = [];
    var buf = "";
    var quote = "";
    var escaped = false;
    var depth = 0;
    var leftBracketToken = "yaml@bug𝟙";
    for (var i = 0; i < str.length; i++) {
      var ch = str[i];
      if (quote) {
        buf += ch;
        if (quote == "\"" && ch == "\\" && !escaped) {
          escaped = true;
          continue;
        }
        if (quote == "'" && ch == "'" && str[i + 1] == "'") {
          buf += str[++i];
          continue;
        }
        if (ch == quote && !escaped) {
          quote = "";
        }
        escaped = false;
      } else if (str.slice(i, i + leftBracketToken.length) == leftBracketToken) {
        depth++;
        buf += leftBracketToken;
        i += leftBracketToken.length - 1;
      } else if (ch == "\"" || ch == "'") {
        quote = ch;
        buf += ch;
      } else if (ch == "{" || ch == "[") {
        depth++;
        buf += ch;
      } else if (ch == "}" || ch == "]") {
        depth--;
        buf += ch;
      } else if (ch == "," && depth == 0) {
        if (buf.trim() != "") {
          parts.push(buf.trim());
        }
        buf = "";
      } else {
        buf += ch;
      }
    }
    if (buf.trim() != "") {
      parts.push(buf.trim());
    }
    return parts;
  }

  function expandInlineYamlMapLine(line) {
    var match = line.match(/^(\s*)-\s*(\{[\s\S]*\})\s*(?:#.*)?$/);
    if (!match) {
      return line;
    }
    var indent = match[1];
    var body = match[2].trim().slice(1, -1);
    var parts = splitInlineYamlMapItems(body);
    if (parts.length == 0) {
      return line;
    }
    var out = [];
    for (var i = 0; i < parts.length; i++) {
      out.push((i == 0 ? indent + "- " : indent + "  ") + parts[i]);
    }
    return out.join("\n");
  }

  cnt = cnt.replace(/\[/g,"yaml@bug𝟙").replace(/\\r/g,"").replace(/\*/g,"yaml@bug𝟚")
   
  if (cnt.indexOf("{") != -1 && /\{\s*\"*(name|type|server)/.test(cnt)){  
    cnt =  cleanYamlSpaces(cnt)  
    cnt = cnt.replace(/(^|\n)- /g, "$1  - ").replace(/    - /g,"  - ")
     
    console.log("1st:\n"+cnt)
    cnt = cnt.split("\n").map(expandInlineYamlMapLine).join("\n").replace(/, short-id\"{0,1}/gi,", short-id")
  }
  cnt = cnt.replace(/\n\s*\-\s*\n.*name/g,"\n  - name").replace(/\$|\`/g,"").split("proxy-providers:")[0].split("proxy-groups:")[0].replace(/\"(name|type|server|port|cipher|password|uuid|alterId|udp)(\"*)/g,"$1")
    if(Pdbg == 1) {
  $notify("part-fix0:","","part-fix0:\nproxies:\n"+cnt.split("proxies:")[1])}
   
   
   
   
  cnt = /\n\-\s[a-zA-Z]/.test(cnt)? cnt.replace(/\n(.*(\:|\-))/g,"\n  $1"):cnt.replace(/\n\s{2}([a-zA-Z]+.*\:)/g,"\n    $1").replace(/\n(\-.*)/g,"\n  $1")
  if(Pdbg == 1) {
  $notify("part-fix1:","","part-fix1:\nproxies:\n"+cnt.split("proxies:")[1])}
   
  cnt = cnt.replace(/name\:(.*?)\:(.*?)\n/gmi,"name:$1冒号$2\n").replace(/\s{6}Host\:/g,"      Host:") 
  items=cnt.split("\n").map(yamlcheck)
  cnt=items.join("\n")
   
   
   
   
   
   
   
  cnt = cnt.indexOf("proxies:") != -1 && /\n\s{4}server/.test(cnt)  ? cnt.replace(/\n\s{4}(headers|path)/g,"\n      $1").replace(/\n\s{6}Host/g,"\n        Host").replace(/\t/g,""):cnt
   
  cnt = cnt.indexOf("proxies:") == -1? "proxies:\n" + cnt :"proxies:"+cnt.split("proxies:")[1]
  cnt = cnt.replace(/>/g,"⟩")  
   
  console.log("after-fix\n"+cnt)
  if(Pdbg == 1) {
  $notify("After-Fix","this is", "After-fix:\n"+cnt)}
   

  return cnt
}

 
function cleanYamlSpaces(yamlText) {
  return yamlText.split('\n').map(line => {
    if (line.includes('{') && line.includes('}')) {
      return '  ' + line.trim().replace(/ {2,}/g, ' ');
    }
    return line;
  }).join('\n');
}

function yamlcheck(cnt){
  if (cnt.indexOf("name") !=-1){  
    for (var i=0;i<10;i++) {
      cnt = cnt.replace(new RegExp(patn[0][i], "gmi"),patn[4][i])
    }
    
  }
  if (/(:)/.test(cnt) && !/alpn\s*\:/.test(cnt)) {
    return cnt
  }
}

 

 


function superMagicParse(str) {
  let s = str;
  $notify(1,1,s)
   
   
   
  s = s.replace(/(:\s*(?:".*?"|[^,}\]]+?))\s*]/g, '$1}]');
  $notify(1,2,s)
   
   
   
  s = s.replace(/([{\s,])([a-zA-Z0-9_\-]+)\s*:/g, '$1"$2":');
  
   
   
  s = s.replace(/:\s*([^",}\]]+?)\s*(?=[,}\]])/g, (match, rawValue) => {
    const val = rawValue.trim();
    
     
    if (!isNaN(Number(val))) {
      return `:${val}`;
    }
    
     
    if (['true', 'false', 'null', 'undefined'].includes(val)) {
      return `:${val}`;
    }
    
     
    return `:"${val}"`;
  });
  $notify(1,3,s)
   
   
  
  try {
    return s; 
  } catch (e) {
     
    return null;  
  }
}

 
function YJSON(cnt) {
  cnt=cnt.replace(/proxies\:\n.*?\-/g,"{\"proxies\":[").replace(/}\s*\n.*?\-/g,"},").replace(/\n/g,"")+"]}"
   
  cnt=superMagicParse(cnt)
   
  return cnt
}

function reorderYamlByNesting(yamlString, decodeUnicode = true) {
   
  if (decodeUnicode) {
    yamlString = decodeUnicodeEscapes(yamlString);
  }
  
  const lines = yamlString.split('\n');
  const result = [];
  let i = 0;
   
  function collectFieldBlock(startIdx, parentIndent) {
    const block = [lines[startIdx]];
    let idx = startIdx + 1;
    while (idx < lines.length) {
      const line = lines[idx];
      const indent = line.search(/\S/);
      const trimmed = line.trim();
      if (!trimmed) {
        idx++;
        continue;
      }
      if (indent <= parentIndent) {
        break;
      }
      block.push(line);
      idx++;
    }
    return { block, nextIdx: idx };
  }
   
  function hasChildren(block, parentIndent) {
    return block.slice(1).some(line => {
      const trimmed = line.trim();
      return trimmed && line.search(/\S/) > parentIndent;
    });
  }
   
  function processListItem(startIdx, listIndent) {
    const simpleFields = [];
    const nestedFields = [];
    const fieldIndent = listIndent + 2;
    let idx = startIdx;
    while (idx < lines.length) {
      const line = lines[idx];
      const indent = line.search(/\S/);
      const trimmed = line.trim();
      if (!trimmed) {
        idx++;
        continue;
      }
      if (indent <= listIndent) {
        break;
      }
      if (indent === fieldIndent && trimmed.includes(':')) {
        const { block, nextIdx } = collectFieldBlock(idx, fieldIndent);
        
        if (hasChildren(block, fieldIndent)) {
          nestedFields.push(...block);
        } else {
          simpleFields.push(block[0]);
        }
        
        idx = nextIdx;
      } else {
        idx++;
      }
    }
    return { simpleFields, nestedFields, endIdx: idx };
  }
   
  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith('- ')) {
      const listIndent = line.search(/\S/);
      result.push(line);
      
      const { simpleFields, nestedFields, endIdx } = processListItem(i + 1, listIndent);
      result.push(...simpleFields, ...nestedFields);
      
      i = endIdx;
    } else {
      result.push(line);
      i++;
    }
  }
  return result.join('\n');
}
function decodeUnicodeEscapes(str) {
  return str
  .replace(/\\U([0-9A-Fa-f]{8})/g, (match, hex) => {
    return String.fromCodePoint(parseInt(hex, 16));
  })
  .replace(/\\u\{([0-9A-Fa-f]+)\}/g, (match, hex) => {
    return String.fromCodePoint(parseInt(hex, 16));
  })
  .replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex) => {
    return String.fromCodePoint(parseInt(hex, 16));
  })
  .replace(/\\x([0-9A-Fa-f]{2})/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });
}

 
function JCheck(cnt) {
  if (/^{/.test(cnt) &&/}$/.test(cnt)) {
    return 1
  } else {
    return 0
  }
}


 
// 【Clash】YAML 里的 proxies 段逐条转，未知字段不臆造。
function Clash2QX(cnt) {
  const yaml = new YAML()
  var original = HY2ClashOriginal(cnt)
  var bb
   
   
  if (Array.isArray(original) && original.length && original.every(node => node && HY2Type(node.type))) {
    bb = original
  } else {
    try {
      aa = JCheck(cnt)==0 ? JSON.stringify(yaml.parse(reorderYamlByNesting(YAMLFix(cnt)))).replace(/yaml@bug𝟙/g,"[").replace(/冒号/gmi,":").replace(/yaml@bug𝟚/g,"*") : cnt
      for (var i=0;i<10;i++) {
        aa = aa.replace(new RegExp(patn[4][i], "gmi"),patn[0][i])
      }
      bb = JSON.parse(aa).proxies
    } catch (err) {
      if (!Array.isArray(original) || !original.some(node => node && HY2Type(node.type))) throw err
      bb = original
    }
  }
  if (!Array.isArray(bb) && Array.isArray(original) && original.some(node => node && HY2Type(node.type))) bb = original
  var originalAligned = Array.isArray(original) && Array.isArray(bb) && original.length == bb.length &&
    original.every((node, index) => node && bb[index] && node.type == bb[index].type)
  if (Pdbg==1) { $notify("After YAML Parse", "content", JSON.stringify(bb))}
   
  var nl = bb.length
  var nodelist=[]
  var node=""
  for (i=0; i<nl; i++){
    try{
      node=bb[i]
      typecc = node.type
      if (HY2Type(typecc)) {
        node = originalAligned || !HY2Supported
          ? HY2Convert("clash", originalAligned ? original[i] : node)
          : HY2Skip("无法安全读取 Clash 原始字段")
        if (node) nodelist.push(node)
        continue
      }
      if (typecc == "ss") {
        node = CSS2QX(node)
      } else if (typecc == "ssr"){
        node = CSSR2QX(node)
      } else if (typecc == "vmess"){
        node = CV2QX(node)
      } else if (typecc == "trojan"){
        node = CT2QX(node)
      } else if (typecc == "http"){
        node = CH2QX(node)
      } else if (typecc == "socks5"){
        node = CS52QX(node)
      } else if (typecc == "vless"){
        node = CVL2QX(node)
      } else if (typecc=="anytls" && version >913) {  
        node = CTLS2QX(node)
      } else {  
        PNS = PNS+1
        NSList.push(numToEmoji10(PNS)+bb[i])
        if (Pdbg==1) {  
          $notify("不支持该类型节点，已忽略",typecc,JSON.stringify(node))
        }
        typecc="NS"
      }
      node = Pudp0 != 0 ? XUDP(node,Pudp0) : node
      node = Ptfo0 != 0 ? XTFO(node,Ptfo0) : node
      if (typecc!="NS") {
      node=node.replace(/^([^,]*)\s+/g, (match, p1) => {  
        return p1.replace(/\s+/g, '');
      });
      nodelist.push(node)
    } 
    }catch (e) {
      $notify(`⚠️该节点解析错误, 暂时已忽略处理`,`可点击通知并发送链接反馈至 bot`,JSON.stringify(node),bug_link )
      $notify(`⚠️错误内容如下`,`可复制错误内容到反馈 bot`,JSON.stringify(node)+"\n\n"+e)
    }
  }
  return nodelist.join("\n")
}

 








function ClashNameFix(name) {
  var text = typeof name == "undefined" || name === null ? "" : String(name);
  function safeCodePoint(fallback, hex) {
    var code = parseInt(hex, 16);
    if (!isFinite(code) || code < 0 || code > 0x10FFFF) {
      return fallback;
    }
    return String.fromCodePoint(code);
  }
  return text
    .replace(/\\\\U([0-9A-Fa-f]{8})/g, function(match, hex) {
      return safeCodePoint(match, hex);
    })
    .replace(/\\U([0-9A-Fa-f]{8})/g, function(match, hex) {
      return safeCodePoint(match, hex);
    })
    .replace(/\\\\u\{([0-9A-Fa-f]+)\}/g, function(match, hex) {
      return safeCodePoint(match, hex);
    })
    .replace(/\\u\{([0-9A-Fa-f]+)\}/g, function(match, hex) {
      return safeCodePoint(match, hex);
    })
    .replace(/\\\\u([0-9A-Fa-f]{4})/g, function(match, hex) {
      return String.fromCharCode(parseInt(hex, 16));
    })
    .replace(/\\u([0-9A-Fa-f]{4})/g, function(match, hex) {
      return String.fromCharCode(parseInt(hex, 16));
    });
}

 
// 【Clash】SS 与 SS 插件。
function CSS2QX(cnt) {
  tag = "tag="+ClashNameFix(cnt.name)
  ipt = cnt.server+":"+cnt.port
  pwd = "password=" + cnt.password
  mtd = "method="+ cnt.cipher
  udp = cnt.udp ? "udp-relay=true" : "udp-relay=false"
  uot = cnt["udp-over-tcp"] ?  "udp-over-tcp=true" : "udp-over-tcp=false"
  tfo = cnt.tfo ? "fast-open=true" : "fast-open=false"
  obfs = cnt["plugin-opts"] ? "obfs=" + cnt["plugin-opts"].mode : ""
  ohost = cnt["plugin-opts"] ? "obfs-host=" + cnt["plugin-opts"].host : ""
  ouri = ""
  cert = ""
  if (obfs.indexOf("websocket") != -1) {
      obfs = cnt["plugin-opts"].tls? "obfs=wss" : "obfs=ws"
      ohost = cnt["plugin-opts"].host? "obfs-host=" + cnt["plugin-opts"].host:""
      ouri = cnt["plugin-opts"].path? "obfs-uri=" + cnt["plugin-opts"].path: ""
    if (obfs == "obfs=wss") {  
      cert = TLSCertParam(Pcert0, "false")}
  }
  node = "shadowsocks="+[ipt, pwd, mtd, udp, uot, tfo, obfs, ohost, ouri, cert, tag].filter(Boolean).join(", ")
  return node
}

 
function CSSR2QX(cnt) {
  tag = "tag="+ClashNameFix(cnt.name)
  ipt = cnt.server+":"+cnt.port
  pwd = "password=" + cnt.password
  mtd = "method="+ cnt.cipher
  udp = cnt.udp ? "udp-relay=true" : "udp-relay=false"
  tfo = cnt.tfo ? "fast-open=true" : "fast-open=false"
  prot = "ssr-protocol=" + cnt.protocol
  ohost=""
  ppara=""
  if(cnt["protocolparam"]) {
    cnt["protocol-param"] = cnt["protocolparam"]
  }
  if (typeof(cnt["protocol-param"]) == "string") {
    ppara = "ssr-protocol-param=" + cnt["protocol-param"]
  } else if (typeof(cnt["protocol-param"]) == "object") {
    console.log(typeof(cnt["protocol-param"]))
    ppara = "ssr-protocol-param=" + JSON.stringify(cnt["protocol-param"]).replace(/{|}|\s|"/g,"")
  }
  obfs = "obfs=" + cnt.obfs
  if ( cnt["obfs-param"]) {
     ohost = "obfs-host=" + cnt["obfs-param"]
  } else if (cnt["obfsparam"]) {
     ohost = "obfs-host=" + cnt["obfsparam"]
  }
 
  node = "shadowsocks="+[ipt, pwd, mtd, udp, tfo, prot, ppara, obfs, ohost, tag].filter(Boolean).join(", ")
   
  return node
}


 
// 【Clash】VMess，含 ws / grpc / http 各种传输。
function CV2QX(cnt) {
  tag = "tag="+ClashNameFix(cnt.name)
  ipt = cnt.server+":"+cnt.port
  pwd = "password=" + cnt.uuid
  mtd = "method="+ "aes-128-gcm"  
  udp = cnt.udp ? "udp-relay=false" : "udp-relay=false"  
  tfo = cnt.tfo ? "fast-open=true" : "fast-open=false"
  obfs = ""
  if (cnt.network == "ws" && cnt.tls) {
    obfs = "obfs=wss"
  } else if (cnt.network == "ws"){
    obfs = "obfs=ws"
  } else if (cnt.network == "http"){
    obfs = "obfs=http"
  } else if (cnt.tls){
    obfs = "obfs=over-tls"
  }
  console.log(obfs)
  const phost = getValue(()=>cnt["ws-opts"]["headers"]["Host"]) 
  ohost = cnt["ws-headers"]? "obfs-host=" + cnt["ws-headers"]["Host"] : ""
  ohost = phost ? "obfs-host="+phost : ohost
   
  ohost = cnt["servername"]? "obfs-host=" + cnt["servername"] : ohost
  console.log(ohost)
  ouri = cnt["ws-path"]? "obfs-uri="+cnt["ws-path"] : ""
  ouri = cnt["ws-opts"]? "obfs-uri="+cnt["ws-opts"]["path"] : ouri
  cert = cnt.tls ? TLSCertParam(Pcert0, cnt["skip-cert-verify"] ? "false" : "false") : ""
  caead = cnt["alterId"] && cnt["alterId"]!=0? "aead=false" : ""  
   
  console.log(caead)
   
   
  node = "vmess="+[ipt, pwd, mtd, udp, tfo, obfs, ohost, ouri, cert, caead, tag].filter(Boolean).join(", ")
   
  return node
}


 
function CT2QX(cnt) {
  tag = "tag="+ClashNameFix(cnt.name)
  ipt = cnt.server+":"+cnt.port
  pwd = "password=" + cnt.password
  otls = "over-tls=true"
  opath=""
  ohost=""
  cert = TLSCertParam(Pcert0, "false")
  tls13 = PTls13 == 1 ? "tls13=true" : "tls13=false"
  udp = cnt.udp ? "udp-relay=false" : "udp-relay=false"
  tfo = cnt.tfo ? "fast-open=true" : "fast-open=false"
  if (cnt.network=="ws") {  
    otls = "obfs=wss"
     
    if (cnt["ws-opts"]){
    opath = cnt["ws-opts"]["path"]? "obfs-uri="+cnt["ws-opts"]["path"] : ""
    ohost = cnt["ws-opts"]["headers"]? "obfs-host="+cnt["ws-opts"]["headers"]["Host"] : ""
    }
     
  }
  node = "trojan="+[ipt, pwd, otls, opath, ohost, cert, tls13, udp, tfo, tag].filter(Boolean).join(", ")
   
  return node
}

 

function CTLS2QX(cnt) {
  tag = "tag="+ClashNameFix(cnt.name)
  ipt = cnt.server+":"+cnt.port
  pwd = "password=" + cnt.password
  otls = "over-tls=true"
  opath=""
  ohost= "tls-host="+cnt.sni
  cert = TLSCertParam(Pcert0, "false")
  pudp = Pudp0 == -1 ? "udp-relay=false" : "udp-relay=true"  
  node = "anytls="+[ipt, pwd, otls, ohost, pudp, cert, tag].filter(Boolean).join(", ")
   
  return node
}

 
function CH2QX(cnt){
    tag = "tag="+ClashNameFix(cnt.name)
    ipt = cnt.server+":"+cnt.port
    uname = cnt.username ? "username=" + cnt.username : ""
    pwd = cnt.password && typeof(cnt.password) == "string" ? "password=" + cnt.password : ""
    tls = cnt.tls ? "over-tls=true" : ""
    cert = cnt.tls ? TLSCertParam(Pcert0, "false") : ""
    node = "http="+[ipt, uname, pwd, tls, cert, tag].filter(Boolean).join(", ")
     
    return node
}

 
function CS52QX(cnt){
    tag = "tag="+ClashNameFix(cnt.name)
    ipt = cnt.server+":"+cnt.port
    uname = cnt.username ? "username=" + cnt.username : ""
    pwd = cnt.password && typeof(cnt.password) == "string" ? "password=" + cnt.password : ""
    tls = cnt.tls ? "over-tls=true" : ""
    cert = cnt.tls ? TLSCertParam(Pcert0, "false") : ""
    node = "socks5="+[ipt, uname, pwd, tls, cert, tag].filter(Boolean).join(", ")
     
    return node
}

 
function CVL2QX(cnt){
  tag = "tag="+ClashNameFix(cnt.name).replace(/(\"|\')/gi,"")
  ipt = cnt.server+":"+cnt.port
  pwd = "password=" + cnt.uuid
  mtd = "method=none"  
  udp = cnt.udp ? "udp-relay=true" : "udp-relay=false"
  tfo = cnt.tfo ? "fast-open=true" : "fast-open=false"
  obfs = ""
  if (cnt.network == "ws" && cnt.tls) {
    obfs = "obfs=wss"
  } else if (cnt.network == "ws"){
    obfs = "obfs=ws"
  } else if (cnt.tls){
    obfs = "obfs=over-tls"
  }
  vfl=cnt.flow? "vless-flow=xtls-rprx-vision":""
  const ppbk=getValue(()=>cnt["reality-opts"]["public-key"]) 
  const psid=getValue(()=>cnt["reality-opts"]["short-id"])
  pbk=ppbk? "reality-base64-pubkey="+ppbk : ""
  sid=typeof(psid)=='string'? "reality-hex-shortid="+psid : ""
 
  const phost = getValue(()=>cnt["ws-opts"]["headers"]["Host"]) 
  ohost = cnt["ws-headers"]? "obfs-host=" + cnt["ws-headers"]["Host"] : ""
  ohost = phost ? "obfs-host="+phost : ohost
   
  ohost = cnt["servername"]? "obfs-host=" + cnt["servername"] : ohost
  ohost=ohost.toLowerCase()

  const ppath = getValue(()=>cnt["ws-opts"]["path"]) 
  puri = ppath ? "obfs-uri="+ppath : ""

  cert = cnt.tls ? TLSCertParam(Pcert0, "false") : ""
   
  const pspt = getValue(()=>cnt["ws-opts"]["v2ray-http-upgrade"])
  if (pspt==true) {
    PNS = PNS +1
    NSList.push(numToEmoji10(PNS)+cnt)
    node=""
  } else {
    node = "vless="+[ipt, pwd, mtd, udp, tfo, obfs, ohost, puri, vfl, pbk, sid, cert, tag].filter(Boolean).join(", ")
  }
   
  return node
}

 
// 【参数注入】udp / tfo 这类全局开关落到单条节点上。
function XUDP(cnt,pudp) {
  var udp = pudp != -1 && /^(shadowsocks|trojan|vmess|vless|anytls)/.test(cnt.trim()) ? "udp-relay=true, " : "udp-relay=false, "
  if(cnt.indexOf("udp-relay") != -1){
    var cnt0 = cnt.replace(RegExp("udp\-relay.*?\,", "gmi"), udp)
  }else{
    var cnt0 = cnt.replace(new RegExp("tag.*?\=", "gmi"), udp+"tag=")
  }
   
  return cnt0
}

function XTFO(cnt,ptfo) {
    var tfo = ptfo == 1? "fast-open=true, " : "fast-open=false, "
    if(cnt.indexOf("fast-open") != -1){
        var cnt0 = cnt.replace(RegExp("fast\-open.*?\,", "gmi"), tfo)
    }else{
        var cnt0 = cnt.replace(RegExp("tag.*?\=", "gmi"), tfo+"tag=")
    }
    return cnt0
}


 
function UOT(cnt) {
  cnts=cnt.replace(/\s*/g,"")
  if(/^shadowsocks=/.test(cnts)) {
    cnt= cnts.indexOf("udp-over-tcp")!=-1? cnt.replace(/udp-over-tcp\s*\=\s*false/g,"udp-over-tcp=true") : cnt+", udp-over-tcp=true"
    
  }
  return cnt
}

 
/*
 *  base64.js: https://github.com/dankogai/js-base64#readme
 *
 *  Licensed under the BSD 3-Clause License.
 *    http://opensource.org/licenses/BSD-3-Clause
 *
 *  References:
 *    http://en.wikipedia.org/wiki/Base64
 */
 
// 【Base64】内嵌实现，遵循上游 BSD 许可，见下方许可声明。
function Base64Code() {
     
    var b64chars
        = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var b64tab = function (bin) {
        var t = {};
        for (var i = 0, l = bin.length; i < l; i++) t[bin.charAt(i)] = i;
        return t;
    }(b64chars);
    var fromCharCode = String.fromCharCode;
     
    var cb_utob = function (c) {
        if (c.length < 2) {
            var cc = c.charCodeAt(0);
            return cc < 0x80 ? c
                : cc < 0x800 ? (fromCharCode(0xc0 | (cc >>> 6))
                    + fromCharCode(0x80 | (cc & 0x3f)))
                    : (fromCharCode(0xe0 | ((cc >>> 12) & 0x0f))
                        + fromCharCode(0x80 | ((cc >>> 6) & 0x3f))
                        + fromCharCode(0x80 | (cc & 0x3f)));
        } else {
            var cc = 0x10000
                + (c.charCodeAt(0) - 0xD800) * 0x400
                + (c.charCodeAt(1) - 0xDC00);
            return (fromCharCode(0xf0 | ((cc >>> 18) & 0x07))
                + fromCharCode(0x80 | ((cc >>> 12) & 0x3f))
                + fromCharCode(0x80 | ((cc >>> 6) & 0x3f))
                + fromCharCode(0x80 | (cc & 0x3f)));
        }
    };
    var re_utob = /[\uD800-\uDBFF][\uDC00-\uDFFFF]|[^\x00-\x7F]/g;
    var utob = function (u) {
        return u.replace(re_utob, cb_utob);
    };
    var cb_encode = function (ccc) {
        var padlen = [0, 2, 1][ccc.length % 3],
            ord = ccc.charCodeAt(0) << 16
                | ((ccc.length > 1 ? ccc.charCodeAt(1) : 0) << 8)
                | ((ccc.length > 2 ? ccc.charCodeAt(2) : 0)),
            chars = [
                b64chars.charAt(ord >>> 18),
                b64chars.charAt((ord >>> 12) & 63),
                padlen >= 2 ? '=' : b64chars.charAt((ord >>> 6) & 63),
                padlen >= 1 ? '=' : b64chars.charAt(ord & 63)
            ];
        return chars.join('');
    };
    var btoa = function (b) {
        return b.replace(/[\s\S]{1,3}/g, cb_encode);
    };
     
     
     
     
     
    this.encode = function (u) {
        var isUint8Array = Object.prototype.toString.call(u) === '[object Uint8Array]';
        return isUint8Array ? u.toString('base64')
            : btoa(utob(String(u)));
    }
    var uriencode = function (u, urisafe) {
        return !urisafe
            ? _encode(u)
            : _encode(String(u)).replace(/[+\/]/g, function (m0) {
                return m0 == '+' ? '-' : '_';
            }).replace(/=/g, '');
    };
    var encodeURI = function (u) { return uriencode(u, true) };
     
    var re_btou = /[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3}/g;
    var cb_btou = function (cccc) {
        switch (cccc.length) {
            case 4:
                var cp = ((0x07 & cccc.charCodeAt(0)) << 18)
                    | ((0x3f & cccc.charCodeAt(1)) << 12)
                    | ((0x3f & cccc.charCodeAt(2)) << 6)
                    | (0x3f & cccc.charCodeAt(3)),
                    offset = cp - 0x10000;
                return (fromCharCode((offset >>> 10) + 0xD800)
                    + fromCharCode((offset & 0x3FF) + 0xDC00));
            case 3:
                return fromCharCode(
                    ((0x0f & cccc.charCodeAt(0)) << 12)
                    | ((0x3f & cccc.charCodeAt(1)) << 6)
                    | (0x3f & cccc.charCodeAt(2))
                );
            default:
                return fromCharCode(
                    ((0x1f & cccc.charCodeAt(0)) << 6)
                    | (0x3f & cccc.charCodeAt(1))
                );
        }
    };
    var btou = function (b) {
        return b.replace(re_btou, cb_btou);
    };
    var cb_decode = function (cccc) {
        var len = cccc.length,
            padlen = len % 4,
            n = (len > 0 ? b64tab[cccc.charAt(0)] << 18 : 0)
                | (len > 1 ? b64tab[cccc.charAt(1)] << 12 : 0)
                | (len > 2 ? b64tab[cccc.charAt(2)] << 6 : 0)
                | (len > 3 ? b64tab[cccc.charAt(3)] : 0),
            chars = [
                fromCharCode(n >>> 16),
                fromCharCode((n >>> 8) & 0xff),
                fromCharCode(n & 0xff)
            ];
        chars.length -= [0, 0, 2, 1][padlen];
        return chars.join('');
    };
    var _atob = function (a) {
        return a.replace(/\S{1,4}/g, cb_decode);
    };
    var atob = function (a) {
        return _atob(String(a).replace(/[^A-Za-z0-9\+\/]/g, ''));
    };
     
     
     
     
     
     
     
     
     
     
     
    var _decode = function (u) {
        return btou(_atob(u))
    }
    this.decode = function (a, literal) {
        var decoded = _decode(
            String(a).replace(/[-_]/g, function (m0) { return m0 == '-' ? '+' : '/' })
                .replace(/[^A-Za-z0-9\+\/]/g, '')
        );
        return literal ? decoded : decoded.replace(/&gt;/g, ">").replace(/&lt;/g, "<");
    };
}


 









 











// 【YAML】自己写的极简解析器：Clash 配置的缩进、引号、flow 写法、锚点都要吃得下。
function YAML() {
        var self = this;
        var errors = [];
        var reference_blocks = {};
        var processing_time = 0;
        var lines = [];
        var cursor = 0;

        this.errors = errors;
        this.processing_time = processing_time;

        function clone(obj) {
                if (obj === null || typeof obj !== "object") {
                        return obj;
                }
                try {
                        return JSON.parse(JSON.stringify(obj));
                } catch (err) {
                        return obj;
                }
        }

        function isObject(obj) {
                return obj !== null && typeof obj === "object" && !Array.isArray(obj);
        }

        function mergeInto(target, source) {
                if (!isObject(target) || !isObject(source)) {
                        return target;
                }
                for (var key in source) {
                        if (typeof target[key] == "undefined") {
                                target[key] = clone(source[key]);
                        }
                }
                return target;
        }

        function countIndent(line) {
                var match = String(line).match(/^\s*/);
                return match ? match[0].length : 0;
        }

        function trimRight(str) {
                return String(str).replace(/\s+$/, "");
        }

        function stripComments(line) {
                var quote = "";
                var escaped = false;
                var result = "";
                for (var i = 0; i < line.length; i++) {
                        var ch = line[i];
                        if (quote) {
                                result += ch;
                                if (quote == "\"" && ch == "\\" && !escaped) {
                                        escaped = true;
                                        continue;
                                }
                                if (quote == "'" && ch == "'" && line[i + 1] == "'") {
                                        result += line[++i];
                                        continue;
                                }
                                if (ch == quote && !escaped) {
                                        quote = "";
                                }
                                escaped = false;
                                continue;
                        }
                        if (ch == "\"" || ch == "'") {
                                quote = ch;
                                result += ch;
                        } else if (ch == "#" && (i == 0 || /\s/.test(line[i - 1]))) {
                                return trimRight(result);
                        } else {
                                result += ch;
                        }
                }
                return trimRight(result);
        }

        function preProcess(src) {
                return String(src)
                        .replace(/\r/g, "")
                        .split("\n")
                        .map(stripComments)
                        .filter(function(line) {
                                var trimmed = line.trim();
                                return trimmed != "" && trimmed != "---" && trimmed != "...";
                        });
        }

        function splitTopLevel(str, delimiter) {
                var result = [];
                var buf = "";
                var quote = "";
                var escaped = false;
                var depth = 0;
                for (var i = 0; i < str.length; i++) {
                        var ch = str[i];
                        if (quote) {
                                buf += ch;
                                if (quote == "\"" && ch == "\\" && !escaped) {
                                        escaped = true;
                                        continue;
                                }
                                if (quote == "'" && ch == "'" && str[i + 1] == "'") {
                                        buf += str[++i];
                                        continue;
                                }
                                if (ch == quote && !escaped) {
                                        quote = "";
                                }
                                escaped = false;
                                continue;
                        }
                        if (ch == "\"" || ch == "'") {
                                quote = ch;
                                buf += ch;
                        } else if (ch == "[" || ch == "{") {
                                depth++;
                                buf += ch;
                        } else if (ch == "]" || ch == "}") {
                                depth--;
                                buf += ch;
                        } else if (ch == delimiter && depth == 0) {
                                result.push(buf.trim());
                                buf = "";
                        } else {
                                buf += ch;
                        }
                }
                if (buf.trim() != "" || str.trim() == "") {
                        result.push(buf.trim());
                }
                return result;
        }

        function findTopLevelColon(str) {
                var quote = "";
                var escaped = false;
                var depth = 0;
                for (var i = 0; i < str.length; i++) {
                        var ch = str[i];
                        if (quote) {
                                if (quote == "\"" && ch == "\\" && !escaped) {
                                        escaped = true;
                                        continue;
                                }
                                if (quote == "'" && ch == "'" && str[i + 1] == "'") {
                                        i++;
                                        continue;
                                }
                                if (ch == quote && !escaped) {
                                        quote = "";
                                }
                                escaped = false;
                                continue;
                        }
                        if (ch == "\"" || ch == "'") {
                                quote = ch;
                        } else if (ch == "[" || ch == "{") {
                                depth++;
                        } else if (ch == "]" || ch == "}") {
                                depth--;
                        } else if (ch == ":" && depth == 0) {
                                return i;
                        }
                }
                return -1;
        }

        function unescapeDoubleQuoted(str) {
                return str
                        .replace(/\\u([0-9A-Fa-f]{4})/g, function(match, hex) {
                                return String.fromCharCode(parseInt(hex, 16));
                        })
                        .replace(/\\x([0-9A-Fa-f]{2})/g, function(match, hex) {
                                return String.fromCharCode(parseInt(hex, 16));
                        })
                        .replace(/\\(["\\\/bfnrt])/g, function(match, ch) {
                                return {
                                        "\"": "\"",
                                        "\\": "\\",
                                        "/": "/",
                                        "b": "\b",
                                        "f": "\f",
                                        "n": "\n",
                                        "r": "\r",
                                        "t": "\t"
                                }[ch];
                        });
        }

        function parseKey(raw) {
                var key = String(raw).trim();
                if (/^".*"$/.test(key)) {
                        return unescapeDoubleQuoted(key.slice(1, -1));
                }
                if (/^'.*'$/.test(key)) {
                        return key.slice(1, -1).replace(/''/g, "'");
                }
                return key;
        }

        function parseKeyValue(str) {
                var idx = findTopLevelColon(str);
                if (idx <= 0) {
                        return null;
                }
                return {
                        key: parseKey(str.slice(0, idx)),
                        value: str.slice(idx + 1).trim()
                };
        }

        function parseAnchor(value) {
                var match = String(value).match(/^&([^\s]+)\s*(.*)$/);
                if (!match) {
                        return null;
                }
                return {
                        name: match[1],
                        value: match[2].trim()
                };
        }

        function processAlias(value) {
                var name = String(value).slice(1).trim();
                if (typeof reference_blocks[name] == "undefined") {
                        errors.push("Reference '" + name + "' not found");
                        return {};
                }
                return clone(reference_blocks[name]);
        }

        function parseFlowArray(value) {
                var inner = value.slice(1, -1).trim();
                if (inner == "") {
                        return [];
                }
                return splitTopLevel(inner, ",").map(processValue);
        }

        function parseFlowMap(value) {
                var inner = value.slice(1, -1).trim();
                var obj = {};
                if (inner == "") {
                        return obj;
                }
                var parts = splitTopLevel(inner, ",");
                for (var i = 0; i < parts.length; i++) {
                        var item = parseKeyValue(parts[i]);
                        if (!item) {
                                continue;
                        }
                        var parsed = processValue(item.value);
                        if (item.key == "<<") {
                                if (Array.isArray(parsed)) {
                                        for (var j = 0; j < parsed.length; j++) {
                                                mergeInto(obj, parsed[j]);
                                        }
                                } else {
                                        mergeInto(obj, parsed);
                                }
                        } else {
                                obj[item.key] = parsed;
                        }
                }
                return obj;
        }

        function processValue(val) {
                val = typeof val == "undefined" || val === null ? "" : String(val).trim();
                if (val == "") {
                        return null;
                }
                if (val[0] == "*") {
                        return processAlias(val);
                }
                if (/^".*"$/.test(val)) {
                        return unescapeDoubleQuoted(val.slice(1, -1));
                }
                if (/^'.*'$/.test(val)) {
                        return val.slice(1, -1).replace(/''/g, "'");
                }
                if (/^\[[\s\S]*\]$/.test(val)) {
                        return parseFlowArray(val);
                }
                if (/^\{[\s\S]*\}$/.test(val)) {
                        return parseFlowMap(val);
                }
                if (val == "true") {
                        return true;
                }
                if (val == "false") {
                        return false;
                }
                if (val == "null" || val == "~") {
                        return null;
                }
                if (val == ".NaN") {
                        return Number.NaN;
                }
                if (val == ".inf" || val == "+.inf") {
                        return Number.POSITIVE_INFINITY;
                }
                if (val == "-.inf") {
                        return Number.NEGATIVE_INFINITY;
                }
                if (/^[+-]?\d+$/.test(val)) {
                        return parseInt(val, 10);
                }
                if (/^[+-]?(?:\d+\.\d*|\d*\.\d+)(?:e[+-]?\d+)?$/i.test(val)) {
                        return parseFloat(val);
                }
                return val;
        }

        function parseTextBlock(indent, folded) {
                var collected = [];
                while (cursor < lines.length) {
                        var line = lines[cursor];
                        var lineIndent = countIndent(line);
                        if (lineIndent < indent) {
                                break;
                        }
                        collected.push(line.slice(Math.min(indent, line.length)));
                        cursor++;
                }
                return folded ? collected.join(" ").replace(/\s+/g, " ").trim() : collected.join("\n");
        }

        function parseNestedValue(parentIndent, value) {
                if (value == "|" || value == ">") {
                        if (cursor < lines.length && countIndent(lines[cursor]) > parentIndent) {
                                return parseTextBlock(countIndent(lines[cursor]), value == ">");
                        }
                        return "";
                }
                if (value == "") {
                        if (cursor < lines.length && countIndent(lines[cursor]) > parentIndent) {
                                return parseBlock(countIndent(lines[cursor]));
                        }
                        return null;
                }
                return processValue(value);
        }

        function parseMap(indent) {
                var obj = {};
                while (cursor < lines.length) {
                        var line = lines[cursor];
                        var lineIndent = countIndent(line);
                        var trimmed = line.trim();
                        if (lineIndent < indent) {
                                break;
                        }
                        if (lineIndent > indent) {
                                errors.push("Invalid indentation at line " + (cursor + 1) + ": " + line);
                                cursor++;
                                continue;
                        }
                        if (/^-\s*/.test(trimmed)) {
                                break;
                        }
                        var pair = parseKeyValue(trimmed);
                        if (!pair) {
                                errors.push("Invalid map item at line " + (cursor + 1) + ": " + line);
                                cursor++;
                                continue;
                        }
                        cursor++;
                        var anchor = parseAnchor(pair.value);
                        var anchorName = anchor ? anchor.name : "";
                        var value = anchor ? anchor.value : pair.value;
                        var parsed = parseNestedValue(lineIndent, value);
                        if (anchorName) {
                                reference_blocks[anchorName] = clone(parsed);
                        }
                        if (pair.key == "<<") {
                                if (Array.isArray(parsed)) {
                                        for (var i = 0; i < parsed.length; i++) {
                                                mergeInto(obj, parsed[i]);
                                        }
                                } else {
                                        mergeInto(obj, parsed);
                                }
                        } else {
                                obj[pair.key] = parsed;
                        }
                }
                return obj;
        }

        function parseSeq(indent) {
                var arr = [];
                while (cursor < lines.length) {
                        var line = lines[cursor];
                        var lineIndent = countIndent(line);
                        var trimmed = line.trim();
                        if (lineIndent < indent) {
                                break;
                        }
                        if (lineIndent > indent) {
                                errors.push("Invalid indentation at line " + (cursor + 1) + ": " + line);
                                cursor++;
                                continue;
                        }
                        if (!/^-/.test(trimmed)) {
                                break;
                        }
                        var itemText = trimmed.replace(/^-\s*/, "");
                        cursor++;
                        var anchor = parseAnchor(itemText);
                        var anchorName = anchor ? anchor.name : "";
                        itemText = anchor ? anchor.value : itemText;
                        var item;
                        var pair = parseKeyValue(itemText);
                        if (itemText == "") {
                                item = cursor < lines.length && countIndent(lines[cursor]) > lineIndent ? parseBlock(countIndent(lines[cursor])) : null;
                        } else if (pair && !/^[a-z][a-z0-9+.-]*:\/\//i.test(itemText)) {
                                item = {};
                                item[pair.key] = parseNestedValue(lineIndent, pair.value);
                                if (cursor < lines.length && countIndent(lines[cursor]) > lineIndent) {
                                        var next = parseBlock(countIndent(lines[cursor]));
                                        if (isObject(next)) {
                                                mergeInto(next, item);
                                                item = next;
                                        }
                                }
                        } else {
                                item = processValue(itemText);
                                if (cursor < lines.length && countIndent(lines[cursor]) > lineIndent && item === null) {
                                        item = parseBlock(countIndent(lines[cursor]));
                                }
                        }
                        if (anchorName) {
                                reference_blocks[anchorName] = clone(item);
                        }
                        arr.push(item);
                }
                return arr;
        }

        function parseBlock(indent) {
                if (cursor >= lines.length) {
                        return {};
                }
                var lineIndent = countIndent(lines[cursor]);
                if (lineIndent < indent) {
                        return {};
                }
                if (/^-\s*/.test(lines[cursor].trim())) {
                        return parseSeq(lineIndent);
                }
                return parseMap(lineIndent);
        }

        this.parse = function eval0(str) {
                errors = [];
                reference_blocks = {};
                processing_time = (new Date()).getTime();
                lines = preProcess(str);
                cursor = 0;
                var result = lines.length == 0 ? {} : parseBlock(countIndent(lines[0]));
                processing_time = (new Date()).getTime() - processing_time;
                self.errors = errors;
                self.processing_time = processing_time;
                return result;
        }
}


 
// 【工具】给 sfilter / srename 脚本用的辅助函数。
function Tools() {
    const filter = (src, ...regex) => {
        const initial = [...Array(src.length).keys()].map(() => false);
        return regex.reduce((a, expr) => OR(a, src.map(item => expr.test(item))), initial)
    }

    const rename = {
        replace: (src, old, now) => {
            return src.map(item => item.replace(old, now));
        },

        delete: (src, ...args) => {
            return src.map(item => args.reduce((now, expr) => now.replace(expr, ''), item));
        },

        trim: (src) => {
            return src.map(item => item.trim().replace(/[^\S\r\n]{2,}/g, ' '));
        }
    }

    const getNodeInfo = servers => {
        const nodes = {
            names: servers.map(s => s.split("tag=")[1]),
            types: servers.map(s => {
                const type = s.match(/^(vmess|trojan|shadowsocks|http)=/);
                return type ? type[1] : 'unknown';
            })
        };
        return nodes;
    }


    return {
        filter, rename, getNodeInfo
    }
}

function AND(...args) {
    return args.reduce((a, b) => a.map((c, i) => b[i] && c));
}

function OR(...args) {
    return args.reduce((a, b) => a.map((c, i) => b[i] || c))
}

function NOT(array) {
    return array.map(c => !c);
}
