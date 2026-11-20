// 生成测试语料：覆盖解析器声明支持的全部输入格式
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, 'fixtures');
fs.rmSync(dir, { recursive: true, force: true });
fs.mkdirSync(dir, { recursive: true });
const b64 = s => Buffer.from(s, 'utf8').toString('base64');
const w = (n, s) => fs.writeFileSync(path.join(dir, n), s);

const vmessJson = JSON.stringify({ v: '2', ps: 'VM-US-01', add: 'us.example.com', port: '443', id: 'b831381d-6324-4d53-ad4f-8cda48b30811', aid: '0', scy: 'auto', net: 'ws', type: 'none', host: 'cdn.example.com', path: '/ray', tls: 'tls', sni: 'cdn.example.com', alpn: 'h2,http/1.1', fp: '' });
const ssrBody = b64('us.example.com:8443:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:cGFzc3dvcmQ/?remarks=' + Buffer.from('SSR-JP-01').toString('base64')) + '';

const uris = [
  'ss://' + b64('aes-256-gcm:p@ss:word') + '@1.2.3.4:8388#🇭🇰 HK-SS-01',
  'ss://' + b64('chacha20-ietf-poly1305:pass2') + '@5.6.7.8:8389?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#SS-OBFS',
  'vmess://' + b64(vmessJson),
  'trojan://tr0janpass@tj.example.com:443?sni=tj.example.com&allowInsecure=0#🇯🇵 TR-01',
  'vless://b831381d-6324-4d53-ad4f-8cda48b30811@vl.example.com:443?encryption=none&security=reality&sni=www.apple.com&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&sid=0123abcd&type=tcp&flow=xtls-rprx-vision#🇸🇬 VLESS-REALITY',
  'vless://b831381d-6324-4d53-ad4f-8cda48b30811@vl2.example.com:443?encryption=none&security=tls&type=ws&host=ws.example.com&path=%2Fws#VLESS-WS',
  'hysteria2://hy2pass@hy.example.com:8443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=xyz#🇺🇸 HY2-01',
  'ssr://' + ssrBody,
  'socks://' + b64('user:pass@9.9.9.9:1080') + '#SOCKS-01',
  'anytls://anypass@any.example.com:443?sni=any.example.com&insecure=1#ANY-01',
  'http=10.0.0.2:8080, username=u, password=p, over-tls=true, tls-host=proxy.example.com, tag=HTTP-01',
  'trojan=tw.example.com:443, password=tpass, over-tls=true, tls-host=tw.example.com, tag=TR-QX-01, udp-relay=true',
];
w('01_uris_plain.txt', uris.join('\n'));
w('02_uris_b64.txt', b64(uris.join('\n')));

w('03_clash.yaml', `port: 7890
socks-port: 7891
proxies:
  - name: "🇭🇰 Clash-HK"
    type: ss
    server: hk.example.com
    port: 443
    cipher: aes-256-gcm
    password: clashpass
    udp: true
  - name: "Clash-VM"
    type: vmess
    server: vm.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    tls: true
    servername: vm.example.com
    network: ws
    ws-opts:
      path: "/ws"
      headers:
        Host: vm.example.com
  - name: "Clash-TR"
    type: trojan
    server: tr.example.com
    port: 443
    password: trpass
    sni: tr.example.com
    skip-cert-verify: true
  - name: "Clash-HY2"
    type: hysteria2
    server: hy.example.com
    port: 8443
    password: hypass
    sni: hy.example.com
    skip-cert-verify: true
proxy-groups:
  - name: Proxy
    type: select
    proxies: ["🇭🇰 Clash-HK", "Clash-VM"]
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - IP-CIDR,1.1.1.1/32,DIRECT
  - GEOIP,CN,DIRECT
`);

w('04_surge.conf', `[General]
loglevel = notify
[Proxy]
HK-Surge = ss, hk.example.com, 443, encrypt-method=aes-256-gcm, password=sgpass, udp-relay=true
US-Vmess = vmess, us.example.com, 443, username=b831381d-6324-4d53-ad4f-8cda48b30811, ws=true, ws-path=/path, ws-headers=Host:us.example.com, tls=true
JP-Trojan = trojan, jp.example.com, 443, password=tjpass, sni=jp.example.com, skip-cert-verify=true
[Proxy Group]
Proxy = select, HK-Surge, US-Vmess, JP-Trojan
[Rule]
DOMAIN-SUFFIX,netflix.com,Proxy
DOMAIN,apple.com,DIRECT
IP-CIDR,192.168.0.0/16,DIRECT
FINAL,Proxy
`);

w('05_rewrite.list', `# 注释行
https://raw.githubusercontent.com/example/rw/master/a.js url script-response-body a.js
https://raw.githubusercontent.com/example/rw/master/b.js url script-request-header b.js
^https?:\\/\\/api\\.example\\.com\\/v1\\/user url response-body "isVip":\\s*false response-body "isVip":true
^https?:\\/\\/cdn\\.example\\.com\\/ad url reject
^https?:\\/\\/img\\.example\\.com\\/1x1 url reject-img
https://example.com/ad url 302 https://example.com/ad
`);

w('06_filter.list', `host-suffix, google.com, proxy
host, analytics.example.com, reject
host-keyword, adservice, reject
ip-cidr, 1.2.3.4/32, direct
ip6-cidr, 2001:db8::/32, proxy
user-agent, MicroMessenger, direct
host-wildcard, *.example.net, proxy
`);

w('07_surge_ruleset.list', `DOMAIN-SUFFIX,google.com
DOMAIN,ads.example.com
DOMAIN-KEYWORD,tracker
IP-CIDR,10.0.0.0/8,no-resolve
IP-CIDR6,2001:db8::/32
USER-AGENT,MicroMessenger*
`);

w('08_module.sgmodule', `#!name=测试模块
#!desc=用于等价性验证
[Script]
http-response ^https?:\\/\\/api\\.example\\.com\\/v1\\/user script-path=https://raw.githubusercontent.com/example/m/master/user.js, requires-body=1, max-size=0, timeout=10
http-request ^https?:\\/\\/api\\.example\\.com\\/v1\\/login script-path=https://raw.githubusercontent.com/example/m/master/login.js
[URL Rewrite]
^https?:\\/\\/ads\\.example\\.com\\/\\S+ 302 https://blank.example.com/ _redirect
^https?:\\/\\/track\\.example\\.com\\/pixel reject _reject
[Map Local]
^https?:\\/\\/api\\.example\\.com\\/v1\\/config data-type=text data="{\\"ok\\":true}" status-code=200 _data
^https?:\\/\\/api\\.example\\.com\\/v1\\/empty data-type=text data="" status-code=204 _data
[Rule]
DOMAIN-SUFFIX,example.org,Proxy
`);

w('09_domainset.list', `example.com
.google.com
*.githubusercontent.com
+.cloudflare.com
192.168.1.0/24
2001:db8::/32
`);

w('10_ruleset.json', JSON.stringify({ version: 1, rules: [
  { 'domain_suffix': 'netflix.com', 'policy': 'Proxy' },
  { 'domain': 'apple.com', 'policy': 'DIRECT' },
  { 'ip_cidr': '1.1.1.1/32' },
  { 'domain_keyword': 'ads' }
] }, null, 1));

w('11_sip008.json', JSON.stringify({ version: 1, servers: [
  { id: 's1', remarks: 'SIP-SS', server: 'ss.example.com', server_port: 8388, method: 'aes-256-gcm', password: 'sippass', plugin: '', plugin_opts: '' },
  { id: 's2', remarks: 'SIP-SS2', server: 'ss2.example.com', server_port: 8389, method: 'chacha20-ietf-poly1305', password: 'sippass2', plugin: 'obfs-local', plugin_opts: 'obfs=http;obfs-host=bing.com' }
] }, null, 1));

w('12_loon.plugin', `#!name=Loon 测试
[Plugin]
http-request ^https?:\\/\\/api\\.example\\.com \\/path/to/req.js script-path=https://raw.githubusercontent.com/example/l/main/req.js, requires-body=true, timeout=10, tag=req
http-response ^https?:\\/\\/api\\.example\\.com \\/path/to/res.js script-path=https://raw.githubusercontent.com/example/l/main/res.js, requires-body=true, tag=res
[Rewrite]
^https?:\\/\\/ad\\.example\\.com https://blank.example.com/ reject
[Rule]
DOMAIN-SUFFIX,loon.example.com, DIRECT
`);

w('13_profile.conf', `[general]
resource_parser_url=https://qx.tatalvpai.vip/Scripts/resource-parser.js
[server_remote]
https://sub.example.com/a, tag=机场A, opt-parser=true, enabled=true
https://sub.example.com/b, tag=机场B, opt-parser=true, enabled=true
[filter_remote]
https://raw.githubusercontent.com/example/f/master/a.list, tag=分流A, force-policy=Proxy, enabled=true
[rewrite_remote]
https://raw.githubusercontent.com/example/r/master/a.conf, tag=重写A, enabled=true
`);

w('14_clash_provider.yaml', `payload:
  - '+.netflix.com'
  - '+.nflxvideo.net'
  - 'google.com'
`);

w('15_junk.txt', `this is not a subscription at all
{"error":"token expired"}
`);

w('16_mixed_sub.txt', uris.slice(0, 5).join('\n') + '\n\n' + `trojan=example.com:443, password=x, over-tls=true, tls-host=example.com, tag=QX-TR\n`);
console.log('fixtures written:', fs.readdirSync(dir).length);
