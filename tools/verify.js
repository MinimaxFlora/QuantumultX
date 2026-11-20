// 分两种口径验证：
// A) 类型填对（QX 实际会传的类型）→ 必须与上游逐字一致
// B) 类型填错（用户把订阅放进重写引用之类）→ 不再抛异常，且给出跳转通知
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SITE = 'https://qx.tatalvpai.vip';
const REPO = 'https://github.com/MinimaxFlora/QuantumultX';
const NORM = [
  [SITE + '/img/sub.png', 'https://shrtm.nu/ebAr'], [SITE + '/img/bug.png', 'https://shrtm.nu/obcB'],
  [SITE + '/img/fake.png', 'https://shrtm.nu/uo13'], [SITE + '/img/rewrite.png', 'https://shrtm.nu/x3o2'],
  [SITE + '/img/hostname.png', 'https://shrtm.nu/0n5J'], [SITE + '/img/rule.png', 'https://shrtm.nu/cpHD'],
  [SITE + '/img/qx.png', 'https://raw.githubusercontent.com/crossutility/Quantumult-X/master/quantumult-x.png'],
  [SITE + '/Scripts/resource-parser.js', 'https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/resource-parser.js'],
  [SITE, 'https://tinyurl.com/2jyygfom'],
  [REPO + '/issues', 'https://t.me/ShawnKOP_Parser_Bot'],
  [REPO, 'https://t.me/QuanX_API'],
  ['Minimax', 'Shawn'],
];
const norm = s => { let t = s; for (const [a, b] of NORM) t = t.split(a).join(b); return t; };

function run(file, resource, build) {
  const sandbox = {
    console: { log: () => {}, error: () => {}, warn: () => {} },
    $resource: resource, $environment: { version: '1.0.5 build ' + build },
    $done: o => { sandbox.__done = o; }, $notify: (...a) => { sandbox.__notes.push(a.map(String)); },
    $prefs: { valueForKey: () => undefined, setValueForKey: () => {} },
    Date, Math, JSON, Number, String, Array, Object, RegExp, Error, parseInt, parseFloat,
    isNaN, isFinite, encodeURIComponent, decodeURIComponent, encodeURI, decodeURI, escape, unescape,
  };
  sandbox.__done = null; sandbox.__notes = [];
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  let err = null;
  try { vm.runInContext(fs.readFileSync(file, 'utf8'), sandbox, { timeout: 30000, filename: file }); }
  catch (e) { err = String((e && e.message) || e); }
  return JSON.stringify({ done: norm(JSON.stringify(sandbox.__done)), notes: sandbox.__notes.map(n => norm(JSON.stringify(n))), err });
}

const EXPECT_TYPE = {
  '01_uris_plain.txt': 'server', '02_uris_b64.txt': 'server', '16_mixed_sub.txt': 'server',
  '03_clash.yaml': 'server', '04_surge.conf': 'server', '11_sip008.json': 'server',
  '05_rewrite.list': 'rewrite', '08_module.sgmodule': 'rewrite', '12_loon.plugin': 'rewrite',
  '06_filter.list': 'filter', '07_surge_ruleset.list': 'filter', '09_domainset.list': 'filter',
  '10_ruleset.json': 'filter', '14_clash_provider.yaml': 'filter', '13_profile.conf': 'filter',
  '15_junk.txt': 'server',
};
const fixt = path.join(__dirname, 'fixtures');
const builds = [600, 700, 800, 900, 966, 1000];
const extras = ['', '&emoji=1&udp=1&tfo=1&cert=1&tls13=1&alpn=h2',
  '&in=HK+SS&rename=旧@新&rrname=@尾部&ptn=2&npt=3', '&policy=MyPolicy&pset=netflix@NF&replace=(HK)@(SG)',
  '&sort=1&sortx=-1&del=1&hide=0&cnt=1', '&filter=x&out=TR&regex=443&regout=example&suffix=1&cap=1',
  '&profile=111', '&relay=中转&via=0&fcr=1&cdn=1', '&UA=1&dbg=1'];

let a = { total: 0, bad: 0, withOut: 0, err: 0 };
const diff = [];
for (const f of fs.readdirSync(fixt)) {
  const raw = fs.readFileSync(path.join(fixt, f), 'utf8');
  for (const b of builds) for (const extra of extras) {
    const link = 'https://sub.example.com/api?token=abc' + (extra ? '#' + extra.slice(1) : '');
    const res = { link, content: raw, type: EXPECT_TYPE[f], tag: 'fx', user_agent: '' };
    const x = run('orig.js', res, b), y = run('new.js', res, b);
    a.total++;
    if (JSON.parse(x).err || JSON.parse(y).err) a.err++;
    if (JSON.parse(x).done && (JSON.parse(x).done.includes('"content":"') || JSON.parse(x).done.includes('\\"content\\"'))) a.withOut++;
    if (x !== y) { a.bad++; if (diff.length < 3) diff.push({ f, b, extra, x: x.slice(0, 700), y: y.slice(0, 700) }); }
  }
}
console.log('A) 类型正确口径:', JSON.stringify(a));
for (const d of diff) { console.log('\n### ' + d.f + ' build=' + d.b + ' ' + d.extra); console.log('ORIG', d.x); console.log('NEW ', d.y); }

// B) 类型填错
let b2 = { total: 0, crashedOrig: 0, crashedNew: 0, notices: 0 };
for (const f of fs.readdirSync(fixt)) {
  const raw = fs.readFileSync(path.join(fixt, f), 'utf8');
  for (const t of ['server', 'filter', 'rewrite', 'unsupported', '']) {
    if (t === EXPECT_TYPE[f]) continue;
    const res = { link: 'https://sub.example.com/api?token=abc', content: raw, type: t, tag: 'fx', user_agent: '' };
    const x = JSON.parse(run('orig.js', res, 1000)), y = JSON.parse(run('new.js', res, 1000));
    b2.total++;
    if (x.err) b2.crashedOrig++;
    if (y.err) b2.crashedNew++;
    if (y.notes.some(n => n.includes('跳转尝试添加到正确类型'))) b2.notices++;
    if (b2.crashedNew && b2.crashedNew < 4) console.log('NEW CRASH:', f, t, y.err);
  }
}
console.log('\nB) 类型填错口径:', JSON.stringify(b2));
