// 资源解析器等价性测试台：用桩件模拟 Quantumult X 运行环境，跑同一份输入，比对 $done 输出与通知
const fs = require('fs');
const vm = require('vm');
const path = require('path');

function runFile(file, resource, build) {
  const code = fs.readFileSync(file, 'utf8');
  let doneArgs = null, doneCount = 0;
  const notes = [];
  const logs = [];
  const sandbox = {
    console: { log: (...a) => logs.push(a.map(String).join(' ')), error: () => {}, warn: () => {} },
    $resource: resource,
    $environment: { version: '1.0.5 build ' + build },
    $done: (o) => { doneArgs = o; doneCount++; },
    $notify: (...a) => { notes.push(JSON.stringify(a.map(String))); },
    $prefs: { valueForKey: () => undefined, setValueForKey: () => {} },
    Date, Math, JSON, Number, String, Array, Object, RegExp, Error, parseInt, parseFloat,
    isNaN, isFinite, encodeURIComponent, decodeURIComponent, encodeURI, decodeURI, escape, unescape,
    setTimeout: (fn) => { try { fn(); } catch (e) {} }, clearTimeout: () => {},
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  let error = null;
  try { vm.runInContext(code, sandbox, { timeout: 30000, filename: file }); }
  catch (e) { error = String(e && e.message || e); }
  return { done: doneArgs, doneCount, notes, logs, error };
}

module.exports = { runFile };

if (require.main === module) {
  const [fileA, fileB, fixturesDir, outPath] = process.argv.slice(2);
  const types = ['server', 'filter', 'rewrite', 'unsupported', undefined];
  const builds = [700, 1000];
  const fixtures = fs.readdirSync(fixturesDir).filter(f => f.endsWith('.txt') || f.endsWith('.yaml') || f.endsWith('.conf') || f.endsWith('.json') || f.endsWith('.plugin') || f.endsWith('.sgmodule'));
  const results = [];
  let mismatches = 0, errors = 0;
  for (const f of fixtures) {
    const raw = fs.readFileSync(path.join(fixturesDir, f), 'utf8');
    const variants = [['plain', raw]];
    variants.push(['linkhash', raw]);
    for (const [mode, content] of variants) {
      for (const t of types) {
        for (const b of builds) {
          for (const extra of ['', '&emoji=1&udp=1&tfo=1&in=HK+SS&rename=旧@新', '&policy=MyPolicy&pset=netflix@NF&info=1', '&sort=1&ptn=2&npt=3&del=1']) {
            const link = 'https://sub.example.com/api?token=abc' + (mode === 'linkhash' && extra ? '#' + extra.slice(1) : '');
            const resource = { link, content, type: (t === undefined ? '' : t), tag: 'fx-' + f, user_agent: '' };
            const a = runFile(fileA, resource, b);
            const bb = runFile(fileB, resource, b);
            const key = `${f}|${mode}|${t}|${b}|${extra}`;
            const same = JSON.stringify([a.done, a.notes, a.error]) === JSON.stringify([bb.done, bb.notes, bb.error]);
            if (a.error) errors++;
            if (!same) {
              mismatches++;
              results.push({ key, a: { done: a.done, notes: a.notes, error: a.error }, b: { done: bb.done, notes: bb.notes, error: bb.error } });
            } else {
              results.push({ key, same: true, doneLen: a.done && typeof a.done.content === 'string' ? a.done.content.length : null, notes: a.notes.length, error: a.error });
            }
          }
        }
      }
    }
  }
  fs.writeFileSync(outPath, JSON.stringify({ total: results.length, mismatches, errors, results }, null, 1));
  console.log('total', results.length, 'mismatches', mismatches, 'scriptErrors', errors);
  const withOutput = results.filter(r => r.doneLen > 0).length;
  console.log('cases producing content:', withOutput);
  if (mismatches) {
    for (const m of results.filter(r => !r.same).slice(0, 8)) {
      console.log('\n### ' + m.key);
      console.log('A:', JSON.stringify(m.a).slice(0, 700));
      console.log('B:', JSON.stringify(m.b).slice(0, 700));
    }
  }
  const errs = results.filter(r => r.error).slice(0, 5);
  for (const e of errs) console.log('ERR', e.key, e.error);
}
