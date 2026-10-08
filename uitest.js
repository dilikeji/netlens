/*
 * 页面冒烟测试：把 ui.html 里那段真实的脚本放进一个最小 DOM 桩里跑一遍。
 *
 * 目的不是"验证渲染正确"，而是把运行时错误抓出来——手写的 25KB DOM 代码里，
 * 一个拼错的 id、一次空引用，都会让整个页面白屏，而这类问题语法检查发现不了。
 *
 * 用法：node uitest.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const here = __dirname;
const html = fs.readFileSync(path.join(here, 'ui.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

/* ---------------- 最小 DOM ---------------- */
const registry = new Map();
let failures = 0;

function classList() {
  const set = new Set();
  return {
    add: (...c) => c.forEach(x => set.add(x)),
    remove: (...c) => c.forEach(x => set.delete(x)),
    toggle: (c, on) => { if (on === undefined) { set.has(c) ? set.delete(c) : set.add(c); } else { on ? set.add(c) : set.delete(c); } },
    contains: c => set.has(c),
    _set: set,
  };
}

class El {
  constructor(tag, id) {
    this.tagName = (tag || 'div').toUpperCase();
    this.id = id || '';
    this.dataset = {};
    this.style = {};
    this.classList = classList();
    this.children = [];
    this._html = '';
    this._text = '';
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.title = '';
    this.scrollTop = 0;
    this.scrollHeight = 100;
    this.clientHeight = 100;
    this.handlers = {};
  }
  // 设置 innerHTML 时把里面新建的 id 元素收成子节点，
  // 这样容器再被读取时能算上它们后来被写入的内容（真实 DOM 就是这个语义）
  set innerHTML(v) { this._html = String(v); this.children = scanIds(this._html); }
  // 页面既用 innerHTML 整体渲染，也用 prepend/appendChild 增量插入，
  // 所以取值时要把两者拼起来，否则断言会看不到子节点
  get innerHTML() { return this._html + this.children.map(c => c.innerHTML).join(''); }
  set textContent(v) { this._text = String(v); }
  get textContent() { return this._text; }
  appendChild(c) { this.children.push(c); return c; }
  prepend(c) { this.children.unshift(c); return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); }
  remove() {}
  insertBefore(c) { this.children.push(c); return c; }
  addEventListener(k, fn) { (this.handlers[k] = this.handlers[k] || []).push(fn); }
  removeEventListener() {}
  querySelector(sel) { return lookup(sel); }
  querySelectorAll(sel) {
    // 页面里只用到两类：.tabs button（要遍历绑事件）和 .rule（遍历绑事件）
    if (sel === '.tabs button') return [0, 1, 2, 3, 4].slice(0, tabCount(this._html)).map((_, i) => fake('tab' + i, { 'data-tab': ['overview', 'req', 'resp', 'frames', 'raw'][i] }));
    if (sel === '.rule') return ruleEls(this._html);
    if (sel === '[data-act="toggle"]' || sel === '[data-act="del"]' || sel === '[data-act="edit"]') { const e = lookup(sel); return e ? [e] : []; }
    return [];
  }
  closest() { return this; }
  focus() {}
  getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0 }; }
}

function tabCount(h) { return (h.match(/data-tab=/g) || []).length || 1; }

function ruleEls(h) {
  const ids = [...h.matchAll(/class="rule[^"]*" data-id="(\d+)"/g)].map(m => m[1]);
  return ids.map(id => {
    const el = fake('rule' + id, { 'data-id': id });
    el.querySelector = sel => lookup(sel, el);
    return el;
  });
}

function scanIds(h) {
  const created = [];
  for (const m of h.matchAll(/id="([A-Za-z0-9_-]+)"/g)) {
    if (!registry.has('#' + m[1])) {
      const el = new El('div', m[1]);
      registry.set('#' + m[1], el);
      created.push(el);
    }
  }
  return created;
}

function fake(name, ds) {
  const e = new El('div', name);
  if (ds) for (const k in ds) e.dataset[k.replace('data-', '')] = ds[k];
  return e;
}

// 所有 selector 都能拿到一个元素，避免"因为桩不完整而误报"
function lookup(sel, parent) {
  if (registry.has(sel)) return registry.get(sel);
  // id 选择器要如实返回 null：页面里有 `if(!$('#x'))` 这种分支，
  // 桩要是凭空造一个元素出来，就把真实会走的路径盖掉了
  if (sel.startsWith('#')) return null;
  // 非 id 选择器（[data-act="..."] 之类）给个占位，避免桩不完整造成的误报
  const e = new El('div', sel);
  e.dataset.act = (sel.match(/data-act="([^"]+)"/) || [])[1] || '';
  registry.set(sel, e);
  return e;
}

const document = {
  querySelector: sel => lookup(sel),
  getElementById: id => lookup('#' + id),
  createElement: tag => new El(tag),
  createDocumentFragment: () => { const f = new El('#fragment'); f.isFragment = true; return f; },
  addEventListener: () => {},
  body: new El('body'),
};
// 只扫真实 DOM 部分：<script> 里的模板字符串（'<pre id="mlog">' 之类）
// 不是 DOM，一起扫会把还没渲染出来的元素提前注册上，掩盖页面的分支逻辑
scanIds(html.replace(/<script>[\s\S]*<\/script>/g, ''));

/* ---------------- 假数据 ---------------- */
const HTTP_REC = {
  id: 7, kind: 'http', scheme: 'https', method: 'POST', host: 'api.example.com', port: '443',
  path: '/v1/login', query: 'a=1', url: 'https://api.example.com/v1/login?a=1',
  source: 'socks5', client: '127.0.0.1:5001', proto: '首字节嗅探 → TLS 中间人',
  reqHdr: [['Host', 'api.example.com'], ['Content-Type', 'application/json']],
  reqBody: { binary: false, text: '{"user":"zhou"}', len: 15 }, reqSize: 15, reqTrunc: false,
  respHdr: [['Content-Type', 'application/json'], ['Content-Encoding', 'gzip']],
  respBody: { binary: true, b64: 'H4sIAAAA', len: 220 }, respSize: 220, respTrunc: false,
  respBodyDecoded: { binary: false, text: '{"ok":true,"token":"abc"}', len: 24 }, respDecoded: true,
  mocked: false, start: '2026-10-08T14:00:00+08:00', end: '2026-10-08T14:00:00.12+08:00',
  durMs: 120, note: '', rawRequest: 'POST /v1/login HTTP/1.1\r\nHost: api.example.com\r\n\r\n',
  rawResponse: 'HTTP/1.1 200 OK\r\n\r\n',
};
const WS_REC = {
  id: 8, kind: 'ws', scheme: 'wss', method: 'GET', host: 'ws.example.com', port: '443',
  path: '/socket', query: '', url: 'wss://ws.example.com/socket', source: 'socks5',
  client: '127.0.0.1:5002', proto: '首字节嗅探 → TLS 中间人', reqHdr: [['Host', 'ws.example.com']],
  reqBody: { binary: false, text: '', len: 0 }, reqSize: 0, respHdr: [['Upgrade', 'websocket']],
  respBody: { binary: false, text: '', len: 0 }, respSize: 0, status: 101, mocked: false,
  start: '2026-10-08T14:00:01+08:00', durMs: 900,
  frames: [
    { seq: 1, dir: 'C→S', opcode: 'TEXT', len: 13, at: '2026-10-08T14:00:01+08:00', payload: { binary: false, text: 'hello-netlens', len: 13 } },
    { seq: 2, dir: 'S→C', opcode: 'TEXT', len: 20, at: '2026-10-08T14:00:01+08:00', payload: { binary: false, text: '{"pong":true}', len: 14 } },
  ],
  rawRequest: 'GET /socket HTTP/1.1\r\n\r\n', rawResponse: 'HTTP/1.1 101 Switching Protocols\r\n\r\n',
};
const MOCK_REC = Object.assign({}, HTTP_REC, { id: 9, mocked: true, ruleId: 3, status: 200 });
// 二进制响应：只有 respFile，没有 respBody
const PNG_BYTES = Buffer.from('\x89PNG\r\n\x1a\nFAKE-IMAGE-PAYLOAD-FAKE-IMAGE-PAYLOAD', 'binary');
const FILE_REC = {
  id: 11, kind: 'http', scheme: 'https', method: 'GET', host: 'cdn.example.com', port: '443',
  path: '/logo.png', query: '', url: 'https://cdn.example.com/logo.png', source: 'socks5',
  client: '127.0.0.1:5004', proto: '首字节嗅探 → TLS 中间人',
  reqHdr: [['Host', 'cdn.example.com']], reqBody: { binary: false, text: '', len: 0 },
  reqSize: 0, reqTrunc: false,
  respHdr: [['Content-Type', 'image/png'], ['Content-Length', '1048576']],
  respBody: { binary: true, b64: PNG_BYTES.toString('base64'), len: PNG_BYTES.length },
  respSize: 1048576, respTrunc: true,
  respFile: { contentType: 'image/png', size: 1048576 },
  status: 200, mocked: false, start: '2026-10-08T14:00:03+08:00', durMs: 210,
  rawRequest: 'GET /logo.png HTTP/1.1\r\n\r\n', rawResponse: 'HTTP/1.1 200 OK\r\n\r\n',
};
const TCP_REC = {
  id: 10, kind: 'tcp', scheme: 'tcp', method: '-', host: '1.2.3.4', port: '993', path: '/',
  query: '', url: '1.2.3.4:993', source: 'socks5', client: '127.0.0.1:5003',
  proto: '首字节嗅探 → 无法识别，字节透传', reqHdr: [], reqBody: { binary: false, text: '', len: 0 },
  reqSize: 100, respHdr: [], respBody: { binary: false, text: '', len: 0 }, respSize: 4096,
  status: 0, mocked: false, start: '2026-10-08T14:00:02+08:00', durMs: 3000,
  note: '无法解析协议，按字节原样透传',
};
const RULE = {
  id: 3, name: '锁定登录', enabled: true, method: 'POST', host: 'api.example.com', port: '443',
  path: '/v1/login', query: 'a=1', ignoreQuery: true, status: 200,
  pattern: 'POST api.example.com:443/v1/login',
  hdr: [['Content-Type', 'application/json']], body: { binary: false, text: '{"ok":true}', len: 11 },
  delayMs: 0, hits: 2, createdAt: '2026-10-08T14:00:00+08:00',
};
const MIHOMO = {
  running: true, pid: 4242, uptimeSec: 61, dir: 'C:/Users/x/AppData/Roaming/netlens/runtime',
  exePath: 'C:/x/mihomo.exe', cfgPath: 'C:/x/config.yaml', autoStart: false,
  version: 'Mihomo Meta alpha-9f053c4 windows amd64', exitCode: 0, exitErr: '',
  socks5: '127.0.0.1:1080', expectSocks: '127.0.0.1:1080', portMatch: true, tun: true,
  elevated: true, logCount: 12,
};

const ROUTES = {
  '/api/status': { web: 'http://127.0.0.1:9600/', socks: '127.0.0.1:1080', http: '127.0.0.1:8080',
    caPath: 'C:/ca.crt', records: 4, memBytes: 2048, rules: 1, mihomo: MIHOMO,
    hiddenTunnels: 37, showTunnel: false, hiddenOptions: 12, showOptions: false,
    caInstalled: false, tunnelAuto: 2, tunnelManual: 0, blocked: 0 },
  '/api/tunnel': { manual: ['pinned.example.com'], auto: ['electerm.org', 'api.weird.io'] },
  '/api/blocked': { blocked: [] },
  '/api/records?limit=600': { records: [MOCK_REC, TCP_REC, WS_REC, HTTP_REC], total: 4 },
  '/api/rules': { rules: [RULE] },
  '/api/mihomo': MIHOMO,
  '/api/mihomo/config': { config: 'tun:\n  enable: true\nproxies:\n  - type: socks5\n    server: 127.0.0.1\n    port: 1080\n', path: 'C:/x/config.yaml' },
  '/api/mihomo/log?since=0': { lines: ['[14:00:00] Mihomo Meta alpha starting'], total: 1 },
};
function body(rec) { return { record: rec, rules: [RULE] }; }

const fetchCalls = [];
async function fetchStub(url, opt) {
  fetchCalls.push((opt && opt.method ? opt.method + ' ' : '') + url);
  let data = ROUTES[url];
  if (url.startsWith('/api/records/')) {
    const pick = { 7: HTTP_REC, 8: WS_REC, 9: MOCK_REC, 10: TCP_REC, 11: FILE_REC };
    data = body(pick[Number(url.split('/').pop())] || TCP_REC);
  }
  if (url.startsWith('/api/mihomo/log')) data = ROUTES['/api/mihomo/log?since=0'];
  if (!data) data = { ok: true };
  return { ok: true, status: 200, json: async () => data };
}

/* ---------------- 执行 ---------------- */
const sandbox = {
  document, fetch: fetchStub, console,
  EventSource: class { constructor() { sandbox.__es = this; } close() {} },
  navigator: { clipboard: { writeText: async () => {} } },
  confirm: () => false, alert: () => {}, location: { href: '' },
  setTimeout, clearTimeout, setInterval: () => 0, clearInterval: () => {},
  // 页面里解码二进制要用到这几个，桩也得给
  atob, btoa, TextDecoder, Uint8Array,
  JSON, Math, Date, Number, String, Object, Array, Boolean, RegExp, Error, Map, Set, Promise, isNaN, parseInt, parseFloat,
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;

const ctx = vm.createContext(sandbox);
try {
  vm.runInContext(script, ctx, { filename: 'ui.html#script' });
  // 页面里的 const S 是词法绑定，不会挂到 global 上，这里显式取出来供断言使用
  vm.runInContext('globalThis.__state = S;', ctx);
  sandbox.S = sandbox.__state;
} catch (e) {
  console.error('  [FAIL] 脚本执行抛出异常: ' + e.stack.split('\n').slice(0, 3).join(' | '));
  process.exit(1);
}
console.log('  [PASS] 脚本加载并完成初始化');

async function step(name, fn) {
  try {
    await fn();
    console.log('  [PASS] ' + name);
  } catch (e) {
    failures++;
    console.error('  [FAIL] ' + name + ' → ' + e.message);
    console.error('         ' + (e.stack || '').split('\n')[1]);
  }
}

(async () => {
  ctx.location = sandbox.location;   // 断言下载地址要用
  await new Promise(r => setTimeout(r, 20));

  await step('顶栏状态渲染（含 mihomo 圆点）', () => {
    if (!ctx.loadStatus) throw new Error('loadStatus 未导出');
    return ctx.loadStatus();
  });

  await step('状态栏报出被过滤的连接数与 OPTIONS 数', () => {
    const txt = ctx.document.querySelector('#stat').textContent;
    if (txt.indexOf('37 条无法解析') < 0) throw new Error('没提示被过滤的透传数量：' + txt);
    if (txt.indexOf('12 条 OPTIONS') < 0) throw new Error('没提示被过滤的 OPTIONS 数量：' + txt);
  });

  await step('根证书提示：未安装时警告，装好后变已安装', () => {
    let h = ctx.document.querySelector('#chips').innerHTML;
    if (h.indexOf('首次运行请先安装根证书') < 0) throw new Error('缺少首次安装提示：' + h.slice(0, 200));
    ROUTES['/api/status'].caInstalled = true;
    return ctx.loadStatus().then(() => {
      h = ctx.document.querySelector('#chips').innerHTML;
      if (h.indexOf('根证书已安装') < 0) throw new Error('装好后没变成已安装');
      if (h.indexOf('首次运行请先安装根证书') >= 0) throw new Error('装好后提示没消失');
    });
  });

  await step('记录列表渲染四种类型', async () => {
    await ctx.reload();
    const h = ctx.document.querySelector('#rows').innerHTML;
    if (h.indexOf('TCP') < 0 || h.indexOf('WS') < 0) throw new Error('列表内容不完整');
  });

  await step('SSE 增量：新增 + 更新 + 日志 + 状态', async () => {
    const es = sandbox.__es;
    if (!es || !es.onmessage) throw new Error('EventSource 未接入');
    es.onmessage({ data: JSON.stringify({ t: 'batch', add: [Object.assign({}, HTTP_REC, { id: 100 })],
      upd: [Object.assign({}, HTTP_REC, { id: 7, status: 200, end: '2026-10-08T14:00:01+08:00' })],
      log: ['[14:00:02] mihomo 启动'], stat: true }) });
  });

  await step('SSE 重同步信号', async () => {
    sandbox.__es.onmessage({ data: JSON.stringify({ t: 'resync' }) });
  });

  await step('详情：概览 / 请求 / 响应 / 原始', async () => {
    await ctx.showDetail(7);
    for (const tab of ['overview', 'req', 'resp', 'raw']) {
      ctx.S.tab = tab;
      await ctx.showDetail(7, true);
      const h = ctx.document.querySelector('#detail').innerHTML;
      if (tab === 'resp' && h.indexOf('respBodyDecoded') >= 0) throw new Error('响应体字段名泄漏到页面');
      if (!h || h.length < 200) throw new Error(tab + ' 渲染内容过短');
    }
  });

  await step('详情：WebSocket 帧视图', async () => {
    ctx.S.tab = 'frames';
    await ctx.showDetail(8, true);
    const h = ctx.document.querySelector('#detail').innerHTML;
    if (h.indexOf('C→S') < 0 || h.indexOf('hello-netlens') < 0) throw new Error('帧内容没渲染出来');
  });

  await step('详情：字节透传记录（无响应头无响应体）', async () => {
    ctx.S.tab = 'overview';
    await ctx.showDetail(10);
  });

  await step('详情：二进制默认折叠，给「查看文本 / 下载」两个按钮', async () => {
    ctx.S.tab = 'resp';
    ctx.S.textOpen = {};
    await ctx.showDetail(11, true);
    const h = ctx.document.querySelector('#detail').innerHTML;
    if (h.indexOf('filecard') < 0) throw new Error('没有渲染文件卡片');
    if (h.indexOf('图片') < 0 || h.indexOf('image/png') < 0) throw new Error('文件类型没显示');
    if (h.indexOf('1.00 M') < 0) throw new Error('文件大小没显示');
    if (h.indexOf('查看文本') < 0) throw new Error('缺少「查看文本」按钮');
    if (h.indexOf('下载') < 0) throw new Error('缺少「下载」按钮');
    // 默认不铺内容：给的是卡片，不该直接跟一个内容区
    if (h.indexOf('响应体</h4><div class="filecard"') < 0) throw new Error('响应体区域不是文件卡片');
    if (h.indexOf('bintext') >= 0) throw new Error('默认就把二进制内容铺出来了');
  });

  await step('点「查看文本」把二进制按文本展开', async () => {
    ctx.toggleBinText(11, 'resp');
    await new Promise(r => setTimeout(r, 10));
    const h = ctx.document.querySelector('#detail').innerHTML;
    if (h.indexOf('bintext') < 0) throw new Error('展开后没有内容区');
    if (h.indexOf('PNG') < 0) throw new Error('内容没渲染出来');
    if (h.indexOf('收起文本') < 0) throw new Error('按钮没变成「收起文本」');
    // 再点一次收起来
    ctx.toggleBinText(11, 'resp');
    await new Promise(r => setTimeout(r, 10));
    if (ctx.document.querySelector('#detail').innerHTML.indexOf('bintext') >= 0) {
      throw new Error('再点一次没有收起');
    }
  });

  await step('点「下载」会指向 body 接口', () => {
    ctx.downloadBody(11, 'resp');
    if (ctx.location.href.indexOf('/api/records/11/body?which=resp') < 0) {
      throw new Error('下载地址不对：' + ctx.location.href);
    }
  });

  await step('二进制记录的请求 / 概览 / 原始标签页都不报错', async () => {
    for (const tab of ['overview', 'req', 'raw']) {
      ctx.S.tab = tab;
      await ctx.showDetail(11, true);
    }
  });

  await step('锁定编辑器：二进制响应给出替换提示', async () => {
    ctx.openEditor(FILE_REC);
    const h = ctx.document.querySelector('#mask').innerHTML;
    if (h.indexOf('图片') < 0 || h.indexOf('替换') < 0) throw new Error('缺少文件替换提示');
    if (h.indexOf('base64') >= 0) throw new Error('不应该再提 base64');
  });

  await step('列表过滤：关键词 / 类型 / 锁定', () => {
    ctx.S.q = 'login'; ctx.rerender();
    ctx.S.q = ''; ctx.S.kind = 'ws'; ctx.rerender();
    ctx.S.kind = 'mock'; ctx.rerender();
    ctx.S.kind = 'tcp'; ctx.rerender();
    ctx.S.kind = 'all'; ctx.rerender();
  });

  await step('锁定编辑器：HTTP 记录可编辑', () => {
    ctx.openEditor(HTTP_REC);
    const h = ctx.document.querySelector('#mask').innerHTML;
    if (h.indexOf('保存并锁定') < 0) throw new Error('编辑器没渲染');
    if (h.indexOf('token') < 0) throw new Error('响应体没有预填（应为解压后的内容）');
  });

  await step('锁定编辑器：WS / 透传记录按钮被禁用', async () => {
    await ctx.showDetail(8);
    const lock = ctx.document.querySelector('#btnLock');
    if (lock && lock.disabled !== true) throw new Error('WS 记录的锁定按钮应被禁用');
    await ctx.showDetail(10);
    const lock2 = ctx.document.querySelector('#btnLock');
    if (lock2 && lock2.disabled !== true) throw new Error('透传记录的锁定按钮应被禁用');
  });

  await step('规则面板渲染 + 开关', async () => {
    ctx.openDrawer();
    await new Promise(r => setTimeout(r, 10));
    const h = ctx.document.querySelector('#ruleList').innerHTML;
    if (h.indexOf('锁定登录') < 0 || h.indexOf('POST api.example.com') < 0) throw new Error('规则列表没渲染');
  });

  await step('规则编辑器（含 hdr / body 预填）', () => {
    ctx.openRuleEditor(RULE);
    const h = ctx.document.querySelector('#mask').innerHTML;
    if (h.indexOf('Content-Type') < 0) throw new Error('响应头没预填');
    if (h.indexOf('ok') < 0) throw new Error('响应体没预填');
  });

  await step('屏蔽按域名生效：同域名下所有路径都隐藏', async () => {
    ctx.applyBlocked([{ id: 1, host: 'api.example.com', label: 'api.example.com' }]);

    ctx.S.kind = 'all'; ctx.rerender();
    if (ctx.visible(HTTP_REC)) throw new Error('屏蔽后仍出现在「全部」栏');
    if (!ctx.visible(TCP_REC)) throw new Error('没屏蔽的记录被误伤');

    // 关键：同域名、路径不同 → 一样要隐藏（屏蔽粒度是域名，不是 URL）
    const otherPath = Object.assign({}, HTTP_REC, {
      id: 77, path: '/v2/logout', query: 'b=2', url: 'https://api.example.com/v2/logout?b=2' });
    if (ctx.visible(otherPath)) throw new Error('同域名下别的路径没被屏蔽');

    // 别的域名不该受影响
    const otherHost = Object.assign({}, HTTP_REC, { id: 78, host: 'other.com', path: '/v1/login' });
    if (!ctx.visible(otherHost)) throw new Error('别的域名被误伤');

    ctx.S.kind = 'mock'; ctx.rerender();
    if (ctx.visible(MOCK_REC)) throw new Error('屏蔽后仍出现在「锁定」栏');

    ctx.S.kind = 'blocked'; ctx.rerender();
    if (!ctx.visible(HTTP_REC)) throw new Error('「屏蔽」栏里看不到被屏蔽的记录');
    if (!ctx.visible(otherPath)) throw new Error('同域名别的路径也该出现在「屏蔽」栏');
    if (ctx.visible(TCP_REC)) throw new Error('「屏蔽」栏里混进了没屏蔽的记录');

    ctx.applyBlocked([]);
    ctx.S.kind = 'all'; ctx.rerender();
    if (!ctx.visible(HTTP_REC)) throw new Error('取消屏蔽后没恢复显示');
  });

  await step('顶栏屏蔽入口 + 已屏蔽域名抽屉', () => {
    ctx.applyBlocked([{ id: 1, host: 'api.example.com', label: 'api.example.com' }]);
    const chips = ctx.document.querySelector('#chips').innerHTML;
    if (chips.indexOf('已屏蔽') < 0) throw new Error('顶栏没有屏蔽入口：' + chips.slice(0, 200));
    ctx.openBlocked();
    const h = ctx.document.querySelector('#bdrawer').innerHTML;
    if (h.indexOf('api.example.com') < 0) throw new Error('抽屉里没列出被屏蔽的域名：' + h.slice(0, 200));
    ctx.applyBlocked([]);
  });

  await step('右键菜单带屏蔽入口', () => {
    ctx.showCtxMenu(120, 180, HTTP_REC);
    const body = ctx.document.body;
    const menu = body.children[body.children.length - 1];
    const h = menu.innerHTML;
    if (h.indexOf('屏蔽此域名') < 0) throw new Error('菜单里没有屏蔽项：' + h);
    if (h.indexOf('复制 URL') < 0) throw new Error('菜单里没有复制项');
    if (h.indexOf('编辑响应并锁定') < 0) throw new Error('HTTP 记录应该有锁定项');
    ctx.hideCtxMenu();
  });

  await step('右键菜单对 WS / 透传记录不给「锁定」项', () => {
    for (const rec of [WS_REC, TCP_REC]) {
      ctx.showCtxMenu(10, 10, rec);
      const body = ctx.document.body;
      const h = body.children[body.children.length - 1].innerHTML;
      if (h.indexOf('编辑响应并锁定') >= 0) throw new Error(rec.kind + ' 记录不该有锁定项');
      ctx.hideCtxMenu();
    }
  });

  await step('自动透传名单抽屉', async () => {
    ctx.openTunnel();
    await new Promise(r => setTimeout(r, 10));
    // 断言在"抽屉容器"上，而不是那个内容 div 的 id 上——
    // 之前正是 id 撞名写错了地方，断言在 id 上就会跟着一起错
    const h = ctx.document.querySelector('#tdrawer').innerHTML;
    if (h.indexOf('electerm.org') < 0) throw new Error('抽屉里没列出自动透传的域名：' + h.slice(0, 200));
    if (h.indexOf('pinned.example.com') < 0) throw new Error('没列出命令行指定的域名');
    // 顶栏那个按钮不该被写进任何东西
    const chip = ctx.document.querySelector('#tunAutoBtn');
    if (chip && chip.innerHTML.indexOf('electerm.org') >= 0) {
      throw new Error('列表被写进了顶栏按钮里（id 撞名）');
    }
  });

  await step('页面里没有重复的 id', () => {
    // 重名的后果很隐蔽：$('#x') 只会命中文档里第一个，
    // 于是渲染跑到别的地方去了，而且完全不报错
    const ids = [...html.matchAll(/id="([A-Za-z0-9_-]+)"/g)].map(m => m[1]);
    const dup = [...new Set(ids.filter((v, i) => ids.indexOf(v) !== i))];
    if (dup.length) throw new Error('重复的 id：' + dup.join(', '));
  });

  await step('日志区域没有被通用 pre 规则截断', () => {
    const css = html.match(/<style>([\s\S]*?)<\/style>/)[1];
    const rule = css.match(/#mlog\{[^}]*\}/);
    if (!rule) throw new Error('找不到 #mlog 样式');
    if (rule[0].indexOf('max-height:none') < 0) {
      throw new Error('#mlog 没覆盖 max-height，会被 pre{max-height:520px} 截成半屏：' + rule[0]);
    }
    if (rule[0].indexOf('flex:1') < 0) throw new Error('#mlog 没撑满容器');
  });

  await step('运行日志抽屉（桌面模式下唯一的错误出口）', () => {
    ctx.openLog();
    const h = ctx.document.querySelector('#ldrawer').innerHTML;
    if (h.indexOf('运行日志') < 0 || h.indexOf('id="mlog"') < 0) {
      throw new Error('日志抽屉没渲染，实际内容=' + JSON.stringify(h.slice(0, 120)));
    }
    ctx.appendMLog(['[15:00:00] netlens 已启动']);
    const pre = ctx.document.querySelector('#mlog');
    if (pre.textContent.indexOf('netlens 已启动') < 0) throw new Error('日志追加失败');
  });

  await step('mihomo 面板：运行中', async () => {
    ctx.openMihomo();
    // openMihomo 里的状态是异步拉回来的，等它落地再断言
    await new Promise(r => setTimeout(r, 10));
    const h = ctx.document.querySelector('#mHead').innerHTML;
    if (h.indexOf('运行中') < 0 || h.indexOf('4242') < 0) throw new Error('mihomo 状态没渲染');
    if (h.indexOf('Mihomo Meta') < 0) throw new Error('版本号没渲染');
  });

  await step('mihomo 面板：端口不匹配时给出警告', () => {
    ctx.renderMihomo(Object.assign({}, MIHOMO, { portMatch: false, socks5: '127.0.0.1:9999' }));
    const h = ctx.document.querySelector('#mHead').innerHTML;
    if (h.indexOf('不会到达页面') < 0) throw new Error('缺少端口不匹配警告');
    ctx.renderMihomo(MIHOMO);
  });

  await step('mihomo 面板：未运行 + 上次退出异常', () => {
    ctx.renderMihomo(Object.assign({}, MIHOMO, { running: false, pid: 0, uptimeSec: 0, exitErr: 'exit status 1' }));
    const h = ctx.document.querySelector('#mHead').innerHTML;
    if (h.indexOf('未运行') < 0 || h.indexOf('exit status 1') < 0) throw new Error('未运行状态提示缺失');
    if (h.indexOf('管理员') < 0) throw new Error('已提权时权限字段没渲染');
  });

  await step('mihomo 面板：普通权限时提示要提权', () => {
    ctx.renderMihomo(Object.assign({}, MIHOMO, { elevated: false }));
    const h = ctx.document.querySelector('#mHead').innerHTML;
    if (h.indexOf('管理员权限') < 0 || h.indexOf('普通用户') < 0) throw new Error('缺少提权提示');
    ctx.renderMihomo(MIHOMO);
  });

  await step('顶栏 TUN 开关跟随状态显示启动/停止', () => {
    ctx.renderMihomo(Object.assign({}, MIHOMO, { running: true }));
    if (ctx.document.querySelector('#tunText').textContent !== '停止 TUN') {
      throw new Error('运行中时按钮文字不对：' + ctx.document.querySelector('#tunText').textContent);
    }
    ctx.renderMihomo(Object.assign({}, MIHOMO, { running: false, pid: 0 }));
    if (ctx.document.querySelector('#tunText').textContent !== '启动 TUN') {
      throw new Error('未运行时按钮文字不对');
    }
  });

  await step('点顶栏开关会去调 mihomo 启停接口', async () => {
    ctx.renderMihomo(Object.assign({}, MIHOMO, { running: false, pid: 0 }));
    ctx.document.querySelector('#btnTun').onclick();
    await new Promise(r => setTimeout(r, 10));
    if (!fetchCalls.some(c => c.indexOf('/api/mihomo/start') >= 0)) {
      throw new Error('没有调用启动接口，实际调用：' + fetchCalls.slice(-4).join(', '));
    }
    ctx.renderMihomo(MIHOMO);
  });

  await step('暂停按钮已经不存在（改成了 TUN 开关）', () => {
    if (ctx.document.querySelector('#btnPause')) throw new Error('暂停按钮还在');
    if ('paused' in ctx.S) throw new Error('页面里还留着暂停状态');
  });

  await step('清空记录', async () => {
    await (ctx.document.querySelector('#btnClear').onclick)();
    if (ctx.S.recs.size !== 0) throw new Error('清空后仍有记录');
  });

  await step('过滤 / 规则 / 状态 / mihomo 相关接口都被调用过', () => {
    const need = ['/api/records/7', '/api/rules', '/api/status', '/api/mihomo', '/api/mihomo/config'];
    const miss = need.filter(u => !fetchCalls.some(c => c.indexOf(u) >= 0));
    if (miss.length) throw new Error('这些接口没被调用：' + miss.join(', '));
  });

  console.log('\n' + (failures === 0 ? '页面冒烟测试全部通过' : failures + ' 项失败'));
  process.exit(failures === 0 ? 0 : 1);
})();
