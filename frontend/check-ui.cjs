// Dependency-free regressions for API-driven rendering and refresh races.
// Run: node frontend/check-ui.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const elements = new Map();
const listeners = new Map();
function element(selector = '') {
  if (!elements.has(selector)) elements.set(selector, {
    id: selector.slice(1), innerHTML: '', textContent: '', value: '', hidden: true,
    open: false, disabled: false, children: [],
    addEventListener(type, callback) { listeners.set(`${selector}:${type}`, callback); },
    setAttribute() {}, classList: {remove() {}, toggle() {}},
    focus() {}, setSelectionRange() {}, append(child) { this.children.push(child); },
    showModal() { this.open = true; }, close() { this.open = false; }, remove() {},
  });
  return elements.get(selector);
}
const context = vm.createContext({
  document: {querySelector: element, querySelectorAll: () => [], addEventListener() {},
    activeElement: {tagName:'BODY'}, hidden:false, body:{style:{}}, createElement: () => element(`created-${elements.size}`)},
  window: {addEventListener() {}}, location:{hash:'#overview'},
  sessionStorage:{getItem() {return null;}, setItem() {}, removeItem() {}},
  setTimeout() {return 0;}, clearTimeout() {}, setInterval() {}, AbortController,
  URL, Blob, console, fetch: async () => ({ok:true,json:async()=>({})}),
});
const source = fs.readFileSync(path.join(__dirname,'app.js'),'utf8').replace(/initialize\(\);\s*$/, '');
vm.runInContext(source, context, {filename:'app.js'});
const run = code => vm.runInContext(code, context);
const response = data => ({ok:true,json:async()=>data});

(async () => {
  run(`state.data={models:{items:[{version:'test',metrics:{roc_auc:.9726,pr_auc:.9674},simulated_training:true}]}}`);
  assert.match(run('analyticsView()'), /<dt>ROC-AUC<\/dt><dd>0\.973<\/dd>/);
  assert.match(run('analyticsView()'), /<dt>PR-AUC<\/dt><dd>0\.967<\/dd>/);
  assert.equal(run('decimal(null)'), '—');

  run(`state.data={drift:{status:'warming_up',window_size:100,reference_count:2,current_count:0}}`);
  assert.match(run('behaviorView()'), /Current observations<\/dt><dd>0 \/ 100/);
  assert.match(run('behaviorView()'), /Reference observations<\/dt><dd>2 \/ 100/);

  run(`state.role='unknown';state.authenticated=true;state.data={policies:{min_risk:70,min_confidence:.8,max_actions_per_minute:5,ttl_seconds:300,allowlist:[]}}`);
  assert.match(run('policyForm()'), /name="max_actions_per_minute" type="number" min="1" max="60"/);
  assert.match(run('policyForm()'), /type="submit" disabled/);
  assert.match(run(`empty('Empty','No data',true)`), /data-action="replay" disabled/);
  run(`state.role='admin';state.data={overview:{health:{status:'degraded'}}};renderGlobal()`);
  assert.match(element('#connection-status').innerHTML, /Engine degraded/);

  const urls = [];
  context.fetch = async url => { urls.push(url); return response(url==='/api/overview'?{health:{status:'healthy'}}:{items:[]}); };
  run(`state.page='system';state.role='viewer';state.token='viewer-test';state.authenticated=true;state.data.audit={items:[{action:'old.admin.audit'}]};state.errors.audit='Old error'`);
  await run('refresh(true)');
  assert(!urls.includes('/api/audit'), 'Viewer refresh must not request restricted audit endpoint');
  assert.equal(run('state.data.audit'), undefined, 'Old role audit cache must be cleared');
  assert.equal(run('state.errors.audit'), undefined);
  assert.match(run('systemView()'), /audit trail requires the analyst or admin role/);

  // A slower prior search must not overwrite a newer filter or lose its refresh.
  let release;
  context.fetch = async url => {
    if (url.includes('/api/events') && url.includes('search=first')) {
      return new Promise(resolve => { release = () => resolve(response({items:[{event_id:'obsolete-result'}]})); });
    }
    return response(url.includes('/api/events')?{items:[{event_id:'current-result',source:'192.0.2.2',destination:'192.0.2.3'}]}:{health:{status:'healthy'}});
  };
  run(`state.page='events';state.search='first';state.decision='';state.data={};state.errors={}`);
  const pending = run('refresh(true)');
  run(`state.search='second'`);
  await run('refresh(true)');
  release();
  await pending;
  assert.equal(run('state.data.events.items[0].event_id'), 'current-result');
  assert(!element('#content').innerHTML.includes('obsolete-result'));

  // Justifications entered over multiple lines conform to printable API reasons.
  let submitted;
  context.fetch = async (url,options) => {
    if (url==='/api/responses' && options.method==='POST') {
      submitted=JSON.parse(options.body);
      return response({status:'denied',audit:[{reason:'Emergency kill switch is enabled'}]});
    }
    return response(url==='/api/overview'?{health:{status:'healthy'}}:{items:[]});
  };
  element('#action-reason').value='Observed repeated failures.\n\tAnalyst requests review.';
  element('#action-ttl').value='300';
  run(`state.page='overview';state.role='analyst';state.action={kind:'request',id:'test-event',responseAction:'notify'}`);
  context.fakeEvent={preventDefault(){}};
  await run('submitAction(fakeEvent)');
  assert.equal(submitted.reason,'Observed repeated failures. Analyst requests review.');
  assert.match(element('#toasts').children.at(-1).textContent,/Emergency kill switch is enabled/);

  // User-supplied metadata remains escaped; attribution stays separate from raw class.
  run(`state.search='';state.decision=''`);
  assert.match(run(`eventTable([{event_id:'safe',source:'<script>alert(1)</script>',attribution:{label:'unknown_behavior'},prediction:{class:'dos'},fusion:{decision:'anomalous'}}])`), /&lt;script&gt;/);
  assert.match(run(`eventTable([{event_id:'safe',attribution:{label:'unknown_behavior'},prediction:{class:'dos'},fusion:{decision:'anomalous'}}])`), /Unknown Behavior/);
  assert.match(run(`trendChart([{timestamp:'2026-09-14T00:00:00Z',anomalous:3}])`), /Anomalous: 3/);

  // Replayed research captures can be years old; relative times stay readable.
  const ago = seconds => new Date(Date.now() - seconds * 1000).toISOString();
  assert.equal(run(`relative('${ago(7200)}')`), '2h ago');
  assert.equal(run(`relative('${ago(3 * 86400)}')`), '3d ago');
  assert.equal(run(`relative('${ago(8 * 31557600 + 100)}')`), '8y ago');

  // Real-data artifacts show their own escaped provenance warning and cross-capture evidence.
  run(`state.data={models:{items:[{version:'1.1.0',simulated_training:false,metrics:{},provenance:{warning:'<b>lab</b> captures'},evaluation:{protocol:'temporal_blocks',leave_capture_out_binary:{f1:.4321,false_positive_rate:.05}}}]}}`);
  const realModel = run('analyticsView()');
  assert.match(realModel, /&lt;b&gt;lab&lt;\/b&gt; captures/);
  assert.match(realModel, /Cross-capture F1 \(held-out captures\)<\/dt><dd>0\.432/);
  run(`state.data={models:{items:[{version:'1.1.0',simulated_training:false,metrics:{},evaluation:{protocol:'temporal_blocks',leave_capture_out_binary:{status:'not_evaluable'}}}]}}`);
  assert.match(run('analyticsView()'), /Cross-capture F1 \(held-out captures\)<\/dt><dd>Not evaluable/);
  run(`state.data={models:{items:[{version:'1.1.0',simulated_training:false,metrics:{f1:.8771,false_positive_rate:.1},evaluation:{protocol:'leave_capture_out',held_out_captures:['capture-a']}}]}}`);
  assert.match(run('analyticsView()'), /Cross-capture F1 \(held-out captures\)<\/dt><dd>0\.877/);
  assert.match(run('analyticsView()'), /Held-out captures<\/dt><dd>capture-a/);
  console.log('Frontend regressions passed: metric precision, drift counts, role controls, health, stale refresh, response reasons, safe rendering.');
})().catch(error => { console.error(error); process.exitCode=1; });
