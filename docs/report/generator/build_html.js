'use strict';
const fs = require('fs');
const path = require('path');
const { meta, blocks, D } = require('./content.js');

const OUT = process.argv[2] || path.join(__dirname, '..', 'aegisweave-report.html');
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const inline = s => esc(s)
  .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
  .replace(/`([^`]+)`/g, '<code>$1</code>')
  .replace(/(https?:\/\/[^\s<)]+[^\s<).,;])/g, '<a href="$1">$1</a>');
const slug = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const DECISIONS = new Set(['normal', 'suspicious', 'anomalous', 'malicious', 'unknown']);

const toc = [];
let html = '', tableNo = 0, open = false;
for (const b of blocks) {
  switch (b.type) {
    case 'frontmatter': case 'toc': break;
    case 'h1': {
      const m = b.text.match(/^(\d+|Appendix [A-D])\s+(.*)$/);
      const label = m ? (/^\d/.test(m[1]) ? `Chapter ${m[1]}` : m[1]) : null;
      const title = m ? m[2] : b.text;
      const id = slug(b.text);
      toc.push({ id, title: m ? `${/^\d/.test(m[1]) ? m[1] : m[1].replace('Appendix ', '')} ${title}` : title, level: 1 });
      if (open) html += '</section>';
      html += `<section class="chapter" aria-labelledby="${id}">${label ? `<p class="eyebrow">${esc(label)}</p>` : ''}<h2 class="chapter-title" id="${id}">${esc(title)}</h2>`;
      open = true;
      break;
    }
    case 'h2': {
      const id = slug(b.text);
      toc.push({ id, title: b.text.replace(/^(\d+\.\d+)\s+/, '$1 '), level: 2 });
      html += `<h3 id="${id}">${esc(b.text.replace(/^(\d+\.\d+)\s+/, ''))}<span class="num">${esc((b.text.match(/^\d+\.\d+/) || [''])[0])}</span></h3>`;
      break;
    }
    case 'h3': html += `<h4>${esc(b.text)}</h4>`; break;
    case 'p': html += `<p>${inline(b.text)}</p>`; break;
    case 'bullets': html += `<ul>${b.items.map(i => `<li>${inline(i)}</li>`).join('')}</ul>`; break;
    case 'numbers': html += `<ol>${b.items.map(i => `<li>${inline(i)}</li>`).join('')}</ol>`; break;
    case 'table': {
      tableNo += 1;
      const cell = c => DECISIONS.has(String(c)) ? `<span class="chip chip-${c}">${esc(c)}</span>` : inline(c);
      const numeric = b.rows.every(r => r.slice(1).every(c => /^[\d.,≈–%\s—ms;→p→a-z]*$/i.test(String(c)) && /\d/.test(String(c)))) && b.header.length > 2;
      html += `<figure class="table-figure"><figcaption><span class="fig-label">Table ${tableNo}</span>${inline(b.caption)}</figcaption>`
        + `<div class="table-wrap" tabindex="0" role="region" aria-label="Table ${tableNo}"><table class="${numeric ? 'numeric' : ''}">`
        + `<thead><tr>${b.header.map(h => `<th scope="col">${inline(h)}</th>`).join('')}</tr></thead>`
        + `<tbody>${b.rows.map(r => `<tr>${r.map((c, i) => i === 0 ? `<th scope="row">${cell(c)}</th>` : `<td>${cell(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
        + (b.note ? `<p class="table-note">${inline(b.note)}</p>` : '') + '</figure>';
      break;
    }
    case 'code': {
      const figure = /^Figure/.test(b.caption);
      const [label, rest] = figure ? [b.caption.split(':')[0], b.caption.split(':').slice(1).join(':').trim()] : ['', b.caption];
      html += `<figure class="code-figure${figure ? ' diagram' : ''}"><figcaption>${label ? `<span class="fig-label">${esc(label)}</span>` : ''}${esc(rest)}</figcaption>`
        + `<div class="code-wrap" tabindex="0" role="region" aria-label="${esc(b.caption)}"><pre><code>${esc(b.lines.join('\n'))}</code></pre></div></figure>`;
      break;
    }
    case 'callout': html += `<aside class="note"><p>${inline(b.text)}</p></aside>`; break;
    case 'references': html += `<ol class="references">${b.items.map((r, i) => `<li id="ref-${i + 1}"><span class="ref-num">[${i + 1}]</span><span>${inline(r)}</span></li>`).join('')}</ol>`; break;
    default: throw new Error(`Unknown block ${b.type}`);
  }
}
if (open) html += '</section>';
// Link in-text citations like [1] or [1], [2] to the reference list.
html = html.replace(/\[(\d{1,2})\](?![^<]*<\/span>)/g, (m, num) => (Number(num) <= 11 ? `<a class="cite" href="#ref-${num}">[${num}]</a>` : m));

const A = D.iot23.experiments.A_temporal_blocks, B = D.iot23.experiments.B_open_set_withheld_attack_attempt, C = D.iot23.experiments.C_leave_capture_out;
const pct = x => `${(x * 100).toFixed(1)}%`;
const bTotal = Object.values(B.decision_counts.attack_attempt).reduce((s, v) => s + v, 0);
const findings = [
  [A.unseen_binary.f1.toFixed(3), 'F1 on real IoT-23 flow vectors never seen in training', `${A.binary.f1.toFixed(3)} on all test rows`],
  [`${B.decision_counts.attack_attempt.anomalous} / ${bTotal}`, 'withheld real attack flows reported as anomalous', 'no invented attack type'],
  [pct(C.binary.false_positive_rate), 'false-positive rate on an unseen network', `${pct(C.decisions.benign_alert_rate)} of benign flows alerted`],
  [D.live_replay.after_fix.events.toLocaleString('en-US'), 'real flows replayed live through the running system', 'offline results reproduced'],
];

const tocHtml = toc.map(t => `<li class="lvl-${t.level}"><a href="#${t.id}">${esc(t.title)}</a></li>`).join('');
const page = `<title>AegisWeave</title>
<meta name="description" content="${esc(meta.subtitle)}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans+Condensed:wght@500;600&family=IBM+Plex+Sans:wght@400;600&family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,600;1,8..60,400&display=swap">
<style>
:root {
  --ground: #f4f6f8; --surface: #ffffff; --ink: #17212c; --ink-soft: #37424f; --muted: #5d6977; --rule: #d3dae1; --rule-soft: #e6ebf0;
  --accent: #1e4e79; --accent-soft: #e4edf6; --code-ground: #eef2f6; --note-ink: #7a4d0c; --note-ground: #fbf2e1;
  --d-normal: #0d7f70; --d-suspicious: #a86a10; --d-anomalous: #3656c9; --d-malicious: #b3322a; --d-unknown: #6d45b0;
  --serif: "Source Serif 4", "Iowan Old Style", Georgia, serif;
  --sans: "IBM Plex Sans", "Segoe UI", Roboto, Arial, sans-serif;
  --cond: "IBM Plex Sans Condensed", "Arial Narrow", "Segoe UI", sans-serif;
  --mono: "IBM Plex Mono", Consolas, "SFMono-Regular", monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground: #0c1218; --surface: #121a22; --ink: #e3e9ef; --ink-soft: #c2ccd6; --muted: #8e9bab; --rule: #2a3641; --rule-soft: #1e2831;
    --accent: #8fbbe9; --accent-soft: #182635; --code-ground: #0f171f; --note-ink: #eec27c; --note-ground: #2a2116;
    --d-normal: #7be1d0; --d-suspicious: #f6bc73; --d-anomalous: #93aefa; --d-malicious: #ff8791; --d-unknown: #bda3ee;
  }
}
:root[data-theme="dark"] {
  --ground: #0c1218; --surface: #121a22; --ink: #e3e9ef; --ink-soft: #c2ccd6; --muted: #8e9bab; --rule: #2a3641; --rule-soft: #1e2831;
  --accent: #8fbbe9; --accent-soft: #182635; --code-ground: #0f171f; --note-ink: #eec27c; --note-ground: #2a2116;
  --d-normal: #7be1d0; --d-suspicious: #f6bc73; --d-anomalous: #93aefa; --d-malicious: #ff8791; --d-unknown: #bda3ee;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 24px; }
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
body { margin: 0; background: var(--ground); color: var(--ink); font: 400 17.5px/1.68 var(--serif); -webkit-font-smoothing: antialiased; }
a { color: var(--accent); text-underline-offset: 3px; text-decoration-thickness: 1px; overflow-wrap: anywhere; }
.doc { overflow-wrap: break-word; }
a:focus-visible, .table-wrap:focus-visible, .code-wrap:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; border-radius: 3px; }
.layout { display: grid; grid-template-columns: 236px minmax(0, 1fr); gap: 64px; max-width: 1220px; margin: 0 auto; padding: 56px 40px 96px; }
.rail { position: sticky; top: 32px; align-self: start; max-height: calc(100vh - 64px); overflow-y: auto; padding-right: 8px; }
.rail-title, .eyebrow, .fig-label, .finding-note, .meta-label { font-family: var(--mono); text-transform: uppercase; letter-spacing: .09em; font-size: .7rem; }
.rail-title { color: var(--muted); margin: 0 0 14px; }
.toc { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; font-family: var(--sans); }
.toc a { display: block; text-decoration: none; color: var(--ink-soft); padding: 3px 0 3px 12px; border-left: 2px solid transparent; line-height: 1.35; }
.toc .lvl-1 a { font-size: .86rem; font-weight: 600; margin-top: 8px; }
.toc .lvl-2 a { font-size: .78rem; color: var(--muted); padding-left: 22px; }
.toc a:hover { color: var(--accent); }
.toc a.active { color: var(--accent); border-left-color: var(--accent); }
.mobile-toc { display: none; }
main { min-width: 0; }
.doc { background: var(--surface); border: 1px solid var(--rule-soft); border-radius: 4px; padding: 64px 72px 72px; }
.masthead { display: grid; gap: 18px; padding-bottom: 36px; border-bottom: 1px solid var(--rule); }
.masthead .eyebrow { color: var(--accent); margin: 0; }
.masthead h1 { font: 600 clamp(2.1rem, 4vw, 3rem)/1.08 var(--cond); letter-spacing: -.01em; margin: 0; text-wrap: balance; max-width: 22ch; }
.masthead .subtitle { font-size: 1.12rem; color: var(--ink-soft); margin: 0; max-width: 60ch; text-wrap: pretty; }
.meta { display: flex; flex-wrap: wrap; gap: 10px 28px; margin: 4px 0 0; padding: 0; list-style: none; font-family: var(--sans); font-size: .86rem; color: var(--muted); }
.meta .placeholder { color: var(--note-ink); }
.meta-label { display: block; color: var(--muted); margin-bottom: 2px; }
.findings { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0; margin: 36px 0 8px; border-top: 1px solid var(--rule); border-bottom: 1px solid var(--rule); }
.finding { padding: 18px 18px 18px 0; display: grid; gap: 6px; align-content: start; }
.finding + .finding { padding-left: 18px; border-left: 1px solid var(--rule-soft); }
.finding-value { font: 500 1.7rem/1 var(--mono); color: var(--ink); font-variant-numeric: tabular-nums; letter-spacing: -.02em; }
.finding-text { font: 400 .86rem/1.4 var(--sans); color: var(--ink-soft); }
.finding-note { color: var(--muted); font-size: .64rem; }
.chapter { margin-top: 64px; }
.chapter > .eyebrow { color: var(--accent); margin: 0 0 6px; }
.chapter-title { font: 600 1.95rem/1.15 var(--cond); margin: 0 0 22px; text-wrap: balance; }
h3 { font: 600 1.28rem/1.3 var(--cond); margin: 40px 0 12px; display: flex; gap: 12px; align-items: baseline; flex-direction: row-reverse; justify-content: flex-end; text-wrap: balance; }
h3 .num { font: 500 .8rem/1 var(--mono); color: var(--muted); }
h4 { font: 600 1.05rem/1.3 var(--sans); margin: 28px 0 8px; }
p, ul, ol { max-width: 68ch; }
p { margin: 0 0 16px; text-wrap: pretty; }
ul, ol { margin: 0 0 18px; padding-left: 1.35em; display: grid; gap: 8px; }
li::marker { color: var(--muted); font-family: var(--sans); }
strong { font-weight: 600; color: var(--ink); }
code { font: 500 .84em/1 var(--mono); background: var(--code-ground); padding: .12em .35em; border-radius: 3px; }
.cite { text-decoration: none; font-family: var(--sans); font-size: .85em; }
figure { margin: 26px 0 30px; }
figcaption { font: 400 .9rem/1.45 var(--sans); color: var(--ink-soft); margin-bottom: 10px; display: flex; flex-wrap: wrap; gap: 4px 10px; align-items: baseline; }
.fig-label { color: var(--accent); }
.table-wrap, .code-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font: 400 .86rem/1.45 var(--sans); font-variant-numeric: tabular-nums; }
thead th { text-align: left; font-weight: 600; color: var(--ink); background: var(--accent-soft); padding: 9px 12px; border-bottom: 1px solid var(--rule); white-space: nowrap; }
tbody th, tbody td { text-align: left; vertical-align: top; padding: 8px 12px; border-bottom: 1px solid var(--rule-soft); }
tbody th { font-weight: 600; color: var(--ink); }
table.numeric td { white-space: nowrap; }
tbody tr:last-child th, tbody tr:last-child td { border-bottom: 1px solid var(--rule); }
.table-note { font: italic 400 .84rem/1.5 var(--serif); color: var(--muted); margin: 8px 0 0; max-width: none; }
.chip { display: inline-block; font: 500 .74rem/1 var(--mono); padding: 4px 7px 3px; border-radius: 3px; color: var(--chip); background: color-mix(in srgb, var(--chip) 13%, transparent); border: 1px solid color-mix(in srgb, var(--chip) 35%, transparent); }
.chip-normal { --chip: var(--d-normal); } .chip-suspicious { --chip: var(--d-suspicious); } .chip-anomalous { --chip: var(--d-anomalous); }
.chip-malicious { --chip: var(--d-malicious); } .chip-unknown { --chip: var(--d-unknown); }
pre { margin: 0; padding: 16px 18px; background: var(--code-ground); border: 1px solid var(--rule-soft); border-radius: 4px; font: 400 .8rem/1.6 var(--mono); color: var(--ink); tab-size: 4; }
pre code { background: none; padding: 0; font: inherit; }
.diagram pre { font-size: .76rem; line-height: 1.55; }
.note { background: var(--note-ground); color: var(--note-ink); padding: 12px 16px; border-radius: 4px; margin: 0 0 20px; max-width: 68ch; font-family: var(--sans); font-size: .9rem; }
.note p { margin: 0; }
.references { list-style: none; padding: 0; gap: 12px; font-size: .95rem; }
.references li { display: grid; grid-template-columns: 3.2em minmax(0, 1fr); overflow-wrap: anywhere; }
.ref-num { font-family: var(--mono); font-size: .85em; color: var(--muted); padding-top: .15em; }
.references li:target { background: var(--accent-soft); border-radius: 3px; }
.colophon { margin-top: 56px; padding-top: 20px; border-top: 1px solid var(--rule); font: 400 .8rem/1.5 var(--sans); color: var(--muted); max-width: none; }
@media (max-width: 1080px) {
  .layout { grid-template-columns: minmax(0, 1fr); padding: 24px 16px 64px; gap: 20px; }
  .rail { display: none; }
  .mobile-toc { display: block; background: var(--surface); border: 1px solid var(--rule-soft); border-radius: 4px; padding: 12px 18px; }
  .mobile-toc summary { cursor: pointer; font: 600 .95rem/1.4 var(--sans); color: var(--ink); }
  .mobile-toc .toc { margin-top: 10px; }
  .doc { padding: 36px 22px 48px; }
  .findings { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .finding:nth-child(3) { padding-left: 0; border-left: 0; }
  .finding:nth-child(n+3) { border-top: 1px solid var(--rule-soft); }
}
@media (max-width: 520px) {
  body { font-size: 16.5px; }
  .findings { grid-template-columns: minmax(0, 1fr); }
  .finding, .finding + .finding { padding: 14px 0; border-left: 0; }
  .finding + .finding { border-top: 1px solid var(--rule-soft); }
}
@media print {
  .rail, .mobile-toc { display: none; }
  .layout { display: block; padding: 0; }
  .doc { border: 0; padding: 0; }
  .chapter { break-before: page; }
}
</style>
<div class="layout">
  <nav class="rail" aria-label="Report contents"><p class="rail-title">Contents</p><ol class="toc">${tocHtml}</ol></nav>
  <main>
    <details class="mobile-toc"><summary>Contents</summary><ol class="toc">${tocHtml}</ol></details>
    <article class="doc">
      <header class="masthead">
        <p class="eyebrow">Project report · ${esc(meta.date)}</p>
        <h1>${esc(meta.title)}</h1>
        <p class="subtitle">${esc(meta.subtitle)}</p>
        <ul class="meta">
          <li><span class="meta-label">Submitted by</span><span class="placeholder">${esc(meta.placeholders[0])}</span></li>
          <li><span class="meta-label">Programme</span><span class="placeholder">${esc(meta.placeholders[2])}</span></li>
          <li><span class="meta-label">Institution</span><span class="placeholder">${esc(meta.placeholders[3])}</span></li>
          <li><span class="meta-label">Guide</span><span class="placeholder">${esc(meta.placeholders[4])}</span></li>
        </ul>
        <div class="findings" role="list" aria-label="Findings at a glance">
          ${findings.map(([value, text, note]) => `<div class="finding" role="listitem"><span class="finding-value">${esc(value)}</span><span class="finding-text">${esc(text)}</span><span class="finding-note">${esc(note)}</span></div>`).join('')}
        </div>
      </header>
      ${html}
      <p class="colophon">Every figure in this report is generated from the project's committed result files (experiments/results), the live-replay databases and the verification report. Tests: ${D.tests.collected} automated tests and ${D.verification.checks} live verification checks, all passing. Latest commit: ${esc(D.git[0].slice(0, 7))}.</p>
    </article>
  </main>
</div>
<script>
(() => {
  const links = [...document.querySelectorAll('.rail .toc a')];
  const byId = new Map(links.map(a => [a.getAttribute('href').slice(1), a]));
  const targets = [...byId.keys()].map(id => document.getElementById(id)).filter(Boolean);
  if (!('IntersectionObserver' in window) || !targets.length) return;
  const visible = new Map();
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) visible.set(entry.target.id, entry.isIntersecting ? entry.boundingClientRect.top : null);
    const current = targets.find(t => visible.get(t.id) !== null && visible.get(t.id) !== undefined) || null;
    if (!current) return;
    links.forEach(a => a.classList.toggle('active', a === byId.get(current.id)));
    byId.get(current.id)?.scrollIntoView({ block: 'nearest' });
  }, { rootMargin: '0px 0px -70% 0px' });
  targets.forEach(t => observer.observe(t));
  document.querySelectorAll('.mobile-toc a').forEach(a => a.addEventListener('click', () => a.closest('details').removeAttribute('open')));
})();
</script>
`;
fs.writeFileSync(OUT, page, 'utf8');
console.log(`wrote ${OUT} (${Buffer.byteLength(page)} bytes, ${tableNo} tables, ${toc.length} contents entries)`);
