/* Drift Sentinel - rule catalogue.
   Each rule is its own <details> block, so the explanation opens directly
   underneath the rule you clicked. The previous version pushed detail into a
   single panel at the foot of the page, which meant losing your place in a
   40-row table every time you wanted to read one rule. */

let RULES = [];
let openIds = new Set();

function chipList(items, cls, emptyText){
  const list = items || [];
  if(!list.length) return `<span class="dim">${esc(emptyText)}</span>`;
  return list.map(x => `<span class="chip ${cls}">${esc(x)}</span>`).join('');
}

function ruleItem(r){
  const isOpen = openIds.has(r.id);
  const instituted = r.institutionalised
    ? `<span class="chip good" title="Added after you approved finding ${esc(r.source_finding)}">✦ you approved this</span>`
    : '';
  return `
  <details class="rule-item" data-id="${esc(r.id)}"${isOpen ? ' open' : ''}>
    <summary class="rule-sum">
      <span class="rule-chev">▸</span>
      <span class="rule-id">${esc(r.id)}</span>
      <span class="rule-name">${esc(r.name)}</span>
      <span class="rule-tags">
        ${instituted}
        <span class="type ${esc(r.rule_type)}">${esc(r.rule_type)}</span>
        <span class="sev ${esc(r.risk_severity)}">${esc(r.risk_severity)}</span>
        <span class="ai-flag ${r.ai_relevant ? 'yes' : 'no'}">${r.ai_relevant ? 'AI-relevant' : 'standard'}</span>
      </span>
    </summary>
    <div class="rule-body">
      <div class="rule-field">
        <div class="rf-label">What the rule says</div>
        <div class="rf-val quote">${esc(r.text || '—')}</div>
      </div>
      <div class="rule-field">
        <div class="rf-label">What sets it off</div>
        <div class="rf-val">${esc(r.trigger || '—')}</div>
      </div>
      <div class="detail-grid">
        <div class="d"><b>Category</b><span>${esc(r.category || '—')}</span></div>
        <div class="d"><b>Where it comes from</b><span>${esc(r.source || '—')}</span></div>
        <div class="d"><b>Source reference</b><span class="mono">${esc(r.source_ref || '—')}</span></div>
        <div class="d"><b>Rule type</b><span>${esc(r.rule_type || '—')}</span></div>
        <div class="d"><b>Attack techniques (MITRE ATLAS)</b>
          <div class="chip-row">${chipList(r.mitre_atlas, 'bad', 'not yet mapped')}</div></div>
        <div class="d"><b>AI capability primitives</b>
          <div class="chip-row">${chipList(r.capability_primitives, 'good', 'none recorded')}</div></div>
        <div class="d" style="grid-column:1/-1"><b>Keywords the engine looks for</b>
          <div class="chip-row">${chipList(r.keywords, '', 'none')}</div></div>
      </div>
    </div>
  </details>`;
}

function visibleRules(){
  const q = ($('search').value || '').toLowerCase();
  const ty = $('fType').value, sev = $('fSev').value, ai = $('fAI').value;
  return RULES.filter(r =>
    (!ty || r.rule_type === ty) &&
    (!sev || r.risk_severity === sev) &&
    (ai === '' || (ai === 'yes' ? r.ai_relevant : !r.ai_relevant)) &&
    (!q || [r.id, r.name, r.text, r.trigger, r.source, r.category, r.source_ref, r.rule_type]
            .join(' ').toLowerCase().includes(q)));
}

function render(){
  const rows = visibleRules();
  $('count').textContent = rows.length + ' of ' + RULES.length + ' rules';
  $('ruleList').innerHTML = rows.map(ruleItem).join('');
  $('ruleEmpty').style.display = rows.length ? 'none' : 'block';

  // Remember which rules are open so filtering or searching doesn't
  // silently collapse what you were reading.
  $('ruleList').querySelectorAll('.rule-item').forEach(d => {
    d.addEventListener('toggle', () => {
      const id = d.getAttribute('data-id');
      if(d.open) openIds.add(id); else openIds.delete(id);
      syncExpandLabel();
    });
  });
  syncExpandLabel();
}

function syncExpandLabel(){
  const btn = $('expandAll'); if(!btn) return;
  const rows = visibleRules();
  const allOpen = rows.length > 0 && rows.every(r => openIds.has(r.id));
  btn.textContent = allOpen ? 'Collapse all' : 'Expand all';
}

function toggleAll(){
  const rows = visibleRules();
  const allOpen = rows.length > 0 && rows.every(r => openIds.has(r.id));
  if(allOpen) rows.forEach(r => openIds.delete(r.id));
  else rows.forEach(r => openIds.add(r.id));
  render();
}

['search','fType','fSev','fAI'].forEach(id => {
  const node = $(id);
  if(!node) return;
  node.addEventListener('change', render);
  node.addEventListener('input', render);
});
if($('expandAll')) $('expandAll').addEventListener('click', toggleAll);

async function load(){
  try{
    const d = await api('/api/rules');
    RULES = d.rules || [];
    const s = await api('/api/state');
    if($('analystName')) $('analystName').textContent = s.analyst;
    const am = s.amendments || {};
    const banner = $('instBanner');
    if((am.rules || []).length){
      banner.style.display = 'flex';
      $('instTitle').textContent = 'Rules you approved · ' + (am.covered || []).length + ' gap(s) closed';
      $('instSub').textContent = am.rules.map(r => r.id + ' · ' + r.name).join('  ·  ');
    }else{
      banner.style.display = 'none';
    }
    render();
  }catch(e){
    toast('Could not load the rulebook: ' + e.message);
  }
}
load();
