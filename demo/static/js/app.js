/* Drift Sentinel - shared app JS */
const $ = (id) => document.getElementById(id);

function toast(msg){
  const t = $('toast'); if(!t) return;
  t.textContent = msg; t.classList.add('show');
  clearTimeout(t._h); t._h = setTimeout(()=>t.classList.remove('show'), 2600);
}

async function api(path, opts = {}){
  const headers = opts.body ? {'Content-Type':'application/json'} : (opts.headers||{});
  const r = await fetch(path, {...opts, headers});
  const json = await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(json.error || ('HTTP ' + r.status));
  return json;
}

function esc(s){ return (s==null?'':String(s)).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function setActiveNav(){
  const page = location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-link').forEach(a=>{
    a.classList.toggle('active', a.getAttribute('href') === page);
  });
}

async function refreshStatusPill(){
  const pill = $('statusPill'); if(!pill) return;
  try{
    const s = await api('/api/state');
    if(s.running){
      pill.textContent='● Running'; pill.className='badge-status busy';
    }else if(s.status){
      const map = {
        awaiting_human_approval: 'Awaiting approval',
        under_review: 'Under review · ' + (s.reviewed||0) + '/' + (s.total||0) + ' decided',
        review_complete: 'Review complete · ' + (s.total||0) + ' findings decided',
        aborted: 'Run aborted',
        ready_no_findings: 'Ready',
      };
      pill.textContent = '● ' + (map[s.status] || s.status);
      pill.className = 'badge-status ' + (s.status==='aborted' ? 'offline' : 'online');
    } else { pill.textContent='● Ready'; pill.className='badge-status online'; }
  }catch(e){ pill.textContent='● Offline'; pill.className='badge-status offline'; }
}

function fmt(n){ if(n==null) return '—'; return Number(n).toLocaleString(); }
function timeAgo(iso){ if(!iso) return '—'; const s=Math.max(0,(Date.now()-new Date(iso).getTime())/1000|0); if(s<60) return s+'s ago'; const m=s/60|0; if(m<60) return m+'m ago'; return (m/60|0)+'h ago'; }

/* ---------- Chart helpers (pure CSS/SVG, no deps) ---------- */
function renderBars(el, data, color='var(--accent)'){
  const host = $(el); if(!host) return;
  const vals = Object.values(data);
  const max = Math.max(...vals, 1);
  host.innerHTML = Object.entries(data).map(([k,v])=>`
    <div class="bar" title="${esc(k)}: ${v}">
      <span class="v">${v}</span>
      <div class="b" style="height:${Math.max(3,(v/max)*100)}%;background:${color}"></div>
      <span class="lbl">${esc(k)}</span>
    </div>`).join('');
}

function renderDonut(el, parts, colors, center=null){
  const host = $(el); if(!host) return;
  const total = Object.values(parts).reduce((a,b)=>a+b,0) || 1;
  let acc = 0;
  const segs = Object.entries(parts).filter(([,v])=>v>0).map(([k,v])=>{
    const pct = (v/total)*360;
    const seg = `<circle cx="60" cy="60" r="42" fill="none" stroke="${colors[k]||'var(--accent)'}" stroke-width="16" stroke-dasharray="${pct} ${360-pct}" stroke-dashoffset="${-acc}" transform="rotate(-90 60 60)"/>`;
    acc += pct; return seg;
  }).join('');
  host.innerHTML = `<div style="position:relative;width:120px;height:120px">
    <svg viewBox="0 0 120 120">${segs}</svg>
    <div style="position:absolute;inset:0;display:grid;place-items:center;font-size:16px;font-weight:800">${center??total}</div>
  </div>`;
}

function renderHeatmap(el, matrix, covered=[]){
  /* Evasion heatmap, rebuilt as a CSS grid rather than a hand-laid-out SVG.
     The SVG version rotated its column labels 60 degrees and truncated them to
     fit a 36px column pitch, which made the axis effectively unreadable and
     forced a tooltip hover to identify any column. A grid lets the browser do
     the layout, keeps the labels legible, and keeps the row labels pinned when
     the table scrolls sideways.

     Colour runs on the brand orange - drift - rather than an unrelated blue,
     and intensity is never the only signal: every cell also carries its count
     as a number, so the chart is readable without relying on colour. */
  const host = $(el); if(!host) return;
  if(!matrix || !matrix.rows || !matrix.rows.length){
    host.innerHTML = '<div class="empty">Run a check to populate this.</div>'; return;
  }
  const cats = matrix.categories || [];
  const sevRank = {critical:0, high:1, medium:2, low:3};
  const sevFill = {critical:'#C4462A', high:'#D85A30', medium:'#F2A623', low:'#7BAFA2', default:'#F2A623'};
  const rows = matrix.rows.slice().sort((a,b)=>
    (sevRank[b.severity]!=null?sevRank[b.severity]:2) - (sevRank[a.severity]!=null?sevRank[a.severity]:2) ||
    b.total - a.total);
  const max = Math.max(1, ...rows.map(r=>Math.max(0, ...r.cells)));

  const cellStyle = (v) => {
    if(v<=0) return 'background:var(--panel-3);color:var(--dim)';
    const t = v/max;
    // 0.18 -> 1.0 alpha on the brand orange; white text once dark enough to need it
    const a = (0.18 + 0.82*t).toFixed(2);
    const fg = t > 0.55 ? '#fff' : 'var(--brand-deep)';
    return `background:rgba(216,90,48,${a});color:${fg}`;
  };

  let html = '<div class="hm2-scroll"><div class="hm2-grid" style="grid-template-columns:auto repeat('
           + cats.length + ', 34px) 34px">';

  // header row
  html += '<div></div>';
  cats.forEach(c=>{
    html += `<div class="hm2-colhead" title="${esc(c)}">${esc(c)}</div>`;
  });
  html += '<div class="hm2-colhead" title="Total rules evaded"><b>Total</b></div>';

  // body
  rows.forEach(r=>{
    const isCovered = covered.includes(r.id);
    const sv = r.severity || 'medium';
    const dot = sevFill[sv] || sevFill.default;
    html += `<div class="hm2-rowlabel" title="${esc(r.id)} · ${esc(r.name)} · severity ${esc(sv)}">
        <span class="hm2-sevdot" style="background:${dot}"></span>
        <span class="hm2-rowid" style="color:${isCovered?'var(--good)':'var(--accent)'}">${esc(r.id)}</span>
        <span class="hm2-rowname">${esc(r.name)}</span>
        ${isCovered?'<span title="You approved a rule that closes this" style="color:var(--good);font-weight:800">✦</span>':''}
      </div>`;
    r.cells.forEach((v,ci)=>{
      const label = v>0
        ? `${r.id} evades ${v} ${esc(cats[ci])} rule(s)`
        : `${r.id} evades nothing in ${esc(cats[ci])}`;
      html += `<div class="hm2-cell" style="${cellStyle(v)}" title="${esc(label)}">${v>0?v:'·'}</div>`;
    });
    html += `<div class="hm2-total ${r.total>0?'on':''}" title="${esc(r.id)} evades ${r.total} rule(s) in total">${r.total}</div>`;
  });
  html += '</div></div>';

  // legend
  const swatches = [0,0.25,0.5,0.75,1].map(t=>{
    const a=(0.18+0.82*t).toFixed(2);
    return `<span class="hm2-swatch" style="background:${t===0?'var(--panel-3)':'rgba(216,90,48,'+a+')'}"></span>`;
  }).join('');
  html += `<div class="hm2-legend">
      <span class="hm2-scale">Fewer rules evaded ${swatches} more</span>
      <span class="hm2-scale"><span class="hm2-covered-key"></span> ✦ marks a typology you have already closed</span>
      <span>Each cell shows how many rules in that category this typology got past.</span>
    </div>`;

  host.innerHTML = `<div class="hm2-wrap">${html}</div>`;
}

function renderLine(el, labels, values, color='var(--accent)', h=140){
  const host = $(el); if(!host) return;
  if(!values.length){ host.innerHTML='<div class="empty">no series</div>'; return; }
  const W=560, H=h, PAD=22;
  const min=Math.min(...values), max=Math.max(...values);
  const span=(max-min)||1;
  const pts = values.map((v,i)=>[
    PAD + (W-2*PAD)*i/Math.max(1,values.length-1),
    H-PAD - ((v-min)/span)*(H-2*PAD)
  ]);
  const line = pts.map((p,i)=>`${i?'L':'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
  const dots = pts.map(p=>`<circle cx="${p[0]}" cy="${p[1]}" r="3.2" fill="${color}"/>`).join('');
  const grid = [0,0.25,0.5,0.75,1].map(f=>{
    const y = H-PAD-f*(H-2*PAD);
    return `<line x1="${PAD}" y1="${y}" x2="${W-PAD}" y2="${y}" stroke="var(--border)" stroke-width="1"/>`;
  }).join('');
  host.innerHTML = `<svg class="trend-svg" viewBox="0 0 ${W} ${H}" style="height:${h}px">
    ${grid}<path d="${line}" fill="none" stroke="${color}" stroke-width="2.5"/>${dots}
  </svg><div class="dot-legend">${labels.map((l,i)=>`<span class="li"><span class="sw" style="background:${color}"></span>${esc(l)}</span>`).join('')}</div>`;
}

/* Forecast chart: actuals (history) + prediction line with confidence band.
   `trend` comes from /api/forecast: {history, forecast, values, labels, low, high}. */
function renderForecast(el, trend, h=150){
  const host = $(el); if(!host) return;
  if(!trend || !(trend.values||[]).length){ host.innerHTML='<div class="empty">no forecast series</div>'; return; }
  const W=560, H=h, PAD=22;
  const values = trend.values;
  const lows = trend.low||[], highs = trend.high||[];
  const lo = Math.min(...values, ...lows.filter(v=>v!=null));
  const hi = Math.max(...values, ...highs.filter(v=>v!=null));
  const span = (hi-lo)||1;
  const X = (i) => PAD + (W-2*PAD)*i/Math.max(1,values.length-1);
  const Y = (v) => H-PAD - ((v-lo)/span)*(H-2*PAD);
  const nHist = (trend.history||[]).length;
  const grid = [0,0.25,0.5,0.75,1].map(f=>{
    const y = H-PAD-f*(H-2*PAD);
    return `<line x1="${PAD}" y1="${y}" x2="${W-PAD}" y2="${y}" stroke="var(--border)" stroke-width="1"/>`;
  }).join('');
  let band = '';
  const bandPts = lows.map((v,i)=> v!=null ? `${i?'L':'M'}${X(i).toFixed(1)},${Y(v).toFixed(1)}` : '').filter(Boolean);
  const bandTop = highs.map((v,i)=> v!=null ? `${i?'L':'M'}${X(i).toFixed(1)},${Y(v).toFixed(1)}` : '').filter(Boolean);
  if(bandPts.length){
    band = `<polygon points="${values.map((v,i)=> v!=null?`${X(i).toFixed(1)},${Y((lows[i]??v)).toFixed(1)}`:'').filter(Boolean).join(' ')} ` +
           `${values.map((v,i)=> v!=null?`${X(i).toFixed(1)},${Y((highs[i]??v)).toFixed(1)}`:'').filter(Boolean).reverse().join(' ')}" fill="var(--accent-soft)" stroke="none"/>`;
  }
  const histPts = values.slice(0, nHist).map((v,i)=>`${i?'L':'M'}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(' ');
  const fcPts = values.slice(nHist).map((v,i)=>`${i?'L':'M'}${X(i+nHist).toFixed(1)},${Y(v).toFixed(1)}`).join(' ');
  const histDots = values.slice(0, nHist).map((v,i)=>`<circle cx="${X(i).toFixed(1)}" cy="${Y(v).toFixed(1)}" r="3" fill="var(--accent)"/>`).join('');
  const fcDots = values.slice(nHist).map((v,i)=>`<circle cx="${X(i+nHist).toFixed(1)}" cy="${Y(v).toFixed(1)}" r="3" fill="var(--accent-2)"/>`).join('');
  const sep = nHist>0 && nHist<values.length ? `<line x1="${X(nHist-0.5)}" y1="${PAD}" x2="${X(nHist-0.5)}" y2="${H-PAD}" stroke="var(--border)" stroke-dasharray="4 4"/>` : '';
  host.innerHTML = `<svg class="trend-svg" viewBox="0 0 ${W} ${H}" style="height:${h}px">
    ${grid}${band}${sep}<path d="${histPts}" fill="none" stroke="var(--accent)" stroke-width="2.5"/>${histDots}
    <path d="${fcPts}" fill="none" stroke="var(--accent-2)" stroke-width="2.5" stroke-dasharray="6 4"/>${fcDots}
  </svg>
  <div class="trend-legend">
    <span class="lg"><i class="ls" style="background:var(--accent)"></i>measured drift</span>
    ${nHist<values.length?`<span class="lg"><i class="ld" style="border-top:2px dashed var(--accent-2)"></i>projection · confidence band</span>`:''}
  </div>`;
}

setActiveNav();
refreshStatusPill();
setInterval(()=>{ if(!location.pathname.endsWith('index.html')) refreshStatusPill(); }, 4000);