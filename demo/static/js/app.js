/* Rulebook Drift Monitor - shared app JS */
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
  const host = $(el); if(!host) return;
  if(!matrix || !matrix.rows || !matrix.rows.length){ host.innerHTML='<div class="empty">no matrix</div>'; return; }
  const cats = matrix.categories;
  const sevRank = {critical:0, high:1, medium:2, low:3};
  const sevFill = {critical:'#e25563', high:'#e1a135', medium:'#3b82f6', low:'#9aa3b5', default:'#3b82f6'};
  const rows = matrix.rows.slice().sort((a,b)=>
    (sevRank[b.severity]!=null?sevRank[b.severity]:2) - (sevRank[a.severity]!=null?sevRank[a.severity]:2) ||
    b.total - a.total);
  const max = Math.max(1, ...rows.map(r=>Math.max(...r.cells)));
  const cw = 36, rh = 18, labelW = 168, totalW = 46, headH = 80;
  const W = labelW + cats.length*cw + totalW;
  const H = headH + rows.length*rh + 34;
  const px = (c) => labelW + c*cw;
  const color = (v) => {
    if(v<=0) return 'transparent';
    const a = Math.min(1, 0.14 + 0.86*(v/max));
    return `rgba(59,71,176,${a.toFixed(2)})`;
  };
  const textColor = (v)=>'#ffffff';

  // Category headers: single line, 60° up-left with a char cap so labels never cross column pitch.
  const constrain = (label) => {
    const mw = 9*0.6, pitch = cw, allowed = pitch - 10;
    const cap = Math.floor(allowed/(mw*Math.cos(Math.PI/3)));
    return label.length > cap ? label.slice(0, Math.max(1,cap-1))+'…' : label;
  };

  let header = '';
  header += `<text x="${labelW/2}" y="14" text-anchor="middle" class="hm-colh">TYPOLOGY</text>`;
  cats.forEach((c,i)=>{
    const cx = px(i)+cw-3, cy = headH-7;
    header += `<text x="${cx}" y="${cy}" text-anchor="end" class="hm-label" transform="rotate(60 ${cx} ${cy})"><title>${esc(c)}</title>${esc(constrain(c))}</text>`;
  });
  header += `<text x="${W-totalW/2}" y="14" text-anchor="middle" class="hm-colh">EVADED</text>`;
  header += `<line x1="0" y1="${headH-5}" x2="${W}" y2="${headH-5}" stroke="var(--border)" stroke-width="1"/>`;

  let body = '';
  rows.forEach((r,ridx)=>{
    const y = headH + ridx*rh;
    const isCovered = covered.includes(r.id);
    const band = ridx%2 ? 'rgba(15,20,40,0.05)' : 'transparent';
    body += `<rect x="0" y="${y}" width="${W}" height="${rh}" fill="${band}"/>`;
    // label column: severity dot + id + name (two lines) + covered marker
    const sv = r.severity||'medium';
    body += `<circle cx="8" cy="${y+10}" r="4" fill="${sevFill[sv]||sevFill.default}"/>`;
    body += `<text x="16" y="${y+8}" class="hm-rowid ${isCovered?'hm-covered':''}" fill="${isCovered?'var(--good)':'var(--accent)'}">${esc(r.id)}</text>`;
    body += `<text x="16" y="${y+16}" class="hm-name">${esc(r.name.length>26?r.name.slice(0,25)+'…':r.name)}</text>`;
    if(isCovered) body += `<text x="${labelW-8}" y="${y+17}" text-anchor="end" fill="var(--good)" font-size="9" font-weight="800">✦</text>`;
    // cells
    r.cells.forEach((v,ci)=>{
      const x = px(ci);
      const fill = color(v);
      if(fill!=='transparent'){
        body += `<rect x="${x+1}" y="${y+1}" width="${cw-2}" height="${rh-2}" rx="2" fill="${fill}">
          <title>${esc(r.id)} evades ${v} rule(s) in ${esc(cats[ci])}</title></rect>`;
        body += `<text x="${x+cw/2}" y="${y+rh-5}" text-anchor="middle" class="hm-count" fill="${textColor(v)}">${v}</text>`;
      } else {
        body += `<line x1="${x+3}" y1="${y+rh-5}" x2="${x+cw-3}" y2="${y+rh-5}" stroke="var(--border-2)" stroke-width="1" stroke-dasharray="2 2" opacity="0.55"><title>no evasion · ${esc(cats[ci])}</title></line>`;
      }
    });
    if(isCovered){
      body += `<rect x="${px(0)+1}" y="${y+1}" width="${cats.length*cw-2}" height="${rh-2}" fill="none" stroke="var(--good)" stroke-width="1.5" rx="3"><title>covered by institutionalised indicator</title></rect>`;
    }
    // total column
    body += `<text x="${W-totalW/2}" y="${y+rh-5}" text-anchor="middle" class="hm-total ${r.total>0?'on':''}">${r.total}</text>`;
  });

  // legend: intensity scale + covered
  const ly = headH + rows.length*rh;
  const legW = 150;
  const stops = [0,0.25,0.5,0.75,1].map(f=>{ const a=(0.14+0.86*f); return `${Math.round(f*100)}% #3b47b0`;}).join(',');
  let legend = '';
  legend += `<rect x="0" y="${ly+10}" width="${legW}" height="10" fill="url(#hmgrad)"/>`;
  legend += `<text x="0" y="${ly+27}" class="hm-legend">0 evaded rules</text>`;
  legend += `<text x="${legW}" y="${ly+27}" text-anchor="end" class="hm-legend">${max} rule(s) evaded</text>`;
  legend += `<line x1="${labelW+6}" y1="${ly+15}" x2="${labelW+26}" y2="${ly+15}" stroke="var(--good)" stroke-width="2"/><text x="${labelW+30}" y="${ly+19}" class="hm-legend">typology covered by instituted indicator</text>`;

  const svg = `<svg class="trend-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="evasion heatmap by rule category">
    <defs><linearGradient id="hmgrad" x1="0" x2="1" y1="0" y2="0">
      <stop offset="0" stop-color="#3b47b0" stop-opacity="0.14"/><stop offset="1" stop-color="#3b47b0" stop-opacity="1"/>
    </linearGradient></defs>
    ${header}${body}${legend}</svg>`;
  host.innerHTML = `<div class="hm-scroll">${svg}</div>`;
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