/* Drift Sentinel - shared app shell (sidebar + topbar).
   The nav lives here rather than being copy-pasted into eight HTML files, so
   a label or a route only ever changes in one place.

   Labels are written for the person doing the job, not for the person who
   built it: an FIC/FSCA analyst opening this cold should be able to tell what
   a page does from its name alone. */

const NAV = [
  { href: 'home.html',      icon: '⌂', label: 'Home',
    title: 'Drift Sentinel',
    blurb: 'What this is, who it is for, and who built it' },

  { section: 'Check the rulebook' },
  { href: 'index.html',     icon: '▶', label: 'Run a check',
    title: 'Run a check',
    blurb: 'Test the rulebook against known and invented fraud' },
  { href: 'review.html',    icon: '☑', label: 'Decisions waiting for you',
    title: 'Decisions waiting for you', countId: 'navReviewCount',
    blurb: 'Accept, amend or reject each gap the system found' },
  { href: 'sandbox.html',   icon: '⚗', label: 'Try your own scenario',
    title: 'Try your own scenario',
    blurb: 'Describe a fraud and watch which rules catch it' },

  { section: 'See the bigger picture' },
  { href: 'dashboard.html', icon: '◈', label: 'Where the gaps are',
    title: 'Where the gaps are',
    blurb: 'Coverage, drift and pressure across the whole rulebook' },
  { href: 'forecast.html',  icon: '⌁', label: 'Where drift is heading',
    title: 'Where drift is heading',
    blurb: 'How the gap is likely to widen if nothing changes' },
  { href: 'compare.html',   icon: '⇄', label: 'Known vs emerging fraud',
    title: 'Known vs emerging fraud',
    blurb: 'How documented typologies compare with invented ones' },

  { section: 'Look things up' },
  { href: 'rules.html',     icon: '⚖', label: 'The rulebook',
    title: 'The rulebook',
    blurb: 'All 40 rules, what each one catches, and where it came from' },
  { href: 'audit.html',     icon: '🕮', label: 'Paper trail',
    title: 'Paper trail',
    blurb: 'Every action logged, in order, with who decided what' },
];

function currentPage(){
  /* '/' serves the landing page, so an empty filename means home - not the run
     console, which now lives only at its own /index.html. */
  const f = (location.pathname.split('/').pop() || 'home.html');
  return f === '' ? 'home.html' : f;
}

function renderShell(){
  const here = currentPage();
  const entry = NAV.find(n => n.href === here) || {};

  const navHtml = NAV.map(n => {
    if (n.section) return `<div class="nav-sec">${n.section}</div>`;
    const active = n.href === here ? ' active' : '';
    const count = n.countId ? `<span class="nav-count" id="${n.countId}"></span>` : '';
    return `<a class="nav-link${active}" href="${n.href}" title="${n.blurb}">` +
           `<span class="ic">${n.icon}</span>${n.label}${count}</a>`;
  }).join('');

  const side = document.querySelector('.sidebar');
  if (side) {
    side.innerHTML = `
      <div class="side-brand">
        <div class="side-logo"><img src="static/img/logo.svg" alt=""/></div>
        <div>
          <div class="name">Drift Sentinel</div>
          <div class="sub">Keeping the rulebook current</div>
        </div>
      </div>
      <nav class="side-nav">${navHtml}</nav>
      <div class="side-foot">
        40 rules · DS-01 to DS-40<br/>
        Synthetic data · prototype
      </div>`;
  }

  const title = document.getElementById('pageTitle');
  if (title && entry.title) title.textContent = entry.title;
  if (entry.title) document.title = `Drift Sentinel · ${entry.title}`;
}

document.addEventListener('DOMContentLoaded', renderShell);
