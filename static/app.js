/* Page behaviour. Same-origin script, so it runs under the CSP without a nonce. */
(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  /* ── Plotly: re-measure once layout has settled so charts fill their container ── */
  window.addEventListener('load', function () {
    if (!window.Plotly) return;
    $$('.js-plotly-plot').forEach(function (el) { window.Plotly.Plots.resize(el); });
  });

  /* ── Sortable tables: <th data-sort="num|text"> ── */
  $$('table').forEach(function (table) {
    var heads = $$('th[data-sort]', table);
    heads.forEach(function (th, _i) {
      th.addEventListener('click', function () {
        var col = $$('th', table).indexOf(th);
        var dir = th.getAttribute('aria-sort') === 'ascending' ? 'descending' : 'ascending';
        heads.forEach(function (h) { h.removeAttribute('aria-sort'); });
        th.setAttribute('aria-sort', dir);
        var body = $('tbody', table);
        var rows = $$('tr', body);
        var num = th.dataset.sort === 'num';
        rows.sort(function (a, b) {
          var x = a.children[col].textContent.trim(), y = b.children[col].textContent.trim();
          var r = num ? (parseFloat(x.replace(/[^0-9.\-]/g, '')) || 0) - (parseFloat(y.replace(/[^0-9.\-]/g, '')) || 0)
                      : x.localeCompare(y);
          return dir === 'ascending' ? r : -r;
        });
        rows.forEach(function (r) { body.appendChild(r); });
      });
    });
  });

  /* ── Report: highlight the section in view in the sticky index ── */
  var navLinks = $$('.pagenav a');
  if (navLinks.length && 'IntersectionObserver' in window) {
    var byId = {};
    navLinks.forEach(function (a) { byId[a.getAttribute('href').slice(1)] = a; });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting && byId[e.target.id]) {
          navLinks.forEach(function (a) { a.classList.remove('on'); });
          byId[e.target.id].classList.add('on');
        }
      });
    }, { rootMargin: '-30% 0px -60% 0px' });
    Object.keys(byId).forEach(function (id) { var el = document.getElementById(id); if (el) io.observe(el); });
  }

  /* ── Dependency map: hover a node to isolate what it triggers / what triggers it ── */
  $$('svg.depmap').forEach(function (svg) {
    var edges = $$('.dep-edge', svg), nodes = $$('.dep-node', svg);
    function focus(id) {
      var seen = {}; seen[id] = true;
      // walk downstream and upstream so whole chains light up
      [['data-from', 'data-to'], ['data-to', 'data-from']].forEach(function (dir) {
        var frontier = [id];
        while (frontier.length) {
          var cur = frontier.pop();
          edges.forEach(function (e) {
            if (e.getAttribute(dir[0]) === cur) {
              e.classList.add('hot');
              var nxt = e.getAttribute(dir[1]);
              if (!seen[nxt]) { seen[nxt] = true; frontier.push(nxt); }
            }
          });
        }
      });
      nodes.forEach(function (n) { n.classList.toggle('hot', !!seen[n.dataset.id]); });
      svg.classList.add('focus');
    }
    function clear() {
      svg.classList.remove('focus');
      edges.forEach(function (e) { e.classList.remove('hot'); });
      nodes.forEach(function (n) { n.classList.remove('hot'); });
    }
    nodes.forEach(function (n) {
      n.addEventListener('mouseenter', function () { focus(n.dataset.id); });
      n.addEventListener('mouseleave', clear);
    });
  });

  /* ── Security log: filter rows by severity ── */
  var filters = $$('.filters button');
  filters.forEach(function (btn) {
    btn.addEventListener('click', function () {
      filters.forEach(function (b) { b.classList.toggle('on', b === btn); });
      var want = btn.dataset.sev;
      $$('.sec-table tbody tr[data-sev]').forEach(function (tr) {
        tr.hidden = !!want && tr.dataset.sev !== want;
      });
    });
  });

  /* ── Upload page ── */
  var form = document.getElementById('riskForm');
  if (!form) return;

  var segBtns = $$('.seg-btn');
  function activeTab() { return $('.seg-btn.active').dataset.tab; }
  segBtns.forEach(function (t) {
    t.addEventListener('click', function () {
      segBtns.forEach(function (x) { x.classList.remove('active'); });
      $$('.tabpane').forEach(function (p) { p.classList.remove('active'); });
      t.classList.add('active');
      document.getElementById('pane-' + t.dataset.tab).classList.add('active');
    });
  });

  var drop = document.getElementById('drop'),
      fi = document.getElementById('fileInput'),
      chip = document.getElementById('fileChip'),
      pasted = document.getElementById('pasted');
  function showFile() {
    if (fi.files[0]) { chip.hidden = false; chip.textContent = '✓ ' + fi.files[0].name; }
    else { chip.hidden = true; chip.textContent = ''; }
  }
  drop.addEventListener('click', function () { fi.click(); });
  ['dragover', 'dragenter'].forEach(function (e) {
    drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (e) {
    drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.remove('over'); });
  });
  drop.addEventListener('drop', function (ev) { fi.files = ev.dataTransfer.files; showFile(); });
  fi.addEventListener('change', showFile);

  /* examples */
  var EXAMPLES = [
    {"project_name":"Mobile Banking App","project_manager":"Sanay","date":"2026-10-10","risks":[
      {"id":"R1","title":"Biometric login fails on older phones","category":"Technical","probability":4,"impact":4,"description":"Fingerprint auth crashes on Android 10 and below, a fifth of the user base."},
      {"id":"R2","title":"App store review rejection","category":"Schedule","probability":3,"impact":3,"description":"Last release was rejected twice over permission wording, each round cost a week."},
      {"id":"R3","title":"Third-party payment SDK deprecated","category":"Technical","probability":3,"impact":5,"cost_impact":80000,"description":"The SDK vendor announced EOL; migration is a major lift.","triggers":["R4"]},
      {"id":"R4","title":"Launch delay","category":"Schedule","probability":2,"impact":4,"description":"Cascades from any blocking technical risk."}
    ]},
    {"project_name":"Campus Music Festival","project_manager":"Sanay","date":"2026-10-10","risks":[
      {"id":"R1","title":"Headliner cancels last minute","category":"External","probability":4,"impact":5,"description":"The main act has cancelled twice before and no backup is signed.","triggers":["R2"]},
      {"id":"R2","title":"Ticket refund surge","category":"Cost","probability":3,"impact":4,"cost_impact":30000,"description":"Cancellation triggers refund window; revenue impact is severe."},
      {"id":"R3","title":"Food vendors arrive late","category":"Schedule","probability":3,"impact":3,"description":"Two vendors drive in same-day and event-day traffic is heavy."},
      {"id":"R4","title":"Poster typo","category":"Quality","probability":2,"impact":2,"description":"A spelling mistake on printed posters embarrasses but is cheap to reprint."}
    ]},
    {"project_name":"Hospital Records Migration","project_manager":"Sanay","date":"2026-10-10","risks":[
      {"id":"R1","title":"Patient data mapping errors","category":"Quality","probability":4,"impact":5,"description":"Legacy fields don't match the new schema; silent mismatch could corrupt records.","triggers":["R3"]},
      {"id":"R2","title":"Nurses undertrained on new system","category":"Resource","probability":4,"impact":4,"description":"Only half the ward staff can attend training before go-live weekend."},
      {"id":"R3","title":"Regulatory audit triggered","category":"External","probability":2,"impact":5,"cost_impact":200000,"description":"Data errors during migration could trigger a mandatory audit."}
    ]},
    {"project_name":"Indie Game Launch","project_manager":"Sanay","date":"2026-10-10","risks":[
      {"id":"R1","title":"Lead artist leaves mid-production","category":"Resource","probability":3,"impact":5,"description":"The art style lives in one person's head with almost no style guide.","triggers":["R2"]},
      {"id":"R2","title":"Art pipeline blocked","category":"Schedule","probability":2,"impact":4,"description":"Cascades when art lead departs; all remaining assets stall."},
      {"id":"R3","title":"Console certification failure","category":"Technical","probability":3,"impact":4,"description":"First submission failed on save-data rules; a second fail slips launch a month."},
      {"id":"R4","title":"Server bill spike at launch","category":"Cost","probability":3,"impact":3,"cost_impact":15000,"description":"Day-one traffic could triple the hosting estimate."}
    ]},
    {"project_name":"Office Relocation","project_manager":"Sanay","date":"2026-10-10","risks":[
      {"id":"R1","title":"Internet downtime on move day","category":"Technical","probability":3,"impact":4,"description":"The ISP connection window overlaps with the team's first day in the new space."},
      {"id":"R2","title":"Lease paperwork delay","category":"External","probability":2,"impact":4,"description":"The landlord's legal review has already slipped once.","triggers":["R3"]},
      {"id":"R3","title":"Move day pushed back","category":"Schedule","probability":2,"impact":3,"description":"Delay to lease finalisation pushes the entire move schedule."},
      {"id":"R4","title":"Movers no-show","category":"Resource","probability":2,"impact":2,"description":"The booked crew has mixed reviews for punctuality."}
    ]}
  ];
  var exIdx = Math.floor(Math.random() * EXAMPLES.length);
  var exPre = document.getElementById('exPre');
  function paintExample() { exPre.textContent = JSON.stringify(EXAMPLES[exIdx], null, 2); }
  paintExample();
  document.getElementById('exToggle').addEventListener('click', function () {
    exPre.hidden = !exPre.hidden; if (!exPre.hidden) paintExample();
  });
  document.getElementById('exRandom').addEventListener('click', function () {
    exPre.hidden = false;
    var n; do { n = Math.floor(Math.random() * EXAMPLES.length); } while (n === exIdx && EXAMPLES.length > 1);
    exIdx = n; paintExample();
  });
  document.getElementById('exUse').addEventListener('click', function () {
    exPre.hidden = false; paintExample();
    pasted.value = exPre.textContent;
    fi.value = ''; showFile();
    pasted.scrollIntoView({ behavior: 'smooth', block: 'center' }); pasted.focus();
  });

  /* sliders */
  var PNAMES = ['', 'Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'];
  var INAMES = ['', 'Negligible', 'Minor', 'Moderate', 'Major', 'Catastrophic'];
  var mp = document.getElementById('mProb'), mi = document.getElementById('mImp');
  mp.addEventListener('input', function () { document.getElementById('pVal').textContent = mp.value + ' · ' + PNAMES[mp.value]; });
  mi.addEventListener('input', function () { document.getElementById('iVal').textContent = mi.value + ' · ' + INAMES[mi.value]; });

  /* manual risk list */
  var risks = [], ctr = 1;
  var listBox = document.getElementById('manualList'), cnt = document.getElementById('riskCount');
  function sev(v) { return v >= 20 ? 'b-Critical' : v >= 13 ? 'b-High' : v >= 7 ? 'b-Medium' : 'b-Low'; }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function render() {
    listBox.textContent = '';
    cnt.textContent = risks.length ? '· ' + risks.length + ' added' : '';
    risks.forEach(function (r, idx) {
      var s = r.probability * r.impact;
      var d = el('div', 'rcard'), left = el('div');
      var b = el('b', null, r.id);
      left.appendChild(b);
      left.appendChild(document.createTextNode(' — ' + r.title + ' '));
      left.appendChild(el('span', 'pill ' + sev(s), String(s)));
      var meta = r.category + ' · P' + r.probability + ' I' + r.impact +
        (r.cost_impact != null ? ' · ' + r.cost_impact.toLocaleString() : '') +
        (r.triggers ? ' → ' + r.triggers.join(', ') : '');
      left.appendChild(el('small', null, meta));
      var del = el('button', 'rdel', 'Remove'); del.type = 'button';
      del.addEventListener('click', function () { risks.splice(idx, 1); render(); });
      d.appendChild(left); d.appendChild(del); listBox.appendChild(d);
    });
  }
  document.getElementById('addBtn').addEventListener('click', function () {
    var title = document.getElementById('mTitle').value.trim();
    var desc = document.getElementById('mDesc').value.trim();
    if (!title) { alert('Give the risk a title first'); return; }
    var costRaw = document.getElementById('mCost').value.trim();
    var trigRaw = document.getElementById('mTrig').value.trim();
    var r = { id: 'R' + (ctr++), title: title, category: document.getElementById('mCat').value,
      probability: +mp.value, impact: +mi.value, description: desc || title };
    if (costRaw !== '') {
      var c = parseFloat(costRaw);
      if (!isFinite(c) || c < 0) { alert('Cost impact must be a number ≥ 0'); ctr--; return; }
      r.cost_impact = c;
    }
    if (trigRaw !== '') {
      r.triggers = trigRaw.split(',').map(function (s) { return s.trim().toUpperCase(); }).filter(Boolean);
    }
    risks.push(r);
    ['mTitle', 'mDesc', 'mCost', 'mTrig'].forEach(function (id) { document.getElementById(id).value = ''; });
    render();
  });

  /* submit */
  form.addEventListener('submit', function (e) {
    if (activeTab() === 'manual') {
      if (!risks.length) { alert('Add at least one risk first'); e.preventDefault(); return; }
      document.getElementById('manualJson').value = JSON.stringify(risks);
    } else {
      document.getElementById('manualJson').value = '';
      if (!fi.files.length && !pasted.value.trim()) { alert('Drop a file or paste JSON first'); e.preventDefault(); return; }
    }
    var btn = document.getElementById('submitBtn');
    // disable after the submit event so the form still posts
    setTimeout(function () { btn.disabled = true; btn.classList.add('loading'); }, 0);
    document.getElementById('submitTxt').textContent = 'Analyzing…';
  });
})();
