(library (manual-js)
  (export manual-loader)
  (import (rnrs))
  (define manual-loader "
  var SRC = 'docs/manual.md';

  function slug(s) {
    return s.toLowerCase().trim()
      .replace(/[^\\w一-龥\\s-]/g, '')
      .replace(/\\s+/g, '-');
  }

  (function loadManual() {
    var el = document.getElementById('md');
    el.innerHTML = '<p class=\"md-loading\">Loading…</p>';
    fetch(SRC).then(function (r) {
      if (!r.ok) throw new Error(r.status);
      return r.text();
    }).then(function (md) {
      el.innerHTML = marked.parse(md, { gfm: true, breaks: false });
      // give headings stable ids so the in-doc table of contents jumps work
      el.querySelectorAll('h1,h2,h3,h4').forEach(function (h) {
        if (!h.id) h.id = slug(h.textContent);
      });
      if (location.hash) {
        var t = document.getElementById(location.hash.slice(1));
        if (t) t.scrollIntoView();
      }
    }).catch(function (e) {
      el.innerHTML = '<p class=\"md-loading\">Could not render the manual ('
        + e.message + '). Read it on '
        + '<a href=\"' + SRC + '\">the raw file</a> or on '
        + '<a href=\"https://github.com/guenchi/Igropyr/blob/website/'
        + SRC + '\">GitHub</a>.</p>';
    });
  })();
"))
