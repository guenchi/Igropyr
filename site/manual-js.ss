(library (manual-js)
  (export manual-loader)
  (import (rnrs))
  (define manual-loader "
  var SRC = { en: 'docs/manual.md', zh: 'docs/manual.zh-cn.md' };

  function slug(s) {
    return s.toLowerCase().trim()
      .replace(/[^\\w一-龥\\s-]/g, '')
      .replace(/\\s+/g, '-');
  }

  function loadManual(lang) {
    document.getElementById('btn-en').classList.toggle('on', lang === 'en');
    document.getElementById('btn-zh').classList.toggle('on', lang === 'zh');
    document.documentElement.lang = (lang === 'zh') ? 'zh' : 'en';
    var el = document.getElementById('md');
    el.innerHTML = '<p class=\"md-loading\">Loading…</p>';
    fetch(SRC[lang]).then(function (r) {
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
        + '<a href=\"' + SRC[lang] + '\">the raw file</a> or on '
        + '<a href=\"https://github.com/guenchi/Igropyr/blob/website/'
        + SRC[lang] + '\">GitHub</a>.</p>';
    });
  }

  // language from ?lang=zh or #zh, else default English
  var q = (location.search.match(/[?&]lang=(zh|en)/) || [])[1];
  var initial = q || (/^#?zh/.test(location.hash) ? 'zh' : 'en');
  loadManual(initial === 'zh' ? 'zh' : 'en');
"))
