(library (md-js)
  (export md-loader)
  (import (rnrs))

  ;; The client-side renderer shared by every markdown page: fetch the
  ;; source, run it through marked.js, and give the headings stable ids
  ;; so a table of contents inside the document can jump to them.
  ;;
  ;; SRC is the path fetched; NOUN names the page in the failure message
  ;; ("the manual", "the changelog"), which is the only sentence a reader
  ;; sees when the fetch or the render fails. Both are spliced in here
  ;; rather than read from the DOM, so a page that forgets to say which
  ;; document it is cannot compile.
  (define (md-loader src noun)
    (string-append "
  var SRC = '" src "';
  var NOUN = '" noun "';

  function slug(s) {
    return s.toLowerCase().trim()
      .replace(/[^\\w一-龥\\s-]/g, '')
      .replace(/\\s+/g, '-');
  }

  (function loadDoc() {
    var el = document.getElementById('md');
    el.innerHTML = '<p class=\"md-loading\">Loading…</p>';
    fetch(SRC).then(function (r) {
      if (!r.ok) throw new Error(r.status);
      return r.text();
    }).then(function (md) {
      el.innerHTML = marked.parse(md, { gfm: true, breaks: false });
      // The page shell already prints the document's title above this
      // element, so a leading <h1> from the source would be the second
      // one on the page. It stays in the file -- read raw or on GitHub,
      // a document wants its own title -- and is dropped here, where the
      // shell's heading is the one in view.
      var lead = el.firstElementChild;
      if (lead && lead.tagName === 'H1') el.removeChild(lead);
      el.querySelectorAll('h1,h2,h3,h4').forEach(function (h) {
        if (!h.id) h.id = slug(h.textContent);
      });
      if (location.hash) {
        var t = document.getElementById(location.hash.slice(1));
        if (t) t.scrollIntoView();
      }
    }).catch(function (e) {
      el.innerHTML = '<p class=\"md-loading\">Could not render ' + NOUN + ' ('
        + e.message + '). Read it on '
        + '<a href=\"' + SRC + '\">the raw file</a> or on '
        + '<a href=\"https://github.com/guenchi/Igropyr/blob/website/'
        + SRC + '\">GitHub</a>.</p>';
    });
  })();
")))
