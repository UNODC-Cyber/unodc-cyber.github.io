// redirect.js - used by 404.html only. Maps /v/<ID> (optionally with #k=<reveal key>) to the
// lookup page: /?id=<ID>#k=<reveal key>. The fragment is never sent to any server; it is
// carried across by location.hash. Nothing is stored or logged.
(function () {
  var p = location.pathname;
  if (/^\/v\/?$/.test(p)) { location.replace('/' + location.hash); return; }
  var m = /^\/v\/([^/?#]+)\/?$/.exec(p);
  if (!m) return; // any other unknown path: stay on the "page not found" message
  var id = m[1];
  try { id = decodeURIComponent(id); } catch (e) { /* keep as is */ }
  if (id.length > 64) id = id.slice(0, 64); // bound the length; the lookup page validates the content
  location.replace('/?id=' + encodeURIComponent(id) + location.hash);
})();
