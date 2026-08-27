// Harmless minimal browserify bundle for the js.unpack_bundle gate.
// Distinct from the webpack fixture: browserify carries the require-string map
// ({"./greet":2}), so webcrack resolves the dependency back to its real name
// (greet.js) rather than a numeric id. Two modules with a cross-module edge:
// the entry (module 1) requires module 2 and calls it. No I/O, no eval.
(function () {
  function r(e, n, t) {
    function o(i, f) {
      if (!n[i]) {
        if (!e[i]) {
          var c = "function" == typeof require && require;
          if (!f && c) return c(i, !0);
          if (u) return u(i, !0);
          var a = new Error("Cannot find module '" + i + "'");
          throw ((a.code = "MODULE_NOT_FOUND"), a);
        }
        var p = (n[i] = { exports: {} });
        e[i][0].call(
          p.exports,
          function (r) {
            var n = e[i][1][r];
            return o(n || r);
          },
          p,
          p.exports,
          r,
          e,
          n,
          t,
        );
      }
      return n[i].exports;
    }
    for (var u = "function" == typeof require && require, i = 0; i < t.length; i++) o(t[i]);
    return o;
  }
  return r;
})()(
  {
    1: [
      function (require, module, exports) {
        var greet = require("./greet");
        console.log(greet("BRIFY_GATE_MARKER"));
      },
      { "./greet": 2 },
    ],
    2: [
      function (require, module, exports) {
        module.exports = function (name) {
          return "hi " + name;
        };
      },
      {},
    ],
  },
  {},
  [1],
);
