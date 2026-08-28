// A minimal, classic webpack (v4-style) bundle used by the JS RE gate.
//
// It is deliberately a *single* file whose three modules are inlined into the
// webpack runtime's module array and wired together with __webpack_require__.
// The gate asserts that webcrack splits this back into per-module files and
// rewrites the numeric __webpack_require__ calls into real relative-path
// require edges -- i.e. that it unpacks the bundle rather than copying it.
//
// Module 2 carries the marker string UNPACK_MARKER so the gate can prove the
// recovered file is that module's body, not the entry or the runtime.
(function (modules) {
  var installedModules = {};
  function __webpack_require__(moduleId) {
    if (installedModules[moduleId]) {
      return installedModules[moduleId].exports;
    }
    var module = (installedModules[moduleId] = {
      i: moduleId,
      l: false,
      exports: {},
    });
    modules[moduleId].call(
      module.exports,
      module,
      module.exports,
      __webpack_require__
    );
    module.l = true;
    return module.exports;
  }
  return __webpack_require__((__webpack_require__.s = 0));
})([
  function (module, exports, __webpack_require__) {
    "use strict";
    var greeter = __webpack_require__(1);
    var mathlib = __webpack_require__(2);
    console.log(greeter.hello("headless"));
    console.log("sum=" + mathlib.add(19, 23));
  },
  function (module, exports) {
    "use strict";
    exports.hello = function hello(name) {
      return "hello " + name + " from module one";
    };
  },
  function (module, exports) {
    "use strict";
    exports.add = function add(a, b) {
      return a + b;
    };
    exports.MARKER = "unpack-fixture-2718";
  },
]);
