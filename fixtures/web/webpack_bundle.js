// Minimal classic-webpack bundle fixture for the js.unpack_bundle gate.
//
// webcrack recognises the (function(modules){...})([...]) runtime and splits it
// back into one file per module (index.js for the entry, 1.js, 2.js, ...), plus
// bundle.json and deobfuscated.js. It is self-contained: no I/O, no eval, no
// network -- three tiny modules whose only job is to give the unpacker real
// module boundaries to recover.
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
  __webpack_require__.s = 0;
  return __webpack_require__(0);
})([
  function (module, exports, __webpack_require__) {
    var greet = __webpack_require__(1);
    var util = __webpack_require__(2);
    module.exports = greet(util.name());
  },
  function (module, exports) {
    module.exports = function greet(name) {
      return "hello " + name;
    };
  },
  function (module, exports) {
    exports.name = function name() {
      return "headless-re-bundle";
    };
  },
]);
