// Harmless minimal webpack-style bundle for the js.unpack_bundle gate.
// Two modules with a real cross-module call edge: the entry (module 0) pulls
// in module 1 and calls it. webcrack recognises the classic webpack runtime
// and splits this into per-module files, so the gate can prove the split
// preserved both the marker and the module-1 body. No I/O, no eval.
(function (modules) {
  var installedModules = {};
  function __webpack_require__(moduleId) {
    if (installedModules[moduleId]) return installedModules[moduleId].exports;
    var module = (installedModules[moduleId] = { i: moduleId, l: false, exports: {} });
    modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
    module.l = true;
    return module.exports;
  }
  return __webpack_require__(0);
})([
  function (module, exports, __webpack_require__) {
    var greet = __webpack_require__(1);
    console.log(greet("UNPACK_GATE_MARKER"));
  },
  function (module, exports) {
    module.exports = function (name) {
      return "hello " + name;
    };
  },
]);
