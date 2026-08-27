// Minimal, harmless webpack-style bundle for the webcrack unpack gate.
// A classic webpack runtime wraps two modules: the entry (id 0) pulls in a
// helper (id 1). webcrack recognises the runtime and splits it back into one
// file per module, which is what js.unpack_bundle exists to do. The marker
// strings let the gate prove the helper module was really extracted with its
// body, not merely deobfuscated as a single blob. No I/O, no eval.
(function (modules) {
  var installed = {};
  function __webpack_require__(id) {
    if (installed[id]) return installed[id].exports;
    var module = (installed[id] = { i: id, l: false, exports: {} });
    modules[id].call(module.exports, module, module.exports, __webpack_require__);
    module.l = true;
    return module.exports;
  }
  return __webpack_require__((__webpack_require__.s = 0));
})([
  function (module, exports, __webpack_require__) {
    var greet = __webpack_require__(1);
    console.log(greet("webpack-gate-entry"));
  },
  function (module, exports) {
    module.exports = function (name) {
      return "webpack-gate-module:" + name;
    };
  },
]);
