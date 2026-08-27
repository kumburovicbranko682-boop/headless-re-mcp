(function (modules) {
  var installedModules = {};
  function __webpack_require__(moduleId) {
    if (installedModules[moduleId]) return installedModules[moduleId].exports;
    var module = (installedModules[moduleId] = { i: moduleId, l: false, exports: {} });
    modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
    module.l = true;
    return module.exports;
  }
  return __webpack_require__((__webpack_require__.s = 0));
})([
  function (module, exports, __webpack_require__) {
    "use strict";
    var greet = __webpack_require__(1);
    var mathUtil = __webpack_require__(2);
    console.log(greet.sayHello("world"), mathUtil.add(2, 3));
  },
  function (module, exports) {
    "use strict";
    exports.sayHello = function (name) { return "hello " + name; };
  },
  function (module, exports) {
    "use strict";
    exports.add = function (a, b) { return a + b; };
  },
]);
