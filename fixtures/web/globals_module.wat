;; Fixture for the wasm.globals gate: a module whose globals mirror the
;; memory-layout anchors a real compiler emits. Compiled with debug names so the
;; name section's global namemap carries the $-identifiers, and one global is
;; exported so export-name resolution is exercised too.
;;
;;   wat2wasm --debug-names globals_module.wat -o globals_module.wasm
(module
  (global $__stack_pointer (mut i32) (i32.const 66560))
  (global $__data_end i32 (i32.const 1024))
  (global $__heap_base i32 (i32.const 67584))
  (export "sp" (global $__stack_pointer))
)
