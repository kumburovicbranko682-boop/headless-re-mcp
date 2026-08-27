;; Small, self-contained WebAssembly module for the wabt gate.
;; Source of truth for fixtures/web/gate_module.wasm; rebuild with:
;;   wat2wasm fixtures/web/gate_module.wat -o fixtures/web/gate_module.wasm
;;
;; It is deliberately shaped to exercise the sections wasm.info (wasm-objdump
;; -h -x) reports and the constructs wasm.wat (wasm2wat) prints back: a typed
;; import, two exported functions, a global, a memory, and a named data string.
(module
  (import "env" "log" (func $log (param i32)))
  (global $answer (export "answer") i32 (i32.const 42))
  (memory (export "memory") 1)
  (data (i32.const 16) "H3adl3ss-wasm")
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (func $checksum (export "checksum") (param $n i32) (result i32)
    (local $acc i32)
    (local $i i32)
    (loop $loop
      local.get $acc
      local.get $i
      i32.add
      local.set $acc
      local.get $i
      i32.const 1
      i32.add
      local.set $i
      local.get $i
      local.get $n
      i32.lt_s
      br_if $loop)
    local.get $acc))
