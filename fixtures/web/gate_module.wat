;; Source for gate_module.wasm, the WebAssembly fixture the WASM inspection gate
;; reads. Kept in the tree so the binary can be regenerated and reviewed:
;;
;;   wat2wasm fixtures/web/gate_module.wat -o fixtures/web/gate_module.wasm
;;
;; It is deliberately not the empty "\0asm\x01" header. Every major section is
;; present -- type, import, function, table, memory, global, export, data and
;; code -- so wasm-objdump lists real sections and wasm2wat round-trips real
;; content the gate can assert on, including the "headless-re" marker string.
(module
  (import "env" "log" (func $log (param i32)))
  (memory (export "memory") 1)
  (table 1 funcref)
  (global $counter (mut i32) (i32.const 0))
  (data (i32.const 0) "headless-re wasm gate fixture")
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (func $bump (export "bump") (result i32)
    global.get $counter
    i32.const 1
    i32.add
    global.set $counter
    global.get $counter)
  (func $greet (export "greet")
    i32.const 0
    call $log))
