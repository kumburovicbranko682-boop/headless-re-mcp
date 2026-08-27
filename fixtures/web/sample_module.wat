;; Source for sample_module.wasm, a tiny valid WebAssembly module used by the
;; Web RE gate to exercise wasm2wat / wasm-objdump on real sections (not just an
;; empty magic+version module). Rebuild: wat2wasm sample_module.wat -o sample_module.wasm
(module
  (memory (export "memory") 1)
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (func $answer (export "answer") (result i32)
    i32.const 42))
