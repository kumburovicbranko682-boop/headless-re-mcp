;; Small but real WebAssembly module for the wabt gates. Compiled to .wasm at
;; test time with wat2wasm, then inspected with wasm2wat (round trip) and
;; wasm-objdump. It has an exported function with a body, an exported global,
;; and an exported memory so the tools have actual sections/functions to report
;; -- unlike the empty magic+version module, which only ever prints "(module)".
(module
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (global $answer (export "answer") i32 (i32.const 42))
  (memory (export "mem") 1))
