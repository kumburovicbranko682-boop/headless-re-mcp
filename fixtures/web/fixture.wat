;; Source for the committed fixtures/web/fixture.wasm (a real, tiny WASM module).
;;
;; The WASM gates need genuine content, not the empty magic+version header the
;; existing smoke test uses: wasm2wat's disassembly and wasm-objdump's section
;; dump are version-sensitive CLI surfaces (wabt), and an empty module exercises
;; almost none of either. This module carries a type, two exported functions, a
;; memory, a mutable global, and a data segment so both tools have real structure
;; to render:
;;   wasm2wat  -> (func ...), (export "add" ...), i32.add, (memory ...), (global ...)
;;   wasm-objdump -h -x -> Type / Function / Memory / Global / Export / Code / Data
;;
;; Rebuild fixture.wasm from this source with wabt's wat2wasm:
;;   wat2wasm fixtures/web/fixture.wat -o fixtures/web/fixture.wasm
(module
  (memory (export "mem") 1)
  (global $counter (mut i32) (i32.const 0))
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (func $inc (export "inc") (result i32)
    global.get $counter
    i32.const 1
    i32.add
    global.set $counter
    global.get $counter)
  (data (i32.const 0) "wasm-fixture-marker"))
