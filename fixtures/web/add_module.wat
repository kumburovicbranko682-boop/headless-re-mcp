;; Source of fixtures/web/add_module.wasm, kept in-tree for provenance and so
;; the binary can be regenerated. Deliberately small but non-degenerate: it
;; carries type, function, memory, export, and code sections so both wasm2wat
;; and wasm-objdump have real structure to report. Regenerate with:
;;   wat2wasm fixtures/web/add_module.wat -o fixtures/web/add_module.wasm
(module
  (func $add (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (memory (export "mem") 1)
  (export "add" (func $add)))
