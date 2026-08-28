;; Fixture for the wasm.elements gate: a module with a funcref table filled by
;; two active element segments, so slot->function resolution (the indirect-call
;; target map) is exercised. Compiled with debug names so the name section's
;; function namemap resolves each target.
;;
;;   wat2wasm --debug-names table_module.wat -o table_module.wasm
(module
  (type $ft (func (param i32) (result i32)))
  (func $inc (type $ft) (param i32) (result i32)
    (i32.add (local.get 0) (i32.const 1)))
  (func $dec (type $ft) (param i32) (result i32)
    (i32.sub (local.get 0) (i32.const 1)))
  (func $sq (type $ft) (param i32) (result i32)
    (i32.mul (local.get 0) (local.get 0)))
  (table $t 8 funcref)
  (elem (i32.const 1) $inc $dec)
  (elem (i32.const 5) $sq)
  (export "t" (table $t))
  (export "run" (func $inc))
)
