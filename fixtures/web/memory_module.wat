(module
  ;; A named, exported linear memory with min=2 / max=16 pages so wasm.memory
  ;; can recover both the page limits and the byte sizes they scale to.
  (memory $mem (export "memory") 2 16)
  ;; Two active data segments placed at known linear-memory offsets, plus one
  ;; passive segment (which forces a DataCount section) so the placement map,
  ;; the occupied span and data_count all have something real to resolve.
  (data $hello (i32.const 1024) "hello")
  (data $world (i32.const 2048) "world!!")
  (data $extra "passive")
)
