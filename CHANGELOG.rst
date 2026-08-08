CHANGELOG
--------------

v1.0.0 2026/08/08
~~~~~~~~~~~~~~~~~~~~~~~

- Rename the project from ``xxtea`` to ``xxteang``.
- Switch padding from the non-standard 4-byte block to an 8-byte block
  PKCS#7 scheme (pad values 1–8, inputs padded to a multiple of 8 bytes).
- Refactor: unify the duplicated module/type argument parsers into one
  table-driven parser, collapse the duplicated ``longs2bytes`` byte-order
  paths, and add a module docstring.
- Performance: assemble the tail/padding bytes as endian-independent
  word values (no buffer pre-zeroing, removing the full-buffer
  ``memset``), make ``bytes2longs`` return ``void``, and drop the
  redundant keyword-slot tracking in the shared parser.
