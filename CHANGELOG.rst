CHANGELOG
--------------

v1.0.0.dev0 2026/08/07
~~~~~~~~~~~~~~~~~~~~~~~

- Rename the project from ``xxtea`` to ``xxteang``.
- Switch padding from the non-standard 4-byte block to an 8-byte block
  PKCS#7 scheme (pad values 1–8, inputs padded to a multiple of 8 bytes).
