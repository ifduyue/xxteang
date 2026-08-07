xxteang |github-actions-badge| |pypi-badge| |supported-pythons-badge| |license-badge| |codspeed-badge|
======================================================================================================

.. |github-actions-badge| image:: https://github.com/ifduyue/xxteang/actions/workflows/test.yml/badge.svg
    :target: https://github.com/ifduyue/xxteang/actions/workflows/test.yml
    :alt: Github Actions Status

.. |pypi-badge| image:: https://img.shields.io/pypi/v/xxteang.svg
   :target: https://pypi.python.org/pypi/xxteang
   :alt: Latest Version

.. |supported-pythons-badge| image:: https://img.shields.io/pypi/pyversions/xxteang.svg
    :target: https://pypi.python.org/pypi/xxteang
    :alt: Supported Python versions

.. |license-badge| image:: https://img.shields.io/pypi/l/xxteang.svg
    :target: https://pypi.python.org/pypi/xxteang
    :alt: License

.. |codspeed-badge| image:: https://img.shields.io/endpoint?url=https://codspeed.io/badge.json
    :target: https://codspeed.io/ifduyue/xxteang?utm_source=badge
    :alt: CodSpeed

.. _XXTEA: http://en.wikipedia.org/wiki/XXTEA
.. _longs2bytes: https://github.com/ifduyue/xxteang/blob/master/xxteang.c#L128
.. _bytes2longs: https://github.com/ifduyue/xxteang/blob/master/xxteang.c#L88
.. _PKCS#7: http://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7

XXTEA_ implemented as a Python extension module, licensed under 2-clause BSD.

The XXTEA_ algorithm takes a 128-bit key and operates on an array of 32-bit
integers (at least 2 integers), but it doesn't define the conversions between
bytes and array. Due to this reason, many XXTEA implementations out there are
not compatible with each other.

In this implementation,  the conversions between bytes and array are
taken care of by longs2bytes_ and bytes2longs_. An 8-byte block
`PKCS#7`_ padding is used to make sure that the input bytes are padded
to a multiple of 8-byte (the size of two 32-bit integers, which is the
minimum required by the XXTEA_ algorithm). As a result of these
measures, you can encrypt not only texts, but also any binary bytes of
any length.

.. note::

   This implementation uses an **8-byte block** PKCS#7 padding.  Because
   many XXTEA implementations use different padding schemes (4-byte,
   16-byte, or none at all), the output is **NOT** compatible with those
   implementations.  Pass ``padding=False`` for raw XXTEA (requires data
   length ≥ 8 and multiple of 4).


Installation
-------------

::

    $ pip install xxteang -U


Usage
-----------

This module provides four functions: ``encrypt()``, ``decrypt()``,
``encrypt_hex()``, and ``decrypt_hex()``, plus an ``XXTEA`` type for
reusable cipher objects.

.. code-block:: Python

    >>> import os
    >>> import xxteang
    >>> import binascii
    >>>
    >>> key = os.urandom(16)  # Key must be a 16-byte string.
    >>> s = b"xxtea is good"
    >>>
    >>> enc = xxteang.encrypt(s, key)
    >>> dec = xxteang.decrypt(enc, key)
    >>> s == dec
    True
    >>>
    >>> hexenc = xxteang.encrypt_hex(s, key)
    >>> s == xxteang.decrypt_hex(hexenc, key)
    True
    >>>
    >>> binascii.hexlify(enc) == hexenc
    True


XXTEA Type
-----------

The ``XXTEA`` type holds a 16-byte key, rounds, and padding setting,
so you can encrypt and decrypt multiple times without passing them each call.

.. code-block:: python

    >>> from xxteang import XXTEA
    >>>
    >>> cipher = XXTEA(key, padding=False, rounds=128)
    >>> cipher
    <xxteang.XXTEA object at 0x...>
    >>>
    >>> enc = cipher.encrypt(b'12345678')
    >>> cipher.decrypt(enc)
    b'12345678'
    >>>
    >>> hexenc = cipher.encrypt_hex(b'12345678')
    >>> cipher.decrypt_hex(hexenc)
    b'12345678'

``rounds`` defaults to ``0`` (auto), ``padding`` defaults to ``True``.
``rounds=0`` means ``6 + 52 / n``, where n is the number of 32-bit words in the data.
They are stored on the object and used by every ``encrypt()``, ``decrypt()``,
``encrypt_hex()``, and ``decrypt_hex()`` call:

.. code-block:: python

    >>> c = XXTEA(key)                          # rounds=0, padding=True
    >>> c = XXTEA(key, rounds=64)         # override rounds
    >>> c = XXTEA(key, padding=False)     # disable padding
    >>> c = XXTEA(key, padding=False, rounds=42)


``encrypt_hex()`` and ``decrypt_hex()`` operate on ciphertext in a hexadecimal
representation. They are exactly equivalent to:

.. code-block:: python

    >>> hexenc = binascii.hexlify(xxteang.encrypt(s, key))
    >>> s == xxteang.decrypt(binascii.unhexlify(hexenc), key)
    True


Padding
---------

Padding is enabled by default, using an **8-byte block PKCS#7** scheme.
The pad byte value is ``8 - (len(data) & 7)`` (range 1–8).  Inputs
shorter than 8 bytes are padded to exactly 8 bytes, which satisfies
XXTEA's minimum of two 32-bit words.

Because padding always adds at least one byte, encrypting an 8-byte input
produces a 16-byte ciphertext.  Use ``padding=False`` for raw, unpadded
XXTEA.

.. code-block:: python

    >>> xxteang.decrypt_hex(xxteang.encrypt_hex(b'', key), key)
    b''
    >>> xxteang.decrypt_hex(xxteang.encrypt_hex(b' ', key), key)
    b' '

You can disable padding by setting padding parameter to ``False``.
In this case data will not be padded, so data length must be a multiple of 4 bytes and must not be less than 8 bytes.
Otherwise ``ValueError`` will be raised:

.. code-block:: python

    >>> xxteang.encrypt_hex(b'', key, padding=False)
    ValueError: Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> xxteang.encrypt_hex(b'xxtea is good', key, padding=False)
    ValueError: Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> xxteang.decrypt_hex(xxteang.encrypt_hex(b'12345678', key, padding=False), key, padding=False)
    b'12345678'


Rounds
----------

By default xxteang manipulates the input data for ``6 + 52 / n`` rounds,
where n denotes how many 32-bit integers the input data can fit in.
We can change this by setting ``rounds`` parameter.

Do note that the more rounds it is, the more time will be consumed.
``rounds`` must fit in a 32-bit unsigned integer; values exceeding
``2**32 - 1`` raise ``OverflowError``.

.. code-block:: python

    >>> import xxteang
    >>> import string
    >>> data = string.digits.encode()
    >>> key = string.ascii_letters[:16].encode()
    >>> xxteang.encrypt_hex(data, key)
    b'90f829f7271461d1d47efae4f5fde383'
    >>> 6 + 52 // ((len(data) + 7) // 8 * 2)  # 8-byte PKCS#7 blocks, 4 bytes per 32-bit integer
    19
    >>> xxteang.encrypt_hex(data, key, rounds=19)
    b'90f829f7271461d1d47efae4f5fde383'
    >>> xxteang.encrypt_hex(data, key, rounds=1024)
    b'd391e3e5396fb34d86863e4521363269'


Catching Exceptions
---------------------

When calling these functions, a ``ValueError``, ``TypeError``, or ``OverflowError``
may be raised.  Note that invalid hex input raises ``binascii.Error``, which is
a subclass of ``ValueError``:

.. code-block:: python

    >>> import xxteang
    >>> from xxteang import XXTEA
    >>>
    >>> def try_catch(func, *args, **kwargs):
    ...     try:
    ...         func(*args, **kwargs)
    ...     except Exception as e:
    ...         print(e.__class__.__name__, ':', e)
    ...
    ...
    ...
    >>> try_catch(xxteang.decrypt, b'', key=b'')
    ValueError : Need a 16-byte key.
    >>> try_catch(xxteang.decrypt, b'', key=b' '*16)
    ValueError : Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> try_catch(xxteang.decrypt, b' '*8, key=b' '*16)
    ValueError : Invalid data, illegal padding. Could be using a wrong key.
    >>> try_catch(xxteang.decrypt_hex, b' '*8, key=b' '*16)
    Error : Non-hexadecimal digit found
    >>> try_catch(xxteang.decrypt_hex, b'abc', key=b' '*16)
    Error : Odd-length string
    >>> try_catch(xxteang.decrypt_hex, b'abcd', key=b' '*16)
    ValueError : Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> try_catch(xxteang.encrypt, b'x', b'k'*16, rounds=2**32)
    OverflowError : rounds value too large
    >>> try_catch(XXTEA, key=b'short')
    ValueError : Need a 16-byte key.
    >>> try_catch(XXTEA, key=b'k'*16, rounds=2**32)
    OverflowError : rounds value too large
