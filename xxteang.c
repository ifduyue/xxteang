/*
 * Copyright (c) 2014-2026, Yue Du
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <Python.h>
#include <stdint.h>
#include <string.h>

#define VERSION "1.0.0.dev0"

#define DELTA 0x9e3779b9U
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

typedef struct xxteang_mod_state {
    PyObject *binascii_hexlify;
    PyObject *binascii_unhexlify;
} xxteang_mod_state;

static inline void btea(uint32_t *v, int n, uint32_t const key[4], unsigned int rounds)
{
    uint32_t y, z, sum;
    unsigned p, e;

    if (n > 1) {          /* Coding Part */
        rounds = rounds == 0 ? (unsigned)(6 + 52 / n) : rounds;
        sum = 0;
        z = v[n - 1];

        do {
            sum += DELTA;
            e = (sum >> 2) & 3;

            for (p = 0; p < (unsigned)(n - 1); p++) {
                y = v[p + 1];
                z = v[p] += MX;
            }

            y = v[0];
            z = v[n - 1] += MX;
        }
        while (--rounds);
    }
    else if (n < -1) {    /* Decoding Part */
        n = -n;
        rounds = rounds == 0 ? (unsigned)(6 + 52 / n) : rounds;
        sum = (uint32_t)(rounds * DELTA);
        y = v[0];

        do {
            e = (sum >> 2) & 3;

            for (p = (unsigned)(n - 1); p > 0; p--) {
                z = v[p - 1];
                y = v[p] -= MX;
            }

            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        }
        while (--rounds);
    }
}

static void bytes2longs(const char *in, Py_ssize_t inlen, uint32_t *out, int padding)
{
    Py_ssize_t i, nwords;
    int pad;
    const unsigned char *s = (const unsigned char *)in;
    unsigned char *b = (unsigned char *)out;

    /* Fast path: process 4 bytes at a time */
    nwords = inlen >> 2;
    for (i = 0; i < nwords; i++) {
#if PY_LITTLE_ENDIAN
        memcpy(&out[i], s + 4 * i, 4);
#else
        const unsigned char *p = s + 4 * i;
        out[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
#endif
    }

    /*
     * Copy the remaining 0-3 bytes, then pad to a multiple of 8 bytes.
     * Every output byte is written exactly once, so the caller does not
     * need to zero the buffer first.  Padding to 8 bytes also guarantees
     * the two 32-bit words (8 bytes) that XXTEA requires, so short
     * inputs need no extra handling.
     */
    i = nwords << 2;
    for (; i < inlen; i++) {
        b[i] = s[i];
    }
    if (padding) {
        pad = 8 - (inlen & 7);
        for (; i < inlen + pad; i++) {
            b[i] = (unsigned char)pad;
        }
    }
}

static Py_ssize_t longs2bytes(const uint32_t *in, Py_ssize_t inlen, char *out, int padding)
{
    Py_ssize_t i, outlen;
    int pad;
    unsigned char *s = (unsigned char *)out;

#if PY_LITTLE_ENDIAN
    /* Little endian: the words are already in the right byte order.
     * The in-place path (_decrypt_impl) needs no copy at all. */
    if (in != (const uint32_t *)out) {
        memcpy(out, in, (size_t)inlen * 4);
    }
#else
    /*
     * Big endian: write each word as little-endian bytes.  Snapshot the
     * whole word into a local before writing any of its bytes, because
     * in and out may alias (the in-place decrypt path).
     */
    for (i = 0; i < inlen; i++) {
        uint32_t word = in[i];
        s[4 * i]     = (unsigned char)(word & 0xFF);
        s[4 * i + 1] = (unsigned char)((word >> 8) & 0xFF);
        s[4 * i + 2] = (unsigned char)((word >> 16) & 0xFF);
        s[4 * i + 3] = (unsigned char)((word >> 24) & 0xFF);
    }
#endif

    outlen = inlen * 4;

    /* 8-byte PKCS#7-style unpadding. */
    if (padding) {
        pad = s[outlen - 1];
        if (pad < 1 || pad > 8) {
            /* invalid padding */
            return -1;
        }
        outlen -= pad;
        if (outlen < 0) {
            return -2;
        }
        for (i = outlen; i < inlen * 4; i++) {
            if (s[i] != pad) {
                return -3;
            }
        }
    }

    s[outlen] = '\0';

    /* How many bytes we've got */
    return outlen;
}

/*****************************************************************************
 * Module Functions ***********************************************************
 ****************************************************************************/

/*
 * One keyword argument slot.  `parse` stores the parsed value into `dst`;
 * a NULL `parse` stores the raw PyObject* into *(PyObject **)dst.
 * The slot index is also the positional argument index.
 */
typedef struct {
    const char *name;
    int (*parse)(PyObject *value, void *dst);
    void *dst;
} xxteang_kwarg;

typedef PyObject *(*xxteang_crypt_func)(const char *, Py_ssize_t,
                                        const char *, int, unsigned int);

static int
_parse_bool(PyObject *value, void *dst)
{
    int res = PyObject_IsTrue(value);
    if (res < 0)
        return -1;
    *(int *)dst = res;
    return 0;
}

static int
_parse_rounds(PyObject *obj, void *dst)
{
    unsigned long val = PyLong_AsUnsignedLong(obj);
    if (val == (unsigned long)-1 && PyErr_Occurred())
        return -1;
    if (val > UINT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "rounds value too large");
        return -1;
    }
    *(unsigned int *)dst = (unsigned int)val;
    return 0;
}

/*
 * Shared argument parser for the module functions and the XXTEA
 * constructor.  Positional arguments fill spec[0..nargs-1]; keywords are
 * matched by name and rejected if they collide with a filled slot or are
 * unknown.  Returns 0 on success, -1 on error with an exception set.
 * `funcname` is used in error messages (NULL for the module functions).
 * nspec must be <= 4.
 */
static int
_parse_kwargs(PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
              const char *funcname, const xxteang_kwarg *spec, Py_ssize_t nspec)
{
    Py_ssize_t i, j;

    if (nargs > nspec) {
        if (funcname == NULL) {
            PyErr_Format(PyExc_TypeError,
                "function takes at most %zd positional arguments", nspec);
        }
        else {
            PyErr_Format(PyExc_TypeError,
                "%s() takes at most %zd positional arguments", funcname, nspec);
        }
        return -1;
    }

    /* Positional arguments map to spec[0..nargs-1]. */
    for (i = 0; i < nargs; i++) {
        if (spec[i].parse) {
            if (spec[i].parse(args[i], spec[i].dst) < 0)
                return -1;
        }
        else {
            *((PyObject **)spec[i].dst) = args[i];
        }
    }

    /* Keyword arguments.  Slot j was already filled if j < nargs. */
    if (kwnames != NULL) {
        Py_ssize_t nkwargs = PyTuple_GET_SIZE(kwnames);
        for (i = 0; i < nkwargs; i++) {
            PyObject *name = PyTuple_GET_ITEM(kwnames, i);
            PyObject *value = args[nargs + i];

            for (j = 0; j < nspec; j++) {
                if (PyUnicode_CompareWithASCIIString(name, spec[j].name) == 0)
                    break;
            }
            if (j == nspec) {
                if (funcname == NULL) {
                    PyErr_Format(PyExc_TypeError,
                        "'%U' is an invalid keyword argument", name);
                }
                else {
                    PyErr_Format(PyExc_TypeError,
                        "'%U' is an invalid keyword argument for %s()",
                        name, funcname);
                }
                return -1;
            }
            if (j < nargs) {
                PyErr_Format(PyExc_TypeError,
                    "argument '%s' given both as positional and keyword",
                    spec[j].name);
                return -1;
            }
            if (spec[j].parse) {
                if (spec[j].parse(value, spec[j].dst) < 0)
                    return -1;
            }
            else {
                *((PyObject **)spec[j].dst) = value;
            }
        }
    }

    return 0;
}

/*
 * Parse all arguments of the module-level encrypt/decrypt functions.
 * Returns 0 on success, -1 on error with an exception set.
 */
static inline int
_parse_args(PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
            PyObject **data_obj, PyObject **key_obj,
            int *padding, unsigned int *rounds)
{
    PyObject *data = NULL, *key = NULL;
    int pad = 1;
    unsigned int r = 0;

    const xxteang_kwarg spec[] = {
        {"data", NULL, &data},
        {"key", NULL, &key},
        {"padding", _parse_bool, &pad},
        {"rounds", _parse_rounds, &r},
    };

    if (_parse_kwargs(args, nargs, kwnames, NULL, spec, 4) < 0)
        return -1;

    if (!data || !key) {
        PyErr_SetString(PyExc_TypeError,
            "function missing required arguments: 'data' and 'key'");
        return -1;
    }

    *data_obj = data;
    *key_obj = key;
    *padding = pad;
    *rounds = r;
    return 0;
}

static inline PyObject *
_call_one_arg(PyObject *func, PyObject *arg)
{
    if (func == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "module state not available");
        return NULL;
    }
    return PyObject_CallOneArg(func, arg);
}

/* Validate the key buffer length. Returns 0 on success, -1 on error. */
static inline int
_check_key_length(const Py_buffer *key)
{
    if (key->len != 16) {
        PyErr_SetString(PyExc_ValueError, "Need a 16-byte key.");
        return -1;
    }
    return 0;
}

/* Acquire buffers and validate key length. Returns 0 on success, -1 on error. */
static inline int
_get_buffers(PyObject *data_obj, PyObject *key_obj,
             Py_buffer *data, Py_buffer *key)
{
    if (PyObject_GetBuffer(data_obj, data, PyBUF_SIMPLE) < 0)
        return -1;
    if (PyObject_GetBuffer(key_obj, key, PyBUF_SIMPLE) < 0) {
        PyBuffer_Release(data);
        return -1;
    }
    if (_check_key_length(key) < 0) {
        PyBuffer_Release(data);
        PyBuffer_Release(key);
        return -1;
    }
    return 0;
}

static inline PyObject *
_call_module_crypt(PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
                   xxteang_crypt_func crypt)
{
    Py_buffer data = {NULL}, key = {NULL};
    PyObject *data_obj, *key_obj;
    int padding;
    unsigned int rounds;

    if (_parse_args(args, nargs, kwnames, &data_obj, &key_obj, &padding, &rounds) < 0)
        return NULL;
    if (_get_buffers(data_obj, key_obj, &data, &key) < 0)
        return NULL;

    PyObject *retval = crypt(data.buf, data.len, key.buf, padding, rounds);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    return retval;
}

/* Set the shared "bad data length" ValueError. */
static inline PyObject *
_raise_bad_length(void)
{
    PyErr_SetString(PyExc_ValueError,
        "Data length must be a multiple of 4 bytes and must not be less than 8 bytes");
    return NULL;
}

/*
 * Internal encrypt implementation — takes raw buffers, returns PyBytes or NULL.
 *
 * Writes directly into the PyBytes object's internal buffer to avoid an
 * intermediate heap allocation and an extra longs->bytes copy.
 */
static inline PyObject *
_encrypt_impl(const char *data_buf, Py_ssize_t data_len,
              const char *key_buf, int padding, unsigned int rounds)
{
    uint32_t k[4] = {0};

    if (!padding && (data_len < 8 || (data_len & 3) != 0)) {
        return _raise_bad_length();
    }

    /* 8-byte PKCS#7 padding rounds up to a multiple of 8 bytes
     * (i.e. an even number of 32-bit words), so the word count is
     * ((data_len >> 3) + 1) * 2. */
    Py_ssize_t alen = padding ? ((data_len >> 3) + 1) * 2 : (data_len >> 2);
    if (alen > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "data too large");
        return NULL;
    }

    PyObject *retval = PyBytes_FromStringAndSize(NULL, alen << 2);
    if (!retval) {
        return NULL;
    }

    uint32_t *d = (uint32_t *)PyBytes_AsString(retval);

    Py_BEGIN_ALLOW_THREADS
    bytes2longs(data_buf, data_len, d, padding);
    bytes2longs(key_buf, 16, k, 0);
    btea(d, (int)alen, k, rounds);
#if !PY_LITTLE_ENDIAN
    /*
     * On a big-endian host the raw uint32_t memory layout in the PyBytes
     * buffer would be big-endian, but we want the ciphertext to be
     * little-endian on the wire.  Rewrite the buffer word-by-word as
     * little-endian bytes (safe because we read each word before writing
     * its bytes).
     */
    longs2bytes(d, alen, (char *)d, 0);
#endif
    Py_END_ALLOW_THREADS

    return retval;
}

/*
 * Internal decrypt implementation — takes raw buffers, returns PyBytes or NULL.
 *
 * The ciphertext length is already a multiple of 4 and >= 8, so we decrypt
 * in place inside the output PyBytes object and then shrink it if padding
 * is enabled.
 */
static inline PyObject *
_decrypt_impl(const char *data_buf, Py_ssize_t data_len,
              const char *key_buf, int padding, unsigned int rounds)
{
    uint32_t k[4] = {0};

    if ((data_len & 3) != 0 || data_len < 8) {
        return _raise_bad_length();
    }

    Py_ssize_t alen = data_len / 4;
    if (alen > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "data too large");
        return NULL;
    }

    PyObject *retval = PyBytes_FromStringAndSize(NULL, data_len);
    if (!retval) {
        return NULL;
    }

    char *retbuf = PyBytes_AsString(retval);
    Py_ssize_t rc;
    Py_BEGIN_ALLOW_THREADS
    bytes2longs(data_buf, data_len, (uint32_t *)retbuf, 0);
    bytes2longs(key_buf, 16, k, 0);
    btea((uint32_t *)retbuf, -(int)alen, k, rounds);
    rc = longs2bytes((uint32_t *)retbuf, alen, retbuf, padding);
    Py_END_ALLOW_THREADS

    if (padding) {
        if (rc >= 0) {
            /* Remove padding bytes. */
            Py_SET_SIZE(retval, rc);
        }
        else {
            PyErr_SetString(PyExc_ValueError,
                "Invalid data, illegal padding. Could be using a wrong key.");
            Py_DECREF(retval);
            retval = NULL;
        }
    }

    return retval;
}


PyDoc_STRVAR(
    xxteang_encrypt_doc,
    "encrypt(data, key, padding=True, rounds=0)\n\n"
    "Encrypt bytes-like data with a 16-byte key and return bytes.");

static PyObject *
xxteang_encrypt(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    (void)self;
    return _call_module_crypt(args, nargs, kwnames, _encrypt_impl);
}


PyDoc_STRVAR(
    xxteang_encrypt_hex_doc,
    "encrypt_hex(data, key, padding=True, rounds=0)\n\n"
    "Encrypt bytes-like data with a 16-byte key and return hex-encoded bytes.");

static PyObject *
xxteang_encrypt_hex(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *tmp = _call_module_crypt(args, nargs, kwnames, _encrypt_impl);
    if (!tmp)
        return NULL;

    xxteang_mod_state *state = (xxteang_mod_state*)PyModule_GetState(self);
    PyObject *retval = _call_one_arg(state ? state->binascii_hexlify : NULL, tmp);
    Py_DECREF(tmp);
    return retval;
}


PyDoc_STRVAR(
    xxteang_decrypt_doc,
    "decrypt(data, key, padding=True, rounds=0)\n\n"
    "Decrypt bytes-like data with a 16-byte key and return bytes.");

static PyObject *
xxteang_decrypt(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    (void)self;
    return _call_module_crypt(args, nargs, kwnames, _decrypt_impl);
}


PyDoc_STRVAR(
    xxteang_decrypt_hex_doc,
    "decrypt_hex(data, key, padding=True, rounds=0)\n\n"
    "Decrypt hex-encoded data with a 16-byte key and return bytes.");

static PyObject *
xxteang_decrypt_hex(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    Py_buffer data = {NULL}, key = {NULL};
    PyObject *data_obj, *key_obj;
    int padding;
    unsigned int rounds;

    if (_parse_args(args, nargs, kwnames, &data_obj, &key_obj, &padding, &rounds) < 0)
        return NULL;

    xxteang_mod_state *state = (xxteang_mod_state*)PyModule_GetState(self);
    PyObject *tmp = _call_one_arg(state ? state->binascii_unhexlify : NULL, data_obj);
    if (!tmp)
        return NULL;

    if (_get_buffers(tmp, key_obj, &data, &key) < 0) {
        Py_DECREF(tmp);
        return NULL;
    }

    PyObject *retval = _decrypt_impl(data.buf, data.len, key.buf, padding, rounds);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    Py_DECREF(tmp);
    return retval;
}

/*****************************************************************************
 * XXTEA Type ****************************************************************
 ****************************************************************************/

typedef struct {
    PyObject_HEAD
    char key[16];
    unsigned int rounds;
    int padding;
} xxteang_object;

static PyObject *
_call_object_crypt(xxteang_object *self, PyObject *data, xxteang_crypt_func crypt)
{
    Py_buffer data_buf = {NULL};
    if (PyObject_GetBuffer(data, &data_buf, PyBUF_SIMPLE) < 0)
        return NULL;

    PyObject *retval = crypt(data_buf.buf, data_buf.len,
                             self->key, self->padding, self->rounds);
    PyBuffer_Release(&data_buf);
    return retval;
}

/*
 * Parse XXTEA(key, padding=True, rounds=0) for both the vectorcall
 * constructor and the legacy tp_init fallback.
 * Returns 0 on success, -1 on error with an exception set.
 */
static int
_parse_init_args(PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
                 PyObject **key_obj, int *padding, unsigned int *rounds)
{
    PyObject *key = NULL;
    int pad = 1;
    unsigned int r = 0;

    const xxteang_kwarg spec[] = {
        {"key", NULL, &key},
        {"padding", _parse_bool, &pad},
        {"rounds", _parse_rounds, &r},
    };

    if (_parse_kwargs(args, nargs, kwnames, "XXTEA", spec, 3) < 0)
        return -1;

    if (key == NULL) {
        PyErr_SetString(PyExc_TypeError,
            "XXTEA() missing required argument: 'key'");
        return -1;
    }

    *key_obj = key;
    *padding = pad;
    *rounds = r;
    return 0;
}

/*
 * Apply parsed key/padding/rounds to a fresh xxteang_object.
 * Returns 0 on success, -1 on error with an exception set.
 */
static int
_apply_init_args(xxteang_object *self, PyObject *key_obj, int padding, unsigned int rounds)
{
    Py_buffer key_buf = {NULL};

    if (PyObject_GetBuffer(key_obj, &key_buf, PyBUF_SIMPLE) < 0)
        return -1;

    if (_check_key_length(&key_buf) < 0) {
        PyBuffer_Release(&key_buf);
        return -1;
    }

    memcpy(self->key, key_buf.buf, 16);
    self->rounds = rounds;
    self->padding = padding;
    PyBuffer_Release(&key_buf);
    return 0;
}

/*
 * Legacy tp_init fallback.  Convert the (args, kwargs) tuple/dict form into
 * the vectorcall layout and reuse _parse_init_args so there is only one copy
 * of the argument-parsing logic.
 */
static int
xxteang_object_init(xxteang_object *self, PyObject *args, PyObject *kwargs)
{
    PyObject *key_obj = NULL;
    int padding = 1;
    unsigned int rounds = 0;

    Py_ssize_t nargs = PyTuple_GET_SIZE(args);
    Py_ssize_t nkwargs = (kwargs != NULL) ? PyDict_GET_SIZE(kwargs) : 0;

    if (nargs + nkwargs > 3) {
        PyErr_SetString(PyExc_TypeError,
            "XXTEA() takes at most 3 arguments");
        return -1;
    }

    PyObject *all_args[3] = {NULL};
    for (Py_ssize_t i = 0; i < nargs; i++) {
        all_args[i] = PyTuple_GET_ITEM(args, i);
    }

    PyObject *kwnames = NULL;
    if (nkwargs > 0) {
        kwnames = PyTuple_New(nkwargs);
        if (kwnames == NULL)
            return -1;
        Py_ssize_t pos = 0, idx = 0;
        PyObject *key, *value;
        while (PyDict_Next(kwargs, &pos, &key, &value)) {
            if (!PyUnicode_Check(key)) {
                PyErr_SetString(PyExc_TypeError, "keywords must be strings");
                Py_DECREF(kwnames);
                return -1;
            }
            Py_INCREF(key);
            PyTuple_SET_ITEM(kwnames, idx, key);
            all_args[nargs + idx] = value;
            idx++;
        }
    }

    int rc = _parse_init_args(all_args, nargs, kwnames,
                              &key_obj, &padding, &rounds);
    Py_XDECREF(kwnames);
    if (rc < 0)
        return -1;

    return _apply_init_args(self, key_obj, padding, rounds);
}

/* Vectorcall constructor for XXTEA(key, ...). */
static PyObject *
xxteang_vectorcall(PyObject *type, PyObject *const *args,
                 size_t nargsf, PyObject *kwnames)
{
    PyObject *key_obj = NULL;
    int padding = 1;
    unsigned int rounds = 0;
    Py_ssize_t nargs = PyVectorcall_NARGS(nargsf);

    if (_parse_init_args(args, nargs, kwnames, &key_obj, &padding, &rounds) < 0)
        return NULL;

    /* Allocate a new instance via tp_alloc (not PyObject_New, because it
     * must be a heap type with the right ob_type). */
    PyObject *self = ((PyTypeObject *)type)->tp_alloc((PyTypeObject *)type, 0);
    if (self == NULL)
        return NULL;

    if (_apply_init_args((xxteang_object *)self, key_obj, padding, rounds) < 0) {
        Py_DECREF(self);
        return NULL;
    }
    return self;
}

static void
xxteang_object_dealloc(xxteang_object *self)
{
    PyTypeObject *tp = Py_TYPE(self);
    tp->tp_free((PyObject *)self);
    Py_DECREF(tp);
}

static PyObject *
xxteang_object_encrypt(xxteang_object *self, PyObject *data)
{
    return _call_object_crypt(self, data, _encrypt_impl);
}

static PyObject *
xxteang_object_decrypt(xxteang_object *self, PyObject *data)
{
    return _call_object_crypt(self, data, _decrypt_impl);
}

static PyObject *
xxteang_object_encrypt_hex(xxteang_object *self, PyObject *data)
{
    PyObject *tmp = _call_object_crypt(self, data, _encrypt_impl);
    if (!tmp)
        return NULL;

    xxteang_mod_state *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *retval = _call_one_arg(state ? state->binascii_hexlify : NULL, tmp);
    Py_DECREF(tmp);
    return retval;
}

static PyObject *
xxteang_object_decrypt_hex(xxteang_object *self, PyObject *data)
{
    xxteang_mod_state *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *tmp = _call_one_arg(state ? state->binascii_unhexlify : NULL, data);
    if (!tmp)
        return NULL;

    PyObject *retval = _call_object_crypt(self, tmp, _decrypt_impl);
    Py_DECREF(tmp);
    return retval;
}

static PyMethodDef xxteang_object_methods[] = {
    {"encrypt", (PyCFunction)xxteang_object_encrypt, METH_O,
     "encrypt(data)\n\n"
     "Encrypt data with the stored key, padding, and rounds."},
    {"decrypt", (PyCFunction)xxteang_object_decrypt, METH_O,
     "decrypt(data)\n\n"
     "Decrypt data with the stored key, padding, and rounds."},
    {"encrypt_hex", (PyCFunction)xxteang_object_encrypt_hex, METH_O,
     "encrypt_hex(data)\n\n"
     "Encrypt data and return hex-encoded bytes."},
    {"decrypt_hex", (PyCFunction)xxteang_object_decrypt_hex, METH_O,
     "decrypt_hex(data)\n\n"
     "Decrypt hex-encoded data and return original bytes."},
    {NULL, NULL, 0, NULL}
};


static PyType_Slot xxteang_type_slots[] = {
    {Py_tp_dealloc, (void *)xxteang_object_dealloc},
    {Py_tp_doc, (void *)"XXTEA(key, padding=True, rounds=0)\n\n"
                "XXTEA cipher object.  rounds=0 means auto: 6 + 52 / n, "
                "where n is the number of 32-bit words in the data.\n"
                "Methods: encrypt(data), decrypt(data), "
                "encrypt_hex(data), decrypt_hex(data)."},
    {Py_tp_methods, xxteang_object_methods},
    {Py_tp_init, (void *)xxteang_object_init},
    {Py_tp_new, PyType_GenericNew},
    {0, NULL}
};

static PyType_Spec xxteang_type_spec = {
    .name = "xxteang.XXTEA",
    .basicsize = sizeof(xxteang_object),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030c0000
           | Py_TPFLAGS_IMMUTABLETYPE
#endif
           ,
    .slots = xxteang_type_slots,
};

/*****************************************************************************
 * Module Init ****************************************************************
 ****************************************************************************/

PyDoc_STRVAR(
    xxteang_doc,
    "xxteang is a simple block cipher (XXTEA) implemented as a C extension.\n"
    "\n"
    "Functions:\n"
    "    encrypt(data, key, padding=True, rounds=0)\n"
    "    decrypt(data, key, padding=True, rounds=0)\n"
    "    encrypt_hex(data, key, padding=True, rounds=0)\n"
    "    decrypt_hex(data, key, padding=True, rounds=0)\n"
    "\n"
    "Type:\n"
    "    XXTEA(key, padding=True, rounds=0)  -- reusable cipher object\n"
    "\n"
    "Constants:\n"
    "    VERSION  -- version string of this module");

static int _exec(PyObject *module)
{
    xxteang_mod_state *state = (xxteang_mod_state*)PyModule_GetState(module);
    if (state == NULL)
        return -1;

    PyObject *binascii = PyImport_ImportModule("binascii");
    if (!binascii) {
        return -1;
    }

    state->binascii_hexlify = PyObject_GetAttrString(binascii, "hexlify");
    state->binascii_unhexlify = PyObject_GetAttrString(binascii, "unhexlify");
    Py_DECREF(binascii);

    if (!state->binascii_hexlify || !state->binascii_unhexlify) {
        Py_XDECREF(state->binascii_hexlify);
        Py_XDECREF(state->binascii_unhexlify);
        state->binascii_hexlify = NULL;
        state->binascii_unhexlify = NULL;
        PyErr_SetString(PyExc_AttributeError,
            "Failed to get binascii.hexlify or binascii.unhexlify");
        return -1;
    }

    if (PyModule_AddStringConstant(module, "VERSION", VERSION) < 0)
        return -1;

    PyObject *xxteang_type = PyType_FromModuleAndSpec(module, &xxteang_type_spec, NULL);
    if (xxteang_type == NULL)
        return -1;

#if PY_VERSION_HEX >= 0x03090000
    /*
     * Hook up the vectorcall constructor.  Since 3.9, PyType_Type sets its
     * tp_vectorcall_offset to the offset of tp_vectorcall within
     * PyTypeObject, so _PyVectorcall_Function reads xxteang_type->tp_vectorcall
     * directly.
     *
     * The flag is set here (not in PyType_Spec) to avoid a 3.12+
     * debug-build assertion on heap types without tp_vectorcall_offset.
     */
    ((PyTypeObject *)xxteang_type)->tp_flags |= Py_TPFLAGS_HAVE_VECTORCALL;
    ((PyTypeObject *)xxteang_type)->tp_vectorcall = xxteang_vectorcall;
#else
#error "xxteang requires Python >= 3.9"
#endif

    if (PyDict_SetItemString(PyModule_GetDict(module), "XXTEA", xxteang_type) < 0) {
        Py_DECREF(xxteang_type);
        return -1;
    }
    Py_DECREF(xxteang_type);

    return 0;
}

static PyMethodDef methods[] = {
    {"encrypt", (PyCFunction)xxteang_encrypt, METH_FASTCALL | METH_KEYWORDS, xxteang_encrypt_doc},
    {"decrypt", (PyCFunction)xxteang_decrypt, METH_FASTCALL | METH_KEYWORDS, xxteang_decrypt_doc},
    {"encrypt_hex", (PyCFunction)xxteang_encrypt_hex, METH_FASTCALL | METH_KEYWORDS, xxteang_encrypt_hex_doc},
    {"decrypt_hex", (PyCFunction)xxteang_decrypt_hex, METH_FASTCALL | METH_KEYWORDS, xxteang_decrypt_hex_doc},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef_Slot slots[] = {
    {Py_mod_exec, _exec},
#if PY_VERSION_HEX >= 0x030c0000
    /* Subinterpreter + per-interpreter GIL support (3.12+).
       Value 2 (PER_INTERPRETER_GIL_SUPPORTED) is required
       because value 1 (SUPPORTED, the default) means "shared
       GIL only", which _xxsubinterpreters rejects on 3.12. */
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
#ifdef Py_GIL_DISABLED
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
#endif
    {0, NULL}
};


static int _traverse(PyObject *module, visitproc visit, void *arg)
{
    xxteang_mod_state *state = (xxteang_mod_state*)PyModule_GetState(module);
    if (state) {
        Py_VISIT(state->binascii_hexlify);
        Py_VISIT(state->binascii_unhexlify);
    }
    return 0;
}

static int _clear(PyObject *module)
{
    xxteang_mod_state *state = (xxteang_mod_state*)PyModule_GetState(module);
    if (state) {
        Py_CLEAR(state->binascii_hexlify);
        Py_CLEAR(state->binascii_unhexlify);
    }
    return 0;
}

static void _free(void *module)
{
    _clear((PyObject *)module);
}

static struct PyModuleDef moduledef = {
    .m_base     = PyModuleDef_HEAD_INIT,
    .m_name     = "xxteang",
    .m_doc      = xxteang_doc,
    .m_size     = sizeof(struct xxteang_mod_state),
    .m_methods  = methods,
    .m_slots    = slots,
    .m_traverse = _traverse,
    .m_clear    = _clear,
    .m_free     = _free,
};

PyMODINIT_FUNC PyInit_xxteang(void)
{
    return PyModuleDef_Init(&moduledef);
}
