
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <queue>
#include <string>

#define MODULE_NAME "EAPModule"
#define MODULE_DESCRIPTION "A EAP module\nPackets received are answered according to wpa_supplicant/hostapd implementation"

extern "C"
{
#include "includes.h"
#include "common.h"
#include "eap_peer/eap.h"
#include "eap_peer/eap_config.h"
#include "wpabuf.h"
#include "EAPModule.h"
}

static PyObject *PythonError;

uint8_t eap_peer_initialized = 0;
const u8 *peer_key;
size_t peer_key_len;

void ReverseBytes(uint8_t *start, int size)
{
    uint8_t *istart = start, *iend = istart + size;
    std::reverse(istart, iend);
}

static PyObject *configure_peer(PyObject *self, PyObject *args)
{
    Py_buffer username, password, certificate;

    if (eap_peer_initialized == 0)
    {
        eap_peer_initialized = 1;
    }
    else
    {
        eap_peer_deinit();
        peer_key = NULL;
        peer_key_len = 0;
    }

    if (!PyArg_ParseTuple(args, "s*s*s*", &username, &password, &certificate))
    {
        Py_RETURN_NONE;
    }

    if (certificate.len > 0)
    {
        eap_peer_init((const u8 *)username.buf, (const u8 *)password.buf, (const u8 *)certificate.buf);
    }
    else
    {
        eap_peer_init((const u8 *)username.buf, (const u8 *)password.buf, NULL);
    }

    PyBuffer_Release(&username);
    PyBuffer_Release(&password);
    PyBuffer_Release(&certificate);

    Py_RETURN_NONE;
}

static PyObject *send_peer_request(PyObject *self, PyObject *args)
{
    Py_buffer request;
    struct peer_response r;

    if (!PyArg_ParseTuple(args, "s*", &request))
    {
        return NULL;
    }

    eap_peer_rx((const u8 *)request.buf, request.len);
    r = eap_peer_step();

    if (r.key_available)
    {
        peer_key = r.key;
        peer_key_len = r.key_len;
    }

    if (r.response)
    {
        PyObject *obj = Py_BuildValue("s#", wpabuf_head(r.response), wpabuf_len((r.response)));
        wpabuf_free(r.response);
        return obj;
    }

    PyBuffer_Release(&request);

    Py_RETURN_NONE;
}

static PyObject *get_key_peer(PyObject *self, PyObject *args)
{
    if (peer_key)
        return Py_BuildValue("s#", peer_key, peer_key_len);
    else
        Py_RETURN_NONE;
}

static PyObject *restart_peer(PyObject *self, PyObject *args)
{
    eap_peer_reset();
    peer_key = NULL;
    peer_key_len = 0;
    Py_RETURN_NONE;
}

static PyMethodDef module_methods[] = {
    {
        "configure_peer",
        configure_peer,
        METH_VARARGS,
        "Configure the EAP username, password and optional certificate file.",
    },
    {
        "send_peer_request",
        send_peer_request,
        METH_VARARGS,
        "Send EAP raw packet to the SMP peer.\nA successful processing will return a string response\nError will return None",
    },
    {
        "get_key_peer",
        get_key_peer,
        METH_NOARGS,
        "Get Pairwise Master Key from peer",
    },
    {
        "restart_peer",
        restart_peer,
        METH_NOARGS,
        "Restart peer",
    },

    {NULL, NULL, 0, NULL}, // sentinel
};

#if PY_MAJOR_VERSION >= 3
static PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    MODULE_NAME,
    MODULE_DESCRIPTION,
    -1,
    module_methods,
};

PyMODINIT_FUNC PyInit_EAPModule()
{
    PyObject *module;

    module = PyModule_Create(&module_definition);
    if (module == NULL)
    {
        return NULL;
    }
    PythonError = PyErr_NewException(MODULE_NAME ".Error", NULL, NULL);
    Py_INCREF(PythonError);
    PyModule_AddObject(module, "Error", PythonError);
    return module;
}
#else
PyMODINIT_FUNC initEAPModule()
{
    PyObject *module;

    module = Py_InitModule3(
        MODULE_NAME, module_methods, MODULE_DESCRIPTION);
    if (module == NULL)
    {
        return;
    }
    PythonError = PyErr_NewException((char *)MODULE_NAME ".Error", NULL, NULL);
    Py_INCREF(PythonError);
    PyModule_AddObject(module, "Error", PythonError);
}
#endif