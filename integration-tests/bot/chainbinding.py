#!/usr/bin/env python3
import os
import sys
import ctypes

from decouple import config

target_dir = config('CARGO_TARGET_DIR', os.path.join(os.path.dirname(__file__), '../../target'))
build_profile = config('BUILD_PROFILE', 'debug')
ext = 'dylib' if sys.platform == 'darwin' else 'so'
dll = ctypes.cdll.LoadLibrary(os.path.join(target_dir, '%s/libcro_clib.%s' % (build_profile, ext)))

dll.cro_jsonrpc_call.argtypes = dll.cro_jsonrpc_call_mock.argtypes = [
    ctypes.c_char_p,  # storage_dir
    ctypes.c_char_p,  # websocket_url
    ctypes.c_char,    # network id
    ctypes.c_char_p,  # request
    ctypes.c_char_p,  # buf
    ctypes.c_size_t,  # buf_size
    ctypes.c_void_p,  # progress callback
    ctypes.c_void_p,  # user_data
]
dll.cro_jsonrpc_call.restype = dll.cro_jsonrpc_call_mock.restype = ctypes.c_int

dll.cro_create_jsonrpc.argtypes = dll.cro_create_mock_jsonrpc.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # rpc_out
    ctypes.c_char_p,                  # storage_dir
    ctypes.c_char_p,                  # websocket_url
    ctypes.c_char,                    # network_id
    ctypes.c_void_p,                  # progress callback
]
dll.cro_create_jsonrpc.restype = dll.cro_create_mock_jsonrpc.restype = ctypes.c_int

dll.cro_run_jsonrpc.argtypes = [
    ctypes.c_void_p,  # jsonrpc
    ctypes.c_char_p,  # request
    ctypes.c_char_p,  # buf
    ctypes.c_size_t,  # buf_size
    ctypes.c_void_p,  # user_data
]
dll.cro_run_jsonrpc.restype = ctypes.c_int

dll.cro_destroy_jsonrpc.argtypes = [
    ctypes.c_void_p,  # jsonrpc
]
dll.cro_destroy_jsonrpc.restype = ctypes.c_int


class RpcBinding:
    def __init__(self, storage, tendermint_ws, network_id=0xab, mock_mode=False):
        create_jsonrpc = dll.cro_create_mock_jsonrpc if mock_mode else dll.cro_create_jsonrpc
        self._p = ctypes.c_void_p()
        retcode = create_jsonrpc(ctypes.byref(self._p), storage.encode(), tendermint_ws.encode(), network_id, None)
        assert retcode == 0, 'create jsonrpc failed'

    def __del__(self):
        dll.cro_destroy_jsonrpc(self._p)

    def call(self, req):
        rsp = ctypes.create_string_buffer(10240)
        retcode = dll.cro_run_jsonrpc(self._p, req.encode(), rsp, len(rsp), None)
        assert retcode == 0, rsp.value
        return rsp.value


if __name__ == '__main__':
    import fire
    fire.Fire(RpcBinding)
