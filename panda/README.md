PANDA, but in QEMU
===

Temporary home for test plugins.

## `ppp_srv`
Simple plugin which provides a simple PPP-style callback, `on_exit` which runs at the end of execution
Run with `-plugin ./build/panda/libppp_client.so`. Be sure to Ctrl+C to make the callback trigger.

## `ppp_client`
Simple plugin which registers a PPP function to run on the `on_exit` callback provided by `ppp_srv`
Run with `-plugin ./build/panda/libppp_client.so -plugin ./build/panda/libppp_srv.so`

## `my_tcg`
Example to modify the TCG stream on block translation to end with call into a plugin-provided function. Currently broken
