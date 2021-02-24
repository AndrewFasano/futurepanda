Future PANDA
----
An attempt to get PANDA-style TCG callbacks working in upstream QEMU (5.2.50) through
the QEMU plugin interface.


Build. You may need ninja-build from apt
```
git clone ...
mkdir build
cd build
../configure --enable-plugins --target-list=i386-softmmu
make -j $(nproc)
```

Look at the plugin `panda/my_tcg.c`

Run the plugin on a qcow:
```
./i386-softmmu/qemu-system-i386 \
  -plugin ./panda/libmy_tcg.so\
  -display none\
  ~/.panda/ubuntu_1604_x86.qcow
```

Output:
```
Instrumenting block at: 0xfffffff0
Insert call
Func called 0x1 times
Instrumenting block at: 0xfe05b
Insert call
Func called 0x2 times
Instrumenting block at: 0xfe066
Insert call
Func called 0x3 times
Instrumenting block at: 0xfe06a
Insert call
Func called 0x4 times
Instrumenting block at: 0xfe070
Insert call
Func called 0x5 times
Instrumenting block at: 0xfcf9c
Insert call
Func called 0x6 times
Instrumenting block at: 0xfcfd1
Insert call
Func called 0x7 times
Instrumenting block at: 0xfcfd9
Insert call
Func called 0x8 times
PANDA: need to fix this - exec has stalled - are we in an infite loop with insert_call?
qemu-system-i386: ../accel/tcg/cpu-exec.c:694: cpu_loop_exec_tb: Assertion `icount_enabled()' failed.
Aborted (core dumped)
```

Current status:
----
I think it gets stuck in an infinte loop repeatedly inserting calls into the same basic block after like 10 blocks.

Wishlist:
----
[] Pass custom arguments to callbacks
[] Pass CPUState or `qemu_plugin_tb` to callbacks
[] Expand plugin api (plugins/api.c) to provide more features - `current_pc`
