Future PANDA
----
An attempt to get some of PANDA built on top of the QEMU 6 plugin interface


Build. You may need ninja-build from apt
```
git clone ...
mkdir build
cd build
../configure --enable-plugins --target-list=i386-softmmu
make -j $(nproc)
```

Look at the plugins  in `panda/`

Run a plugin, `foo` on a qcow:
```
./i386-softmmu/qemu-system-i386 \
  -plugin ./panda/libfoo.so\
  -display none\
  ~/.panda/ubuntu_1604_x86.qcow
```

Current status
----
[x] PPP-style inter-plugin interactions (callbacks + direct calls)
[partial] API for accessing CPU state
[] API for modifying CPU state


Current plugins
----
* `Syscalls3`: provide an `on_all_sys_enter` callback
* `Syscalls_logger`: use syscalls3 to log syscall numbers on enter
* `ppp_srv`: plugin which provides some PPP functions that other plugins can call
* `ppp_client{,2}`: plugin which interacts with `ppp_srv`
