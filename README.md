# Project Archived

This prototype has moved into the PANDA organization at https://github.com/panda-re/qemu.


Future PANDA
----
A prototype dynamic analysis platform built atop QEMU's plugin interface.

## Build.
You may need ninja-build from apt
```
git clone ...
mkdir build
cd build
../configure --enable-plugins --target-list=i386-softmmu
make -j $(nproc)
```

# Run.
Look at the plugins available in `build/panda/`

Run a plugin, `ppp_srv` on a qcow:
```
./build/i386-softmmu/qemu-system-i386 \
  -plugin ./build/panda/libppp_srv.so\
 -display none\
  ~/.panda/ubuntu_1604_x86.qcow
```

Current status
----
- [x] PPP-style inter-plugin interactions (callbacks + direct calls)
- [ ] (partly done) API for accessing CPU state
- [ ] API for modifying CPU state


Current plugins
----
* `Syscalls3`: provide an `on_all_sys_enter` callback
* `Syscalls_logger`: use syscalls3 to log syscall numbers on enter
* `ppp_srv`: plugin which provides some PPP functions that other plugins can call
* `ppp_client{,2}`: plugin which interacts with `ppp_srv`
