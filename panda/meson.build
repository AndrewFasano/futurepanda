t = []
foreach i : ['ppp_srv', 'ppp_client' , 'ppp_client2', 'syscalls3', 'syscalls_logger', 'my_tcg']
  t += shared_module(i, files(i + '.c'),
                     include_directories: '../include/qemu',
                     dependencies: glib)
endforeach
alias_target('panda-plugins', t)
