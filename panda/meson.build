t = []
foreach i : ['ppp_srv', 'ppp_client' ]
  t += shared_module(i, files(i + '.c'),
                     include_directories: '../include/qemu',
                     dependencies: glib)
endforeach
alias_target('panda-plugins', t)
