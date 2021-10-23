t = []
foreach i : ['my_tcg', 'ppp_srv', 'ppp_client' , 'ppp_client2']
  t += shared_module(i, files(i + '.c'),
                     include_directories: '../include/qemu',
                     dependencies: glib)
endforeach
alias_target('panda-plugins', t)
