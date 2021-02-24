t = []
foreach i : ['my_tcg']
  t += shared_module(i, files(i + '.c'),
                     include_directories: '../include/qemu',
                     dependencies: glib)
endforeach
alias_target('panda-plugins', t)
