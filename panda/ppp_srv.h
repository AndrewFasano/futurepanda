// Idealy we want to have one macro per exposed function, be it a callback or a normal fn
//PPP_CB_TYPEDEF(void, on_exit, int, bool); => void on_exit(int, bool); typedef void (*on_exit_t)(int,bool)


#ifndef PPP_SRV_H
#define PPP_SRV_H
//void on_exit(int, bool); // XXX: Incompatable with some macroized codegen
typedef void (*on_exit_t)(int, bool);

//PPP_CB_TYPEDEF(void, on_exit_t, int, bool); => both of the following
int do_add(int x);
typedef int (*do_add_t)(int x);

int do_sub(int x);
typedef int (*do_sub_t)(int x);
#endif

// Do not define these for ppp_srv.c - if we do the constructor will dlsym on itself and cause
// issues

#ifndef PLUGIN_MAIN
// TODO: unify this macro to support a list of fn names and generate a single constructor
PPP_IMPORT(ppp_srv, do_add);
PPP_IMPORT(ppp_srv, do_sub);
#endif

