#ifndef SYSCALLS3_H
#define SYSCALLS3_H
// PPP functions
//PPP_CB_TYPEDEF(void, on_all_sys_enter, uint64_t, uint64_t);
void (*on_all_sys_enter)(uint64_t pc, uint64_t callno);
typedef void (*on_all_sys_enter_t)(uint64_t pc, uint64_t callno);


// Regular functions
typedef bool (*is_syscall_t)(unsigned char* buf, size_t buf_len);
bool is_syscall_i386(unsigned char* buf, size_t buf_len);
bool is_syscall_x86_64(unsigned char* buf, size_t buf_len);
bool is_syscall_arm(unsigned char* buf, size_t buf_len);
bool is_syscall_aarch64(unsigned char* buf, size_t buf_len);
bool is_syscall_mips(unsigned char* buf, size_t buf_len);
bool is_syscall_other(unsigned char* buf, size_t buf_len);

typedef uint64_t (*get_callno_t)(bool* error);
uint64_t get_callno_i386(bool* error);
uint64_t get_callno_x86_64(bool* error);
uint64_t get_callno_arm(bool* error);
uint64_t get_callno_aarch64(bool* error);
uint64_t get_callno_mips(bool* error);
uint64_t get_callno_other(bool* error);


#endif

#ifndef PLUGIN_MAIN
// TODO: unify this macro to support a list of fn names and generate a single constructor
PPP_IMPORT(syscalls3, on_all_sys_enter);
#endif

