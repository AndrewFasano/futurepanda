#ifndef SYSCALLS_H
#define SYSCALLS_H

/* 
 * Non-public functions 
 */
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
