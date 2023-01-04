#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <unordered_set>
#include <plugin-qpp.h>

// Internal headers
#include "osi_types.h"
#include "osi_linux.h"
#include "osi_linux_int_fns.h"
#include "default_profile.h"

// Other plugins
extern "C" {
#include <qemu-plugin.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "osi_linux";
#include "../osi.h"
#include "../hw_proc_id.h"
}
#include "../syscalls.h"

void on_first_syscall(gpointer evdata, gpointer udata);

// Using these
void on_get_process(gpointer evdata, gpointer udata);
void on_get_current_process_handle(gpointer evdata, gpointer udata);
void on_get_current_process(gpointer evdata, gpointer udata);

// Not yet using these
//void on_get_process_handles(GArray **out);
//void on_get_processes(GArray **out);
void on_get_mappings(OsiProc *p, GArray **out);
//void on_get_current_thread(OsiThread *t);

void init_per_cpu_offsets();
struct kernelinfo ki;
struct KernelProfile const *kernel_profile;

extern const char *qemu_file;
bool osi_initialized;
static bool first_osi_check = true;
char * target_name;

/**
 * @brief Resolves a file struct and returns its full pathname.
 */
static char *get_file_name(target_ptr_t file_struct) {
    char *name = NULL;
    target_ptr_t file_dentry, file_mnt;

    // Read addresses for dentry, vfsmnt structs.
    file_dentry = get_file_dentry(file_struct);
    file_mnt = get_file_mnt(file_struct);

    if (unlikely(file_dentry == (target_ptr_t)NULL || file_mnt == (target_ptr_t)NULL)) {
        LOG_INFO("failure resolving file struct " TARGET_PTR_FMT "/" TARGET_PTR_FMT, file_dentry, file_mnt);
        return NULL;
    }

    char *s1, *s2;
    s1 = read_vfsmount_name(file_mnt);
    s2 = read_dentry_name(file_dentry);
    name = g_strconcat(s1, s2, NULL);
    g_free(s1);
    g_free(s2);

    return name;
}

static uint64_t get_file_position(target_ptr_t file_struct) {
    return get_file_pos(file_struct);
}

static target_ptr_t get_file_struct_ptr( target_ptr_t task_struct, int fd) {
    target_ptr_t files = get_files(task_struct);
    target_ptr_t fds = kernel_profile->get_files_fds(files);
    target_ptr_t fd_file_ptr, fd_file;

    // fds is a flat array with struct file pointers.
    // Calculate the address of the nth pointer and read it.
    fd_file_ptr = fds + fd*sizeof(target_ptr_t);
    if (-1 == panda_virtual_memory_rw(fd_file_ptr, (uint8_t *)&fd_file, sizeof(target_ptr_t), 0)) {
        return (target_ptr_t)NULL;
    }
    fixupendian(fd_file);
    if (fd_file == (target_ptr_t)NULL) {
        return (target_ptr_t)NULL;
    }
    return fd_file;
}

/**
 * @brief Resolves a file struct and returns its full pathname.
 */
static char *get_fd_name( target_ptr_t task_struct, int fd) {
    target_ptr_t fd_file = get_file_struct_ptr(task_struct, fd);
    if (fd_file == (target_ptr_t)NULL) return NULL;
    return get_file_name(fd_file);
}

/**
 * @brief Retrieves the current offset of a file descriptor.
 */
static uint64_t get_fd_pos(target_ptr_t task_struct, int fd) {
    target_ptr_t fd_file = get_file_struct_ptr(task_struct, fd);
    if (fd_file == (target_ptr_t)NULL) return ((uint64_t) INVALID_FILE_POS);
    return get_file_position(fd_file);
}

/**
 * @brief Fills an OsiProcHandle struct.
 */
static void fill_osiprochandle(OsiProcHandle *h,
        target_ptr_t task_addr) {
    struct_get_ret_t UNUSED(err);

    // h->asid = taskd->mm->pgd (some kernel tasks are expected to return error)
    err = struct_get(&h->asid, task_addr, {ki.task.mm_offset, ki.mm.pgd_offset});

    // Convert asid to physical to be able to compare it with the pgd register.
    h->asid = qemu_plugin_virt_to_phys(h->asid);
    h->taskd = kernel_profile->get_group_leader(task_addr);
}

/**
 * @brief Fills an OsiProc struct. Any existing contents are overwritten.
 */
void fill_osiproc(OsiProc *p, target_ptr_t task_addr) {
    struct_get_ret_t UNUSED(err);
    memset(p, 0, sizeof(OsiProc));

    // p->asid = taskd->mm->pgd (some kernel tasks are expected to return error)
    err = struct_get(&p->asid, task_addr, {ki.task.mm_offset, ki.mm.pgd_offset});
    //assert(err == struct_get_ret_t::SUCCESS);
    if(err != struct_get_ret_t::SUCCESS) {
      p->asid = 0;
      printf("Yikes, couldn't read asid\n");
    }

    // p->ppid = taskd->real_parent->pid
    err = struct_get( &p->ppid, task_addr,
                     {ki.task.real_parent_offset, ki.task.tgid_offset});
    assert(err == struct_get_ret_t::SUCCESS);

    // Convert asid to physical to be able to compare it with the pgd register.
    p->asid = p->asid ? qemu_plugin_virt_to_phys(p->asid) : (target_ulong) NULL;
    p->taskd = kernel_profile->get_group_leader(task_addr);

    p->name = get_name(task_addr, p->name);
    p->pid = get_tgid(task_addr);
    //p->ppid = get_real_parent_pid(task_addr);
    p->pages = NULL;  // OsiPage - TODO

    //if kernel version is < 3.17
    if(ki.version.a < 3 || (ki.version.a == 3 && ki.version.b < 17)) {
        uint64_t tmp = get_start_time(task_addr);

        //if there's an endianness mismatch TODO PORT TO Q7 XXX
        #if defined(TARGET_WORDS_BIGENDIAN) != defined(HOST_WORDS_BIGENDIAN)
            //convert the most significant half into nanoseconds, then add the rest of the nanoseconds
            p->create_time = (((tmp & 0xFFFFFFFF00000000) >> 32) * 1000000000) + (tmp & 0x00000000FFFFFFFF);
        #else
            //convert the least significant half into nanoseconds, then add the rest of the nanoseconds
            p->create_time = ((tmp & 0x00000000FFFFFFFF) * 1000000000) + ((tmp & 0xFFFFFFFF00000000) >> 32);
        #endif
       
    } else {
        p->create_time = get_start_time(task_addr);
    }
}

/**
 * @brief Fills an OsiModule struct.
 */
static void fill_osimodule(OsiModule *m, target_ptr_t vma_addr) {
    target_ulong vma_start, vma_end;
    target_ptr_t vma_vm_file;
    target_ptr_t vma_dentry;
    target_ptr_t mm_addr, start_brk, brk, start_stack;

    vma_start = get_vma_start(vma_addr);
    vma_end = get_vma_end(vma_addr);
    vma_vm_file = get_vma_vm_file(vma_addr);

    // Fill everything but m->name and m->file.
    m->modd = vma_addr;
    m->base = vma_start;
    m->size = vma_end - vma_start;

    if (vma_vm_file !=
        (target_ptr_t)NULL) {  // Memory area is mapped from a file.
        vma_dentry = get_vma_dentry(vma_addr);
        m->file = read_dentry_name(vma_dentry);
        m->name = g_strrstr(m->file, "/");
        if (m->name != NULL) m->name = g_strdup(m->name + 1);
    } else {  // Other memory areas.
        mm_addr = get_vma_vm_mm(vma_addr);
        start_brk = get_mm_start_brk(mm_addr);
        brk = get_mm_brk(mm_addr);
        start_stack = get_mm_start_stack(mm_addr);

        m->file = NULL;
        if (vma_start <= start_brk && vma_end >= brk) {
            m->name = g_strdup("[heap]");
        } else if (vma_start <= start_stack && vma_end >= start_stack) {
            m->name = g_strdup("[stack]");
        } else {
            m->name = g_strdup("[???]");
        }
    }
}

/**
 * @brief Fills an OsiThread struct. Any existing contents are overwritten.
 */
void fill_osithread(OsiThread *t,
                           target_ptr_t task_addr) {
    memset(t, 0, sizeof(*t));
    t->tid = get_pid(task_addr);
    t->pid = get_tgid(task_addr);
}

/* ******************************************************************
 Initialization logic
****************************************************************** */
/**
 * @brief When necessary, after the first syscall ensure we can read current task
 */

void on_first_syscall(gpointer evdata, gpointer udata) {
    //uint64_t pc = ((uint64_t*)evdata)[0];
    //uint64_t callno = ((uint64_t*)evdata)[1];
    // Make sure we can now read current. Note this isn't like all the other on_...
    // functions that are registered as OSI callbacks
    /*
    if (can_read_current() == false) {
      printf("Failed to read at first syscall. Retrying...\n");
      return;
    }
    */
    assert(can_read_current() && "Couldn't find current task struct at first syscall");
    if (!osi_initialized)
      LOG_INFO("osi_linux: initialization complete.");
    osi_initialized=true;
    qemu_plugin_unreg_callback("syscalls", "on_all_sys_enter", on_first_syscall);
}


/**
 * @brief Test to see if we can read the current task struct
 */
inline bool can_read_current() {
    target_ptr_t ts = kernel_profile->get_current_task_struct(target_name);
    return 0x0 != ts;
}

/**
 * @brief Check if we've successfully initialized OSI for the guest.
 * Returns true if introspection is available.
 *
 * If introspection is unavailable at the first check, this will register a PPP-style
 * callback with syscalls to try reinitializing at the first syscall.
 *
 * If that fails, then we raise an assertion because OSI has really failed.
 */
bool osi_guest_is_ready(void** ret) {

    if (osi_initialized) { // If osi_initialized is set, the guest must be ready
      return true;      // or, if it isn't, the user wants an assertion error
    }

    // If it's the very first time, try reading current, if we can't
    // wait until first sycall and try again
    if (first_osi_check) {
        // not MIPS
        first_osi_check = false;

        printf("Check if guest ready\n");
        init_per_cpu_offsets(); // Formerly in _machine_init callback, but now it will work with loading OSI after init and snapshots

        // Try to load current, if it works, return true
        if (can_read_current()) {
            // Disable on_first_syscall PPP callback because we're all set
            qemu_plugin_unreg_callback("syscalls", "on_all_sys_enter", on_first_syscall);
            LOG_INFO("osi_linux: initialization complete.\n");
            osi_initialized=true;
            return true;
        }

        // We can't read the current task right now. This isn't a surprise,
        // it could be happening because we're in boot.
        // Wait until on_first_syscall runs, everything should work then
        LOG_INFO("osi_linux: cannot find current task struct. Deferring OSI initialization until first syscall.\n");

        qemu_plugin_reg_callback("syscalls", "on_all_sys_enter", on_first_syscall);
    }
    // Not yet initialized, just set the caller's result buffer to NULL
    ret = NULL;
    return false;
}

/* ******************************************************************
 PPP Callbacks
****************************************************************** */

/**
 * @brief PPP callback to retrieve process list from the running OS.
 *
 */
/*
void on_get_processes(GArray **out) {
    if (!osi_guest_is_ready((void**)out)) return;
    // instantiate and call function from get_process_info template
    get_process_info<>(out, fill_osiproc, free_osiproc_contents);
}
*/

/**
 * @brief PPP callback to retrieve process handles from the running OS.
 */
/*
void on_get_process_handles(GArray **out) {
    if (!osi_guest_is_ready((void**)out)) return;

    // instantiate and call function from get_process_info template
    get_process_info<>(out, fill_osiprochandle, free_osiprochandle_contents);
}
*/

/**
 * @brief PPP callback to retrieve info about the currently running process.
 */
void on_get_current_process(gpointer evdata, gpointer udata) {
    OsiProc **out = (OsiProc**)evdata;
    if (!osi_guest_is_ready((void**)out)) return;

    static target_ptr_t last_ts = 0x0;
    static target_ptr_t cached_taskd = 0x0;
    static target_ptr_t cached_asid = 0x0;
    static char *cached_name = (char *)g_malloc0(ki.task.comm_size);
    static target_ptr_t cached_pid = -1;
    static target_ptr_t cached_ppid = -1;
    static void *cached_comm_ptr = NULL;
    static uint64_t cached_start_time = 0;
    // OsiPage - TODO

    OsiProc *p = NULL;
    target_ptr_t ts = kernel_profile->get_current_task_struct(target_name);
    if (0x0 != ts) {
        p = (OsiProc *)g_malloc(sizeof(*p));
        if ((ts != last_ts) || (NULL == cached_comm_ptr) ||
            (0 != strncmp((char *)cached_comm_ptr, cached_name,
                          ki.task.comm_size))) {
            last_ts = ts;
            printf("Task struct is %lx\n", ts);
            fill_osiproc(p, ts);

            // update the cache
            cached_taskd = p->taskd;
            cached_asid = p->asid;
            memset(cached_name, 0, ki.task.comm_size);
            strncpy(cached_name, p->name, ki.task.comm_size);
            cached_pid = p->pid;
            cached_ppid = p->ppid;
            cached_start_time = p->create_time;
            cached_comm_ptr = qemu_plugin_virt_to_host(
                ts + ki.task.comm_offset, ki.task.comm_size);
        } else {
            p->taskd = cached_taskd;
            p->asid = cached_asid;
            p->name = g_strdup(cached_name);
            p->pid = cached_pid;
            p->ppid = cached_ppid;
            p->pages = NULL;
            p->create_time = cached_start_time;
        }
    }
    *out = p;
}

/**
 * @brief PPP callback to the handle of the currently running process.
 */
void on_get_current_process_handle(gpointer evdata, gpointer udata) {
    OsiProcHandle **out = (OsiProcHandle**)evdata;
    if (!osi_guest_is_ready((void**)out)) return;

    OsiProcHandle *p = NULL;
    // Very first thing that happens. Woop
    target_ptr_t ts = kernel_profile->get_current_task_struct(target_name);
    if (ts) {
        p = (OsiProcHandle *)g_malloc(sizeof(OsiProcHandle));
        fill_osiprochandle(p, ts);
    }
    *out = p;
}

/**
 * @brief PPP callback to retrieve info about a running process using its
 * handle.
 */
void on_get_process(gpointer evdata, gpointer udata) {
    struct get_process_data *data = (struct get_process_data*)(evdata);
    const OsiProcHandle *h = data->h;
    OsiProc **out = data->p;
    if (!osi_guest_is_ready((void**)out)) return;

    OsiProc *p = NULL;
    if (h != NULL && h->taskd != (target_ptr_t)NULL) {
        p = (OsiProc *)g_malloc(sizeof(OsiProc));
        fill_osiproc(p, h->taskd);
    }
    *out = p;
}

/**
 * @brief PPP callback to retrieve OsiModules from the running OS.
 *
 * Current implementation returns all the memory areas mapped by the
 * process and the files they were mapped from. Libraries that have
 * many mappings will appear multiple times.
 *
 * @todo Remove duplicates from results.
 */
void on_get_mappings(gpointer evdata, gpointer udata) {
    struct get_mappings_data *data = (struct get_mappings_data*)(evdata);
    GArray **out = data->out;
    OsiProc *p = data->p;
    if (!osi_guest_is_ready((void**)out)) return;

    OsiModule m;
    target_ptr_t vma_first, vma_current;
    __asm__("int3");

    if (p == 0) {
      printf("taskd invalid\n");
      goto error0;
    }

    // Read the module info for the process.
    vma_first = vma_current = get_vma_first(p->taskd);
    if (vma_current == (target_ptr_t)NULL) goto error0;

    if (*out == NULL) {
        // g_array_sized_new() args: zero_term, clear, element_sz, reserved_sz
        *out = g_array_sized_new(false, false, sizeof(OsiModule), 128);
        g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
    }

    do {
        memset(&m, 0, sizeof(OsiModule));
        fill_osimodule(&m, vma_current);
        g_array_append_val(*out, m);
        vma_current = get_vma_next(vma_current);
    } while(vma_current != (target_ptr_t)NULL && vma_current != vma_first);

    return;

error0:
    if(*out != NULL) {
        g_array_free(*out, true);
    }
    *out = NULL;
    return;
}



/**
 * @brief PPP callback to retrieve current thread.
 */
/*
void on_get_current_thread(OsiThread **out) {
    static target_ptr_t last_ts = 0x0;
    static target_pid_t cached_tid = 0;
    static target_pid_t cached_pid = 0;

    if (!osi_guest_is_ready((void**)out)) return;

    OsiThread *t = NULL;
    target_ptr_t ts = kernel_profile->get_current_task_struct(target_name);
    if (0x0 != ts) {
        t = (OsiThread *)g_malloc(sizeof(OsiThread));
        if (last_ts != ts) {
            fill_osithread(t, ts);
            cached_tid = t->tid;
            cached_pid = t->pid;
        } else {
            t->tid = cached_tid;
            t->pid = cached_pid;
        }
    }

    *out = t;
}
*/

/**
 * @brief PPP callback to retrieve the process pid from a handle.
 */
void on_get_process_pid(const OsiProcHandle *h, target_pid_t *pid) {
    if (!osi_guest_is_ready((void**)pid)) return;

    if (h->taskd == NULL || h->taskd == (target_ptr_t)-1) {
        *pid = (target_pid_t)-1;
    } else {
        *pid = get_tgid(h->taskd);
    }
}

/**
 * @brief PPP callback to retrieve the process parent pid from a handle.
 */
void on_get_process_ppid(const OsiProcHandle *h, target_pid_t *ppid) {
    struct_get_ret_t UNUSED(err);
    if (!osi_guest_is_ready((void**)ppid)) return;

    if (h->taskd == (target_ptr_t)-1) {
        *ppid = (target_pid_t)-1;
    } else {
        // ppid = taskd->real_parent->pid
        err = struct_get(ppid, h->taskd,
                         {ki.task.real_parent_offset, ki.task.pid_offset});
        if (err != struct_get_ret_t::SUCCESS) {
            *ppid = (target_pid_t)-1;
        }
    }
}

/* ******************************************************************
 osi_linux extra API
****************************************************************** */

char *osi_linux_fd_to_filename(OsiProc *p, int fd) {
    char *filename = NULL;
    target_ptr_t ts_current;
    //const char *err = NULL;

    if (p == NULL) {
        //err = "Null OsiProc argument";
        goto end;
    }

    ts_current = p->taskd;
    if (ts_current == 0) {
        //err = "can't get task";
        goto end;
    }

    filename = get_fd_name(ts_current, fd);
    if (unlikely(filename == NULL)) {
        //err = "can't get filename";
        goto end;
    }

    filename = g_strchug(filename);
    if (unlikely(g_strcmp0(filename, "") == 0)) {
        //err = "filename is empty";
        g_free(filename);
        filename = NULL;
        goto end;
    }

end:
    //if (unlikely(err != NULL)) {
    //    LOG_ERROR("%s -- (pid=%d, fd=%d)", err, (int)p->pid, fd);
    //}
    return filename;
}


target_ptr_t ext_get_file_dentry(target_ptr_t file_struct) {
	return get_file_dentry(file_struct);
} 

target_ptr_t ext_get_file_struct_ptr(target_ptr_t task_struct, int fd) {
	return get_file_struct_ptr(task_struct, fd);
}


unsigned long long  osi_linux_fd_to_pos(OsiProc *p, int fd) {
    //    target_ulong asid = panda_current_asid(env);
    target_ptr_t ts_current = 0;
    ts_current = p->taskd;
    if (ts_current == 0) return INVALID_FILE_POS;
    return get_fd_pos(ts_current, fd);
}

/* ******************************************************************
 Testing functions
****************************************************************** */
#if 0
/**
 * @brief Tests the osi_linux functionality by directly calling the
 * respective introspection functions. For testing the functions via
 * their callbacks, use the osi_test plugin.
 */
int osi_linux_test(target_ulong oldval, target_ulong newval) {
    static uint32_t asid_change_count = 0;
    GArray *ps = NULL;

    on_get_processes(&ps);
    assert(ps != NULL && ps->len > 0 && "no processes retrieved");

#if PANDA_LOG_LEVEL >= PANDA_LOG_INFO
    char mode = '?'; //panda_in_kernel(env) ? 'K' : 'U';
    LOG_INFO("--- START(%c) %06u ------------------------------------------", mode, asid_change_count);
    for (uint32_t i = 0; i < ps->len; i++) {
        OsiProc *p = &g_array_index(ps, OsiProc, i);
        LOG_INFO(TARGET_PID_FMT ":" TARGET_PID_FMT ":%s:" TARGET_PTR_FMT ":" TARGET_PTR_FMT,
                 p->pid, p->ppid, p->name, p->asid, p->taskd);
#if defined(OSI_LINUX_TEST_MODULES)
        GArray *ms = NULL;
        on_get_mappings(p, &ms);
        if (ms != NULL) {
            for (uint32_t j = 0; j < ms->len; j++) {
                OsiModule *m = &g_array_index(ms, OsiModule, j);
                LOG_INFO("\t" TARGET_PTR_FMT ":%04up:%s:%s", m->base, NPAGES(m->size), m->name, m->file);
            }
            g_array_free(ms, true);
        }
#endif
#if defined(OSI_LINUX_TEST_MODULES) && defined(OSI_LINUX_TEST_FDNAME)
        if (ms != NULL) {
            LOG_INFO("\t------------------------");
        }
#endif
#if defined(OSI_LINUX_TEST_FDNAME)
        for (uint32_t fd=0; fd<16; fd++) {
            char *s = get_fd_name(ps->proc[i].offset, fd);
            LOG_INFO("\tfd%d -> %s", fd, s);
            g_free(s);
        }
#endif
    }
    LOG_INFO("--- END(%c)  %06u ------------------------------------------", mode, asid_change_count);
#endif // PANDA_LOG_LEVEL >= PANDA_LOG_INFO

    g_array_free(ps, true);
    asid_change_count++;
    return 0;
}
#endif // OSI_LINUX_TEST

/* ******************************************************************
 Plugin Initialization/Cleanup
****************************************************************** */
/**
 * @brief Updates any per-cpu offsets we need for introspection.
 * This allows kernel profiles to be independent of boot-time configuration.
 * If ki.task.per_cpu_offsets_addr is set to 0, the values of the per-cpu
 * offsets in the profile will not be updated.
 *
 * Currently the only per-cpu offset we use in osi_linux is
 * ki.task.per_cpu_offset_0_addr.
 */
void init_per_cpu_offsets() {
    // old kernel - no per-cpu offsets to update
    if (PROFILE_KVER_LE(ki, 2, 4, 254)) {
        return;
    }

    // skip update because there's no per_cpu_offsets_addr
    if (ki.task.per_cpu_offsets_addr == 0) {
        LOG_INFO("Using profile-provided value for ki.task.per_cpu_offset_0_addr: "
                 TARGET_PTR_FMT, (target_ptr_t)ki.task.per_cpu_offset_0_addr);
        return;
    }

    // skip update because of failure to read from per_cpu_offsets_addr
    target_ptr_t per_cpu_offset_0_addr;
    auto r = struct_get(&per_cpu_offset_0_addr, ki.task.per_cpu_offsets_addr,
                        0*sizeof(target_ptr_t));
    if (r != struct_get_ret_t::SUCCESS) {
        LOG_ERROR("Unable to update value of ki.task.per_cpu_offset_0_addr.\n");
        assert(false);
        return;
    }

    ki.task.per_cpu_offset_0_addr = per_cpu_offset_0_addr;
    //LOG_INFO("Updated value for ki.task.per_cpu_offset_0_addr: "
    //         TARGET_PTR_FMT "\n", per_cpu_offset_0_addr);

}

/**
 * @brief After guest has restored snapshot, reset so we can redo
 * initialization
 */
void restore_after_snapshot(qemu_plugin_id_t id, unsigned int cpu_index) {
    LOG_INFO("Snapshot loaded. Re-initializing\n");

    // By setting these, we'll redo our init logic which determines
    // if OSI is ready at the first time it's used, otherwise 
    // it runs at the first syscall (and asserts if it fails)
    osi_initialized=false;
    first_osi_check = true;
    qemu_plugin_reg_callback("syscalls", "on_all_sys_enter", on_first_syscall);
}


// Keep track of which tasks have entered execve. Note that we simply track
// based on the task struct. This works because the other threads in the thread
// group will be terminated and the current task will be the only task in the
// group once execve completes. Even if execve fails, this should still work
// because the execve call will return to the calling thread.
static std::unordered_set<target_ptr_t> tasks_in_execve;

void on_syscall(gpointer evdata, gpointer udata);

void on_syscall(gpointer evdata, gpointer udata)
{
    uint64_t pc = ((uint64_t*)evdata)[0];
    uint64_t callno = ((uint64_t*)evdata)[1];

    char * sc_name = syscalls_get_name_qpp(callno);
    if (sc_name == NULL) return;

    bool is_execve = 0 == strcmp(sc_name, "execve");
    free(sc_name);
    if (!is_execve) return;
    printf("EXECVE\n");

    bool **out=0;
    if (!osi_guest_is_ready((void**)out)) return;
    target_ptr_t ts = kernel_profile->get_current_task_struct(target_name);
    tasks_in_execve.insert(ts);
}

void do_notify_task_change(unsigned int cpu_index, void* udata)
{
    notify_task_change_qpp(cpu_index, udata);
}

//static void exec_check(CPUState *cpu)
void exec_check(unsigned int cpu_index, void* udata)
{
    // XXX: per cpu?
    // Fast Path: Nothing is in execve, so there's nothing to do.
    if (0 == tasks_in_execve.size()) {
        return;
    }
    bool** out=0;
    if (!osi_guest_is_ready((void**)out)) return;

    // Slow Path: Something is in execve, so we have to check.
    target_ptr_t ts = kernel_profile->get_current_task_struct(target_name);
    auto it = tasks_in_execve.find(ts);
    if (tasks_in_execve.end() != it && !qemu_plugin_in_privileged_mode()) {
        do_notify_task_change(cpu_index, udata);
        tasks_in_execve.erase(ts);
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
  //Formerly "Before_tcg_codegen"
  uint64_t pc = qemu_plugin_tb_vaddr(tb);

  // Always do exec_check
  qemu_plugin_register_vcpu_tb_exec_cb(tb, exec_check,
                                       QEMU_PLUGIN_CB_NO_REGS,
                                       NULL);


  if (0x0 != ki.task.switch_task_hook_addr && pc == ki.task.switch_task_hook_addr) {
    // Instrument the task switch address.
    qemu_plugin_register_vcpu_tb_exec_cb(tb, do_notify_task_change,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         NULL);
  }
}

/**
 * @brief Initializes plugin.
 */
extern "C" QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {

  // Register hooks in the kernel to provide task switch notifications.
  qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    gchar* kconf_file = NULL;
    gchar* kconf_group = NULL;
    osi_initialized = false;

    target_name = strdup(info->target_name);

    //parse the arguments
    for (int i = 0; i < argc; i++) {
        g_autofree gchar** tokens = g_strsplit(argv[i], "=", 2);

        if (g_strcmp0(tokens[0], "kconf_file") == 0) {
            kconf_file = g_strdup(tokens[1]);
        } else if (g_strcmp0(tokens[0], "kconf_group") == 0) {
            kconf_group = g_strdup(tokens[1]);
        }
    }

    if (!kconf_file || !kconf_group) {
        printf("osi_linux is missing arguments\n");
        printf("USAGE: -plugin /path/to/libosi_linux.so,kconf_file=/path/to/kconf_file,kconf_group=name_of_group\n");
        goto error;
    }

    // Load kernel offsets.
    if (read_kernelinfo(kconf_file, kconf_group, &ki) != 0) {
        printf("Failed to read group %s from %s.\n", kconf_group, kconf_file);
        goto error;
    }
    LOG_INFO("Read kernel info from group \"%s\" of file \"%s\".\n", kconf_group, kconf_file);

    if (PROFILE_KVER_LE(ki, 2, 4, 254)) {
        //kernel_profile = &KERNEL24X_PROFILE;
        assert(0); // TODO
    } else {
        kernel_profile = &DEFAULT_PROFILE;
    }

    // OSI only supports these two for now:
    qemu_plugin_reg_callback("osi", "on_get_process", on_get_process);
    qemu_plugin_reg_callback("osi", "on_get_current_process_handle", on_get_current_process_handle);
    qemu_plugin_reg_callback("osi", "on_get_current_process", on_get_current_process);
    qemu_plugin_reg_callback("osi", "on_get_mappings", on_get_mappings);

    /*
    QPP_REG_CB("osi", on_get_processes, on_get_processes);
    QPP_REG_CB("osi", on_get_process_handles, on_get_process_handles);
    QPP_REG_CB("osi", on_get_current_thread, on_get_current_thread);
    QPP_REG_CB("osi", on_get_process_pid, on_get_process_pid);
    QPP_REG_CB("osi", on_get_process_ppid, on_get_process_ppid);
    */

    // execve analysis
    //qemu_plugin_reg_callback("syscalls", "on_all_sys_enter", on_syscall);

    qemu_plugin_register_vcpu_loadvm_cb(id, restore_after_snapshot);

    return 0;

error:
    return 1;
}

/**
 * @brief Retrieves the task_struct address using per cpu information.
 */
target_ptr_t default_get_current_task_struct(char* target_name)
{
    struct_get_ret_t err;
    target_ptr_t current_task_addr;
    target_ptr_t ts;

    if (strcmp(target_name, "x86_64") == 0) {
      current_task_addr = ki.task.current_task_addr;
    } else if (strcmp(target_name, "mipsel") == 0) {
      // __current_thread_info is stored in KERNEL r28
      // userspace clobbers it but kernel restores (somewhow?)
      // First field of struct is task - no offset needed
      current_task_addr = hw_proc_id_get_qpp(); // HWID returned by hw_proc_id is the cached r28 value
    } else {
      printf("ERROR: Unsupported target\n");
      assert(0);
    }
    err = struct_get(&ts, current_task_addr, ki.task.per_cpu_offset_0_addr);
    //assert(err == struct_get_ret_t::SUCCESS && "failed to get current task struct");
    if (err != struct_get_ret_t::SUCCESS) {
      // Callers need to check if we return NULL!
      return 0;
    }
    fixupendian(ts);
    return ts;
}

/**
 * @brief Retrieves the address of the following task_struct in the process list.
 */
target_ptr_t default_get_task_struct_next(target_ptr_t task_struct)
{
    struct_get_ret_t err;
    target_ptr_t tasks;
    err = struct_get(&tasks, task_struct, ki.task.tasks_offset);
    fixupendian(tasks);
    assert(err == struct_get_ret_t::SUCCESS && "failed to get next task");
    return tasks-ki.task.tasks_offset;
}

/**
 * @brief Retrieves the thread group leader address from task_struct.
 */
target_ptr_t default_get_group_leader(target_ptr_t ts)
{
    struct_get_ret_t err;
    target_ptr_t group_leader;
    err = struct_get(&group_leader, ts, ki.task.group_leader_offset);
    fixupendian(group_leader);
    assert(err == struct_get_ret_t::SUCCESS && "failed to get group leader for task");
    return group_leader;
}

/**
 * @brief Retrieves the array of file structs from the files struct.
 * The n-th element of the array corresponds to the n-th open fd.
 */
target_ptr_t default_get_file_fds(target_ptr_t files)
{
    struct_get_ret_t err;
    target_ptr_t files_fds;
    err = struct_get(&files_fds, files, {ki.fs.fdt_offset, ki.fs.fd_offset});
    if (err != struct_get_ret_t::SUCCESS) {
        printf("Failed to retrieve file structs (error code: %d)", err);
        return (target_ptr_t)NULL;
    }
    fixupendian(files_fds);
    return files_fds;
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
