#ifndef PLUGIN_QPP_H
#define PLUGIN_QPP_H

/*
 * Facilities for "Plugin to plugin" (QPP) interactions between tcg plugins.
 * These allows for direct function calls between loaded plugins. For more
 * details see docs/devel/plugin.rst.
 */


/*
 * Internal macros
 */
#define _PLUGIN_STR(s) #s
#define PLUGIN_STR(s) _PLUGIN_STR(s)
#define _PLUGIN_CONCAT(x, y) x##y
#define PLUGIN_CONCAT(x, y) _PLUGIN_CONCAT(x, y)
#define _QPP_SETUP_NAME(fn) PLUGIN_CONCAT(_qpp_setup_, fn)

/*
 * A header file that defines an exported function should use
 * the QPP_FUN_PROTOTYPE macro to create the necessary types.
 *
 * The generated function named after the output of QPP_SETUP_NAME should
 * dynamically resolve a target function in another plugin or raise a fatal
 * error on failure. In particular, it must handle the following two cases:
 * 1) When the header is loaded by the plugin that defines the function.
 *    In this case, we do not need to find the symbol externally.
 *    qemu_plugin_name_to_handle will return NULL, we see that the
 *    target plugin matches qemu_plugin_name (required to be defined by
 *    plugins of API v2+) and do nothing.
 * 2) When the header is loaded by another plugin. In this case
 *    we get the function pointer from qemu_plugin_import_function
 *    and correctly cast and assign the function pointer
 */

#define QPP_FUN_PROTOTYPE(plugin_name, fn_ret, fn, args)              \
  fn_ret fn(args);                                                    \
  typedef fn_ret(*PLUGIN_CONCAT(fn, _t))(args);                       \
  fn##_t fn##_qpp;                                                    \
  void _QPP_SETUP_NAME(fn) (void);                                    \
                                                                      \
  void __attribute__ ((constructor)) _QPP_SETUP_NAME(fn) (void) {     \
    if (strcmp(qemu_plugin_name, #plugin_name) != 0) {                \
      fn##_qpp = qemu_plugin_import_function(PLUGIN_STR(plugin_name), \
                                             PLUGIN_STR(fn));         \
    }                                                                 \
  }
#endif /* PLUGIN_QPP_H */
