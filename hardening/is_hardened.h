#ifndef __HARDENING_TEST_IS_HARDENED
#define __HARDENING_TEST_IS_HARDENED

#include <version>

#define STR2(x) #x
#define STR(x) STR2(x)

#ifdef __cpp_lib_hardened_array
#pragma message("__cpp_lib_hardened_array = " STR(__cpp_lib_hardened_array))
#else
#pragma message("__cpp_lib_hardened_array : not defined")
#endif

#ifdef __cpp_lib_hardened_basic_string
#pragma message("__cpp_lib_hardened_basic_string = " STR(__cpp_lib_hardened_basic_string))
#else
#pragma message("__cpp_lib_hardened_basic_string : not defined")
#endif

#ifdef __cpp_lib_hardened_basic_string_view
#pragma message("__cpp_lib_hardened_basic_string_view = " STR(__cpp_lib_hardened_basic_string_view))
#else
#pragma message("__cpp_lib_hardened_basic_string_view : not defined")
#endif

#ifdef __cpp_lib_hardened_bitset
#pragma message("__cpp_lib_hardened_bitset = " STR(__cpp_lib_hardened_bitset))
#else
#pragma message("__cpp_lib_hardened_bitset : not defined")
#endif

#ifdef __cpp_lib_hardened_deque
#pragma message("__cpp_lib_hardened_deque = " STR(__cpp_lib_hardened_deque))
#else
#pragma message("__cpp_lib_hardened_deque : not defined")
#endif

#ifdef __cpp_lib_hardened_expected
#pragma message("__cpp_lib_hardened_expected = " STR(__cpp_lib_hardened_expected))
#else
#pragma message("__cpp_lib_hardened_expected : not defined")
#endif

#ifdef __cpp_lib_hardened_forward_list
#pragma message("__cpp_lib_hardened_forward_list = " STR(__cpp_lib_hardened_forward_list))
#else
#pragma message("__cpp_lib_hardened_forward_list : not defined")
#endif

#ifdef __cpp_lib_hardened_inplace_vector
#pragma message("__cpp_lib_hardened_inplace_vector = " STR(__cpp_lib_hardened_inplace_vector))
#else
#pragma message("__cpp_lib_hardened_inplace_vector : not defined")
#endif

#ifdef __cpp_lib_hardened_list
#pragma message("__cpp_lib_hardened_list = " STR(__cpp_lib_hardened_list))
#else
#pragma message("__cpp_lib_hardened_list : not defined")
#endif

#ifdef __cpp_lib_hardened_mdspan
#pragma message("__cpp_lib_hardened_mdspan = " STR(__cpp_lib_hardened_mdspan))
#else
#pragma message("__cpp_lib_hardened_mdspan : not defined")
#endif

#ifdef __cpp_lib_hardened_optional
#pragma message("__cpp_lib_hardened_optional = " STR(__cpp_lib_hardened_optional))
#else
#pragma message("__cpp_lib_hardened_optional : not defined")
#endif

#ifdef __cpp_lib_hardened_span
#pragma message("__cpp_lib_hardened_span = " STR(__cpp_lib_hardened_span))
#else
#pragma message("__cpp_lib_hardened_span : not defined")
#endif

#ifdef __cpp_lib_hardened_valarray
#pragma message("__cpp_lib_hardened_valarray = " STR(__cpp_lib_hardened_valarray))
#else
#pragma message("__cpp_lib_hardened_valarray : not defined")
#endif

#ifdef __cpp_lib_hardened_vector
#pragma message("__cpp_lib_hardened_vector = " STR(__cpp_lib_hardened_vector))
#else
#pragma message("__cpp_lib_hardened_vector : not defined")
#endif

#endif // __HARDENING_TEST_IS_HARDENED

