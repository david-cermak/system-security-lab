# Coroutine CFI Experiments

This directory contains experiments demonstrating how C++20 coroutines can bypass Control Flow Integrity (CFI) protection.

## Overview

This experiment demonstrates that CFI fails to protect against coroutine frame corruption attacks, even when CFI is enabled. The fundamental issue is the same as in the simple function pointer hijacking case: CFI validates function pointer *types* (signatures), not specific addresses.

## Files

- `step3_coroutine_overflow.cpp` - C++20 coroutine example with buffer overflow
  - Coroutine frame contains function pointer `resume` with signature `void (*)(const char *)`
  - Buffer overflow corrupts this pointer
  - Both `safe_resume()` and `win()` share the same signature
  - CFI fails because it cannot distinguish between functions with matching signatures
- `step3_coroutine_exploit.py` - Automated exploit script
- `step3_coroutine_overflow` - Compiled binary

## Build Instructions

### Without CFI

```bash
g++ -O0 -g -std=c++20 -fno-stack-protector -no-pie \
  -o step3_coroutine_overflow step3_coroutine_overflow.cpp
```

### With CFI (Attack Still Succeeds!)

```bash
# Standard CFI
clang++ -O0 -g -std=c++20 -flto -fsanitize=cfi -fvisibility=default \
  -fno-sanitize-trap=cfi -o step3_coroutine_cfi step3_coroutine_overflow.cpp

# CFI-ICALL specifically
clang++ -O0 -g -std=c++20 -flto -fsanitize=cfi-icall -fvisibility=default \
  -fno-sanitize-trap=cfi-icall -o step3_coroutine_cfi_icall step3_coroutine_overflow.cpp
```

## Running the Exploit

```bash
# Using the automated exploit script
python3 step3_coroutine_exploit.py
```

**Expected results:**
- Attack succeeds even with CFI enabled
- CFI validates that `win()` has the correct signature `void (*)(const char *)`
- CFI cannot distinguish between `safe_resume()` and `win()` because they share the same signature

## How It Works

1. **Coroutine frame allocation**: The program allocates a `Frame` structure on the heap containing:
   - `buf[32]` - buffer vulnerable to overflow
   - `resume` - function pointer initialized to `safe_resume()`
   - `cmd` - command string

2. **Buffer overflow**: The coroutine reads 200 bytes into a 32-byte buffer, corrupting the `resume` pointer

3. **Function pointer hijacking**: The corrupted `resume` pointer is overwritten with `win()` address

4. **CFI validation**: When `frame->resume()` is called:
   - CFI checks that the function pointer has signature `void (*)(const char *)`
   - Both `safe_resume()` and `win()` match this signature ✓
   - CFI allows the call to proceed

5. **Arbitrary code execution**: `win()` executes `system(cmd)`, giving the attacker control

## Why CFI Fails

**Same fundamental limitation as Step 1 (simple function pointer hijacking):**

- CFI validates function pointer *types* (signatures), not specific addresses
- When multiple functions share the same signature, CFI cannot distinguish between them
- This creates a "silver gadget" problem where attackers can redirect to any function with matching type

**Key insight:** Coroutines introduce the same vulnerability pattern as direct function pointer corruption, but in a heap-allocated coroutine frame structure. The CFI protection mechanism has the same limitation in both cases.

## Requirements

- C++20 compatible compiler (GCC 10+ or Clang 10+)
- Python 3 (for exploit script)
- Clang with CFI support (for CFI-enabled builds)

## Related

See `../simple/README.md` for the simpler function pointer hijacking examples that demonstrate the same CFI limitation.
