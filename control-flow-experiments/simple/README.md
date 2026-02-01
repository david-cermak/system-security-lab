# Simple CFI Experiments

This directory contains practical demonstrations of Control Flow Integrity (CFI) protection and its limitations.

## Overview

These experiments demonstrate:
- **Step 0**: CFI successfully protecting against function pointer hijacking when signatures differ
- **Step 1**: CFI failing to protect when functions share the same signature
- **Step 2**: CFI-vcall successfully protecting against virtual call vtable corruption

## Files

### Step 0: CFI Protection (Works)

- `step0_cfi.c` - Buffer overflow example where CFI works
  - `check_password()` has signature `void (*)(const char *)`
  - `win()` has signature `void (*)(void)` - different signature!
  - CFI detects signature mismatch and blocks the attack

### Step 1: CFI Protection Failure

- `step1_overflow.c` - Buffer overflow with function pointer hijacking
  - `safe()` and `win()` both have signature `void (*)(const char *)`
  - CFI fails because both functions match the expected type
- `step1_exploit.py` - Automated exploit script
- `step1_gen.py` - Payload generator (also generates Godbolt JavaScript)
- `step1_overflow` - Compiled binary (without CFI)
- `step1_cfi` - Compiled binary (with CFI - attack still succeeds)
- `step1_cfi_icall` - Compiled binary (with CFI-ICALL - attack still succeeds)

### Step 2: Virtual Call Overflow

- `step2_vcall_overflow.cpp` - Virtual call vtable corruption example
- `step2_vcall_exploit.py` - Automated exploit script
- `step2_vcall_gen.py` - Payload generator
- `step2_vcall_overflow` - Compiled binary (without CFI)
- `step2_vcall_cfi` - Compiled binary (with CFI-vcall - attack blocked)

## Build Instructions

### Step 0: CFI Protection (Works)

```bash
# Without CFI (for comparison)
gcc -O0 -g -fno-stack-protector -no-pie -o step0 step0_cfi.c

# With CFI (protection enabled)
clang -O0 -g -flto -fsanitize=cfi -fvisibility=default \
  -fno-sanitize-trap=cfi -o step0_cfi step0_cfi.c
```

### Step 1: Function Pointer Hijacking

```bash
# Without CFI
gcc -O0 -g -fno-stack-protector -no-pie -o step1_overflow step1_overflow.c

# With CFI (attack still succeeds!)
clang -O0 -g -flto -fsanitize=cfi -fvisibility=default \
  -fno-sanitize-trap=cfi -o step1_cfi step1_overflow.c

# With CFI-ICALL (attack still succeeds!)
clang -O0 -g -flto -fsanitize=cfi-icall -fvisibility=default \
  -fno-sanitize-trap=cfi-icall -o step1_cfi_icall step1_overflow.c
```

### Step 2: Virtual Call Overflow

```bash
# Without CFI
g++ -O0 -g -fno-stack-protector -no-pie \
  -o step2_vcall_overflow step2_vcall_overflow.cpp

# With CFI-vcall (protection enabled)
clang++ -O0 -g -flto -fsanitize=cfi-vcall -fvisibility=hidden \
  -fno-sanitize-trap=cfi-vcall -o step2_vcall_cfi step2_vcall_overflow.cpp
```

## Running the Exploits

### Step 0: CFI Protection (Works)

```bash
# Attempt exploit (should be blocked by CFI)
echo -n "AAAA" | python3 -c "import struct; import sys; sys.stdout.buffer.write(b'A'*32 + struct.pack('<Q', 0x12345678))" | ./step0_cfi test
```

### Step 1: Function Pointer Hijacking

```bash
# Using the automated exploit script
python3 step1_exploit.py

# Or manually with payload generator
./step1_overflow "echo 'TEST'" 2>&1 | python3 step1_gen.py | ./step1_overflow "echo 'TEST'"
```

**Expected results:**
- `step1_overflow` (no CFI): Attack succeeds
- `step1_cfi` (with CFI): Attack still succeeds! (CFI limitation)
- `step1_cfi_icall` (with CFI-ICALL): Attack still succeeds! (CFI limitation)

### Step 2: Virtual Call Overflow

```bash
# Using the automated exploit script
python3 step2_vcall_exploit.py

# Or manually with payload generator
./step2_vcall_overflow 2>&1 | python3 step2_vcall_gen.py | ./step2_vcall_overflow
```

**Expected results:**
- `step2_vcall_overflow` (no CFI): Attack succeeds
- `step2_vcall_cfi` (with CFI-vcall): Attack blocked! (CFI-vcall works)

## Key Takeaways

1. **CFI works** when function signatures differ (Step 0)
2. **CFI fails** when functions share the same signature (Step 1)
   - Type-based validation cannot distinguish between `safe()` and `win()`
   - This is a fundamental limitation, not a bug
3. **CFI-vcall works** for virtual call protection (Step 2)
   - Validates vtable integrity, not just function signatures
   - More restrictive than function pointer type checking

## Requirements

- GCC/Clang compiler
- Python 3 (for exploit scripts)
- Clang with CFI support (for CFI-enabled builds)
