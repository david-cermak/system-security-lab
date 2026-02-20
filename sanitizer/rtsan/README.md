# Real-Time Sanitizer (RTSan) for Embedded Modem Code

This directory demonstrates **Clang 20's RealtimeSanitizer** applied to patterns
from the [esp_modem](https://github.com/espressif/esp-protocols/tree/master/components/esp_modem)
component -- the AT modem library used with ESP32 and ESP-IDF.

The idea: compile your embedded C++ code on a **Linux host**, annotate real-time
entry points with `[[clang::nonblocking]]`, and let RTSan catch violations
(mutex locks, heap allocations, blocking waits) **at runtime**.

## Prerequisites

- **Clang 20** with `compiler-rt` (provides the RTSan runtime)
- A Linux host (tested on x86_64, WSL2)

Install on Ubuntu/Debian:

```bash
# Add LLVM 20 repo (see https://apt.llvm.org)
wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 20
# Verify
clang++-20 --version
```

## Quick start

```bash
# Build and run the esp_modem demo (RTSan will abort on the violation)
make esp_modem_rtsan
./esp_modem_rtsan

# Or use the Makefile targets:
make run_modem          # run, show first violation, print exit code
make run_modem_all      # run with halt_on_error=false (show ALL violations)
make run_modem_safe     # build without RTSan (no checks, runs to completion)
```

## What is RealtimeSanitizer?

RTSan is a **runtime** checker for real-time safety. In embedded and real-time
systems, certain execution contexts (ISRs, timer callbacks, audio processing
loops) must complete in **bounded, deterministic time**. They must never:

- Lock a mutex (`pthread_mutex_lock`) -- may block indefinitely
- Allocate heap memory (`malloc`) -- non-deterministic time
- Wait on a condition variable (`pthread_cond_wait`) -- blocks
- Call any function with non-deterministic execution time

RTSan works with two C++ attributes:

| Attribute | Meaning |
|-----------|---------|
| `[[clang::nonblocking]]` | "This function runs in a real-time context. Do NOT call anything blocking." |
| `[[clang::blocking]]` | "This function blocks. Do NOT call it from a `nonblocking` context." |

At runtime, RTSan intercepts calls to `malloc`, `free`, `pthread_mutex_lock`,
`pthread_cond_wait`, etc. If any of these are reached from within a
`[[clang::nonblocking]]` call stack, RTSan reports the violation with a full
stack trace and aborts.

Compile-time cost: **zero** (attributes are metadata).
Runtime overhead: **negligible** (checks only run in annotated paths).

## The demo: `esp_modem_rtsan.cpp`

### Background: esp_modem architecture

The [esp_modem](../README.md) component provides a C++ framework for controlling
cellular modems (SIM7600, BG96, SIM7070, etc.) over AT commands. Its
architecture:

```
Application
    |
    v
+--------+     AT+CSQ, AT+CIMI, ...     +--------+
|  DCE   | ---------------------------> |  DTE   | ---> UART ---> Modem
| (modem)|   command library             |(terminal)
+--------+                               +--------+
                                            |
                                     Lock internal_lock_
                                     SignalGroup (cond_var)
```

Key pattern: **`DTE::command()` acquires a mutex** to serialize AT command
access to the UART. This is correct for normal tasks but is **not real-time
safe**.

### Platform abstraction

esp_modem abstracts synchronization primitives across platforms:

| Platform | Lock | Signal | Task |
|----------|------|--------|------|
| ESP32 (FreeRTOS) | `xSemaphoreCreateRecursiveMutex` | `xEventGroupWaitBits` | `xTaskCreate` |
| Linux host | `std::recursive_mutex` | `std::condition_variable` | `std::thread` |

This abstraction is what makes host-based testing possible. The demo uses the
same Linux path that esp_modem uses when compiled with `CONFIG_IDF_TARGET_LINUX`.

### Code structure

The demo (`esp_modem_rtsan.cpp`) is a **single self-contained file** that
mirrors the real esp_modem patterns:

#### Section 1: Platform abstraction

```cpp
// ESP32 path (shown in comments for reference):
//   struct Lock { QueueHandle_t m; ... };

// Linux host path (same as esp_modem):
using Lock = std::recursive_mutex;

// RAII guard (identical to esp_modem::Scoped<T>):
template<class T>
class Scoped {
    explicit Scoped(T &l) : lock_(l) { lock_.lock(); }
    ~Scoped() { lock_.unlock(); }
};
```

#### Section 2: AT command types

```cpp
enum class command_result { OK, FAIL, TIMEOUT };
using got_line_cb = std::function<command_result(uint8_t *data, size_t len)>;
```

#### Section 3: Simulated modem

Returns canned AT responses (`+CSQ: 18,99`, IMSI, etc.) so the demo is
self-contained without real hardware.

#### Section 4: SimpleDTE

The core class, mirroring `esp_modem::DTE`:

```cpp
class SimpleDTE {
    command_result command(const std::string &cmd, got_line_cb got_line,
                           uint32_t timeout_ms) [[clang::blocking]]
    {
        Scoped<Lock> l(internal_lock_);              // mutex lock
        std::string response = modem_.process(cmd);  // heap allocation
        return got_line((uint8_t *)response.data(), response.size());
    }

    // High-level commands (same pattern as esp_modem command library)
    command_result sync();                           // AT\r
    command_result get_signal_quality(int&, int&);   // AT+CSQ
    command_result get_imsi(std::string&);           // AT+CIMI
};
```

Note the `[[clang::blocking]]` attribute on `command()` -- this explicitly marks
it as unsafe for real-time contexts.

#### Section 5: Real-time callbacks

Two timer callbacks representing a common embedded scenario:

```cpp
// SAFE: only reads pre-cached atomic variables
void rt_timer_callback_safe() [[clang::nonblocking]] {
    int rssi = g_cached_rssi.load(std::memory_order_relaxed);
}

// UNSAFE: calls into the DTE (mutex + malloc + blocking)
void rt_timer_callback_unsafe() [[clang::nonblocking]] {
    g_dte->get_signal_quality(rssi, ber);   // BUG!
}
```

#### Section 6: Main

Runs normal AT commands (fine), then the safe callback (fine), then the unsafe
callback (RTSan catches it).

### The violation chain

When `rt_timer_callback_unsafe()` executes, RTSan detects this call chain:

```
rt_timer_callback_unsafe()          [[clang::nonblocking]]
  -> SimpleDTE::get_signal_quality()
    -> SimpleDTE::command()         [[clang::blocking]]      <-- violation #1
      -> Scoped<Lock>::lock()
        -> std::recursive_mutex::lock()
          -> pthread_mutex_lock()                            <-- violation #2
      -> SimModem::process()
        -> std::string constructor
          -> malloc()                                        <-- violation #3
      -> ~std::string
        -> free()                                            <-- violation #4
      -> ~Scoped<Lock>
        -> pthread_mutex_unlock()                            <-- violation #5
```

With the default `halt_on_error=true`, RTSan aborts at violation #1 (the
`[[clang::blocking]]` call). With `halt_on_error=false`, all five violations
are reported.

## Example output

### Default run (halts on first violation)

```
$ make run_modem
./esp_modem_rtsan; echo "Exit code: $?"
==59111==ERROR: RealtimeSanitizer: blocking-call
Call to blocking function `SimpleDTE::command(...)` in real-time context!
    #0 in SimpleDTE::command(...) esp_modem_rtsan.cpp:131
    #1 in SimpleDTE::generic_command_with_parse(...) esp_modem_rtsan.cpp:202
    #2 in SimpleDTE::get_signal_quality(int&, int&) esp_modem_rtsan.cpp:149
    #3 in rt_timer_callback_unsafe() esp_modem_rtsan.cpp:262
    #4 in main esp_modem_rtsan.cpp:317

SUMMARY: RealtimeSanitizer: blocking-call esp_modem_rtsan.cpp:131
Exit code: 43
```

### All violations (`halt_on_error=false`)

```
$ make run_modem_all
RTSAN_OPTIONS="halt_on_error=false" ./esp_modem_rtsan; echo "Exit code: $?"

==ERROR: RealtimeSanitizer: blocking-call
  Call to blocking function `SimpleDTE::command(...)` in real-time context!

==ERROR: RealtimeSanitizer: unsafe-library-call
  Intercepted call to `pthread_mutex_lock` in real-time context!

==ERROR: RealtimeSanitizer: unsafe-library-call
  Intercepted call to `malloc` in real-time context!

==ERROR: RealtimeSanitizer: unsafe-library-call
  Intercepted call to `free` in real-time context!

==ERROR: RealtimeSanitizer: unsafe-library-call
  Intercepted call to `pthread_mutex_unlock` in real-time context!

[task] AT sync: OK
[task] Signal quality: RSSI=18, BER=99  (OK)
[task] IMSI: 310260000000000  (OK)
[rt]   Safe timer callback -- OK
[rt]   Unsafe timer callback -- violations reported above!
Exit code: 0
```

## The correct embedded pattern

The safe approach: **decouple data producers from real-time consumers** using
lock-free shared state.

```
┌─────────────────────┐       std::atomic       ┌──────────────────────┐
│  Background task    │  ──────────────────────> │  RT timer callback   │
│  (normal priority)  │   g_cached_rssi = 18     │  [[clang::nonblocking]] │
│                     │   g_cached_ber  = 99     │                      │
│  AT+CSQ via DTE     │                          │  reads atomic only   │
│  (mutex OK here)    │                          │  no mutex, no malloc │
└─────────────────────┘                          └──────────────────────┘
```

In a real ESP32 application:
- A FreeRTOS task periodically calls `dce->get_signal_quality()` and stores
  results in a shared atomic / ring buffer
- A hardware timer ISR or high-priority callback reads the cached values
- RTSan (on the Linux host build) verifies this separation is maintained

## Makefile targets

| Target | Description |
|--------|-------------|
| `make esp_modem_rtsan` | Build the demo with `-fsanitize=realtime` |
| `make run_modem` | Run; aborts on first violation (exit code 43) |
| `make run_modem_all` | Run with `halt_on_error=false` (reports all violations) |
| `make esp_modem_rtsan_safe` | Build **without** RTSan (no checks) |
| `make run_modem_safe` | Run the safe build (completes normally) |
| `make real_time` | Build the trivial example (`real_time.cpp`) |
| `make all` | Build both examples |
| `make clean` | Remove all built binaries |

## Relationship to esp_modem

This demo is a **simplified, standalone extract** of the patterns used in the
real esp_modem component. The mapping:

| Demo | esp_modem |
|------|-----------|
| `Lock` (`std::recursive_mutex`) | `esp_modem::Lock` in [esp_modem_primitives.hpp](../include/cxx_include/esp_modem_primitives.hpp) |
| `Scoped<Lock>` | `esp_modem::Scoped<T>` in the same file |
| `SimpleDTE::command()` | `esp_modem::DTE::command()` in [esp_modem_dte.cpp](../src/esp_modem_dte.cpp) |
| `command_result`, `got_line_cb` | `esp_modem::command_result` in [esp_modem_types.hpp](../include/cxx_include/esp_modem_types.hpp) |
| `generic_command()` | `esp_modem::dce_commands::generic_command()` in [esp_modem_command_library.cpp](../src/esp_modem_command_library.cpp) |
| `SimModem` | Real UART terminal + cellular module |

The full esp_modem can also be compiled on Linux host -- see the
[linux_modem](../examples/linux_modem) example. The approach shown here could
be applied to the full component to verify real-time safety of application
callbacks.

## RTSan runtime flags

Control RTSan behavior via the `RTSAN_OPTIONS` environment variable:

```bash
# Show all violations (don't abort on first)
RTSAN_OPTIONS="halt_on_error=false" ./esp_modem_rtsan

# Print statistics on exit
RTSAN_OPTIONS="halt_on_error=false:print_stats_on_exit=true" ./esp_modem_rtsan

# Suppress specific functions
echo "function-name-matches:malloc" > suppressions.txt
RTSAN_OPTIONS="suppressions=suppressions.txt" ./esp_modem_rtsan

# Disable colors (for CI logs)
RTSAN_OPTIONS="color=never" ./esp_modem_rtsan
```

| Flag | Default | Description |
|------|---------|-------------|
| `halt_on_error` | `true` | Abort after first violation |
| `suppress_equal_stacks` | `true` | Deduplicate identical violations |
| `print_stats_on_exit` | `false` | Print error counts on exit |
| `color` | `auto` | Colorize output (`always`/`never`/`auto`) |
| `suppressions` | `""` | Path to suppression file |

## Further reading

- [RTSan documentation (LLVM)](https://clang.llvm.org/docs/RealtimeSanitizer.html)
- [esp_modem component](https://github.com/espressif/esp-protocols/tree/master/components/esp_modem)
- [esp_modem linux_modem example](../examples/linux_modem)
- [Function Effect Analysis (compile-time companion)](https://clang.llvm.org/docs/FunctionEffectAnalysis.html)
