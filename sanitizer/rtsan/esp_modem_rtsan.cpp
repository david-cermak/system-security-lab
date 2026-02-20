// =============================================================================
// esp_modem Real-Time Sanitizer (RTSan) Demo
// =============================================================================
//
// Demonstrates using Clang 20's RealtimeSanitizer with embedded modem patterns
// inspired by the esp_modem component (ESP-IDF).
//
// KEY IDEA:
//   In embedded systems, timer callbacks / ISRs must execute in bounded time.
//   AT modem commands use mutexes and blocking waits -- they are NOT real-time
//   safe. RTSan catches this at runtime when a [[clang::nonblocking]] function
//   calls into blocking code (mutex lock, malloc, condition_variable wait).
//
// PATTERNS FROM esp_modem:
//   - Lock abstraction: FreeRTOS recursive mutex on ESP32, std::recursive_mutex
//     on Linux host  (see esp_modem_primitives.hpp)
//   - Scoped<Lock>: RAII lock guard  (see esp_modem_primitives.hpp)
//   - DTE::command(): mutex-protected AT send + wait for response
//   - command_result / got_line_cb: AT response parsing
//   - generic_command(): command library pattern
//
// Build:  make esp_modem_rtsan
// Run:    ./esp_modem_rtsan
//         RTSAN_OPTIONS="halt_on_error=false" ./esp_modem_rtsan   (see all violations)
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <functional>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>

// =============================================================================
// Section 1: Platform abstraction layer
//
// Same pattern as esp_modem_primitives.hpp:
//   ESP32  -> FreeRTOS xSemaphoreCreateRecursiveMutex
//   Linux  -> std::recursive_mutex
// =============================================================================

#ifdef CONFIG_IDF_TARGET_ESP32
// ---- ESP32 / FreeRTOS path (shown for reference, not compiled here) --------
//
//  #include "freertos/semphr.h"
//  struct Lock {
//      QueueHandle_t m;
//      Lock()  { m = xSemaphoreCreateRecursiveMutex(); }
//      ~Lock() { vSemaphoreDelete(m); }
//      void lock()   { xSemaphoreTakeRecursive(m, portMAX_DELAY); }
//      void unlock() { xSemaphoreGiveRecursive(m); }
//  };
//
// ---- end ESP32 path --------------------------------------------------------
#else
// ---- Linux host path (identical to esp_modem on CONFIG_IDF_TARGET_LINUX) ----
using Lock = std::recursive_mutex;
#endif

// RAII lock guard -- same as esp_modem::Scoped<T>
template<class T>
class Scoped {
public:
    explicit Scoped(T &l) : lock_(l) { lock_.lock(); }
    ~Scoped() { lock_.unlock(); }
private:
    T &lock_;
};

// =============================================================================
// Section 2: AT command types (from esp_modem_types.hpp)
// =============================================================================

enum class command_result {
    OK,
    FAIL,
    TIMEOUT
};

using got_line_cb = std::function<command_result(uint8_t *data, size_t len)>;

// =============================================================================
// Section 3: Simulated modem
//
// In a real system this would be a UART-connected cellular module (SIM7600,
// BG96, etc.). Here we return canned responses to keep the demo self-contained.
// =============================================================================

class SimModem {
public:
    std::string process(const std::string &cmd) {
        if (cmd.find("AT+CSQ") != std::string::npos)
            return "+CSQ: 18,99\r\nOK\r\n";            // signal quality
        if (cmd.find("AT+CIMI") != std::string::npos)
            return "310260000000000\r\nOK\r\n";         // IMSI
        if (cmd.find("AT+CGSN") != std::string::npos)
            return "860000000000000\r\nOK\r\n";         // IMEI
        return "\r\nOK\r\n";
    }
};

// =============================================================================
// Section 4: Simplified DTE (Data Terminal Equipment)
//
// Mirrors esp_modem::DTE -- the core pattern:
//   command() acquires internal_lock_, sends AT cmd, waits for response.
//
// This is where the real-time violation lives: mutex lock + string allocation
// are non-deterministic operations that RTSan will flag.
// =============================================================================

class SimpleDTE {
public:
    // ---- Send AT command and wait for parsed response -----------------------
    //
    // This method is inherently blocking:
    //   1. Acquires internal_lock_ (pthread_mutex_lock under the hood)
    //   2. Allocates std::string for the response (malloc)
    //   3. Calls got_line callback to parse response
    //
    // Marking it [[clang::blocking]] tells RTSan (and developers) explicitly:
    // "Do NOT call this from a [[clang::nonblocking]] context."
    //
    command_result command(const std::string &cmd, got_line_cb got_line,
                           uint32_t timeout_ms) [[clang::blocking]]
    {
        Scoped<Lock> l(internal_lock_);                   // <-- blocks! (mutex)

        std::string response = modem_.process(cmd);       // <-- allocates! (malloc)

        if (got_line) {
            return got_line((uint8_t *)response.data(), response.size());
        }
        return command_result::TIMEOUT;
    }

    // ---- High-level commands (same pattern as esp_modem command library) ----

    command_result sync() {
        return generic_command("AT\r", "OK", "ERROR", 1000);
    }

    command_result get_signal_quality(int &rssi, int &ber) {
        return generic_command_with_parse("AT+CSQ\r", 1000,
            [&](std::string_view line) {
                return sscanf(line.data(), "+CSQ: %d,%d", &rssi, &ber) == 2;
            });
    }

    command_result get_imsi(std::string &imsi) {
        return generic_get_string("AT+CIMI\r", imsi, 1000);
    }

private:
    // -- Command library helpers (from esp_modem_command_library.cpp) ---------

    command_result generic_command(const std::string &cmd,
                                   const std::string &pass,
                                   const std::string &fail,
                                   uint32_t timeout_ms)
    {
        return command(cmd, [&](uint8_t *data, size_t len) {
            std::string_view response((char *)data, len);
            if (response.find(pass) != std::string_view::npos)
                return command_result::OK;
            if (response.find(fail) != std::string_view::npos)
                return command_result::FAIL;
            return command_result::TIMEOUT;
        }, timeout_ms);
    }

    command_result generic_get_string(const std::string &cmd, std::string &out,
                                       uint32_t timeout_ms)
    {
        return command(cmd, [&](uint8_t *data, size_t len) {
            std::string_view response((char *)data, len);
            if (response.find("OK") != std::string_view::npos) {
                // Extract payload before \r\nOK (same as esp_modem's parsing)
                auto end = response.find("\r\nOK");
                if (end != std::string_view::npos) {
                    out = std::string(response.substr(0, end));
                } else {
                    out = std::string(response);
                }
                return command_result::OK;
            }
            if (response.find("ERROR") != std::string_view::npos)
                return command_result::FAIL;
            return command_result::TIMEOUT;
        }, timeout_ms);
    }

    command_result generic_command_with_parse(const std::string &cmd,
                                              uint32_t timeout_ms,
                                              std::function<bool(std::string_view)> parse)
    {
        return command(cmd, [&](uint8_t *data, size_t len) {
            std::string_view response((char *)data, len);
            if (response.find("OK") != std::string_view::npos) {
                parse(response);
                return command_result::OK;
            }
            if (response.find("ERROR") != std::string_view::npos)
                return command_result::FAIL;
            return command_result::TIMEOUT;
        }, timeout_ms);
    }

    Lock internal_lock_;    // Same as esp_modem::DTE::internal_lock
    SimModem modem_;
};

// =============================================================================
// Section 5: Application layer -- modem monitor + real-time callbacks
//
// EMBEDDED SCENARIO:
//   - A background "task" periodically polls signal quality via AT+CSQ and
//     stores the result in a shared atomic variable.  (CORRECT pattern)
//   - A real-time timer callback reads the cached value.  (SAFE)
//   - A buggy timer callback queries the modem directly.  (VIOLATION!)
// =============================================================================

// Shared state: updated by the monitor task, read by the RT callback
static std::atomic<int> g_cached_rssi{0};
static std::atomic<int> g_cached_ber{0};

// -- SAFE real-time callback --------------------------------------------------
// Only reads atomic variables. No mutex, no malloc, no blocking.
// This is the correct embedded pattern: pre-compute in a normal task,
// consume from the real-time context via lock-free shared state.

void rt_timer_callback_safe() [[clang::nonblocking]]
{
    int rssi = g_cached_rssi.load(std::memory_order_relaxed);
    int ber  = g_cached_ber.load(std::memory_order_relaxed);

    // In a real system: update a display, trigger an alarm, adjust TX power...
    // All of these would also need to be nonblocking.
    (void)rssi;
    (void)ber;
}

// -- UNSAFE real-time callback ------------------------------------------------
// Directly calls the DTE to query signal quality.
// RTSan will catch the violation chain:
//   rt_timer_callback_unsafe  [[clang::nonblocking]]
//     -> get_signal_quality
//       -> command  [[clang::blocking]]           <-- blocking-call violation!
//         -> Scoped<Lock>::lock()                 <-- pthread_mutex_lock
//         -> std::string alloc                    <-- malloc

static SimpleDTE *g_dte = nullptr;

void rt_timer_callback_unsafe() [[clang::nonblocking]]
{
    int rssi = 0, ber = 0;
    g_dte->get_signal_quality(rssi, ber);    // BUG: blocks in RT context!
    g_cached_rssi.store(rssi);
    g_cached_ber.store(ber);
}

// =============================================================================
// Section 6: Main -- run the demo
// =============================================================================

static const char *result_str(command_result r) {
    switch (r) {
        case command_result::OK:      return "OK";
        case command_result::FAIL:    return "FAIL";
        case command_result::TIMEOUT: return "TIMEOUT";
    }
    return "?";
}

int main()
{
    printf("===========================================================\n");
    printf("  esp_modem Real-Time Sanitizer (RTSan) Demo\n");
    printf("  Clang 20 -fsanitize=realtime\n");
    printf("===========================================================\n\n");

    SimpleDTE dte;
    g_dte = &dte;

    // -- Step 1: Normal (non-RT) AT commands -- perfectly fine ----------------
    printf("[task] Sending AT sync command...\n");
    auto r = dte.sync();
    printf("[task] AT sync: %s\n\n", result_str(r));

    int rssi = 0, ber = 0;
    printf("[task] Querying signal quality (AT+CSQ)...\n");
    r = dte.get_signal_quality(rssi, ber);
    printf("[task] Signal quality: RSSI=%d, BER=%d  (%s)\n", rssi, ber, result_str(r));

    std::string imsi;
    printf("[task] Reading IMSI (AT+CIMI)...\n");
    r = dte.get_imsi(imsi);
    printf("[task] IMSI: %s  (%s)\n\n", imsi.c_str(), result_str(r));

    // Cache results for the safe RT callback
    g_cached_rssi.store(rssi);
    g_cached_ber.store(ber);

    // -- Step 2: Safe RT callback -- reads atomics only ----------------------
    printf("[rt]   Safe timer callback (reads cached atomic)...\n");
    rt_timer_callback_safe();
    printf("[rt]   OK -- no RTSan violation\n\n");

    // -- Step 3: Unsafe RT callback -- RTSan will catch this! ----------------
    printf("[rt]   Unsafe timer callback (calls AT+CSQ from RT context)...\n");
    printf("[rt]   RTSan should report a violation here:\n\n");
    rt_timer_callback_unsafe();

    // If RTSan is enabled, we never reach here (halt_on_error=true by default)
    printf("\n[rt]   (unreachable with RTSan -- if you see this, RTSan is off)\n");

    g_dte = nullptr;
    return 0;
}
