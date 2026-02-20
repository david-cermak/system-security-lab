# RealtimeSanitizer (RTSan) examples
# Requires clang-20 with compiler-rt support

CXX = clang++-20
CXXFLAGS = -fsanitize=realtime -g -O0 -std=c++17
LDFLAGS = -fsanitize=realtime

# === Trivial example (malloc in nonblocking context) =========================

real_time: real_time.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

run: real_time
	./real_time

# Safe build: compile without -fsanitize=realtime (no RTSan checks)
real_time_safe: real_time.cpp
	$(CXX) -g -O0 -o $@ $<

run_safe: real_time_safe
	./real_time_safe

# === esp_modem RTSan demo (AT commands + mutex from RT context) ==============

esp_modem_rtsan: esp_modem_rtsan.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

# Run with RTSan (will abort on first violation -- expected!)
run_modem: esp_modem_rtsan
	./esp_modem_rtsan; echo "Exit code: $$?"

# Run showing ALL violations (continues past first error)
run_modem_all: esp_modem_rtsan
	RTSAN_OPTIONS="halt_on_error=false" ./esp_modem_rtsan; echo "Exit code: $$?"

# Build without RTSan (no violations, runs to completion)
esp_modem_rtsan_safe: esp_modem_rtsan.cpp
	$(CXX) -g -O0 -std=c++17 -o $@ $<

run_modem_safe: esp_modem_rtsan_safe
	./esp_modem_rtsan_safe

# =============================================================================

all: real_time esp_modem_rtsan

clean:
	rm -f real_time real_time_safe esp_modem_rtsan esp_modem_rtsan_safe

.PHONY: run run_safe run_modem run_modem_all run_modem_safe all clean
