// RealtimeSanitizer (RTSan) example
// Compile with: make real_time
// Run: ./real_time
//
// RTSan detects real-time violations: calls to malloc, blocking functions, etc.
// in code marked [[clang::nonblocking]].

#include <vector>

// A function marked [[clang::nonblocking]] must not call malloc, blocking
// functions, or anything with non-deterministic execution time.
void violation() [[clang::nonblocking]] {
  std::vector<float> v;
  v.resize(100);  // allocates via malloc - triggers RTSan error!
}

// Safe real-time function: no dynamic allocation or blocking calls
void safe_realtime_fn() [[clang::nonblocking]] {
  float stack_buffer[100];
  (void)stack_buffer;
}

int main() {
  // Uncomment to trigger the violation:
  violation();

  // Safe path (no violation):
  // safe_realtime_fn();

  return 0;
}
