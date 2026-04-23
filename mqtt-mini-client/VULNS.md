# Planted vulnerabilities (mqtt-mini-client)

This project includes **intentional memory-safety and robustness weaknesses** so automated or manual security reviews have concrete targets. Normal use against a local Mosquitto broker with short hostnames, topics, and messages stays functional; abuse or malformed traffic can trigger undefined behavior or crashes.

The list below is **non-exhaustive** (other edge cases may exist); it focuses on the defects that were **deliberately introduced** or left obvious for training and pipeline testing.

---

## 1. Stack buffer overflow on `-h` / hostname handling

- **Location**: `parse_args_pub`, `parse_args_sub` — `strcpy(o.host, optarg)` into `Options::host` (`char host[64]`).
- **Issue**: There is no length check before copying. A hostname longer than 63 bytes plus terminator **overflows** the stack buffer.
- **Typical trigger**: `./mqtt_pub -h "$(python3 -c 'print("A"*128)')" -t t -m m`
- **Notes**: Classic C string API misuse; modern toolchains may emit warnings for `strcpy`, but the bug is left in on purpose.

---

## 2. Stack buffer overflow / terminator write past end on inbound PUBLISH topic

- **Location**: `unsafe_copy_topic` — copies `topic_len` bytes from the packet into `topic_buf[256]`, then writes `dst[topic_len] = '\0'`, while **`dst_cap` is ignored** (`(void)dst_cap`).
- **Issue**: The MQTT **two-byte topic length** is taken from the broker. If `topic_len` is **255 or larger**, the terminating `NUL` is written **out of bounds** past `topic_buf`. For `topic_len > 256`, **`memcpy` also writes past** the end of `topic_buf`.
- **Typical trigger**: A malicious or buggy broker sending a PUBLISH with a very large topic length (or inconsistent length vs. packet body) in combination with this client’s parsing path.
- **Notes**: In the current subscriber loop, topic extraction is still guarded elsewhere for some consistency checks before calling `unsafe_copy_topic`, but the helper itself is **intentionally unsafe** and documents the intended bug class.

---

## 3. “Debug” read past the logical end of the topic field

- **Location**: `debug_peek_past_topic` — XORs bytes at indices `topic_start + topic_len + i` for `i in [0,7)` within the received **packet body** buffer.
- **Issue**: This is framed as debug correlation but **reads past the MQTT topic bytes** (still bounded by `base_len`, so it is an **out-of-bounds read relative to the topic string**, not an unbounded wild read off the end of the allocation). It encourages auditors to ask whether any future refactor could remove `base_len` discipline or extend the peek range unsafely.
- **Typical trigger**: Any received PUBLISH where the code path runs with a short remaining packet (the loop is clamped by `base_len`; worst case is redundant reads of padding/garbage after the topic within the same buffer).

---

## 4. Unchecked remaining-length accumulation

- **Location**: `read_remaining_length` — accumulates MQTT **variable-byte remaining length** into a `uint32_t` with **no overflow / sanity bound** on the running sum or multiplier growth beyond the loop continuing while the continuation bit is set.
- **Issue**: Malformed or hostile length encodings can cause **integer wraparound or absurd lengths** before other caps (for example in `handle_server_traffic` or `drain_connack`) intervene. Effects range from **logic errors** to **huge allocations** or inconsistent state depending on call site.
- **Typical trigger**: Crafted first byte of a packet followed by a non-terminating variable-length sequence (pen-test tooling or a broken peer).

---

## Severity disclaimer

Impact depends on trust model: against **only Mosquitto on localhost** with benign topics, these may never fire. Against **untrusted brokers or on-path attackers**, several of the above become **realistic memory corruption or DoS** vectors. Do not use this client as a reference for production MQTT code.
