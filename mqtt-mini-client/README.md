# mqtt-mini-client

A deliberately small **MQTT 3.1.1** client for Linux, using **plain TCP** and the **BSD-style socket API** (`socket`, `connect`, `send`, `recv`, `poll`, `getaddrinfo`). It exists to exercise security review tooling (for example the `llm-vuln-check` pipeline) on a codebase that is easy to build and run locally against **Mosquitto** or any compatible broker.

## Features implemented

- **Transport**: TCP only (no TLS, no WebSockets).
- **Protocol**: MQTT **3.1.1** subset sufficient for basic pub/sub:
  - **CONNECT** with a UTF-8 client identifier and configurable keep-alive.
  - **CONNACK** handling (session present / return code).
  - **PUBLISH** QoS 0 from client to broker.
  - **SUBSCRIBE** with requested **QoS 0** (no `PUBACK` / `PUBREC` handling).
  - **SUBACK** drain after subscribe.
  - **PINGREQ** / **PINGRESP** on the subscriber idle path (long `poll` timeout).
  - **DISCONNECT** before closing the socket on both binaries.
- **CLI**: Two utilities, similar in spirit to `mosquitto_pub` / `mosquitto_sub`:
  - **`mqtt_pub`**: `-h` host, `-p` port (default 1883), `-t` topic, `-m` message; connects, publishes once, disconnects, exits.
  - **`mqtt_sub`**: `-h` host, `-p` port, `-t` topic; connects, subscribes, prints **each received payload on its own line**; exits on **Ctrl-C** (`SIGINT`) or **`SIGTERM`**.
- **Hostname resolution**: IPv4/IPv6 via `getaddrinfo`.
- **Build**: Single translation unit compiled twice via `BINARY_MODE`; `Makefile` targets `mqtt_pub` and `mqtt_sub`.
- **Smoke test**: `test/pubsub_exchange.sh` runs one subscriber in the background, one publisher, and checks that the payload appears on stdout.

## What is not implemented

TLS, authentication, will / testament, QoS 1/2 end-to-end for publishes you send, session persistence beyond “clean session”, automatic reconnect, shared subscriptions, MQTT 5, and strict compliance checking. Packet framing assumes a cooperative broker for normal use.

## Build

```bash
make
```

Produces `mqtt_pub` and `mqtt_sub` in this directory.

## Usage examples

```bash
./mqtt_sub -h localhost -p 1883 -t sensors/temp
# in another shell:
./mqtt_pub -h localhost -p 1883 -t sensors/temp -m "23.5"
```

You can mix with Eclipse Mosquitto tools, for example `mosquitto_pub` to `mqtt_sub` or `mqtt_pub` to `mosquitto_sub`, on the same topic.

## Test script

Requires a broker listening on the chosen host/port (defaults `127.0.0.1:1883`):

```bash
./test/pubsub_exchange.sh
```

Optional environment variables: `MQTT_HOST`, `MQTT_PORT`, `MQTT_TOPIC`, `MQTT_MSG`.

## Planted defects

Intentionally unsafe patterns are embedded for tooling experiments. See **`VULNS.md`** for a structured list and pointers into the code.
