# BDC2 v1 Protocol

All integers are big-endian. The protocol runs over a WebSocket (`/ws`) and can be carried over TLS.

## Frame header (24 bytes)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `BDC2` |
| 4 | 1 | version, currently `1` |
| 5 | 1 | type |
| 6 | 1 | flags (bit 0 = cleartext payload; only HELLO) |
| 7 | 1 | reserved, zero |
| 8 | 8 | session id (u64) |
| 16 | 4 | sequence number (u32, per connection and direction) |
| 20 | 4 | payload length (u32) |
| 24 | n | payload |

Every frame except HELLO is encrypted:

```text
AES-128-GCM(key, nonce = [direction, 0,0,0,0,0,0,0, seq_be32],
            plaintext = TLV payload,
            AAD = header[0:24])
```

`direction` is `0` for client-to-server and `1` for server-to-client. The 32-bit sequence number is monotonically increasing per connection and direction; a frame with a sequence number less than or equal to the last accepted value is rejected. A server keeps a short-lived in-memory replay/nonce cache; operators should treat replay protection as best-effort.

## HELLO and session key

HELLO is the only cleartext frame. Its payload is TLV:

```text
id=<client id>
os=<windows|linux|...>
arch=<x86_64|...>
ver=<build id>
pid=<decimal pid>
nonce=<16 random bytes>
mac=HMAC-SHA256(psk, "hello" || id || nonce)
```

The server computes the same MAC and rejects mismatches. The per-connection key is:

```text
key = HKDF-SHA256(ikm=psk,
                  salt=id || nonce,
                  info="backd-c2-v1",
                  length=16)
```

A fresh nonce per connection gives a fresh key while preserving replay protection. The PSK is still static, so there is **no forward secrecy**.

## Operator AUTH

The operator channel uses a separate PSK and user name:

```text
key  = HKDF-SHA256(psk, "op:" || user, "backd-c2-v1", 16)
mac  = HMAC-SHA256(psk, "opauth" || user || nonce)
```

The operator sends AUTH with `user`, `nonce`, and `mac`; the server replies AUTH_OK with the derived channel.

## Message types

### Client/server

| Type | Name | Purpose |
| --- | --- | --- |
| 1 | HELLO | cleartext registration |
| 2 | HELLO_ACK | session accepted, heartbeat settings |
| 3 | TASK | server-to-client task |
| 4 | TASK_RESULT | client task result |
| 5 | FILE_META | file transfer metadata |
| 6 | FILE_CHUNK | file data |
| 7 | FILE_ACK | file acknowledgement |
| 8 | PING | heartbeat |
| 9 | PONG | heartbeat reply |
| 10 | AUTH | operator authentication |
| 11 | AUTH_OK | operator accepted |
| 12 | NOTICE | asynchronous notice (sub=...) |
| 13 | ERROR | protocol/business error |

### Operator RPC

| Type | Name |
| --- | --- |
| 20 | OP_LIST |
| 21 | OP_LIST_RESULT |
| 22 | OP_TASK |
| 23 | OP_RESULT |
| 24 | OP_FILE_PUSH |
| 25 | OP_FILE_PULL |
| 26 | OP_FILE_FETCH |
| 27 | OP_FILE_CHUNK |
| 28 | OP_FILE_DONE |
| 29 | OP_KILL |
| 30 | OP_KICK |

## TLV encoding

A TLV payload is a sequence of records:

```text
u16 key_len | u16 value_len | key bytes | value bytes
```

Keys are UTF-8. Values are byte strings; text fields are UTF-8, except for shell output which may be CP936/GBK on older Windows systems. The operator performs best-effort decoding (UTF-8, UTF-16, GBK) before display.

## Tasks and file transfer

- Tasks carry `kind` (`sysinfo`, `echo`, `shell`, `ps`, `cat`, `persist`, `inject`, `screenshot`, ...) and a TLV argument map.
- File push uses `FILE_META` + `FILE_CHUNK` frames, a per-transfer id, and a SHA-256 digest.
- Chunk size is at most 48 KiB in the reference implementation.
- File transfer is resumable by absolute offset where the operator supports it.

## Notices

`NOTICE` carries a `sub` field. `sub=tunnel` is used for tunneled stream data; the operator demultiplexes it so it never mixes with task output. Other notices are diagnostic.

## Compatibility

The v1 layout is frozen. Adding fields to TLV maps is backward-compatible; changing the header layout or cryptographic construction requires a version bump.
