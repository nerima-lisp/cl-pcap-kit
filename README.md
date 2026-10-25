# cl-pcap-kit

`cl-pcap-kit` provides libpcap capture and packet injection to Common Lisp
through CFFI. It returns copied packet bytes and timestamps, reads saved
capture files, applies BPF filters, and enumerates capture devices.

## Development

Run `nix develop` to enter the development shell, then run `nix flake check`.
The default check uses a checked-in offline capture fixture and does not require
a capture device or elevated privileges. Live capture, injection, and device
enumeration are manual checks because they depend on host permissions and
available interfaces.

The development shell sets `CL_PCAP_KIT_LIBRARY` to the libpcap shared library.
Outside that shell, arrange for libpcap to be available to the process loader.

## API

`capture-open-offline` and `capture-open-live` create capture handles. Use
`with-offline-capture` or `with-live-capture` to close handles automatically.
`capture-next` returns two values: `(packet, :packet)` when it reads a packet,
`(nil, :timeout)` when a live read times out, or `(nil, :eof)` at the end of a
saved capture. Packet timestamps are exact rational seconds since the Unix
epoch. Packet bytes are copied into an owned octet vector; `packet-length`
reports the original packet length and `packet-captured-length` reports the
number of copied bytes. `capture-loop` passes each copied packet record to its
callback.

Use `capture-set-filter` to compile and install a BPF expression on a capture
handle, and `capture-devices` to enumerate available capture devices. Errors
from opening, reading, filtering, or enumerating devices signal `pcap-error`.

`injector-open-live` opens an injector for a live interface. Use
`with-injector` for scoped cleanup or call `close-injector` directly.
`injector-send` synchronously submits caller-supplied octets through libpcap
and returns their byte length. Its `:timeout` argument is accepted for
request-callback compatibility but does not impose a deadline. Sending and
closing the same injector are serialized; sends after close signal `pcap-error`.

## Capture and injector ownership

Capture handles own their native libpcap handle until closed. Use `with-capture`
for scoped cleanup. Copied packet bytes remain available after the capture
handle closes.

An injector owns its native libpcap handle until closed.
`injector-closed-p` reports its lifecycle state.
