(in-package #:cl-pcap-kit)

(include "pcap/pcap.h")
(pkg-config-cflags "libpcap")

(ctype pcap-time-t "time_t")
(ctype pcap-suseconds-t "suseconds_t")
(ctype pcap-u-int "u_int")

(constant (+pcap-errbuf-size+ "PCAP_ERRBUF_SIZE"))
(constant (+pcap-netmask-unknown+ "PCAP_NETMASK_UNKNOWN"))

(cstruct timeval "struct timeval"
  (seconds "tv_sec" :type pcap-time-t)
  (microseconds "tv_usec" :type pcap-suseconds-t))

(cstruct pcap-pkthdr "struct pcap_pkthdr"
  (timestamp "ts" :type (:struct timeval))
  (captured-length "caplen" :type :uint32)
  (length "len" :type :uint32))

(cstruct bpf-program "struct bpf_program"
  (instruction-count "bf_len" :type pcap-u-int)
  (instructions "bf_insns" :type :pointer))

(cstruct pcap-if "struct pcap_if"
  (next "next" :type :pointer)
  (name "name" :type :pointer)
  (description "description" :type :pointer)
  (addresses "addresses" :type :pointer)
  (flags "flags" :type pcap-u-int))
