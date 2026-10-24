(in-package #:cl-pcap-kit)

(let ((library-path (uiop:getenv "CL_PCAP_KIT_LIBRARY")))
  (when library-path
    (pushnew (make-pathname :name nil :type nil :defaults (pathname library-path))
             cffi:*foreign-library-directories*
             :test #'equal)))

(cffi:define-foreign-library libpcap
  (:darwin (:or "libpcap.dylib" "libpcap.A.dylib"))
  (:unix (:or "libpcap.so.1" "libpcap.so"))
  (t (:default "pcap")))

(cffi:use-foreign-library libpcap)

(cffi:defcfun ("pcap_open_offline" %pcap-open-offline) :pointer
  (filename :pointer)
  (errbuf :pointer))

(cffi:defcfun ("pcap_open_live" %pcap-open-live) :pointer
  (device :pointer)
  (snapshot-length :int)
  (promiscuous :int)
  (timeout-ms :int)
  (errbuf :pointer))

(cffi:defcfun ("pcap_close" %pcap-close) :void
  (handle :pointer))

(cffi:defcfun ("pcap_next_ex" %pcap-next-ex) :int
  (handle :pointer)
  (header :pointer)
  (bytes :pointer))

(cffi:defcfun ("pcap_loop" %pcap-loop) :int
  (handle :pointer)
  (count :int)
  (callback :pointer)
  (user :pointer))

(cffi:defcfun ("pcap_breakloop" %pcap-breakloop) :void
  (handle :pointer))

(cffi:defcfun ("pcap_compile" %pcap-compile) :int
  (handle :pointer)
  (program :pointer)
  (expression :pointer)
  (optimize :int)
  (netmask :uint32))

(cffi:defcfun ("pcap_setfilter" %pcap-setfilter) :int
  (handle :pointer)
  (program :pointer))

(cffi:defcfun ("pcap_freecode" %pcap-freecode) :void
  (program :pointer))

(cffi:defcfun ("pcap_geterr" %pcap-geterr) :pointer
  (handle :pointer))

(cffi:defcfun ("pcap_get_tstamp_precision" %pcap-get-tstamp-precision) :int
  (handle :pointer))

(cffi:defcfun ("pcap_findalldevs" %pcap-findalldevs) :int
  (devices :pointer)
  (errbuf :pointer))

(cffi:defcfun ("pcap_freealldevs" %pcap-freealldevs) :void
  (devices :pointer))
