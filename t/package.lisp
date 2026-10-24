(defpackage #:cl-pcap-kit/test
  (:use #:cl #:cl-pcap-kit)
  (:shadowing-import-from #:cl-weave #:describe)
  (:import-from #:cl-weave #:expect #:it)
  (:export #:run-tests))

(in-package #:cl-pcap-kit/test)
