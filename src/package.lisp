(defpackage #:cl-pcap-kit
  (:use #:cl)
  (:import-from #:cl-cffi-kit
                #:foreign-slot-value
                #:foreign-string-to-lisp
                #:with-foreign-object
                #:with-foreign-objects
                #:with-foreign-string)
  (:export
   #:capture
   #:capture-next
   #:capture-loop
   #:capture-set-filter
   #:capture-devices
   #:capture-open-offline
   #:capture-open-live
   #:close-capture
   #:with-capture
   #:with-offline-capture
   #:with-live-capture
   #:capture-closed-p
   #:packet
   #:packet-timestamp
   #:packet-captured-length
   #:packet-length
   #:packet-bytes
   #:device
   #:device-name
   #:device-description
   #:device-flags
   #:pcap-error
   #:pcap-error-operation
   #:pcap-error-message))

(in-package #:cl-pcap-kit)
