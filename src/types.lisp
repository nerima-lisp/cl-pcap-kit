(in-package #:cl-pcap-kit)

(defstruct (capture (:constructor %make-capture (handle timestamp-scale)))
  handle
  timestamp-scale
  (closed-p nil))

(defstruct (packet (:constructor %make-packet
                    (timestamp captured-length length bytes)))
  timestamp
  captured-length
  length
  bytes)

(defstruct (device (:constructor %make-device (name description flags)))
  name
  description
  flags)

(defvar *loop-callback-function* nil)
(defvar *loop-callback-capture* nil)
(defvar *loop-callback-condition* nil)

(defconstant +pcap-error+ -1)
