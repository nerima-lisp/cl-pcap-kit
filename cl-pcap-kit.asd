(asdf:defsystem "cl-pcap-kit"
  :description "Passive libpcap capture for Common Lisp"
  :version "0.1.0"
  :license "MIT"
  :defsystem-depends-on ("cffi-grovel")
  :depends-on ("cffi" "cl-cffi-kit")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "package")
     (:file "conditions")
     (:cffi-grovel-file "grovel/pcap")
     (:file "ffi")
     (:file "types")
     (:file "capture")
     (:file "inject"))))
  :in-order-to
  ((asdf:test-op (asdf:test-op "cl-pcap-kit/test"))))

(asdf:defsystem "cl-pcap-kit/test"
  :depends-on ("cl-pcap-kit" "cl-weave")
  :serial t
  :components
  ((:module "t"
    :serial t
    :components
    ((:file "package")
     (:file "cl-pcap-kit-test"))))
  :perform (asdf:test-op (operation system)
    (declare (ignore operation system))
    (uiop:symbol-call :cl-pcap-kit/test :run-tests)))
