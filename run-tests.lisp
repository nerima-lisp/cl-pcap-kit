(require "asdf")
(handler-case
    (progn
      (asdf:test-system "cl-pcap-kit")
      (finish-output *standard-output*)
      (uiop:quit 0))
  (error (condition)
    (format *error-output* "~&cl-pcap-kit tests failed: ~A~%" condition)
    (finish-output *error-output*)
    (uiop:quit 1)))
