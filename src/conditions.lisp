(in-package #:cl-pcap-kit)

(define-condition pcap-error (error)
  ((operation
    :initarg :operation
    :reader pcap-error-operation)
   (message
    :initarg :message
    :reader pcap-error-message))
  (:report (lambda (condition stream)
             (format stream "libpcap ~A failed: ~A"
                     (pcap-error-operation condition)
                     (pcap-error-message condition)))))
