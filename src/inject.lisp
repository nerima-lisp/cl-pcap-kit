(in-package #:cl-pcap-kit)

(defstruct (injector
             (:constructor %make-injector (handle))
             (:conc-name %injector-))
  handle
  (closed-p nil)
  (lock (sb-thread:make-mutex :name "cl-pcap-kit injector")))

(defun injector-closed-p (injector)
  (check-type injector injector)
  (sb-thread:with-mutex ((%injector-lock injector))
    (%injector-closed-p injector)))

(defun %injector-error-message (injector)
  (let ((message-pointer (%pcap-geterr (%injector-handle injector))))
    (if (%null-pointer-p message-pointer)
        "unknown libpcap error"
        (foreign-string-to-lisp message-pointer))))

(defun %make-open-injector (handle operation)
  (when (%null-pointer-p handle)
    (return-from %make-open-injector nil))
  (handler-case
      (%make-injector handle)
    (pcap-error (condition)
      (%pcap-close handle)
      (error condition))
    (error (condition)
      (%pcap-close handle)
      (%signal-pcap-error operation (princ-to-string condition)))))

(defun injector-open-live (device &key timeout-ms (snapshot-length 65535))
  "Open a live libpcap handle for injection. TIMEOUT-MS is required by
pcap_open_live, but it does not limit later sends."
  (check-type device string)
  (check-type snapshot-length (integer 1 #x7fffffff))
  (check-type timeout-ms (integer 0 #x7fffffff))
  (with-foreign-object (errbuf :char +pcap-errbuf-size+)
    (dotimes (index +pcap-errbuf-size+)
      (setf (cffi:mem-aref errbuf :char index) 0))
    (with-foreign-string (foreign-device device)
      (let ((handle (%pcap-open-live foreign-device
                                     snapshot-length
                                     0
                                     timeout-ms
                                     errbuf)))
        (if (%null-pointer-p handle)
            (%signal-pcap-error "pcap_open_live" (%error-buffer-message errbuf))
            (or (%make-open-injector handle "pcap_open_live")
                (%signal-pcap-error "pcap_open_live" "failed to open injector")))))))

(defun injector-send (injector packet &key timeout)
  "Inject PACKET and return its byte length.
TIMEOUT is accepted for request-callback compatibility, but is not enforced.
pcap_sendpacket is synchronous and provides no send timeout or cancellation."
  (declare (ignore timeout))
  (check-type injector injector)
  (check-type packet (vector (unsigned-byte 8)))
  (let ((length (length packet)))
    (check-type length (integer 1 #x7fffffff))
    (with-foreign-object (foreign-packet :unsigned-char length)
      (dotimes (index length)
        (setf (cffi:mem-aref foreign-packet :unsigned-char index)
              (aref packet index)))
      (let ((closed-p nil)
            (send-result nil)
            (send-error-message nil)
            (failure-condition nil))
        (sb-thread:with-mutex ((%injector-lock injector))
          (setf closed-p (%injector-closed-p injector))
          (unless closed-p
            (handler-case
                (progn
                  (setf send-result
                        (%pcap-sendpacket (%injector-handle injector)
                                          foreign-packet
                                          length))
                  (unless (= send-result 0)
                    (setf send-error-message
                          (%injector-error-message injector))))
              (error (condition)
                (setf failure-condition condition)))))
        (when failure-condition
          (error failure-condition))
        (when closed-p
          (%signal-pcap-error "injector" "injector is already closed"))
        (unless (= send-result 0)
          (%signal-pcap-error "pcap_sendpacket" send-error-message))
        length))))

(defun close-injector (injector)
  (check-type injector injector)
  (let ((handle nil)
        (failure-condition nil))
    (sb-thread:with-mutex ((%injector-lock injector))
      (unless (%injector-closed-p injector)
        (setf handle (%injector-handle injector)
              (%injector-closed-p injector) t
              (%injector-handle injector) (cffi:null-pointer))
        (handler-case
            (%pcap-close handle)
          (error (condition)
            (setf failure-condition condition)))))
    (when failure-condition
      (error failure-condition))
    injector))

(defmacro with-injector ((variable injector-form) &body body)
  `(let ((,variable ,injector-form))
     (unwind-protect
          (progn ,@body)
       (close-injector ,variable))))
