(in-package #:cl-pcap-kit)

(defun %null-pointer-p (pointer)
  (cffi:null-pointer-p pointer))

(defun %error-buffer-message (buffer)
  (let ((message (foreign-string-to-lisp buffer)))
    (if (and message (plusp (length message)))
        message
        "unknown libpcap error")))

(defun %signal-pcap-error (operation message)
  (error 'pcap-error :operation operation :message message))

(defun %signal-handle-error (capture operation)
  (let ((message-pointer (%pcap-geterr (capture-handle capture))))
    (%signal-pcap-error
     operation
     (if (%null-pointer-p message-pointer)
         "unknown libpcap error"
         (foreign-string-to-lisp message-pointer)))))

(defun %timestamp-scale (handle)
  (let ((precision (%pcap-get-tstamp-precision handle)))
    (case precision
      (0 1000000)
      (1 1000000000)
      (-1 1000000)
      (otherwise
       (error 'pcap-error
              :operation "pcap_get_tstamp_precision"
              :message (format nil "unexpected precision value ~D" precision))))))

(defun %make-open-capture (handle operation)
  (when (%null-pointer-p handle)
    (return-from %make-open-capture nil))
  (handler-case
      (%make-capture handle (%timestamp-scale handle))
    (pcap-error (condition)
      (%pcap-close handle)
      (error condition))
    (error (condition)
      (%pcap-close handle)
      (%signal-pcap-error operation (princ-to-string condition)))))

(defun %ensure-open (capture)
  (check-type capture capture)
  (when (capture-closed-p capture)
    (%signal-pcap-error "capture" "capture is already closed"))
  capture)

(defun capture-open-offline (path)
  (check-type path (or string pathname))
  (let ((filename-string (if (pathnamep path) (namestring path) path)))
    (with-foreign-object (errbuf :char +pcap-errbuf-size+)
      (dotimes (index +pcap-errbuf-size+)
        (setf (cffi:mem-aref errbuf :char index) 0))
      (with-foreign-string (filename filename-string)
        (let ((handle (%pcap-open-offline filename errbuf)))
          (if (%null-pointer-p handle)
              (%signal-pcap-error "pcap_open_offline" (%error-buffer-message errbuf))
              (or (%make-open-capture handle "pcap_open_offline")
                  (%signal-pcap-error "pcap_open_offline" "failed to open capture"))))))))

(defun capture-open-live (device
                          &key
                            (snapshot-length 65535)
                            (promiscuous-p nil)
                            (timeout-ms 1000))
  (check-type device string)
  (check-type snapshot-length (integer 1 #x7fffffff))
  (check-type timeout-ms (integer 0 #x7fffffff))
  (check-type promiscuous-p boolean)
  (with-foreign-object (errbuf :char +pcap-errbuf-size+)
    (dotimes (index +pcap-errbuf-size+)
      (setf (cffi:mem-aref errbuf :char index) 0))
    (with-foreign-string (foreign-device device)
      (let ((handle (%pcap-open-live foreign-device
                                     snapshot-length
                                     (if promiscuous-p 1 0)
                                     timeout-ms
                                     errbuf)))
        (if (%null-pointer-p handle)
            (%signal-pcap-error "pcap_open_live" (%error-buffer-message errbuf))
            (or (%make-open-capture handle "pcap_open_live")
                (%signal-pcap-error "pcap_open_live" "failed to open capture")))))))

(defun close-capture (capture)
  (check-type capture capture)
  (unless (capture-closed-p capture)
    (%pcap-close (capture-handle capture))
    (setf (capture-closed-p capture) t
          (capture-handle capture) (cffi:null-pointer)))
  capture)

(defmacro with-capture ((variable capture-form) &body body)
  `(let ((,variable ,capture-form))
     (unwind-protect
          (progn ,@body)
       (close-capture ,variable))))

(defmacro with-offline-capture ((variable path) &body body)
  `(with-capture (,variable (capture-open-offline ,path))
     ,@body))

(defmacro with-live-capture ((variable device &rest options) &body body)
  `(with-capture (,variable (capture-open-live ,device ,@options))
     ,@body))

(defun %copy-packet (capture header bytes)
  (let* ((captured-length
           (foreign-slot-value header '(:struct pcap-pkthdr) 'captured-length))
         (length (foreign-slot-value header '(:struct pcap-pkthdr) 'length))
         (timestamp-pointer
           (cffi:foreign-slot-pointer header '(:struct pcap-pkthdr) 'timestamp))
         (seconds
           (foreign-slot-value timestamp-pointer '(:struct timeval) 'seconds))
         (fraction
           (foreign-slot-value timestamp-pointer '(:struct timeval) 'microseconds))
         (scale (capture-timestamp-scale capture))
         (contents (make-array captured-length
                               :element-type '(unsigned-byte 8))))
    (dotimes (index captured-length)
      (setf (aref contents index)
            (cffi:mem-aref bytes :unsigned-char index)))
    (%make-packet (+ seconds (/ fraction scale))
                  captured-length
                  length
                  contents)))

(defun capture-next (capture)
  (%ensure-open capture)
  (with-foreign-objects ((header-pointer :pointer)
                         (bytes-pointer :pointer))
    (setf (cffi:mem-ref header-pointer :pointer) (cffi:null-pointer)
          (cffi:mem-ref bytes-pointer :pointer) (cffi:null-pointer))
    (let ((status (%pcap-next-ex (capture-handle capture)
                                header-pointer
                                bytes-pointer)))
      (case status
        (1 (values (%copy-packet capture
                                 (cffi:mem-ref header-pointer :pointer)
                                 (cffi:mem-ref bytes-pointer :pointer))
                   :packet))
        (0 (values nil :timeout))
        (-2 (values nil :eof))
        (-1 (%signal-handle-error capture "pcap_next_ex"))
        (otherwise
         (%signal-pcap-error "pcap_next_ex"
                             (format nil "unexpected status value ~D" status)))))))

(cffi:defcallback %packet-callback :void
    ((user :pointer) (header :pointer) (bytes :pointer))
  (declare (ignore user))
  (handler-case
      (funcall *loop-callback-function* (%copy-packet *loop-callback-capture*
                                                    header
                                                    bytes))
    (error (condition)
      (setf *loop-callback-condition* condition)
      (%pcap-breakloop (capture-handle *loop-callback-capture*)))))

(defun capture-loop (capture function &key (count :all))
  (%ensure-open capture)
  (check-type function function)
  (let ((native-count (etypecase count
                        ((integer 1 #x7fffffff) count)
                        ((member :all) -1))))
    (let ((*loop-callback-function* function)
          (*loop-callback-capture* capture)
          (*loop-callback-condition* nil))
      (let ((status (%pcap-loop (capture-handle capture)
                                native-count
                                (cffi:callback %packet-callback)
                                (cffi:null-pointer))))
        (when *loop-callback-condition*
          (error *loop-callback-condition*))
        (when (= status +pcap-error+)
          (%signal-handle-error capture "pcap_loop"))
        status))))

(defun capture-set-filter (capture expression &key (optimize-p t))
  (%ensure-open capture)
  (check-type expression string)
  (check-type optimize-p boolean)
  (with-foreign-object (program '(:struct bpf-program))
    (with-foreign-string (foreign-expression expression)
      (let ((compile-status
              (%pcap-compile (capture-handle capture)
                             program
                             foreign-expression
                             (if optimize-p 1 0)
                             +pcap-netmask-unknown+)))
        (when (/= compile-status 0)
          (%signal-handle-error capture "pcap_compile"))))
    (unwind-protect
         (let ((filter-status (%pcap-setfilter (capture-handle capture) program)))
           (unless (= filter-status 0)
             (%signal-handle-error capture "pcap_setfilter"))
           capture)
      (%pcap-freecode program))))

(defun %foreign-string-or-nil (pointer)
  (unless (%null-pointer-p pointer)
    (foreign-string-to-lisp pointer)))

(defun capture-devices ()
  (with-foreign-objects ((devices-pointer :pointer)
                         (errbuf :char +pcap-errbuf-size+))
    (setf (cffi:mem-ref devices-pointer :pointer) (cffi:null-pointer))
    (dotimes (index +pcap-errbuf-size+)
      (setf (cffi:mem-aref errbuf :char index) 0))
    (let* ((status (%pcap-findalldevs devices-pointer errbuf))
           (head (cffi:mem-ref devices-pointer :pointer)))
      (unwind-protect
           (progn
             (unless (= status 0)
               (%signal-pcap-error "pcap_findalldevs"
                                   (%error-buffer-message errbuf)))
             (loop for current = head then next
                   while (not (%null-pointer-p current))
                   for next = (foreign-slot-value current '(:struct pcap-if) 'next)
                   for name = (foreign-slot-value current '(:struct pcap-if) 'name)
                   for description = (foreign-slot-value current
                                                         '(:struct pcap-if)
                                                         'description)
                   for flags = (foreign-slot-value current '(:struct pcap-if) 'flags)
                   collect (%make-device (%foreign-string-or-nil name)
                                         (%foreign-string-or-nil description)
                                         flags)))
        (unless (%null-pointer-p head)
          (%pcap-freealldevs head))))))
