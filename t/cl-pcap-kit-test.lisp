(in-package #:cl-pcap-kit/test)

(cffi:defcfun ("pcap_open_dead" %pcap-open-dead :library cl-pcap-kit::libpcap)
  :pointer
  (linktype :int)
  (snapshot-length :int))

(defun %fixture-path ()
  (asdf:system-relative-pathname "cl-pcap-kit" "tests/fixtures/minimal.pcap"))

(defun %signals-condition-p (condition-type thunk)
  (handler-case (progn
                  (funcall thunk)
                  nil)
    (error (condition)
      (typep condition condition-type))))

(describe "offline capture"
          (it "copies packet metadata and bytes, then reports savefile EOF"
              (with-offline-capture (capture (%fixture-path))
                (multiple-value-bind (packet status) (capture-next capture)
                  (expect status :to-be :packet)
                  (expect (packet-timestamp packet)
                          :to-be
                          (/ 1700000000123456 1000000))
                  (expect (packet-captured-length packet) :to-be 46)
                  (expect (packet-length packet) :to-be 46)
                  (expect (packet-bytes packet)
                          :to-equalp
                          #(#x00 #x11 #x22 #x33 #x44 #x55
                            #x66 #x77 #x88 #x99 #xaa #xbb
                            #x08 #x00 #x45 #x00 #x00 #x20
                            #x00 #x01 #x00 #x00 #x40 #x11
                            #x00 #x00 #xc0 #x00 #x02 #x01
                            #xc6 #x33 #x64 #x02 #x30 #x39
                            #x00 #x35 #x00 #x0c #x00 #x00
                            #x74 #x65 #x73 #x74))
                  (multiple-value-bind (eof eof-status) (capture-next capture)
                    (expect eof :to-be nil)
                    (expect eof-status :to-be :eof)))))
          (it "compiles and installs a BPF filter on the same capture"
              (with-offline-capture (capture (%fixture-path))
                (expect (capture-set-filter capture "udp and dst port 53")
                        :to-be
                        capture)
                (multiple-value-bind (packet status) (capture-next capture)
                  (expect status :to-be :packet)
                  (expect (packet-length packet) :to-be 46))))
          (it "reports invalid BPF expressions as libpcap errors"
              (with-offline-capture (capture (%fixture-path))
                (expect (%signals-condition-p
                         'pcap-error
                         (lambda () (capture-set-filter capture "udp and and")))
                        :to-be
                        t))))

(describe "capture loop"
  (it "passes owned packet records to its callback"
    (with-offline-capture (capture (%fixture-path))
      (let ((packets '()))
        (expect (capture-loop capture
                              (lambda (packet)
                                (push packet packets))
                              :count 1)
                :to-be
                0)
        (close-capture capture)
        (expect (packet-bytes (first packets))
                :to-equalp
                #(#x00 #x11 #x22 #x33 #x44 #x55
                  #x66 #x77 #x88 #x99 #xaa #xbb
                  #x08 #x00 #x45 #x00 #x00 #x20
                  #x00 #x01 #x00 #x00 #x40 #x11
                  #x00 #x00 #xc0 #x00 #x02 #x01
                  #xc6 #x33 #x64 #x02 #x30 #x39
                  #x00 #x35 #x00 #x0c #x00 #x00
                  #x74 #x65 #x73 #x74)))))
  (it "re-signals callback conditions after returning from libpcap"
    (with-offline-capture (capture (%fixture-path))
      (expect (%signals-condition-p
               'simple-error
               (lambda ()
                 (capture-loop capture
                               (lambda (packet)
                                 (declare (ignore packet))
                                 (error "callback failed"))
                               :count 1)))
              :to-be
              t))))

(describe "capture cleanup"
          (it "closes on nonlocal exit and allows repeated close calls"
              (let ((capture nil))
                (catch 'finished
                  (with-offline-capture (opened (%fixture-path))
                    (setf capture opened)
                    (throw 'finished :finished)))
                (expect (cl-pcap-kit::capture-closed-p capture) :to-be t)
                (expect (close-capture capture) :to-be capture)
                (expect (cl-pcap-kit::capture-closed-p capture) :to-be t))))

(defun run-tests ()
  (unless (cl-weave:run-all :reporter :spec :pass-with-no-tests nil)
    (error "cl-pcap-kit test suite failed.")))

(defun %open-dead-test-injector ()
  (let ((handle (%pcap-open-dead 1 65535)))
    (when (cl-pcap-kit::%null-pointer-p handle)
      (error "pcap_open_dead returned a null handle"))
    (or (cl-pcap-kit::%make-open-injector handle "pcap_open_dead")
        (error "could not create an injector from a dead pcap handle"))))

(describe "packet injection binding"
  (it "keeps closed handles immutable and serializes sends with close"
    (let* ((send-symbol (find-symbol "%PCAP-SENDPACKET" "CL-PCAP-KIT"))
           (original-send (symbol-function send-symbol))
           (setter-name (list (find-symbol "SETF" "COMMON-LISP")
                              (find-symbol "INJECTOR-CLOSED-P" "CL-PCAP-KIT")))
           (pcap-error-type (find-symbol "PCAP-ERROR" "CL-PCAP-KIT"))
           (packet (make-array 1 :element-type '(unsigned-byte 8)
                               :initial-element 0))
           (lifecycle-injector (%open-dead-test-injector))
           (race-injector (%open-dead-test-injector))
           (event-lock (sb-thread:make-mutex :name "injector test events"))
           (send-entered (sb-thread:make-semaphore))
           (release-send (sb-thread:make-semaphore))
           (close-attempted (sb-thread:make-semaphore))
           (send-calls 0)
           (send-active nil)
           (block-sends nil)
           (sender nil)
           (closer nil))
      (flet ((finish-thread (thread)
               (when thread
                 (multiple-value-bind (result status)
                     (sb-thread:join-thread thread :timeout 1 :default :timed-out)
                   (declare (ignore result))
                   (when (eq status :timeout)
                     (sb-thread:terminate-thread thread)
                     (sb-thread:join-thread thread :default :terminated))))))
        (unwind-protect
             (progn
               (setf (symbol-function send-symbol)
                     (lambda (handle foreign-packet length)
                       (declare (ignore handle foreign-packet length))
                       (let ((wait-p nil))
                         (sb-thread:with-mutex (event-lock)
                           (incf send-calls)
                           (setf wait-p block-sends)
                           (when wait-p
                             (setf send-active t)))
                         (when wait-p
                           (sb-thread:signal-semaphore send-entered)
                           (sb-thread:wait-on-semaphore release-send)
                           (sb-thread:with-mutex (event-lock)
                             (setf send-active nil)))
                         0)))
               (expect (not (fboundp setter-name)) :to-be t)
               (expect (injector-closed-p lifecycle-injector) :to-be nil)
               (expect (close-injector lifecycle-injector)
                       :to-be
                       lifecycle-injector)
               (expect (injector-closed-p lifecycle-injector) :to-be t)
               (expect (%signals-condition-p
                        pcap-error-type
                        (lambda ()
                          (injector-send lifecycle-injector packet)))
                       :to-be
                       t)
               (sb-thread:with-mutex (event-lock)
                 (expect send-calls :to-be 0)
                 (setf block-sends t))
               (setf sender
                     (sb-thread:make-thread
                      (lambda ()
                        (injector-send race-injector packet))))
               (expect (not (null (sb-thread:wait-on-semaphore
                                  send-entered
                                  :timeout 1)))
                       :to-be
                       t)
               (setf closer
                     (sb-thread:make-thread
                      (lambda ()
                        (sb-thread:signal-semaphore close-attempted)
                        (close-injector race-injector)
                        :closed)))
               (expect (not (null (sb-thread:wait-on-semaphore
                                  close-attempted
                                  :timeout 1)))
                       :to-be
                       t)
               (multiple-value-bind (result status)
                   (sb-thread:join-thread closer
                                          :timeout 0.2
                                          :default :blocked)
                 (expect status :to-be :timeout)
                 (expect result :to-be :blocked))
               (sb-thread:with-mutex (event-lock)
                 (expect send-calls :to-be 1)
                 (expect send-active :to-be t))
               (sb-thread:signal-semaphore release-send)
               (multiple-value-bind (result status)
                   (sb-thread:join-thread sender
                                          :timeout 1
                                          :default :timed-out)
                 (expect status :to-be nil)
                 (expect result :to-be 1))
               (multiple-value-bind (result status)
                   (sb-thread:join-thread closer
                                          :timeout 1
                                          :default :timed-out)
                 (expect status :to-be nil)
                 (expect result :to-be :closed))
               (expect (injector-closed-p race-injector) :to-be t)
               (expect (%signals-condition-p
                        pcap-error-type
                        (lambda ()
                          (injector-send race-injector packet)))
                       :to-be
                       t)
               (expect (close-injector race-injector)
                       :to-be
                       race-injector)
               (sb-thread:with-mutex (event-lock)
                 (expect send-calls :to-be 1)
                 (expect send-active :to-be nil)))
          (sb-thread:signal-semaphore release-send)
          (finish-thread sender)
          (finish-thread closer)
          (unless (injector-closed-p lifecycle-injector)
            (close-injector lifecycle-injector))
          (unless (injector-closed-p race-injector)
            (close-injector race-injector))
          (setf (symbol-function send-symbol) original-send)))))
  (it "loads and resolves pcap_sendpacket without transmitting"
    (expect (not (null (fboundp (find-symbol "%PCAP-SENDPACKET" "CL-PCAP-KIT"))))
            :to-be
            t)
    (expect (not (null (cffi:foreign-symbol-pointer
                        "pcap_sendpacket"
                        :library
                        (find-symbol "LIBPCAP" "CL-PCAP-KIT"))))
            :to-be
            t)))

