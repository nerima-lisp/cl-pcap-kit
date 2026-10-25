(in-package #:cl-pcap-kit/test)

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

(defun %open-test-injector ()
  (let ((device-names (remove nil (mapcar #'device-name (capture-devices))))
        (failures '()))
    (dolist (device-name device-names)
      (handler-case
          (return-from %open-test-injector
            (values (injector-open-live device-name :timeout-ms 1000)
                    device-name))
        (pcap-error (condition)
          (push (format nil "~A: ~A"
                        device-name
                        (pcap-error-message condition))
                failures))))
    (error "Could not open a live injection handle on any enumerated device: ~{~A~^; ~}"
           (or (nreverse failures) '("no devices found")))))

(describe "packet injection binding"
  (it "loads and resolves pcap_sendpacket without transmitting"
    (expect (fboundp 'cl-pcap-kit::%pcap-sendpacket) :to-be t)
    (expect (not (null (cffi:foreign-symbol-pointer
                        "pcap_sendpacket"
                        'cl-pcap-kit::libpcap)))
            :to-be
            t))
  (it "opens and closes an enumerated live injection handle without sending packets"
    (multiple-value-bind (injector device-name) (%open-test-injector)
      (format t "Opened live injection handle on ~A; no packets sent.~%" device-name)
      (unwind-protect
           (progn
             (expect (stringp device-name) :to-be t)
             (expect (injector-closed-p injector) :to-be nil)
             (expect (not (cffi:null-pointer-p
                           (cl-pcap-kit::injector-handle injector)))
                     :to-be
                     t)
             (expect (close-injector injector) :to-be injector)
             (expect (injector-closed-p injector) :to-be t)
             (expect (cffi:null-pointer-p
                      (cl-pcap-kit::injector-handle injector))
                     :to-be
                     t)
             (expect (close-injector injector) :to-be injector)
             (expect (%signals-condition-p
                      'pcap-error
                      (lambda ()
                        (injector-send injector
                                       (make-array 1
                                                   :element-type '(unsigned-byte 8)
                                                   :initial-element 0)
                                       :timeout 0)))
                     :to-be
                     t))
        (close-injector injector)))))
