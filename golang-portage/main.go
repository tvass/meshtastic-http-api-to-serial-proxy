package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/tarm/serial"
)

const (
	maxMessageLength = 512
	queueSize        = 256
	frameHeader1     = 0x94
	frameHeader2     = 0xC3
)

type MeshtasticProxy struct {
	serialPort    string
	baudRate      int
	host          string
	port          int
	certFile      string
	keyFile       string
	useTLS        bool
	debug         bool
	serialConn    *serial.Port
	serialLock    sync.Mutex
	fromRadioQueue chan []byte
	running       bool
	runningLock   sync.Mutex
}

func NewMeshtasticProxy(serialPort string, baudRate int, host string, port int, certFile, keyFile string, debug bool) *MeshtasticProxy {
	return &MeshtasticProxy{
		serialPort:     serialPort,
		baudRate:       baudRate,
		host:           host,
		port:           port,
		certFile:       certFile,
		keyFile:        keyFile,
		useTLS:         certFile != "" && keyFile != "",
		debug:          debug,
		fromRadioQueue: make(chan []byte, queueSize),
		running:        false,
	}
}

func (p *MeshtasticProxy) logInfo(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

func (p *MeshtasticProxy) logError(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

func (p *MeshtasticProxy) logDebug(format string, v ...interface{}) {
	if p.debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (p *MeshtasticProxy) openSerialPort() error {
	config := &serial.Config{
		Name:        p.serialPort,
		Baud:        p.baudRate,
		ReadTimeout: time.Millisecond * 100,
	}

	p.logInfo("Opening serial port %s at %d baud", p.serialPort, p.baudRate)
	conn, err := serial.OpenPort(config)
	if err != nil {
		p.logError("Failed to open serial port: %v", err)
		return err
	}

	p.serialConn = conn
	p.logInfo("Serial port %s opened successfully", p.serialPort)
	return nil
}

func (p *MeshtasticProxy) closeSerialPort() {
	if p.serialConn != nil {
		p.serialConn.Close()
		p.logInfo("Serial port closed")
	}
}

func (p *MeshtasticProxy) serialReaderThread() {
	p.logInfo("Serial reader thread started")
	buffer := make([]byte, 0, 4096)
	readBuf := make([]byte, 1024)

	for p.isRunning() {
		// Read from serial port
		n, err := p.serialConn.Read(readBuf)
		if err != nil && err != io.EOF {
			p.logError("Serial port error: %v", err)
			p.logInfo("Attempting to reconnect...")
			p.closeSerialPort()
			if err := p.openSerialPort(); err != nil {
				p.logError("Reconnection failed: %v", err)
				break
			}
			continue
		}

		if n > 0 {
			p.logDebug("Serial recv: %d bytes", n)
			buffer = append(buffer, readBuf[:n]...)
		}

		// Parse framed messages from buffer
		for len(buffer) >= 4 {
			// Look for frame header: 0x94 0xc3
			if buffer[0] == frameHeader1 && buffer[1] == frameHeader2 {
				// Get message length (big-endian)
				msgLen := int(buffer[2])<<8 | int(buffer[3])

				// Validate length
				if msgLen > maxMessageLength || msgLen == 0 {
					p.logError("Invalid message length %d, resynchronizing", msgLen)
					buffer = buffer[1:]
					continue
				}

				// Check if we have the complete message
				if len(buffer) >= 4+msgLen {
					// Extract the protobuf message (without frame header)
					protobufData := make([]byte, msgLen)
					copy(protobufData, buffer[4:4+msgLen])

					// Add to queue (non-blocking)
					select {
					case p.fromRadioQueue <- protobufData:
						p.logDebug("Serial -> Queue: %d bytes (queue: %d)", len(protobufData), len(p.fromRadioQueue))
					default:
						p.logError("Queue full, dropping message")
					}

					// Remove processed message from buffer
					buffer = buffer[4+msgLen:]
				} else {
					// Wait for more data
					break
				}
			} else {
				// Not a valid frame start, skip byte and resynchronize
				buffer = buffer[1:]
			}
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func (p *MeshtasticProxy) isRunning() bool {
	p.runningLock.Lock()
	defer p.runningLock.Unlock()
	return p.running
}

func (p *MeshtasticProxy) setRunning(running bool) {
	p.runningLock.Lock()
	defer p.runningLock.Unlock()
	p.running = running
}

func (p *MeshtasticProxy) handleToRadio(w http.ResponseWriter, r *http.Request) {
	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "PUT, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != "PUT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the protobuf data from request body
	protobufData, err := io.ReadAll(r.Body)
	if err != nil {
		p.logError("Error reading request body: %v", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(protobufData) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return
	}

	if len(protobufData) > maxMessageLength {
		http.Error(w, "Message too large", http.StatusBadRequest)
		return
	}

	// Add frame header: 0x94 0xc3 [length_msb] [length_lsb]
	msgLen := len(protobufData)
	lengthMSB := byte((msgLen >> 8) & 0xFF)
	lengthLSB := byte(msgLen & 0xFF)
	framedData := append([]byte{frameHeader1, frameHeader2, lengthMSB, lengthLSB}, protobufData...)

	// Write to serial port
	p.serialLock.Lock()
	defer p.serialLock.Unlock()

	if p.serialConn == nil {
		http.Error(w, "Serial connection not available", http.StatusServiceUnavailable)
		return
	}

	_, err = p.serialConn.Write(framedData)
	if err != nil {
		p.logError("Error writing to serial: %v", err)
		http.Error(w, "Failed to write to serial", http.StatusInternalServerError)
		return
	}

	p.logDebug("HTTP -> Serial: %d bytes protobuf (%d bytes framed)", len(protobufData), len(framedData))

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}

func (p *MeshtasticProxy) handleFromRadio(w http.ResponseWriter, r *http.Request) {
	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Header().Set("X-Protobuf-Schema", "https://buf.build/meshtastic/protobufs")

	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if 'all' parameter is present
	allMessages := r.URL.Query().Get("all")
	wantAll := allMessages == "true" || allMessages == "1" || allMessages == "yes"

	var data []byte

	if wantAll {
		// Return all available messages
		var messages [][]byte
		for {
			select {
			case msg := <-p.fromRadioQueue:
				messages = append(messages, msg)
			default:
				goto done
			}
		}
	done:
		if len(messages) > 0 {
			for _, msg := range messages {
				data = append(data, msg...)
			}
			p.logDebug("Serial -> HTTP: %d bytes (all, %d messages)", len(data), len(messages))
		} else {
			p.logDebug("Serial -> HTTP: empty (all=true, no messages)")
		}
	} else {
		// Return one message
		select {
		case msg := <-p.fromRadioQueue:
			data = msg
			p.logDebug("Serial -> HTTP: %d bytes (queue size: %d)", len(data), len(p.fromRadioQueue))
		default:
			// No messages available
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (p *MeshtasticProxy) Start() error {
	// Open serial port
	if err := p.openSerialPort(); err != nil {
		return err
	}

	// Start serial reader thread
	p.setRunning(true)
	go p.serialReaderThread()

	// Give the reader thread a moment to stabilize
	time.Sleep(500 * time.Millisecond)

	// Setup HTTP routes
	http.HandleFunc("/api/v1/toradio", p.handleToRadio)
	http.HandleFunc("/api/v1/fromradio", p.handleFromRadio)

	protocol := "http"
	if p.useTLS {
		protocol = "https"
	}

	addr := fmt.Sprintf("%s:%d", p.host, p.port)
	p.logInfo("Starting Meshtastic HTTP API server on %s://%s", protocol, addr)
	p.logInfo("Endpoints: %s://%s/api/v1/toradio", protocol, addr)
	p.logInfo("           %s://%s/api/v1/fromradio", protocol, addr)

	var err error
	if p.useTLS {
		// Validate certificate files
		if _, err := os.Stat(p.certFile); os.IsNotExist(err) {
			return fmt.Errorf("certificate file not found: %s", p.certFile)
		}
		if _, err := os.Stat(p.keyFile); os.IsNotExist(err) {
			return fmt.Errorf("key file not found: %s", p.keyFile)
		}

		p.logInfo("SSL/TLS enabled with certificate: %s", p.certFile)

		server := &http.Server{
			Addr:      addr,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
		err = server.ListenAndServeTLS(p.certFile, p.keyFile)
	} else {
		err = http.ListenAndServe(addr, nil)
	}

	p.setRunning(false)
	p.closeSerialPort()

	return err
}

func main() {
	// Command line flags
	host := flag.String("host", "0.0.0.0", "Host to bind to")
	portFlag := flag.Int("port", 0, "Port to listen on (default: 443 for HTTPS, 8080 for HTTP)")
	serialPort := flag.String("serial-port", "", "Serial port device (e.g., /dev/ttyACM0 or /dev/ttyUSB0)")
	baudRate := flag.Int("baud-rate", 115200, "Serial baud rate")
	cert := flag.String("cert", "", "Path to TLS certificate file (enables HTTPS if provided with --key)")
	key := flag.String("key", "", "Path to TLS private key file (enables HTTPS if provided with --cert)")
	debug := flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()

	// Validate required arguments
	if *serialPort == "" {
		log.Fatal("--serial-port is required")
	}

	// Validate certificate arguments
	if (*cert != "" && *key == "") || (*key != "" && *cert == "") {
		log.Fatal("Both --cert and --key must be provided together for HTTPS")
	}

	// Auto-set default port based on TLS presence
	port := *portFlag
	if port == 0 {
		if *cert != "" && *key != "" {
			port = 443
			log.Printf("[INFO] Auto-selected port %d (HTTPS mode)", port)
		} else {
			port = 8080
			log.Printf("[INFO] Auto-selected port %d (HTTP mode)", port)
		}
	}

	proxy := NewMeshtasticProxy(*serialPort, *baudRate, *host, port, *cert, *key, *debug)

	if err := proxy.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
