package IEC104

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

// IEC 60870-5-104 constants
const (
	startByte = 0x68

	// U-frame control fields (bytes 3-6 of the APDU after start byte and length)
	uStartDTAct = 0x07
	uStartDTCon = 0x0B
	uStopDTAct  = 0x13
	uStopDTCon  = 0x23
	uTestFRAct  = 0x43
	uTestFRCon  = 0x83

	// Cause of Transmission (COT)
	cotActivation            = 6
	cotActivationConfirmation = 7
	cotActivationTermination = 10

	// Command TypeIDs (single/double point commands etc.)
	typeIDCommandMin = 45
	typeIDCommandMax = 64

	defaultKeepAlive = 30 * time.Second
)

// session holds per-connection sequence numbers
type session struct {
	mu      sync.Mutex
	sendSeq uint16 // VS: send sequence number
	recvSeq uint16 // VR: receive sequence number
}

func (s *session) nextSend() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.sendSeq
	s.sendSeq++
	return n
}

func (s *session) updateRecv(n uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recvSeq = n + 1
}

func (s *session) recvAck() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recvSeq
}

type IEC104Strategy struct{}

func (i *IEC104Strategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	listener, err := net.Listen("tcp", servConf.Address)
	if err != nil {
		log.Errorf("Error during init IEC104 Protocol: %s", err.Error())
		return err
	}

	// Parse common address from banner, default 1
	commonAddr := uint16(1)
	if servConf.Banner != "" {
		if ca, err := strconv.Atoi(servConf.Banner); err == nil {
			commonAddr = uint16(ca)
		}
	}

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Errorf("Error accepting IEC104 connection: %s", err.Error())
				continue
			}
			go handleIEC104Connection(conn, servConf, tr, commonAddr)
		}
	}()

	log.WithFields(log.Fields{
		"port":       servConf.Address,
		"commonAddr": commonAddr,
	}).Infof("Init service %s", servConf.Protocol)
	return nil
}

func handleIEC104Connection(conn net.Conn, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, commonAddr uint16) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second))

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	id := uuid.New().String()
	sess := &session{}
	started := false

	// Keepalive goroutine: send TESTFR_act every t3 seconds once started
	stopKeepalive := make(chan struct{})
	go func() {
		t := time.NewTicker(defaultKeepAlive)
		defer t.Stop()
		for {
			select {
			case <-stopKeepalive:
				return
			case <-t.C:
				if started {
					conn.Write(buildUFrame(uTestFRAct))
				}
			}
		}
	}()
	defer close(stopKeepalive)

	tr.TraceEvent(tracer.Event{
		Msg:         "IEC 104 connection",
		Protocol:    tracer.IEC104.String(),
		Status:      tracer.Start.String(),
		RemoteAddr:  conn.RemoteAddr().String(),
		SourceIp:    host,
		SourcePort:  port,
		ID:          id,
		Description: servConf.Description,
	})

	for {
		// Read APDU: start byte + length byte + 4 control bytes minimum
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			break
		}
		if header[0] != startByte {
			log.Debugf("IEC104: unexpected start byte 0x%02X", header[0])
			break
		}
		apduLen := int(header[1])
		if apduLen < 4 {
			break
		}

		apdu := make([]byte, apduLen)
		if _, err := io.ReadFull(conn, apdu); err != nil {
			break
		}

		// Control field is first 4 bytes of APDU
		cf := apdu[:4]
		frameType := classifyFrame(cf)

		switch frameType {
		case "U":
			uType := cf[0]
			resp, handled := handleUFrame(uType, &started)
			if handled {
				conn.Write(resp)
			}
			tr.TraceEvent(tracer.Event{
				Msg:        fmt.Sprintf("IEC104 U-frame 0x%02X", uType),
				Protocol:   tracer.IEC104.String(),
				Status:     tracer.Stateless.String(),
				RemoteAddr: conn.RemoteAddr().String(),
				SourceIp:   host,
				SourcePort: port,
				ID:         id,
				Description: servConf.Description,
				Command:    fmt.Sprintf("U-frame=0x%02X", uType),
			})

		case "S":
			// Supervisory frame — just an acknowledgment, no action needed

		case "I":
			// I-frame: carries an ASDU
			sendSeqN := binary.LittleEndian.Uint16(cf[0:2]) >> 1
			recvSeqN := binary.LittleEndian.Uint16(cf[2:4]) >> 1
			sess.updateRecv(sendSeqN)
			_ = recvSeqN

			// Send S-frame acknowledgment
			conn.Write(buildSFrame(sess.recvAck()))

			// Parse ASDU if present
			if len(apdu) > 4 {
				asdu := apdu[4:]
				typeID, cot, ca, ioa, rawData := parseASDU(asdu)

				tr.TraceEvent(tracer.Event{
					Msg:        "IEC104 I-frame ASDU",
					Protocol:   tracer.IEC104.String(),
					Status:     tracer.Interaction.String(),
					RemoteAddr: conn.RemoteAddr().String(),
					SourceIp:   host,
					SourcePort: port,
					ID:         id,
					Description: servConf.Description,
					Command: fmt.Sprintf("TypeID=%d COT=%d CA=%d IOA=%d Data=%s",
						typeID, cot, ca, ioa, hex.EncodeToString(rawData)),
				})

				// For command TypeIDs, respond with activation confirm then terminate
				if typeID >= typeIDCommandMin && typeID <= typeIDCommandMax {
					// Activation confirmation
					ackAsdu := buildCommandResponse(typeID, cotActivationConfirmation, commonAddr, ioa)
					conn.Write(buildIFrame(sess.nextSend(), sess.recvAck(), ackAsdu))

					// Activation termination
					termAsdu := buildCommandResponse(typeID, cotActivationTermination, commonAddr, ioa)
					conn.Write(buildIFrame(sess.nextSend(), sess.recvAck(), termAsdu))
				}
			}

		default:
			log.Debugf("IEC104: unknown frame type for CF %X", cf)
		}
	}

	tr.TraceEvent(tracer.Event{
		Msg:      "IEC104 session end",
		Protocol: tracer.IEC104.String(),
		Status:   tracer.End.String(),
		ID:       id,
	})
}

// classifyFrame determines U, S, or I frame from the first control byte
func classifyFrame(cf []byte) string {
	b0 := cf[0]
	if b0&0x01 == 0 {
		return "I"
	}
	if b0&0x03 == 0x01 {
		return "S"
	}
	return "U"
}

// handleUFrame returns the response bytes for a U-frame control byte
func handleUFrame(uType byte, started *bool) ([]byte, bool) {
	switch uType {
	case uStartDTAct:
		*started = true
		return buildUFrame(uStartDTCon), true
	case uStopDTAct:
		*started = false
		return buildUFrame(uStopDTCon), true
	case uTestFRAct:
		return buildUFrame(uTestFRCon), true
	}
	return nil, false
}

// buildUFrame builds a 6-byte APDU for a U-frame
func buildUFrame(uType byte) []byte {
	return []byte{startByte, 0x04, uType, 0x00, 0x00, 0x00}
}

// buildSFrame builds an S-frame APDU acknowledging recvSeq
func buildSFrame(recvSeq uint16) []byte {
	cf := make([]byte, 4)
	cf[0] = 0x01
	cf[1] = 0x00
	binary.LittleEndian.PutUint16(cf[2:4], recvSeq<<1)
	return append([]byte{startByte, 0x04}, cf...)
}

// buildIFrame builds an I-frame APDU with the given ASDU payload
func buildIFrame(sendSeq, recvSeq uint16, asdu []byte) []byte {
	cf := make([]byte, 4)
	binary.LittleEndian.PutUint16(cf[0:2], sendSeq<<1)
	binary.LittleEndian.PutUint16(cf[2:4], recvSeq<<1)
	payload := append(cf, asdu...)
	return append([]byte{startByte, byte(len(payload))}, payload...)
}

// parseASDU extracts TypeID, COT, common address, IOA, and remaining data from an ASDU
func parseASDU(asdu []byte) (typeID byte, cot uint16, ca uint16, ioa uint32, rawData []byte) {
	if len(asdu) < 6 {
		return
	}
	typeID = asdu[0]
	// asdu[1]: variable structure qualifier (SQ bit + number of objects)
	cotBytes := binary.LittleEndian.Uint16(asdu[2:4]) // 2-byte COT
	cot = cotBytes & 0x3F                              // lower 6 bits
	ca = binary.LittleEndian.Uint16(asdu[4:6])
	if len(asdu) >= 9 {
		// IOA is 3 bytes little-endian
		ioa = uint32(asdu[6]) | uint32(asdu[7])<<8 | uint32(asdu[8])<<16
		rawData = asdu[9:]
	}
	return
}

// buildCommandResponse creates a minimal ASDU response for a command
func buildCommandResponse(typeID byte, cot uint16, ca uint16, ioa uint32) []byte {
	asdu := make([]byte, 9)
	asdu[0] = typeID
	asdu[1] = 0x01 // 1 object, no SQ
	binary.LittleEndian.PutUint16(asdu[2:4], cot)
	binary.LittleEndian.PutUint16(asdu[4:6], ca)
	// IOA (3 bytes LE)
	asdu[6] = byte(ioa)
	asdu[7] = byte(ioa >> 8)
	asdu[8] = byte(ioa >> 16)
	return asdu
}
