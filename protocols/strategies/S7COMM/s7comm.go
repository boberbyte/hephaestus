package S7COMM

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

// TPKT / COTP constants
const (
	tpktVersion = 0x03

	cotpCR = 0xE0 // Connection Request
	cotpCC = 0xD0 // Connection Confirm
	cotpDT = 0xF0 // Data Transfer

	// S7 PDU types
	s7TypeJobRequest = 0x01
	s7TypeAckData    = 0x03
	s7TypeUserData   = 0x07

	// S7 parameter codes
	s7ParamSetupComm = 0xF0
	s7ParamReadVar   = 0x04
	s7ParamWriteVar  = 0x05
	s7ParamPlcStop   = 0x29

	// S7 UserData parameter (SZL queries)
	s7UDParamSZL = 0x0000

	// SZL IDs
	szlModuleIdentification = 0x001C
	szlCPUComponent         = 0x0011
	szlModuleInfo           = 0x0111
)

type S7CommStrategy struct{}

func (s *S7CommStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	listener, err := net.Listen("tcp", servConf.Address)
	if err != nil {
		log.Errorf("Error during init S7Comm Protocol: %s", err.Error())
		return err
	}

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Errorf("Error accepting S7Comm connection: %s", err.Error())
				continue
			}
			go handleS7CommConnection(conn, servConf, tr)
		}
	}()

	log.WithFields(log.Fields{
		"port":       servConf.Address,
		"serverName": servConf.ServerName,
	}).Infof("Init service %s", servConf.Protocol)
	return nil
}

func handleS7CommConnection(conn net.Conn, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second))

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	id := uuid.New().String()

	// Step 1: COTP Connection handshake
	if err := handleCOTPHandshake(conn); err != nil {
		log.Debugf("S7Comm COTP handshake error: %s", err.Error())
		return
	}

	tr.TraceEvent(tracer.Event{
		Msg:         "S7Comm connection established",
		Protocol:    tracer.S7COMM.String(),
		Status:      tracer.Start.String(),
		RemoteAddr:  conn.RemoteAddr().String(),
		SourceIp:    host,
		SourcePort:  port,
		ID:          id,
		Description: servConf.Description,
	})

	// Step 2+: Handle S7 PDUs in a loop
	for {
		tpkt, err := readTPKT(conn)
		if err != nil {
			break
		}

		pduType, paramCode, szlID, err := parseS7PDU(tpkt)
		if err != nil {
			log.Debugf("S7Comm PDU parse error: %s", err.Error())
			break
		}

		resp, err := buildS7Response(tpkt, pduType, paramCode, szlID, servConf)
		if err != nil {
			log.Debugf("S7Comm build response error: %s", err.Error())
			break
		}

		if _, err := conn.Write(resp); err != nil {
			break
		}

		tr.TraceEvent(tracer.Event{
			Msg:     "S7Comm PDU",
			Protocol: tracer.S7COMM.String(),
			Status:  tracer.Interaction.String(),
			RemoteAddr: conn.RemoteAddr().String(),
			SourceIp:   host,
			SourcePort: port,
			ID:         id,
			Description: servConf.Description,
			Command: fmt.Sprintf("PDUType=0x%02X Param=0x%04X SZL=0x%04X",
				pduType, paramCode, szlID),
		})
	}

	tr.TraceEvent(tracer.Event{
		Msg:      "S7Comm session end",
		Protocol: tracer.S7COMM.String(),
		Status:   tracer.End.String(),
		ID:       id,
	})
}

// handleCOTPHandshake reads the COTP CR and responds with CC
func handleCOTPHandshake(conn net.Conn) error {
	// Read initial TPKT + COTP CR
	raw, err := readTPKT(conn)
	if err != nil {
		return fmt.Errorf("reading COTP CR: %w", err)
	}

	// raw[0] is COTP length indicator, raw[1] is TPDU type
	if len(raw) < 2 {
		return fmt.Errorf("COTP packet too short")
	}

	tpduType := raw[1]
	if tpduType != cotpCR {
		// Not a CR — could be COTP DT already (some clients skip CR)
		if tpduType == cotpDT {
			return nil
		}
		return fmt.Errorf("expected COTP CR (0xE0), got 0x%02X", tpduType)
	}

	// Build COTP CC response (same structure as CR but type=0xD0)
	// TPKT header (4 bytes) + COTP CC (7 bytes) = 11 bytes
	ccPacket := []byte{
		0x03, 0x00, 0x00, 0x0B, // TPKT: version=3, reserved=0, length=11
		0x06,       // COTP length indicator (6 bytes follow)
		cotpCC,     // TPDU type: Connection Confirm
		0x00, 0x00, // DST ref
		0x00, 0x01, // SRC ref
		0x00, // class / option
	}
	_, err = conn.Write(ccPacket)
	return err
}

// readTPKT reads one TPKT frame (4-byte header + payload) and returns the payload
func readTPKT(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != tpktVersion {
		return nil, fmt.Errorf("invalid TPKT version: 0x%02X", header[0])
	}
	length := binary.BigEndian.Uint16(header[2:4])
	if length < 4 {
		return nil, fmt.Errorf("TPKT length too short: %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// parseS7PDU extracts pduType, paramCode, and szlID from a TPKT payload (after COTP DT header)
func parseS7PDU(payload []byte) (pduType byte, paramCode uint16, szlID uint16, err error) {
	// Skip COTP DT header (3 bytes: length, 0xF0, sequence number)
	if len(payload) < 3 {
		return 0, 0, 0, fmt.Errorf("payload too short for COTP DT")
	}
	// payload[0] = COTP LI, payload[1] = COTP type (0xF0), payload[2] = sequence
	s7Data := payload[3:]

	// S7 header: magic(1) type(1) reserved(2) pduRef(2) paramLen(2) dataLen(2) = 10 bytes
	if len(s7Data) < 10 {
		return 0, 0, 0, fmt.Errorf("S7 header too short")
	}
	if s7Data[0] != 0x32 {
		return 0, 0, 0, fmt.Errorf("invalid S7 magic: 0x%02X", s7Data[0])
	}

	pduType = s7Data[1]
	paramLen := binary.BigEndian.Uint16(s7Data[6:8])

	if len(s7Data) < 10+int(paramLen) {
		return pduType, 0, 0, fmt.Errorf("S7 param area truncated")
	}

	params := s7Data[10 : 10+paramLen]
	if len(params) >= 1 {
		paramCode = uint16(params[0])
	}
	if len(params) >= 2 {
		paramCode = (paramCode << 8) | uint16(params[1])
	}

	// For UserData (type 0x07), SZL ID is in the param area at offset 6
	if pduType == s7TypeUserData && len(params) >= 8 {
		szlID = binary.BigEndian.Uint16(params[6:8])
	}

	return pduType, paramCode, szlID, nil
}

// buildS7Response constructs the appropriate TPKT+COTP+S7 response
func buildS7Response(reqPayload []byte, pduType byte, paramCode uint16, szlID uint16, servConf parser.BeelzebubServiceConfiguration) ([]byte, error) {
	// Extract PDU reference from request S7 header
	s7Data := reqPayload[3:] // skip COTP DT (3 bytes)
	var pduRef uint16
	if len(s7Data) >= 8 {
		pduRef = binary.BigEndian.Uint16(s7Data[4:6])
	}

	var s7Resp []byte

	switch pduType {
	case s7TypeJobRequest:
		if uint8(paramCode>>8) == s7ParamSetupComm {
			// Setup Communication response
			s7Resp = buildSetupCommResponse(pduRef)
		} else {
			// Generic ACK-DATA for write/stop/other job requests
			s7Resp = buildGenericAckData(pduRef, byte(paramCode>>8))
		}

	case s7TypeUserData:
		// SZL read request
		s7Resp = buildSZLResponse(pduRef, szlID, servConf)

	default:
		// Return minimal ACK
		s7Resp = buildGenericAckData(pduRef, 0x00)
	}

	return wrapTPKT(s7Resp), nil
}

// buildSetupCommResponse builds the S7 Setup Communication ACK-DATA
func buildSetupCommResponse(pduRef uint16) []byte {
	// S7 header (10 bytes) + params (8 bytes)
	s7 := make([]byte, 18)
	s7[0] = 0x32           // S7 magic
	s7[1] = s7TypeAckData  // ACK-DATA
	s7[2] = 0x00           // reserved
	s7[3] = 0x00           // reserved
	binary.BigEndian.PutUint16(s7[4:6], pduRef)
	binary.BigEndian.PutUint16(s7[6:8], 8) // param length
	binary.BigEndian.PutUint16(s7[8:10], 0) // data length
	// error class, error code
	s7[10] = 0x00
	s7[11] = 0x00
	// params: F0 00 (setup comm) max jobs 1/1, max PDU 0x03C0
	s7[12] = s7ParamSetupComm
	s7[13] = 0x00
	binary.BigEndian.PutUint16(s7[14:16], 1)      // max AMQ caller
	binary.BigEndian.PutUint16(s7[16:18], 0x03C0) // max PDU length

	return wrapCOTPDT(s7)
}

// buildGenericAckData builds a minimal S7 ACK-DATA response
func buildGenericAckData(pduRef uint16, paramCode byte) []byte {
	s7 := make([]byte, 12)
	s7[0] = 0x32
	s7[1] = s7TypeAckData
	s7[2] = 0x00
	s7[3] = 0x00
	binary.BigEndian.PutUint16(s7[4:6], pduRef)
	binary.BigEndian.PutUint16(s7[6:8], 2) // param length
	binary.BigEndian.PutUint16(s7[8:10], 0) // data length
	s7[10] = 0x00 // error class
	s7[11] = 0x00 // error code
	return wrapCOTPDT(s7)
}

// buildSZLResponse builds an S7 UserData response for SZL reads
func buildSZLResponse(pduRef uint16, szlID uint16, servConf parser.BeelzebubServiceConfiguration) []byte {
	var szlData []byte

	switch szlID {
	case szlModuleIdentification:
		// Module identification: return serverName
		name := servConf.ServerName
		if name == "" {
			name = "6ES7 000-0AA00-0AA0"
		}
		szlData = buildSZLItem(szlID, []byte(fmt.Sprintf("%-20s", name)))

	case szlCPUComponent:
		ver := servConf.ServerVersion
		if ver == "" {
			ver = "V1.0"
		}
		szlData = buildSZLItem(szlID, []byte(fmt.Sprintf("%-20s", ver)))

	case szlModuleInfo:
		serial := servConf.Banner
		if serial == "" {
			serial = "S7300-01"
		}
		szlData = buildSZLItem(szlID, []byte(fmt.Sprintf("%-24s", serial)))

	default:
		// Empty SZL list — valid but no items
		szlData = buildSZLItem(szlID, nil)
	}

	// S7 UserData header + parameter + data
	// Parameter area for UserData response (12 bytes)
	param := []byte{
		0x00, 0x01, 0x12, 0x08, // header
		0x12, 0x84, 0x01, 0x01, // type=response, subtype=SZL
		0x00, 0x00, byte(szlID >> 8), byte(szlID),
	}

	dataArea := make([]byte, 4+len(szlData))
	binary.BigEndian.PutUint16(dataArea[0:2], 0xFF09) // return code + transport size
	binary.BigEndian.PutUint16(dataArea[2:4], uint16(len(szlData)))
	copy(dataArea[4:], szlData)

	s7 := make([]byte, 10)
	s7[0] = 0x32
	s7[1] = s7TypeUserData
	s7[2] = 0x00
	s7[3] = 0x00
	binary.BigEndian.PutUint16(s7[4:6], pduRef)
	binary.BigEndian.PutUint16(s7[6:8], uint16(len(param)))
	binary.BigEndian.PutUint16(s7[8:10], uint16(len(dataArea)))
	s7 = append(s7, param...)
	s7 = append(s7, dataArea...)

	return wrapCOTPDT(s7)
}

// buildSZLItem creates an SZL list header with optional item data
func buildSZLItem(szlID uint16, data []byte) []byte {
	itemLen := uint16(len(data))
	count := uint16(0)
	if len(data) > 0 {
		count = 1
	}
	result := make([]byte, 4)
	binary.BigEndian.PutUint16(result[0:2], szlID)
	binary.BigEndian.PutUint16(result[2:4], itemLen)
	// count
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, count)
	result = append(result, tmp...)
	result = append(result, data...)
	return result
}

// wrapCOTPDT prepends a 3-byte COTP Data Transfer header
func wrapCOTPDT(s7Data []byte) []byte {
	cotp := []byte{0x02, cotpDT, 0x80} // LI=2, TPDU=DT, EOT bit set
	return append(cotp, s7Data...)
}

// wrapTPKT wraps payload in a 4-byte TPKT header
func wrapTPKT(payload []byte) []byte {
	total := 4 + len(payload)
	tpkt := make([]byte, 4)
	tpkt[0] = tpktVersion
	tpkt[1] = 0x00
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(total))
	return append(tpkt, payload...)
}
