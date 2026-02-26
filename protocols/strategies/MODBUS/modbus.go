package MODBUS

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

// Modbus function codes
const (
	fcReadCoils            = 0x01
	fcReadDiscreteInputs   = 0x02
	fcReadHoldingRegisters = 0x03
	fcReadInputRegisters   = 0x04
	fcWriteSingleCoil      = 0x05
	fcWriteSingleRegister  = 0x06
	fcWriteMultipleCoils   = 0x0F
	fcWriteMultipleRegs    = 0x10
	fcReportSlaveID        = 0x11
	fcMEITransport         = 0x2B

	exceptionIllegalFunction = 0x01
)

// mbapHeader is the 7-byte Modbus Application Protocol header
type mbapHeader struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16
	UnitID        uint8
}

type ModbusStrategy struct{}

func (m *ModbusStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	listener, err := net.Listen("tcp", servConf.Address)
	if err != nil {
		log.Errorf("Error during init Modbus Protocol: %s", err.Error())
		return err
	}

	// Parse slave ID from banner field, default 1
	slaveID := byte(1)
	if servConf.Banner != "" {
		if id, err := strconv.Atoi(servConf.Banner); err == nil {
			slaveID = byte(id)
		}
	}

	// Build register override map from commands: regex="FC03:0-9" handler="0064 00C8" (hex words)
	registerOverrides := parseRegisterOverrides(servConf.Commands)

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Errorf("Error accepting Modbus connection: %s", err.Error())
				continue
			}
			go handleModbusConnection(conn, servConf, tr, slaveID, registerOverrides)
		}
	}()

	log.WithFields(log.Fields{
		"port":    servConf.Address,
		"slaveID": slaveID,
	}).Infof("Init service %s", servConf.Protocol)
	return nil
}

func handleModbusConnection(conn net.Conn, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, slaveID byte, overrides map[string][]byte) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second))

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	id := uuid.New().String()

	for {
		// Read MBAP header (7 bytes)
		header := make([]byte, 7)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}

		txID := binary.BigEndian.Uint16(header[0:2])
		// protoID := binary.BigEndian.Uint16(header[2:4]) // always 0x0000
		length := binary.BigEndian.Uint16(header[4:6])
		unitID := header[6]

		if length < 1 {
			return
		}

		// Read PDU (length-1 because unitID is counted in length)
		pdu := make([]byte, length-1)
		if _, err := io.ReadFull(conn, pdu); err != nil {
			return
		}
		if len(pdu) == 0 {
			return
		}

		fc := pdu[0]
		var startAddr, quantity uint16

		if len(pdu) >= 5 {
			startAddr = binary.BigEndian.Uint16(pdu[1:3])
			quantity = binary.BigEndian.Uint16(pdu[3:5])
		}

		// Build response PDU
		responsePDU := buildResponse(fc, startAddr, quantity, unitID, slaveID, servConf, overrides)

		// Build response MBAP
		resp := make([]byte, 6+len(responsePDU))
		binary.BigEndian.PutUint16(resp[0:2], txID)
		binary.BigEndian.PutUint16(resp[2:4], 0x0000) // protocol ID
		binary.BigEndian.PutUint16(resp[4:6], uint16(1+len(responsePDU)))
		resp[6] = unitID
		copy(resp[7:], responsePDU)

		if _, err := conn.Write(resp); err != nil {
			return
		}

		tr.TraceEvent(tracer.Event{
			Msg:         "Modbus request",
			Protocol:    tracer.MODBUS.String(),
			Status:      tracer.Stateless.String(),
			RemoteAddr:  conn.RemoteAddr().String(),
			SourceIp:    host,
			SourcePort:  port,
			ID:          id,
			Description: servConf.Description,
			Command: fmt.Sprintf("UnitID=%d FC=0x%02X StartAddr=%d Quantity=%d",
				unitID, fc, startAddr, quantity),
		})
	}
}

func buildResponse(fc byte, startAddr, quantity uint16, unitID, slaveID byte, servConf parser.BeelzebubServiceConfiguration, overrides map[string][]byte) []byte {
	switch fc {
	case fcReadCoils, fcReadDiscreteInputs:
		byteCount := byte(math.Ceil(float64(quantity) / 8.0))
		resp := make([]byte, 2+byteCount)
		resp[0] = fc
		resp[1] = byteCount
		return resp

	case fcReadHoldingRegisters, fcReadInputRegisters:
		byteCount := quantity * 2
		data := make([]byte, byteCount)
		// Apply overrides if present
		overrideKey := fmt.Sprintf("FC%02X:%d-%d", fc, startAddr, startAddr+quantity-1)
		if overrideData, ok := overrides[overrideKey]; ok && len(overrideData) <= int(byteCount) {
			copy(data, overrideData)
		}
		resp := make([]byte, 2+byteCount)
		resp[0] = fc
		resp[1] = byte(byteCount)
		copy(resp[2:], data)
		return resp

	case fcWriteSingleCoil, fcWriteSingleRegister:
		// Echo back the request (address + value)
		return []byte{fc, byte(startAddr >> 8), byte(startAddr), byte(quantity >> 8), byte(quantity)}

	case fcWriteMultipleCoils, fcWriteMultipleRegs:
		return []byte{fc, byte(startAddr >> 8), byte(startAddr), byte(quantity >> 8), byte(quantity)}

	case fcReportSlaveID:
		name := servConf.ServerName
		if name == "" {
			name = "Beelzebub"
		}
		payload := append([]byte{slaveID, 0xFF}, []byte(name)...)
		return append([]byte{fc, byte(len(payload))}, payload...)

	case fcMEITransport:
		// MEI Device Identification (sub-function 0x0E, object 0x00)
		vendor := servConf.ServerName
		if vendor == "" {
			vendor = "Beelzebub"
		}
		product := servConf.ServerVersion
		if product == "" {
			product = "1.0"
		}
		// Build minimal MEI response
		resp := []byte{
			fc, 0x0E, // MEI type
			0x01,       // conformity level: basic
			0x00,       // more follows: no
			0x00,       // next object id
			0x03,       // number of objects
			0x00, byte(len(vendor)),
		}
		resp = append(resp, []byte(vendor)...)
		resp = append(resp, 0x01, byte(len(product)))
		resp = append(resp, []byte(product)...)
		resp = append(resp, 0x02, byte(len(product))) // revision = product version
		resp = append(resp, []byte(product)...)
		return resp

	default:
		// Exception response
		return []byte{fc | 0x80, exceptionIllegalFunction}
	}
}

// parseRegisterOverrides parses commands with regex="FC03:0-9" handler="0064 00C8" (hex words separated by space)
func parseRegisterOverrides(commands []parser.Command) map[string][]byte {
	overrides := make(map[string][]byte)
	for _, cmd := range commands {
		key := strings.TrimSpace(cmd.RegexStr)
		if key == "" {
			continue
		}
		words := strings.Fields(cmd.Handler)
		var data []byte
		for _, w := range words {
			decoded, err := hex.DecodeString(w)
			if err != nil {
				continue
			}
			data = append(data, decoded...)
		}
		overrides[key] = data
	}
	return overrides
}
