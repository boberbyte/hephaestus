package MODBUS

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freeAddr finds an available TCP address for testing.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	l.Close()
	return addr
}

// mockTracer implements tracer.Tracer for tests.
type mockTracer struct {
	events []tracer.Event
}

func (m *mockTracer) TraceEvent(e tracer.Event) {
	m.events = append(m.events, e)
}

// sendModbus sends a Modbus TCP request and reads exactly one MBAP response.
func sendModbus(t *testing.T, addr string, pdu []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Build MBAP (6 bytes) + unitID (1 byte) + PDU
	frame := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(frame[0:2], 1)                  // transaction ID
	binary.BigEndian.PutUint16(frame[2:4], 0)                  // protocol ID
	binary.BigEndian.PutUint16(frame[4:6], uint16(1+len(pdu))) // length = unitID + PDU
	frame[6] = 1                                                // unit ID
	copy(frame[7:], pdu)

	_, err = conn.Write(frame)
	require.NoError(t, err)

	// Read response MBAP header (6 bytes: txID + protoID + length)
	respHeader := make([]byte, 6)
	_, err = io.ReadFull(conn, respHeader)
	require.NoError(t, err)

	// length field tells us how many bytes follow (unitID + PDU)
	respLen := binary.BigEndian.Uint16(respHeader[4:6])
	respRest := make([]byte, respLen)
	_, err = io.ReadFull(conn, respRest)
	require.NoError(t, err)

	return append(respHeader, respRest...)
}

// startServer starts the Modbus strategy and returns when the listener is ready.
func startServer(t *testing.T, servConf parser.BeelzebubServiceConfiguration) *mockTracer {
	t.Helper()
	tr := &mockTracer{}
	s := &ModbusStrategy{}
	require.NoError(t, s.Init(servConf, tr))
	time.Sleep(20 * time.Millisecond) // let goroutine bind
	return tr
}

// ---- Unit tests for buildResponse ----

func TestBuildResponse_ReadCoils(t *testing.T) {
	resp := buildResponse(fcReadCoils, 0, 10, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	// FC=0x01, byteCount=ceil(10/8)=2, then 2 zero bytes
	assert.Equal(t, byte(fcReadCoils), resp[0])
	assert.Equal(t, byte(2), resp[1])
	assert.Len(t, resp, 4) // fc + byteCount + 2 data bytes
}

func TestBuildResponse_ReadDiscreteInputs(t *testing.T) {
	resp := buildResponse(fcReadDiscreteInputs, 0, 8, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	assert.Equal(t, byte(fcReadDiscreteInputs), resp[0])
	assert.Equal(t, byte(1), resp[1]) // ceil(8/8)=1
}

func TestBuildResponse_ReadHoldingRegisters(t *testing.T) {
	resp := buildResponse(fcReadHoldingRegisters, 0, 5, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	// FC=0x03, byteCount=5*2=10, then 10 zero bytes
	assert.Equal(t, byte(fcReadHoldingRegisters), resp[0])
	assert.Equal(t, byte(10), resp[1])
	assert.Len(t, resp, 12)
}

func TestBuildResponse_ReadInputRegisters(t *testing.T) {
	resp := buildResponse(fcReadInputRegisters, 0, 3, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	assert.Equal(t, byte(fcReadInputRegisters), resp[0])
	assert.Equal(t, byte(6), resp[1]) // 3*2
}

func TestBuildResponse_WriteSingleCoil(t *testing.T) {
	resp := buildResponse(fcWriteSingleCoil, 100, 0xFF00, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	assert.Equal(t, byte(fcWriteSingleCoil), resp[0])
	// echoes address and value
	assert.Equal(t, byte(0), resp[1])
	assert.Equal(t, byte(100), resp[2])
	assert.Equal(t, byte(0xFF), resp[3])
	assert.Equal(t, byte(0x00), resp[4])
}

func TestBuildResponse_WriteSingleRegister(t *testing.T) {
	resp := buildResponse(fcWriteSingleRegister, 10, 1234, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	assert.Equal(t, byte(fcWriteSingleRegister), resp[0])
}

func TestBuildResponse_WriteMultipleCoils(t *testing.T) {
	resp := buildResponse(fcWriteMultipleCoils, 0, 8, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	assert.Equal(t, byte(fcWriteMultipleCoils), resp[0])
}

func TestBuildResponse_WriteMultipleRegisters(t *testing.T) {
	resp := buildResponse(fcWriteMultipleRegs, 0, 4, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	assert.Equal(t, byte(fcWriteMultipleRegs), resp[0])
}

func TestBuildResponse_ReportSlaveID(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{ServerName: "Siemens"}
	resp := buildResponse(fcReportSlaveID, 0, 0, 1, 42, conf, nil)
	assert.Equal(t, byte(fcReportSlaveID), resp[0])
	// payload contains slaveID (42) and run indicator (0xFF) and the name
	assert.Equal(t, byte(42), resp[2])
	assert.Equal(t, byte(0xFF), resp[3])
	assert.Contains(t, string(resp[4:]), "Siemens")
}

func TestBuildResponse_ReportSlaveID_DefaultName(t *testing.T) {
	resp := buildResponse(fcReportSlaveID, 0, 0, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	assert.Contains(t, string(resp), "Beelzebub")
}

func TestBuildResponse_MEIDeviceID(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		ServerName:    "Acme Corp",
		ServerVersion: "2.0",
	}
	resp := buildResponse(fcMEITransport, 0, 0, 1, 1, conf, nil)
	assert.Equal(t, byte(fcMEITransport), resp[0])
	assert.Equal(t, byte(0x0E), resp[1]) // MEI type
	assert.Contains(t, string(resp), "Acme Corp")
	assert.Contains(t, string(resp), "2.0")
}

func TestBuildResponse_UnknownFC_ReturnsException(t *testing.T) {
	resp := buildResponse(0xAB, 0, 0, 1, 1, parser.BeelzebubServiceConfiguration{}, nil)
	assert.Equal(t, byte(0xAB|0x80), resp[0])
	assert.Equal(t, byte(exceptionIllegalFunction), resp[1])
}

// ---- Unit tests for parseRegisterOverrides ----

func TestParseRegisterOverrides_ValidHex(t *testing.T) {
	cmds := []parser.Command{
		{RegexStr: "FC03:0-4", Handler: "0064 00C8 012C"},
	}
	overrides := parseRegisterOverrides(cmds)
	data, ok := overrides["FC03:0-4"]
	assert.True(t, ok)
	assert.Equal(t, []byte{0x00, 0x64, 0x00, 0xC8, 0x01, 0x2C}, data)
}

func TestParseRegisterOverrides_InvalidHex(t *testing.T) {
	cmds := []parser.Command{
		{RegexStr: "FC03:0-0", Handler: "ZZZZ"},
	}
	overrides := parseRegisterOverrides(cmds)
	// Invalid hex words are skipped, resulting in empty data
	assert.Empty(t, overrides["FC03:0-0"])
}

func TestParseRegisterOverrides_EmptyKey(t *testing.T) {
	cmds := []parser.Command{
		{RegexStr: "", Handler: "0001"},
	}
	overrides := parseRegisterOverrides(cmds)
	assert.Empty(t, overrides)
}

// ---- Integration tests ----

func TestModbusStrategy_Init_InvalidAddress(t *testing.T) {
	s := &ModbusStrategy{}
	err := s.Init(parser.BeelzebubServiceConfiguration{
		Address:                "invalid-address",
		DeadlineTimeoutSeconds: 5,
	}, &mockTracer{})
	assert.Error(t, err)
}

func TestModbusStrategy_FC03_OverNetwork(t *testing.T) {
	addr := freeAddr(t)
	tr := startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		Banner:                 "1",
		ServerName:             "Siemens",
		ServerVersion:          "V4.4",
		DeadlineTimeoutSeconds: 5,
	})

	// FC03: Read 2 holding registers from address 0
	pdu := []byte{fcReadHoldingRegisters, 0x00, 0x00, 0x00, 0x02}
	resp := sendModbus(t, addr, pdu)

	// Response: 6-byte MBAP + unitID + FC + byteCount + 4 bytes of data
	require.GreaterOrEqual(t, len(resp), 9)
	assert.Equal(t, byte(fcReadHoldingRegisters), resp[7])
	assert.Equal(t, byte(4), resp[8]) // 2 registers * 2 bytes

	// Verify a trace event was emitted
	assert.NotEmpty(t, tr.events)
	assert.Equal(t, tracer.MODBUS.String(), tr.events[0].Protocol)
}

func TestModbusStrategy_FC01_ReadCoils_OverNetwork(t *testing.T) {
	addr := freeAddr(t)
	startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		DeadlineTimeoutSeconds: 5,
	})

	pdu := []byte{fcReadCoils, 0x00, 0x00, 0x00, 0x08}
	resp := sendModbus(t, addr, pdu)

	require.GreaterOrEqual(t, len(resp), 9)
	assert.Equal(t, byte(fcReadCoils), resp[7])
	assert.Equal(t, byte(1), resp[8]) // ceil(8/8)=1 byte
}

func TestModbusStrategy_FC11_ReportSlaveID_OverNetwork(t *testing.T) {
	addr := freeAddr(t)
	startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		Banner:                 "5",
		ServerName:             "TestVendor",
		DeadlineTimeoutSeconds: 5,
	})

	pdu := []byte{fcReportSlaveID}
	resp := sendModbus(t, addr, pdu)

	require.GreaterOrEqual(t, len(resp), 8)
	assert.Equal(t, byte(fcReportSlaveID), resp[7])
	assert.Contains(t, string(resp), "TestVendor")
}

func TestModbusStrategy_UnknownFC_OverNetwork(t *testing.T) {
	addr := freeAddr(t)
	startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		DeadlineTimeoutSeconds: 5,
	})

	pdu := []byte{0x63, 0x00, 0x00, 0x00, 0x01} // unknown FC 0x63
	resp := sendModbus(t, addr, pdu)

	require.GreaterOrEqual(t, len(resp), 9)
	assert.Equal(t, byte(0x63|0x80), resp[7])
	assert.Equal(t, byte(exceptionIllegalFunction), resp[8])
}
