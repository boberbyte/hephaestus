package S7COMM

import (
	"encoding/binary"
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

// mockTracer captures trace events.
type mockTracer struct {
	events []tracer.Event
}

func (m *mockTracer) TraceEvent(e tracer.Event) {
	m.events = append(m.events, e)
}

func startServer(t *testing.T, servConf parser.BeelzebubServiceConfiguration) *mockTracer {
	t.Helper()
	tr := &mockTracer{}
	s := &S7CommStrategy{}
	require.NoError(t, s.Init(servConf, tr))
	time.Sleep(20 * time.Millisecond)
	return tr
}

// ---- Unit tests for helper functions ----

func TestWrapTPKT(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	result := wrapTPKT(payload)

	assert.Equal(t, byte(tpktVersion), result[0])
	assert.Equal(t, byte(0x00), result[1])
	totalLen := binary.BigEndian.Uint16(result[2:4])
	assert.Equal(t, uint16(7), totalLen) // 4 header + 3 payload
	assert.Equal(t, payload, result[4:])
}

func TestWrapCOTPDT(t *testing.T) {
	s7Data := []byte{0x32, 0x01}
	result := wrapCOTPDT(s7Data)

	assert.Equal(t, byte(0x02), result[0])   // LI=2
	assert.Equal(t, byte(cotpDT), result[1]) // TPDU type
	assert.Equal(t, byte(0x80), result[2])   // EOT bit
	assert.Equal(t, s7Data, result[3:])
}

func TestBuildSetupCommResponse_Structure(t *testing.T) {
	result := buildSetupCommResponse(0x0001)
	// Should be COTP DT (3 bytes) + S7 header (10 bytes) + params (8 bytes) = 21 bytes
	assert.Len(t, result, 21)
	// S7 magic
	assert.Equal(t, byte(0x32), result[3])
	// PDU type: ACK-DATA
	assert.Equal(t, byte(s7TypeAckData), result[4])
	// PDU reference preserved
	assert.Equal(t, uint16(1), binary.BigEndian.Uint16(result[7:9]))
	// Max PDU = 0x03C0
	assert.Equal(t, uint16(0x03C0), binary.BigEndian.Uint16(result[19:21]))
}

func TestBuildGenericAckData_Structure(t *testing.T) {
	result := buildGenericAckData(0x0002, 0x04)
	// COTP DT (3) + S7 header (10) + error fields (2) = but no params beyond header
	// The function builds 10+2=12 bytes before COTP
	assert.Equal(t, byte(0x32), result[3])
	assert.Equal(t, byte(s7TypeAckData), result[4])
}

func TestBuildSZLItem_WithData(t *testing.T) {
	data := []byte("TestModule          ") // 20 bytes
	result := buildSZLItem(szlModuleIdentification, data)

	assert.Equal(t, uint16(szlModuleIdentification), binary.BigEndian.Uint16(result[0:2]))
	assert.Equal(t, uint16(len(data)), binary.BigEndian.Uint16(result[2:4]))
	// count = 1
	assert.Equal(t, uint16(1), binary.BigEndian.Uint16(result[4:6]))
	assert.Equal(t, data, result[6:])
}

func TestBuildSZLItem_EmptyData(t *testing.T) {
	result := buildSZLItem(0x001C, nil)
	// count = 0
	assert.Equal(t, uint16(0), binary.BigEndian.Uint16(result[4:6]))
	assert.Len(t, result, 6)
}

func TestBuildSZLResponse_ModuleIdentification(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		ServerName: "6ES7 315-2EH14-0AB0",
	}
	result := buildSZLResponse(0x0001, szlModuleIdentification, conf)
	// Must start with COTP DT header
	assert.Equal(t, byte(cotpDT), result[1])
	// S7 magic
	assert.Equal(t, byte(0x32), result[3])
	// Response must contain server name
	assert.Contains(t, string(result), "6ES7 315-2EH14-0AB0")
}

func TestBuildSZLResponse_CPUComponent(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		ServerVersion: "V3.3.13",
	}
	result := buildSZLResponse(0x0001, szlCPUComponent, conf)
	assert.Contains(t, string(result), "V3.3.13")
}

func TestBuildSZLResponse_ModuleInfo(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		Banner: "S7300-SERIAL-01",
	}
	result := buildSZLResponse(0x0001, szlModuleInfo, conf)
	assert.Contains(t, string(result), "S7300-SERIAL-01")
}

func TestBuildSZLResponse_UnknownSZL(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{}
	result := buildSZLResponse(0x0001, 0x9999, conf)
	// Should return a valid (empty) SZL response without panicking
	assert.NotNil(t, result)
	assert.Equal(t, byte(cotpDT), result[1])
}

func TestBuildSZLResponse_DefaultsWhenEmpty(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{}
	result := buildSZLResponse(0x0001, szlModuleIdentification, conf)
	// Default name used
	assert.Contains(t, string(result), "6ES7 000-0AA00-0AA0")
}

// ---- Integration tests ----

func TestS7CommStrategy_Init_InvalidAddress(t *testing.T) {
	s := &S7CommStrategy{}
	err := s.Init(parser.BeelzebubServiceConfiguration{
		Address:                "invalid-address",
		DeadlineTimeoutSeconds: 5,
	}, &mockTracer{})
	assert.Error(t, err)
}

func TestS7CommStrategy_COTPHandshake(t *testing.T) {
	addr := freeAddr(t)
	tr := startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		ServerName:             "6ES7 315-2EH14-0AB0",
		ServerVersion:          "V3.3.13",
		Banner:                 "S7300-01",
		DeadlineTimeoutSeconds: 5,
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Send COTP CR (Connection Request)
	cotpCR := []byte{
		0x03, 0x00, 0x00, 0x16, // TPKT header: version=3, len=22
		0x11,       // COTP LI=17
		0xE0,       // TPDU type: CR
		0x00, 0x00, // DST ref
		0x00, 0x01, // SRC ref
		0x00,       // class
		0xC0, 0x01, 0x0A, // TPDU size option
		0xC1, 0x02, 0x01, 0x00, // src TSAP
		0xC2, 0x02, 0x01, 0x02, // dst TSAP
	}
	_, err = conn.Write(cotpCR)
	require.NoError(t, err)

	// Read COTP CC response (11 bytes)
	resp := make([]byte, 11)
	_, err = conn.Read(resp)
	require.NoError(t, err)

	// Validate TPKT + COTP CC
	assert.Equal(t, byte(tpktVersion), resp[0])
	assert.Equal(t, byte(cotpCC), resp[5]) // TPDU type = CC (0xD0)

	// A start event should have been traced
	time.Sleep(30 * time.Millisecond)
	require.NotEmpty(t, tr.events)
	assert.Equal(t, tracer.S7COMM.String(), tr.events[0].Protocol)
}

func TestS7CommStrategy_SetupCommunication(t *testing.T) {
	addr := freeAddr(t)
	startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		ServerName:             "TestPLC",
		DeadlineTimeoutSeconds: 5,
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Step 1: COTP CR
	cotpCR := buildCOTPCR()
	conn.Write(cotpCR)

	ccBuf := make([]byte, 11)
	conn.Read(ccBuf)

	// Step 2: S7 Setup Communication request
	setupReq := buildS7SetupCommRequest()
	conn.Write(setupReq)

	// Read S7 response
	respBuf := make([]byte, 256)
	n, err := conn.Read(respBuf)
	require.NoError(t, err)
	require.Greater(t, n, 10)

	// TPKT version
	assert.Equal(t, byte(tpktVersion), respBuf[0])
	// COTP DT type in payload
	assert.Equal(t, byte(cotpDT), respBuf[5])
	// S7 magic
	assert.Equal(t, byte(0x32), respBuf[7])
	// PDU type: ACK-DATA (0x03)
	assert.Equal(t, byte(s7TypeAckData), respBuf[8])
}

// ---- Helpers for building test packets ----

func buildCOTPCR() []byte {
	return []byte{
		0x03, 0x00, 0x00, 0x16,
		0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
		0xC0, 0x01, 0x0A,
		0xC1, 0x02, 0x01, 0x00,
		0xC2, 0x02, 0x01, 0x02,
	}
}

func buildS7SetupCommRequest() []byte {
	// TPKT (4) + COTP DT (3) + S7 header (10) + params (8) = 25 bytes
	s7Params := []byte{
		0xF0, 0x00, // setup comm
		0x00, 0x01, // max AMQ caller
		0x00, 0x01, // max AMQ callee
		0x03, 0xC0, // PDU length
	}
	s7Header := []byte{
		0x32, 0x01, // magic, type=job
		0x00, 0x00, // reserved
		0x00, 0x01, // pdu ref
		0x00, 0x08, // param length
		0x00, 0x00, // data length
	}
	cotpDT := []byte{0x02, 0xF0, 0x80}
	payload := append(cotpDT, s7Header...)
	payload = append(payload, s7Params...)

	total := uint16(4 + len(payload))
	tpkt := []byte{0x03, 0x00, byte(total >> 8), byte(total)}
	return append(tpkt, payload...)
}
