package IEC104

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
	s := &IEC104Strategy{}
	require.NoError(t, s.Init(servConf, tr))
	time.Sleep(20 * time.Millisecond)
	return tr
}

// ---- Unit tests for frame helpers ----

func TestClassifyFrame_IFrame(t *testing.T) {
	// I-frame: bit 0 = 0
	cf := []byte{0x00, 0x00, 0x00, 0x00}
	assert.Equal(t, "I", classifyFrame(cf))
}

func TestClassifyFrame_SFrame(t *testing.T) {
	// S-frame: bits 1-0 = 01
	cf := []byte{0x01, 0x00, 0x00, 0x00}
	assert.Equal(t, "S", classifyFrame(cf))
}

func TestClassifyFrame_UFrame(t *testing.T) {
	// U-frame: bits 1-0 = 11
	cf := []byte{0x03, 0x00, 0x00, 0x00}
	assert.Equal(t, "U", classifyFrame(cf))
}

func TestClassifyFrame_UFrameStartDT(t *testing.T) {
	cf := []byte{uStartDTAct, 0x00, 0x00, 0x00}
	assert.Equal(t, "U", classifyFrame(cf))
}

func TestBuildUFrame(t *testing.T) {
	frame := buildUFrame(uStartDTCon)
	assert.Len(t, frame, 6)
	assert.Equal(t, byte(startByte), frame[0])
	assert.Equal(t, byte(0x04), frame[1])
	assert.Equal(t, byte(uStartDTCon), frame[2])
	assert.Equal(t, byte(0x00), frame[3])
	assert.Equal(t, byte(0x00), frame[4])
	assert.Equal(t, byte(0x00), frame[5])
}

func TestBuildSFrame(t *testing.T) {
	frame := buildSFrame(5)
	assert.Len(t, frame, 6)
	assert.Equal(t, byte(startByte), frame[0])
	assert.Equal(t, byte(0x04), frame[1])
	assert.Equal(t, byte(0x01), frame[2]) // S-frame marker
	// recv seq = 5 encoded as 5<<1 in LE uint16
	recvSeq := binary.LittleEndian.Uint16(frame[4:6])
	assert.Equal(t, uint16(10), recvSeq) // 5 << 1 = 10
}

func TestBuildIFrame(t *testing.T) {
	asdu := []byte{0x01, 0x01, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00}
	frame := buildIFrame(3, 7, asdu)

	assert.Equal(t, byte(startByte), frame[0])
	// length = 4 (CF) + len(asdu)
	assert.Equal(t, byte(4+len(asdu)), frame[1])

	// send seq = 3 → 3<<1 = 6 in LE
	sendSeq := binary.LittleEndian.Uint16(frame[2:4])
	assert.Equal(t, uint16(6), sendSeq)

	// recv seq = 7 → 7<<1 = 14 in LE
	recvSeq := binary.LittleEndian.Uint16(frame[4:6])
	assert.Equal(t, uint16(14), recvSeq)

	assert.Equal(t, asdu, frame[6:])
}

func TestParseASDU_Basic(t *testing.T) {
	// TypeID=45, VSQ=0x01, COT=0x06 0x00, CA=0x01 0x00, IOA=0x0A 0x00 0x00
	asdu := []byte{45, 0x01, 0x06, 0x00, 0x01, 0x00, 0x0A, 0x00, 0x00, 0xFF}
	typeID, cot, ca, ioa, raw := parseASDU(asdu)

	assert.Equal(t, byte(45), typeID)
	assert.Equal(t, uint16(cotActivation), cot)
	assert.Equal(t, uint16(1), ca)
	assert.Equal(t, uint32(10), ioa)
	assert.Equal(t, []byte{0xFF}, raw)
}

func TestParseASDU_TooShort(t *testing.T) {
	typeID, cot, ca, ioa, raw := parseASDU([]byte{0x01, 0x01})
	assert.Equal(t, byte(0), typeID)
	assert.Equal(t, uint16(0), cot)
	assert.Equal(t, uint16(0), ca)
	assert.Equal(t, uint32(0), ioa)
	assert.Nil(t, raw)
}

func TestBuildCommandResponse(t *testing.T) {
	resp := buildCommandResponse(45, cotActivationConfirmation, 1, 10)

	assert.Len(t, resp, 9)
	assert.Equal(t, byte(45), resp[0])
	assert.Equal(t, byte(1), resp[1]) // 1 object
	assert.Equal(t, uint16(cotActivationConfirmation), binary.LittleEndian.Uint16(resp[2:4]))
	assert.Equal(t, uint16(1), binary.LittleEndian.Uint16(resp[4:6]))
	// IOA = 10
	ioa := uint32(resp[6]) | uint32(resp[7])<<8 | uint32(resp[8])<<16
	assert.Equal(t, uint32(10), ioa)
}

func TestHandleUFrame_StartDT(t *testing.T) {
	started := false
	resp, handled := handleUFrame(uStartDTAct, &started)
	assert.True(t, handled)
	assert.True(t, started)
	assert.Equal(t, buildUFrame(uStartDTCon), resp)
}

func TestHandleUFrame_StopDT(t *testing.T) {
	started := true
	resp, handled := handleUFrame(uStopDTAct, &started)
	assert.True(t, handled)
	assert.False(t, started)
	assert.Equal(t, buildUFrame(uStopDTCon), resp)
}

func TestHandleUFrame_TestFR(t *testing.T) {
	started := false
	resp, handled := handleUFrame(uTestFRAct, &started)
	assert.True(t, handled)
	assert.Equal(t, buildUFrame(uTestFRCon), resp)
}

func TestHandleUFrame_Unknown(t *testing.T) {
	started := false
	_, handled := handleUFrame(0xFF, &started)
	assert.False(t, handled)
}

func TestSession_SequenceNumbers(t *testing.T) {
	s := &session{}
	assert.Equal(t, uint16(0), s.nextSend())
	assert.Equal(t, uint16(1), s.nextSend())

	s.updateRecv(4)
	assert.Equal(t, uint16(5), s.recvAck())
}

// ---- Integration tests ----

func TestIEC104Strategy_Init_InvalidAddress(t *testing.T) {
	s := &IEC104Strategy{}
	err := s.Init(parser.BeelzebubServiceConfiguration{
		Address:                "invalid-address",
		DeadlineTimeoutSeconds: 5,
	}, &mockTracer{})
	assert.Error(t, err)
}

func TestIEC104Strategy_STARTDT(t *testing.T) {
	addr := freeAddr(t)
	tr := startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		Banner:                 "1",
		DeadlineTimeoutSeconds: 10,
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send STARTDT_act
	startDT := buildUFrame(uStartDTAct)
	_, err = conn.Write(startDT)
	require.NoError(t, err)

	// Read STARTDT_con (6 bytes)
	resp := make([]byte, 6)
	_, err = conn.Read(resp)
	require.NoError(t, err)

	assert.Equal(t, byte(startByte), resp[0])
	assert.Equal(t, byte(0x04), resp[1])
	assert.Equal(t, byte(uStartDTCon), resp[2])

	// A trace event should have been emitted for the connection
	time.Sleep(30 * time.Millisecond)
	require.NotEmpty(t, tr.events)
	assert.Equal(t, tracer.IEC104.String(), tr.events[0].Protocol)
}

func TestIEC104Strategy_TESTFR(t *testing.T) {
	addr := freeAddr(t)
	startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		DeadlineTimeoutSeconds: 10,
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send TESTFR_act
	conn.Write(buildUFrame(uTestFRAct))

	resp := make([]byte, 6)
	_, err = conn.Read(resp)
	require.NoError(t, err)

	assert.Equal(t, byte(startByte), resp[0])
	assert.Equal(t, byte(uTestFRCon), resp[2])
}

func TestIEC104Strategy_STOPDT(t *testing.T) {
	addr := freeAddr(t)
	startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		DeadlineTimeoutSeconds: 10,
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	conn.Write(buildUFrame(uStopDTAct))

	resp := make([]byte, 6)
	_, err = conn.Read(resp)
	require.NoError(t, err)

	assert.Equal(t, byte(startByte), resp[0])
	assert.Equal(t, byte(uStopDTCon), resp[2])
}

func TestIEC104Strategy_IFrame_CommandResponse(t *testing.T) {
	addr := freeAddr(t)
	tr := startServer(t, parser.BeelzebubServiceConfiguration{
		Address:                addr,
		Banner:                 "1",
		DeadlineTimeoutSeconds: 10,
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// First STARTDT so we're in started state
	conn.Write(buildUFrame(uStartDTAct))
	startResp := make([]byte, 6)
	conn.Read(startResp)

	// Build an I-frame with TypeID=45 (single command) — should trigger confirm+terminate
	asdu := []byte{
		45,   // TypeID: C_SC_NA_1 (Single Command)
		0x01, // VSQ: 1 object
		0x06, 0x00, // COT: Activation (6)
		0x01, 0x00, // Common address: 1
		0x01, 0x00, 0x00, // IOA: 1
		0x01, // SCS (command state)
	}
	iframe := buildIFrame(0, 0, asdu)
	_, err = conn.Write(iframe)
	require.NoError(t, err)

	// Read S-frame ack (6 bytes) + 2 I-frame responses (confirm + terminate)
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Greater(t, n, 6) // at least the S-frame

	// First 6 bytes should be S-frame (CF: 0x01 ...)
	assert.Equal(t, byte(startByte), buf[0])
	assert.Equal(t, byte(0x01), buf[2]) // S-frame marker

	// Verify the ASDU interaction was traced
	time.Sleep(50 * time.Millisecond)
	var interactionFound bool
	for _, ev := range tr.events {
		if ev.Status == tracer.Interaction.String() {
			interactionFound = true
			assert.Equal(t, tracer.IEC104.String(), ev.Protocol)
			assert.Contains(t, ev.Command, "TypeID=45")
			break
		}
	}
	assert.True(t, interactionFound, "expected an Interaction trace event for the I-frame")
}
