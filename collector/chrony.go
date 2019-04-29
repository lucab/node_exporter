// Copyright 2019 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !nochrony

package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	// chronySubsystem is the subsystem label for this collector
	chronySubsystem = "chrony"
	// chronyCmdProtoVer is the protocol version for this client
	chronyCmdProtoVer = uint8(6)
	// chronyCmdPktTypeRequest is the request packet type
	chronyCmdPktTypeRequest = uint8(1)
	// chronyCmdPktTypeRequest is the reply packet type
	chronyCmdPktTypeReply = uint8(2)
	// chronyCmdRequestTracking identifies a tracking request
	chronyCmdRequestTracking = uint16(33)
	// chronyCmdReplyTracking identifies a tracking reply
	chronyCmdReplyTracking = uint16(5)
)

var (
	// chronyCmdIp is the `cmdip` flag
	chronyCmdIp = kingpin.Flag("collector.chrony.cmdip", "chrony command IP address").Default("127.0.0.1").String()
	// chronyCmdPort is the `cmdport` flag
	chronyCmdPort = kingpin.Flag("collector.chrony.cmdport", "chrony command port").Default("323").Int()
)

// chronyCollector is the main collector for chrony
type chronyCollector struct {
	// cmdAddr stores the IP address for chrony command service
	cmdAddr net.IP
	// cmdAddr stores the port for chrony command service
	cmdPort uint16
	// trackingStratum is the stratum metrics
	trackingStratum typedDesc
}

func init() {
	registerCollector("chrony", defaultDisabled, NewChronyCollector)
}

// NewChronyCollector returns a new Collector exposing local status of a chrony daemon
func NewChronyCollector() (Collector, error) {
	if chronyCmdIp == nil || chronyCmdPort == nil {
		return nil, errors.New("nil chrony flags")
	}
	if *chronyCmdPort <= 0 {
		return nil, fmt.Errorf("invalid chrony cmdport %q", *chronyCmdPort)

	}
	ipAddr := net.ParseIP(*chronyCmdIp)
	if ipAddr == nil {
		return nil, fmt.Errorf("invalid chrony cmdip %q", *chronyCmdIp)
	}

	return &chronyCollector{
		cmdAddr: ipAddr,
		cmdPort: uint16(*chronyCmdPort),
		trackingStratum: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(namespace, chronySubsystem, "tracking_stratum"),
			"local chrony stratum.",
			nil, nil,
		), prometheus.GaugeValue},
	}, nil
}

// Update update chrony metrics
func (c *chronyCollector) Update(ch chan<- prometheus.Metric) error {
	addr := net.JoinHostPort(c.cmdAddr.String(), fmt.Sprintf("%d", c.cmdPort))

	tracking, err := fetchTracking(addr)
	if err != nil {
		return err
	}
	//ch <- c.trackingStratum.mustNewConstMetric(float64(tracking.RefTime.EpochSeconds()))
	//ch <- c.trackingStratum.mustNewConstMetric(tracking.RefTime.EpochSeconds())
	_ = tracking.CurrentCorrection.Float64()
	_ = tracking.LastOffset.Float64()
	_ = tracking.RmsOffset.Float64()
	_ = tracking.FreqPpm.Float64()
	_ = tracking.ResidFreqPpm.Float64()
	_ = tracking.SkewPpm.Float64()
	_ = tracking.RootDelay.Float64()
	_ = tracking.RootDispersion.Float64()
	ch <- c.trackingStratum.mustNewConstMetric(tracking.LastUpdateInterval.Float64())

	return nil
}

func fetchTracking(addr string) (*trackingPayload, error) {
	var attempt uint16
	var seqNumber uint32

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}

	if err := trackingReq(conn, attempt, seqNumber); err != nil {
		return nil, err
	}

	payload, err := trackingReply(conn, attempt, seqNumber)
	if err != nil {
		return nil, err
	}
	return &payload, nil
}

// trackingRequest holds a tracking request
type trackingRequest struct {
	ProtoVer  uint8
	PktType   uint8
	Res1      uint8
	Res2      uint8
	Command   uint16
	Attempt   uint16
	SeqNumber uint32
	Pad       [92]byte
}

// trackingReply parses a tracking reply
func trackingReq(conn *net.UDPConn, attempt uint16, seqNumber uint32) error {
	buf := new(bytes.Buffer)
	req := trackingRequest{
		ProtoVer: chronyCmdProtoVer,
		PktType:  chronyCmdPktTypeRequest,
		Command:  chronyCmdRequestTracking,
		Attempt:  attempt,
	}
	if err := binary.Write(buf, binary.BigEndian, req); err != nil {
		return err
	}

	n, err := conn.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to write tracking request: %s", err)
	}
	if n != buf.Len() {
		return fmt.Errorf("short write (%d)", n)
	}
	return nil
}

// replyPacket is the common header for all replies
type replyPacket struct {
	ProtoVer uint8
	PktType  uint8
	Res1     uint8
	Res2     uint8
	Command  uint16
	Reply    uint16
	Status   uint16
	Pad1     uint16
	Pad2     uint16
	Pad3     uint16
	SeqNum   uint32
	Pad4     uint32
	Pad5     uint32
}

// chronyFloat is the custom chrony float type (`Float`)
type chronyFloat struct {
	Data [4]uint8
}

// Float64 returns the 64bits float value
func (cf chronyFloat) Float64() float64 {

	exp := int8(cf.Data[0])>>1 - 25

	sign := int32(1)
	if (cf.Data[0] & 1) != 0 {
		sign = -1
	}

	val := uint32(cf.Data[3]) + (uint32(cf.Data[2]) << 8) + (uint32(cf.Data[1]) << 16)
	powerexp := math.Pow(2, float64(exp))

	if sign == -1 {
		fmt.Printf("sign %d\n", sign)
		fmt.Printf("exp %d\n", exp)
		fmt.Printf("data %x\n", cf.Data)
		fmt.Printf("val %d\n", val)
		fmt.Printf("powerexp %d\n", powerexp)
	}

	fl := float64(int32(val)*sign) * powerexp
	fmt.Printf("fl %f\n", fl)

	return fl
}

// chronyFloat is the custom chrony timespec type (`Timespec`)
type chronyTimespec struct {
	TvSecHigh uint32
	TvSecLow  uint32
	TvNSec    uint32
}

// EpochSeconds returns the number of seconds since epoch
func (ct chronyTimespec) EpochSeconds() float64 {
	ts := uint64(ct.TvSecHigh) << 32
	ts += uint64(ct.TvSecLow)
	return float64(ts)
}

// trackingPayload is the payload for tracking replies (`RPY_Tracking`)
//
type trackingPayload struct {
	RefId              uint32
	IpAddrHigh         uint64
	IpAddrLow          uint64
	IpFamily           uint16
	Pad1               uint16
	Stratum            uint16
	LeapStatus         uint16
	RefTime            chronyTimespec
	CurrentCorrection  chronyFloat
	LastOffset         chronyFloat
	RmsOffset          chronyFloat
	FreqPpm            chronyFloat
	ResidFreqPpm       chronyFloat
	SkewPpm            chronyFloat
	RootDelay          chronyFloat
	RootDispersion     chronyFloat
	LastUpdateInterval chronyFloat
}

// trackingReply parses a tracking reply
func trackingReply(conn *net.UDPConn, attempt uint16, seqNumber uint32) (trackingPayload, error) {
	var reply replyPacket
	var payload trackingPayload

	dgram := make([]byte, 4096)
	_, err := conn.Read(dgram)
	if err != nil {
		return payload, err
	}

	rd := bytes.NewReader(dgram)
	if err := binary.Read(rd, binary.BigEndian, &reply); err != nil {
		return payload, fmt.Errorf("failed to read tracking reply: %s", err)
	}
	if reply.ProtoVer != chronyCmdProtoVer {
		return payload, fmt.Errorf("unexpected tracking protocol version: %d", reply.ProtoVer)
	}
	if reply.PktType != chronyCmdPktTypeReply {
		return payload, fmt.Errorf("unexpected tracking packet type: %d", reply.PktType)
	}
	if reply.SeqNum != seqNumber {
		return payload, fmt.Errorf("unexpected tracking packet seqNumber: %d", reply.SeqNum)
	}

	if err := binary.Read(rd, binary.BigEndian, &payload); err != nil {
		return payload, fmt.Errorf("failed reading tracking payload: %s", err)
	}

	return payload, nil
}
