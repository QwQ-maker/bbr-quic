package congestion

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// 数据定义
type bbrMode int
type bbrRecoveryState int

// 4种模式
const (
	// Startup phase of the connection.
	STARTUP = iota
	// After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	DRAIN
	// Cruising mode.
	PROBE_BW
	// Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	PROBE_RTT
)

const (
	// Do not limit.
	NOT_IN_RECOVERY = iota

	// Allow an extra outstanding byte for each byte acknowledged.
	CONSERVATION

	// Allow two extra outstanding bytes for each byte acknowledged (slow
	// start).
	GROWTH
)

var (
	InfiniteRTT = time.Duration(math.MaxInt64)
)
var (
	_ SendAlgorithm               = &bbrSender{}
	_ SendAlgorithmWithDebugInfos = &bbrSender{}
)

// 一些常量
var (
	// The maximum outgoing packet size allowed.
	// The maximum packet size of any QUIC packet over IPv6, based on ethernet's max
	// size, minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds an
	// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
	// max packet size is 1500 bytes,  1500 - 48 = 1452.
	MaxOutgoingPacketSize = protocol.ByteCount(1452)

	// Default maximum packet size used in the Linux TCP implementation.
	// Used in QUIC for congestion window computations in bytes.
	MaxSegmentSize = protocol.DefaultTCPMSS

	// Default initial rtt used before any samples are received.
	InitialRtt = 100 * time.Millisecond

	// Constants based on TCP defaults.
	// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
	// Does not inflate the pacing rate.
	DefaultMinimumCongestionWindow = 4 * protocol.DefaultTCPMSS

	// The gain used for the STARTUP, equal to 2/ln(2).
	DefaultHighGain = 2.885

	// The gain used in STARTUP after loss has been detected.
	// 1.5 is enough to allow for 25% exogenous loss and still observe a 25% growth
	// in measured bandwidth.
	StartupAfterLossGain = 1.5

	// The cycle of gains used during the PROBE_BW stage.
	PacingGain = []float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

	// The length of the gain cycle.
	GainCycleLength = len(PacingGain)

	// The size of the bandwidth filter window, in round-trips.
	BandwidthWindowSize = GainCycleLength + 2

	// The time after which the current min_rtt value expires.
	MinRttExpiry = 10 * time.Second

	// The minimum time the connection can spend in PROBE_RTT mode.
	ProbeRttTime = time.Millisecond * 200

	// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
	// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	StartupGrowthTarget                         = 1.25
	RoundTripsWithoutGrowthBeforeExitingStartup = int64(3)

	// Coefficient of target congestion window to use when basing PROBE_RTT on BDP.
	ModerateProbeRttMultiplier = 0.75

	// Coefficient to determine if a new RTT is sufficiently similar to min_rtt that
	// we don't need to enter PROBE_RTT.
	SimilarMinRttThreshold = 1.125

	// Congestion window gain for QUIC BBR during PROBE_BW phase.
	DefaultCongestionWindowGainConst = 2.0
)

// 新结构体
type bbrSender struct {
	mode     bbrMode
	clock    Clock
	rttStats *utils.RTTStats
	// return total bytes of unacked packets.
	GetBytesInFlight func() protocol.ByteCount
	// Bandwidth sampler provides BBR with the bandwidth measurements at
	// individual points.
	sampler *BandwidthSampler
	// The number of the round trips that have occurred during the connection.
	roundTripCount int64
	// The packet number of the most recently sent packet.
	lastSendPacket protocol.PacketNumber
	// Acknowledgement of any packet after |current_round_trip_end_| will cause
	// the round trip counter to advance.
	currentRoundTripEnd protocol.PacketNumber
	// The filter that tracks the maximum bandwidth over the multiple recent
	// round-trips.
	maxBandwidth *WindowedFilter
	// Tracks the maximum number of bytes acked faster than the sending rate.
	maxAckHeight *WindowedFilter
	// The time this aggregation started and the number of bytes acked during it.
	aggregationEpochStartTime time.Time
	aggregationEpochBytes     protocol.ByteCount
	// Minimum RTT estimate.  Automatically expires within 10 seconds (and
	// triggers PROBE_RTT mode) if no new value is sampled during that period.
	minRtt time.Duration
	// The time at which the current value of |min_rtt_| was assigned.
	minRttTimestamp time.Time
	// The maximum allowed number of bytes in flight.
	congestionWindow protocol.ByteCount
	// The initial value of the |congestion_window_|.
	initialCongestionWindow protocol.ByteCount
	// The largest value the |congestion_window_| can achieve.
	maxCongestionWindow protocol.ByteCount
	// The smallest value the |congestion_window_| can achieve.
	minCongestionWindow protocol.ByteCount
	// The pacing gain applied during the STARTUP phase.
	highGain float64
	// The CWND gain applied during the STARTUP phase.
	highCwndGain float64
	// The pacing gain applied during the DRAIN phase.
	drainGain float64
	// The current pacing rate of the connection.
	pacingRate Bandwidth
	// The gain currently applied to the pacing rate.
	pacingGain float64
	// The gain currently applied to the congestion window.
	congestionWindowGain float64
	// The gain used for the congestion window during PROBE_BW.  Latched from
	// quic_bbr_cwnd_gain flag.
	congestionWindowGainConst float64
	// The number of RTTs to stay in STARTUP mode.  Defaults to 3.
	numStartupRtts int64
	// If true, exit startup if 1RTT has passed with no bandwidth increase and
	// the connection is in recovery.
	exitStartupOnLoss bool
	// Number of round-trips in PROBE_BW mode, used for determining the current
	// pacing gain cycle.
	cycleCurrentOffset int
	// The time at which the last pacing gain cycle was started.
	lastCycleStart time.Time
	// Indicates whether the connection has reached the full bandwidth mode.
	isAtFullBandwidth bool
	// Number of rounds during which there was no significant bandwidth increase.
	roundsWithoutBandwidthGain int64
	// The bandwidth compared to which the increase is measured.
	bandwidthAtLastRound Bandwidth
	// Set to true upon exiting quiescence.
	exitingQuiescence bool
	// Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
	// that the time is yet unknown as the number of packets in flight has not
	// reached the required value.
	exitProbeRttAt time.Time
	// Indicates whether a round-trip has passed since PROBE_RTT became active.
	probeRttRoundPassed bool
	// Indicates whether the most recent bandwidth sample was marked as
	// app-limited.
	lastSampleIsAppLimited bool
	// Indicates whether any non app-limited samples have been recorded.
	hasNoAppLimitedSample bool
	// Indicates app-limited calls should be ignored as long as there's
	// enough data inflight to see more bandwidth when necessary.
	flexibleAppLimited bool
	// Current state of recovery.
	recoveryState bbrRecoveryState
	// Receiving acknowledgement of a packet after |end_recovery_at_| will cause
	// BBR to exit the recovery mode.  A value above zero indicates at least one
	// loss has been detected, so it must not be set back to zero.
	endRecoveryAt protocol.PacketNumber
	// A window used to limit the number of bytes in flight during loss recovery.
	recoveryWindow protocol.ByteCount
	// If true, consider all samples in recovery app-limited.
	isAppLimitedRecovery bool
	// When true, pace at 1.5x and disable packet conservation in STARTUP.
	slowerStartup bool
	// When true, disables packet conservation in STARTUP.
	rateBasedStartup bool
	// When non-zero, decreases the rate in STARTUP by the total number of bytes
	// lost in STARTUP divided by CWND.
	startupRateReductionMultiplier int64
	// Sum of bytes lost in STARTUP.
	startupBytesLost protocol.ByteCount
	// When true, add the most recent ack aggregation measurement during STARTUP.
	enableAckAggregationDuringStartup bool
	// When true, expire the windowed ack aggregation values in STARTUP when
	// bandwidth increases more than 25%.
	expireAckAggregationInStartup bool
	// If true, will not exit low gain mode until bytes_in_flight drops below BDP
	// or it's time for high gain mode.
	drainToTarget bool
	// If true, use a CWND of 0.75*BDP during probe_rtt instead of 4 packets.
	probeRttBasedOnBdp bool
	// If true, skip probe_rtt and update the timestamp of the existing min_rtt to
	// now if min_rtt over the last cycle is within 12.5% of the current min_rtt.
	// Even if the min_rtt is 12.5% too low, the 25% gain cycling and 2x CWND gain
	// should overcome an overly small min_rtt.
	probeRttSkippedIfSimilarRtt bool
	// If true, disable PROBE_RTT entirely as long as the connection was recently
	// app limited.
	probeRttDisabledIfAppLimited bool
	appLimitedSinceLastProbeRtt  bool
	minRttSinceLastProbeRtt      time.Duration
	// Latched value of --quic_always_get_bw_sample_when_acked.
	alwaysGetBwSampleWhenAcked bool
}

//var (
//	_ SendAlgorithm               = &cubicSender{}
//	_ SendAlgorithmWithDebugInfos = &cubicSender{}
//)

func log1() {
	path := "./log1.txt"
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("open file failed, err: %v", err)
		return
	}
	defer file.Close()

	// 写入数据到文件
	_, err = file.WriteString("Hello, this is a log message.\n")
	if err != nil {
		fmt.Printf("write to file failed, err: %v", err)
	}
}

// NewCubicSender makes a new cubic sender
func NewBBRSender(clock Clock, rttStats *utils.RTTStats, initialCongestionWindow, maxCongestionWindow protocol.ByteCount, getBytesInFlight func() protocol.ByteCount) *bbrSender {
	log1()
	return &bbrSender{
		rttStats:                  rttStats,
		GetBytesInFlight:          getBytesInFlight,
		mode:                      STARTUP,
		clock:                     clock,
		sampler:                   NewBandwidthSampler(),
		maxBandwidth:              NewWindowedFilter(int64(BandwidthWindowSize), MaxFilter),
		maxAckHeight:              NewWindowedFilter(int64(BandwidthWindowSize), MaxFilter),
		congestionWindow:          initialCongestionWindow,
		initialCongestionWindow:   initialCongestionWindow,
		maxCongestionWindow:       maxCongestionWindow,
		minCongestionWindow:       DefaultMinimumCongestionWindow,
		highGain:                  DefaultHighGain,
		highCwndGain:              DefaultHighGain,
		drainGain:                 1.0 / DefaultHighGain,
		pacingGain:                1.0,
		congestionWindowGain:      1.0,
		congestionWindowGainConst: DefaultCongestionWindowGainConst,
		numStartupRtts:            RoundTripsWithoutGrowthBeforeExitingStartup,
		recoveryState:             NOT_IN_RECOVERY,
		recoveryWindow:            maxCongestionWindow,
		minRttSinceLastProbeRtt:   InfiniteRTT,
	}
}

//##################################重写区#######################################

// 彻底重写,有点不懂
// TimeUntilSend returns when the next packet should be sent.
func (b *bbrSender) TimeUntilSend(bytesInFlight protocol.ByteCount) time.Time {
	return time.Now()
}

//func (c *cubicSender) TimeUntilSend(_ protocol.ByteCount) time.Time {
//	return c.pacer.TimeUntilSend()
//}

// 不知道咋重写,先重写成空方法
func (b *bbrSender) HasPacingBudget(time.Time) bool { return false }

//func (c *cubicSender) HasPacingBudget() bool {
//	return c.pacer.Budget(c.clock.Now()) >= c.maxDatagramSize
//}

//直接重写成常量
//func (c *cubicSender) maxCongestionWindow() protocol.ByteCount {
//	return c.maxDatagramSize * protocol.MaxCongestionWindowPackets
//}

//重写成常量
//func (c *cubicSender) minCongestionWindow() protocol.ByteCount {
//	return c.maxDatagramSize * minCongestionWindowPackets
//}

// 彻底重写
func (b *bbrSender) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.lastSendPacket = packetNumber

	if bytesInFlight == 0 && b.sampler.isAppLimited {
		b.exitingQuiescence = true
	}

	if b.aggregationEpochStartTime.IsZero() {
		b.aggregationEpochStartTime = sentTime
	}

	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
}

//func (c *cubicSender) OnPacketSent(
//	sentTime time.Time,
//	_ protocol.ByteCount,
//	packetNumber protocol.PacketNumber,
//	bytes protocol.ByteCount,
//	isRetransmittable bool,
//) {
//	c.pacer.SentPacket(sentTime, bytes)
//	if !isRetransmittable {
//		return
//	}
//	c.largestSentPacketNumber = packetNumber
//	c.hybridSlowStart.OnPacketSent(packetNumber)
//}

// 彻底重写
func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

//func (c *cubicSender) CanSend(bytesInFlight protocol.ByteCount) bool {
//	return bytesInFlight < c.GetCongestionWindow()
//}

// 彻底重写
func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != NOT_IN_RECOVERY
}

//func (c *cubicSender) InRecovery() bool {
//	return c.largestAckedPacketNumber != protocol.InvalidPacketNumber && c.largestAckedPacketNumber <= c.largestSentAtLastCutback
//}

// 彻底重写
func (b *bbrSender) InSlowStart() bool {
	return b.mode == STARTUP
}

//func (c *cubicSender) InSlowStart() bool {
//	return c.GetCongestionWindow() < c.slowStartThreshold
//}

// 彻底重写
func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	if b.mode == PROBE_RTT {
		return b.ProbeRttCongestionWindow()
	}

	if b.InRecovery() && !(b.rateBasedStartup && b.mode == STARTUP) {
		return minByteCount(b.congestionWindow, b.recoveryWindow)
	}

	return b.congestionWindow
}

//func (c *cubicSender) GetCongestionWindow() protocol.ByteCount {
//	return c.congestionWindow
//}

// 彻底重写，空白重写
func (b *bbrSender) MaybeExitSlowStart() {

}

//func (c *cubicSender) MaybeExitSlowStart() {
//	if c.InSlowStart() &&
//		c.hybridSlowStart.ShouldExitSlowStart(c.rttStats.LatestRTT(), c.rttStats.MinRTT(), c.GetCongestionWindow()/c.maxDatagramSize) {
//		// exit slow start
//		c.slowStartThreshold = c.congestionWindow
//		c.maybeTraceStateChange(logging.CongestionStateCongestionAvoidance)
//	}
//}

// 彻底重写
func (b *bbrSender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime time.Time) {
	panic("should call OnCongestionEvent()")
}

//func (c *cubicSender) OnPacketAcked(
//	ackedPacketNumber protocol.PacketNumber,
//	ackedBytes protocol.ByteCount,
//	priorInFlight protocol.ByteCount,
//	eventTime time.Time,
//) {
//	c.largestAckedPacketNumber = utils.Max(ackedPacketNumber, c.largestAckedPacketNumber)
//	if c.InRecovery() {
//		return
//	}
//	c.maybeIncreaseCwnd(ackedPacketNumber, ackedBytes, priorInFlight, eventTime)
//	if c.InSlowStart() {
//		c.hybridSlowStart.OnPacketAcked(ackedPacketNumber)
//	}
//}

// 彻底重写，没有丢包对策
func (b *bbrSender) OnPacketLost(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	panic("should call OnCongestionEvent()")
}

//func (c *cubicSender) OnPacketLost(packetNumber protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) {
//	// TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
//	// already sent should be treated as a single loss event, since it's expected.
//	if packetNumber <= c.largestSentAtLastCutback {
//		return
//	}
//	c.lastCutbackExitedSlowstart = c.InSlowStart()
//	c.maybeTraceStateChange(logging.CongestionStateRecovery)
//
//	if c.reno {
//		c.congestionWindow = protocol.ByteCount(float64(c.congestionWindow) * renoBeta)
//	} else {
//		c.congestionWindow = c.cubic.CongestionWindowAfterPacketLoss(c.congestionWindow)
//	}
//	if minCwnd := c.minCongestionWindow(); c.congestionWindow < minCwnd {
//		c.congestionWindow = minCwnd
//	}
//	c.slowStartThreshold = c.congestionWindow
//	c.largestSentAtLastCutback = c.largestSentPacketNumber
//	// reset packet count from congestion avoidance mode. We start
//	// counting again when we're out of recovery.
//	c.numAckedPackets = 0
//}

// 彻底重写为空方法
func (b *bbrSender) maybeIncreaseCwnd() {}

//func (c *cubicSender) maybeIncreaseCwnd(
//	_ protocol.PacketNumber,
//	ackedBytes protocol.ByteCount,
//	priorInFlight protocol.ByteCount,
//	eventTime time.Time,
//) {
//	// Do not increase the congestion window unless the sender is close to using
//	// the current window.
//	if !c.isCwndLimited(priorInFlight) {
//		c.cubic.OnApplicationLimited()
//		c.maybeTraceStateChange(logging.CongestionStateApplicationLimited)
//		return
//	}
//	if c.congestionWindow >= c.maxCongestionWindow() {
//		return
//	}
//	if c.InSlowStart() {
//		// TCP slow start, exponential growth, increase by one for each ACK.
//		c.congestionWindow += c.maxDatagramSize
//		c.maybeTraceStateChange(logging.CongestionStateSlowStart)
//		return
//	}
//	// Congestion avoidance
//	c.maybeTraceStateChange(logging.CongestionStateCongestionAvoidance)
//	if c.reno {
//		// Classic Reno congestion avoidance.
//		c.numAckedPackets++
//		if c.numAckedPackets >= uint64(c.congestionWindow/c.maxDatagramSize) {
//			c.congestionWindow += c.maxDatagramSize
//			c.numAckedPackets = 0
//		}
//	} else {
//		c.congestionWindow = utils.Min(c.maxCongestionWindow(), c.cubic.CongestionWindowAfterAck(ackedBytes, c.congestionWindow, c.rttStats.MinRTT(), eventTime))
//	}
//}

// 彻底重写为空方法
func (c *bbrSender) isCwndLimited() {}

//func (c *cubicSender) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
//	congestionWindow := c.GetCongestionWindow()
//	if bytesInFlight >= congestionWindow {
//		return true
//	}
//	availableBytes := congestionWindow - bytesInFlight
//	slowStartLimited := c.InSlowStart() && bytesInFlight > congestionWindow/2
//	return slowStartLimited || availableBytes <= maxBurstPackets*c.maxDatagramSize
//}

// 彻底重写
func (b *bbrSender) BandwidthEstimate() Bandwidth {
	return Bandwidth(b.maxBandwidth.GetBest())
}

// BandwidthEstimate returns the current bandwidth estimate
//func (c *cubicSender) BandwidthEstimate() Bandwidth {
//	srtt := c.rttStats.SmoothedRTT()
//	if srtt == 0 {
//		// If we haven't measured an rtt, the bandwidth estimate is unknown.
//		return infBandwidth
//	}
//	return BandwidthFromDelta(c.GetCongestionWindow(), srtt)
//}

// 彻底重写为空方法
func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {

}

//func (c *cubicSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
//	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
//	if !packetsRetransmitted {
//		return
//	}
//	c.hybridSlowStart.Restart()
//	c.cubic.Reset()
//	c.slowStartThreshold = c.congestionWindow / 2
//	c.congestionWindow = c.minCongestionWindow()
//}

// 彻底重写为空方法
func (b *bbrSender) OnConnectionMigration() {

}

//func (c *cubicSender) OnConnectionMigration() {
//	c.hybridSlowStart.Restart()
//	c.largestSentPacketNumber = protocol.InvalidPacketNumber
//	c.largestAckedPacketNumber = protocol.InvalidPacketNumber
//	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
//	c.lastCutbackExitedSlowstart = false
//	c.cubic.Reset()
//	c.numAckedPackets = 0
//	c.congestionWindow = c.initialCongestionWindow
//	c.slowStartThreshold = c.initialMaxCongestionWindow
//}

// 彻底重写为空方法
func (b *bbrSender) maybeTraceStateChange() {}

//func (c *cubicSender) maybeTraceStateChange(new logging.CongestionState) {
//	if c.tracer == nil || new == c.lastState {
//		return
//	}
//	c.tracer.UpdatedCongestionState(new)
//	c.lastState = new
//}

// 彻底重写为空方法
func (b *bbrSender) SetMaxDatagramSize(s protocol.ByteCount) {}

//func (c *cubicSender) SetMaxDatagramSize(s protocol.ByteCount) {
//	if s < c.maxDatagramSize {
//		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", c.maxDatagramSize, s))
//	}
//	cwndIsMinCwnd := c.congestionWindow == c.minCongestionWindow()
//	c.maxDatagramSize = s
//	if cwndIsMinCwnd {
//		c.congestionWindow = c.minCongestionWindow()
//	}
//	c.pacer.SetMaxDatagramSize(s)
//}

//####################增补区##############################

func (b *bbrSender) ProbeRttCongestionWindow() protocol.ByteCount {
	if b.probeRttBasedOnBdp {
		return b.GetTargetCongestionWindow(ModerateProbeRttMultiplier)
	} else {
		return b.minCongestionWindow
	}
}

func (b *bbrSender) GetTargetCongestionWindow(gain float64) protocol.ByteCount {
	bdp := protocol.ByteCount(b.GetMinRtt()) * protocol.ByteCount(b.BandwidthEstimate())
	congestionWindow := protocol.ByteCount(gain * float64(bdp))

	// BDP estimate will be zero if no bandwidth samples are available yet.
	if congestionWindow == 0 {
		congestionWindow = protocol.ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return maxByteCount(congestionWindow, b.minCongestionWindow)
}

// 计算小方法区
func (b *bbrSender) GetMinRtt() time.Duration {
	if b.minRtt > 0 {
		return b.minRtt
	} else {
		return InitialRtt
	}
}

func maxByteCount(a, b protocol.ByteCount) protocol.ByteCount {
	if a > b {
		return a
	} else {
		return b
	}
}

func minByteCount(a, b protocol.ByteCount) protocol.ByteCount {
	if a < b {
		return a
	} else {
		return b
	}
}

func minRtt(a, b time.Duration) time.Duration {
	if a < b {
		return a
	} else {
		return b
	}
}
func maxBandwidth(a, b Bandwidth) Bandwidth {
	if a > b {
		return a
	} else {
		return b
	}
}

//计算小方法区

// ############################拥塞事件系列###############################
func (b *bbrSender) OnCongestionEvent(priorInFlight protocol.ByteCount, eventTime time.Time, ackedPackets, lostPackets []*protocol.Packet) {
	totalBytesAckedBefore := b.sampler.totalBytesAcked
	isRoundStart, minRttExpired := false, false

	if lostPackets != nil {
		b.DiscardLostPackets(lostPackets)
	}

	// Input the new data into the BBR model of the connection.
	var excessAcked protocol.ByteCount
	if len(ackedPackets) > 0 {
		lastAckedPacket := ackedPackets[len(ackedPackets)-1].PacketNumber
		isRoundStart = b.UpdateRoundTripCounter(lastAckedPacket)
		minRttExpired = b.UpdateBandwidthAndMinRtt(eventTime, ackedPackets)
		b.UpdateRecoveryState(lastAckedPacket, len(lostPackets) > 0, isRoundStart)
		bytesAcked := b.sampler.totalBytesAcked - totalBytesAckedBefore
		excessAcked = b.UpdateAckAggregationBytes(eventTime, bytesAcked)
	}

	// Handle logic specific to PROBE_BW mode.
	if b.mode == PROBE_BW {
		b.UpdateGainCyclePhase(eventTime, priorInFlight, len(lostPackets) > 0)
	}

	// Handle logic specific to STARTUP and DRAIN modes.
	if isRoundStart && !b.isAtFullBandwidth {
		b.CheckIfFullBandwidthReached()
	}
	b.MaybeExitStartupOrDrain(eventTime)

	// Handle logic specific to PROBE_RTT.
	b.MaybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	// Calculate number of packets acked and lost.
	bytesAcked := b.sampler.totalBytesAcked - totalBytesAckedBefore
	bytesLost := protocol.ByteCount(0)
	for _, packet := range lostPackets {
		bytesLost += packet.Length
	}

	// After the model is updated, recalculate the pacing rate and congestion
	// window.
	b.CalculatePacingRate()
	b.CalculateCongestionWindow(bytesAcked, excessAcked)
	b.CalculateRecoveryWindow(bytesAcked, bytesLost)
}

func (b *bbrSender) DiscardLostPackets(lostPackets []*protocol.Packet) {
	for _, packet := range lostPackets {
		b.sampler.OnPacketLost(packet.PacketNumber)
		if b.mode == STARTUP {
			// if b.rttStats != nil {
			// TODO: slow start.
			// }
			if b.startupRateReductionMultiplier != 0 {
				b.startupBytesLost += packet.Length
			}
		}
	}
}

func (b *bbrSender) UpdateRoundTripCounter(lastAckedPacket protocol.PacketNumber) bool {
	if b.currentRoundTripEnd == 0 || lastAckedPacket > b.currentRoundTripEnd {
		b.currentRoundTripEnd = lastAckedPacket
		b.roundTripCount++
		// if b.rttStats != nil && b.InSlowStart() {
		// TODO: ++stats_->slowstart_num_rtts;
		// }
		return true
	}
	return false
}

func (b *bbrSender) UpdateBandwidthAndMinRtt(now time.Time, ackedPackets []*protocol.Packet) bool {
	sampleMinRtt := InfiniteRTT

	for _, packet := range ackedPackets {
		if !b.alwaysGetBwSampleWhenAcked && packet.Length == 0 {
			// Skip acked packets with 0 in flight bytes when updating bandwidth.
			continue
		}
		bandwidthSample := b.sampler.OnPacketAcked(now, packet.PacketNumber)
		if b.alwaysGetBwSampleWhenAcked && !bandwidthSample.stateAtSend.isValid {
			// From the sampler's perspective, the packet has never been sent, or the
			// packet has been acked or marked as lost previously.
			continue
		}
		b.lastSampleIsAppLimited = bandwidthSample.stateAtSend.isAppLimited
		//     has_non_app_limited_sample_ |=
		//        !bandwidth_sample.state_at_send.is_app_limited;
		if !bandwidthSample.stateAtSend.isAppLimited {
			b.hasNoAppLimitedSample = true
		}
		if bandwidthSample.rtt > 0 {
			sampleMinRtt = minRtt(sampleMinRtt, bandwidthSample.rtt)
		}
		if !bandwidthSample.stateAtSend.isAppLimited || bandwidthSample.bandwidth > b.BandwidthEstimate() {
			b.maxBandwidth.Update(int64(bandwidthSample.bandwidth), b.roundTripCount)
		}
	}

	// If none of the RTT samples are valid, return immediately.
	if sampleMinRtt == InfiniteRTT {
		return false
	}

	b.minRttSinceLastProbeRtt = minRtt(b.minRttSinceLastProbeRtt, sampleMinRtt)
	// Do not expire min_rtt if none was ever available.
	minRttExpired := b.minRtt > 0 && (now.After(b.minRttTimestamp.Add(MinRttExpiry)))
	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		if minRttExpired && b.ShouldExtendMinRttExpiry() {
			minRttExpired = false
		} else {
			b.minRtt = sampleMinRtt
		}
		b.minRttTimestamp = now
		// Reset since_last_probe_rtt fields.
		b.minRttSinceLastProbeRtt = InfiniteRTT
		b.appLimitedSinceLastProbeRtt = false
	}

	return minRttExpired
}
func (b *bbrSender) ShouldExtendMinRttExpiry() bool {
	if b.probeRttDisabledIfAppLimited && b.appLimitedSinceLastProbeRtt {
		// Extend the current min_rtt if we've been app limited recently.
		return true
	}

	minRttIncreasedSinceLastProbe := b.minRttSinceLastProbeRtt > time.Duration(float64(b.minRtt)*SimilarMinRttThreshold)
	if b.probeRttSkippedIfSimilarRtt && b.appLimitedSinceLastProbeRtt && !minRttIncreasedSinceLastProbe {
		// Extend the current min_rtt if we've been app limited recently and an rtt
		// has been measured in that time that's less than 12.5% more than the
		// current min_rtt.
		return true
	}

	return false
}

func (b *bbrSender) UpdateRecoveryState(lastAckedPacket protocol.PacketNumber, hasLosses, isRoundStart bool) {
	// Exit recovery when there are no losses for a round.
	if !hasLosses {
		b.endRecoveryAt = b.lastSendPacket
	}
	switch b.recoveryState {
	case NOT_IN_RECOVERY:
		// Enter conservation on the first loss.
		if hasLosses {
			b.recoveryState = CONSERVATION
			// This will cause the |recovery_window_| to be set to the correct
			// value in CalculateRecoveryWindow().
			b.recoveryWindow = 0
			// Since the conservation phase is meant to be lasting for a whole
			// round, extend the current round as if it were started right now.
			b.currentRoundTripEnd = b.lastSendPacket
			if false && b.lastSampleIsAppLimited {
				b.isAppLimitedRecovery = true
			}
		}
	case CONSERVATION:
		if isRoundStart {
			b.recoveryState = GROWTH
		}
		fallthrough
	case GROWTH:
		// Exit recovery if appropriate.
		if !hasLosses && b.lastSendPacket > b.endRecoveryAt {
			b.recoveryState = NOT_IN_RECOVERY
			b.isAppLimitedRecovery = false
		}
	}

	if b.recoveryState != NOT_IN_RECOVERY && b.isAppLimitedRecovery {
		b.sampler.OnAppLimited()
	}
}

func (b *bbrSender) UpdateAckAggregationBytes(ackTime time.Time, ackedBytes protocol.ByteCount) protocol.ByteCount {
	// Compute how many bytes are expected to be delivered, assuming max bandwidth
	// is correct.
	expectedAckedBytes := protocol.ByteCount(b.maxBandwidth.GetBest()) *
		protocol.ByteCount((ackTime.Sub(b.aggregationEpochStartTime)))
	// Reset the current aggregation epoch as soon as the ack arrival rate is less
	// than or equal to the max bandwidth.
	if b.aggregationEpochBytes <= expectedAckedBytes {
		// Reset to start measuring a new aggregation epoch.
		b.aggregationEpochBytes = ackedBytes
		b.aggregationEpochStartTime = ackTime
		return 0
	}
	// Compute how many extra bytes were delivered vs max bandwidth.
	// Include the bytes most recently acknowledged to account for stretch acks.
	b.aggregationEpochBytes += ackedBytes
	b.maxAckHeight.Update(int64(b.aggregationEpochBytes-expectedAckedBytes), b.roundTripCount)
	return b.aggregationEpochBytes - expectedAckedBytes
}

func (b *bbrSender) UpdateGainCyclePhase(now time.Time, priorInFlight protocol.ByteCount, hasLosses bool) {
	bytesInFlight := b.GetBytesInFlight()
	// In most cases, the cycle is advanced after an RTT passes.
	shouldAdvanceGainCycling := now.Sub(b.lastCycleStart) > b.GetMinRtt()

	// If the pacing gain is above 1.0, the connection is trying to probe the
	// bandwidth by increasing the number of bytes in flight to at least
	// pacing_gain * BDP.  Make sure that it actually reaches the target, as long
	// as there are no losses suggesting that the buffers are not able to hold
	// that much.
	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.GetTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}
	// If pacing gain is below 1.0, the connection is trying to drain the extra
	// queue which could have been incurred by probing prior to it.  If the number
	// of bytes in flight falls down to the estimated BDP value earlier, conclude
	// that the queue has been successfully drained and exit this cycle early.
	if b.pacingGain < 1.0 && bytesInFlight <= b.GetTargetCongestionWindow(1.0) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % GainCycleLength
		b.lastCycleStart = now
		// Stay in low gain mode until the target BDP is hit.
		// Low gain mode will be exited immediately when the target BDP is achieved.
		if b.drainToTarget && b.pacingGain < 1.0 && PacingGain[b.cycleCurrentOffset] == 1.0 &&
			bytesInFlight > b.GetTargetCongestionWindow(1.0) {
			return
		}
		b.pacingGain = PacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) CheckIfFullBandwidthReached() {
	if b.lastSampleIsAppLimited {
		return
	}

	target := Bandwidth(float64(b.bandwidthAtLastRound) * StartupGrowthTarget)
	if b.BandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.BandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {
			// Expire old excess delivery measurements now that bandwidth increased.
			b.maxAckHeight.Reset(0, b.roundTripCount)
		}
		return
	}
	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts || (b.exitStartupOnLoss && b.InRecovery()) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) MaybeExitStartupOrDrain(now time.Time) {
	if b.mode == STARTUP && b.isAtFullBandwidth {
		b.OnExitStartup(now)
		b.mode = DRAIN
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain
	}
	if b.mode == DRAIN && b.GetBytesInFlight() <= b.GetTargetCongestionWindow(1) {
		b.EnterProbeBandwidthMode(now)
	}
}

// 两处通用
func (b *bbrSender) OnExitStartup(now time.Time) {
	if b.rttStats == nil {
		return
	}
	// TODO: slow start.
}
func (b *bbrSender) EnterProbeBandwidthMode(now time.Time) {
	b.mode = PROBE_BW
	b.congestionWindowGain = b.congestionWindowGainConst

	// Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
	// excluded because in that case increased gain and decreased gain would not
	// follow each other.
	b.cycleCurrentOffset = rand.Int() % (GainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = PacingGain[b.cycleCurrentOffset]
}

//两处通用

func (b *bbrSender) MaybeEnterOrExitProbeRtt(now time.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && !b.exitingQuiescence && b.mode != PROBE_RTT {
		if b.InSlowStart() {
			b.OnExitStartup(now)
		}
		b.mode = PROBE_RTT
		b.pacingGain = 1.0
		// Do not decide on the time to exit PROBE_RTT until the |bytes_in_flight|
		// is at the target small value.
		b.exitProbeRttAt = time.Time{}
	}

	if b.mode == PROBE_RTT {
		b.sampler.OnAppLimited()
		if b.exitProbeRttAt.IsZero() {
			// If the window has reached the appropriate size, schedule exiting
			// PROBE_RTT.  The CWND during PROBE_RTT is kMinimumCongestionWindow, but
			// we allow an extra packet since QUIC checks CWND before sending a
			// packet.
			if b.GetBytesInFlight() < b.ProbeRttCongestionWindow()+MaxOutgoingPacketSize {
				b.exitProbeRttAt = now.Add(ProbeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if !now.Before(b.exitProbeRttAt) && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.EnterStartupMode(now)
				} else {
					b.EnterProbeBandwidthMode(now)
				}
			}
		}
	}
	b.exitingQuiescence = false
}
func (b *bbrSender) EnterStartupMode(now time.Time) {
	// if b.rttStats != nil {
	// TODO: slow start.
	// }
	b.mode = STARTUP
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
}

func (b *bbrSender) CalculatePacingRate() {
	if b.BandwidthEstimate() == 0 {
		return
	}

	targetRate := Bandwidth(b.pacingGain * float64(b.BandwidthEstimate()))
	if b.isAtFullBandwidth {
		b.pacingRate = targetRate
		return
	}

	// Pace at the rate of initial_window / RTT as soon as RTT measurements are
	// available.
	if b.pacingRate == 0 && b.rttStats.MinRTT() > 0 {
		b.pacingRate = BandwidthFromDelta(b.initialCongestionWindow, b.rttStats.MinRTT())
		return
	}
	// Slow the pacing rate in STARTUP once loss has ever been detected.
	hasEverDetectedLoss := b.endRecoveryAt > 0
	if b.slowerStartup && hasEverDetectedLoss && b.hasNoAppLimitedSample {
		b.pacingRate = Bandwidth(StartupAfterLossGain * float64(b.BandwidthEstimate()))
		return
	}

	// Slow the pacing rate in STARTUP by the bytes_lost / CWND.
	if b.startupRateReductionMultiplier != 0 && hasEverDetectedLoss && b.hasNoAppLimitedSample {
		b.pacingRate = Bandwidth((1.0 - (float64(b.startupBytesLost) * float64(b.startupRateReductionMultiplier) / float64(b.congestionWindow))) * float64(targetRate))
		// Ensure the pacing rate doesn't drop below the startup growth target times
		// the bandwidth estimate.
		b.pacingRate = maxBandwidth(b.pacingRate, Bandwidth(StartupGrowthTarget*float64(b.BandwidthEstimate())))
		return
	}

	// Do not decrease the pacing rate during startup.
	b.pacingRate = maxBandwidth(b.pacingRate, targetRate)
}
func (b *bbrSender) CalculateCongestionWindow(ackedBytes, excessAcked protocol.ByteCount) {
	if b.mode == PROBE_RTT {
		return
	}

	targetWindow := b.GetTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		// Add the max recently measured ack aggregation to CWND.
		targetWindow += protocol.ByteCount(b.maxAckHeight.GetBest())
	} else if b.enableAckAggregationDuringStartup {
		// Add the most recent excess acked.  Because CWND never decreases in
		// STARTUP, this will automatically create a very localized max filter.
		targetWindow += excessAcked
	}

	// Instead of immediately setting the target CWND as the new one, BBR grows
	// the CWND towards |target_window| by only increasing it |bytes_acked| at a
	// time.
	addBytesAcked := true || !b.InRecovery()
	if b.isAtFullBandwidth {
		b.congestionWindow = minByteCount(targetWindow, b.congestionWindow+ackedBytes)
	} else if addBytesAcked && (b.congestionWindow < targetWindow || b.sampler.totalBytesAcked < b.initialCongestionWindow) {
		// If the connection is not yet out of startup phase, do not decrease the
		// window.
		b.congestionWindow += ackedBytes
	}

	// Enforce the limits on the congestion window.
	b.congestionWindow = maxByteCount(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = minByteCount(b.congestionWindow, b.maxCongestionWindow)
}

func (b *bbrSender) CalculateRecoveryWindow(ackedBytes, lostBytes protocol.ByteCount) {
	if b.rateBasedStartup && b.mode == STARTUP {
		return
	}

	if b.recoveryState == NOT_IN_RECOVERY {
		return
	}

	// Set up the initial recovery window.
	if b.recoveryWindow == 0 {
		b.recoveryWindow = maxByteCount(b.GetBytesInFlight()+ackedBytes, b.minCongestionWindow)
		return
	}

	// Remove losses from the recovery window, while accounting for a potential
	// integer underflow.
	if b.recoveryWindow >= lostBytes {
		b.recoveryWindow -= lostBytes
	} else {
		b.recoveryWindow = MaxSegmentSize
	}
	// In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
	// release additional |bytes_acked| to achieve a slow-start-like behavior.
	if b.recoveryState == GROWTH {
		b.recoveryWindow += ackedBytes
	}
	// Sanity checks.  Ensure that we always allow to send at least an MSS or
	// |bytes_acked| in response, whichever is larger.
	b.recoveryWindow = maxByteCount(b.recoveryWindow, b.GetBytesInFlight()+ackedBytes)
	b.recoveryWindow = maxByteCount(b.recoveryWindow, b.minCongestionWindow)
}

//########################拥塞事件系列#######################################

// 无使用区
//func (b *bbrSender) SetNumEmulatedConnections(n int) {
//
//}
//
//func (b *bbrSender) SetSlowStartLargeReduction(enabled bool) {
//
//}
//
//func (b *bbrSender) HybridSlowStart() *HybridSlowStart {
//	return nil
//}
//
//func (b *bbrSender) SlowstartThreshold() protocol.ByteCount {
//	return 0
//}
//
//func (b *bbrSender) RenoBeta() float32 {
//	return 0.0
//}
//
//func (b *bbrSender) ShouldSendProbingPacket() bool {
//	if b.pacingGain <= 1 {
//		return false
//	}
//	// TODO(b/77975811): If the pipe is highly under-utilized, consider not
//	// sending a probing transmission, because the extra bandwidth is not needed.
//	// If flexible_app_limited is enabled, check if the pipe is sufficiently full.
//	if b.flexibleAppLimited {
//		return !b.IsPipeSufficientlyFull()
//	} else {
//		return true
//	}
//}
//func (b *bbrSender) IsPipeSufficientlyFull() bool {
//	// See if we need more bytes in flight to see more bandwidth.
//	if b.mode == STARTUP {
//		// STARTUP exits if it doesn't observe a 25% bandwidth increase, so the CWND
//		// must be more than 25% above the target.
//		return b.GetBytesInFlight() >= b.GetTargetCongestionWindow(1.5)
//	}
//	if b.pacingGain > 1 {
//		// Super-unity PROBE_BW doesn't exit until 1.25 * BDP is achieved.
//		return b.GetBytesInFlight() >= b.GetTargetCongestionWindow(b.pacingGain)
//	}
//	// If bytes_in_flight are above the target congestion window, it should be
//	// possible to observe the same or more bandwidth if it's available.
//	return b.GetBytesInFlight() >= b.GetTargetCongestionWindow(1.1)
//}
//
//func (b *bbrSender) SetFromConfig() {
//	// TODO: not impl.
//}

//无使用区
