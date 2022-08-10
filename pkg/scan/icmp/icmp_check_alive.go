package icmp

/*
创建人员：云深不知处
创建时间：2022/1/1
程序功能：ICMP检测主机是否存活
*/

import (
	log2 "BeeScan-scan/pkg/log"
	"net"
	"time"
)

// IcmpCheckAlive ICMP检测主机存活
func IcmpCheckAlive(host string, ip string) bool {
	if ip != "" {
		log2.Info("[IcmpCheck]:", ip)
		size := 32
		var seq int16 = 1
		const EchoRequestHeadLen = 8
		const EchoReplyHeadLen = 20

		startTime := time.Now()
		conn, err := net.DialTimeout("ip4:icmp", ip, 2*time.Second)
		if err != nil {
			log2.Warn("[IcmpCheck]", err)
			return false
		}
		defer conn.Close()
		id0, id1 := genIdentifier(ip)

		msg := make([]byte, size+EchoRequestHeadLen)
		msg[0] = 8
		msg[1] = 0
		msg[2] = 0
		msg[3] = 0
		msg[4], msg[5] = id0, id1
		msg[6], msg[7] = genSequence(seq)

		length := size + EchoRequestHeadLen

		check := checkSum(msg[0:length])
		msg[2] = byte(check >> 8)
		msg[3] = byte(check & 255)

		if err := conn.SetDeadline(startTime.Add(5 * time.Second)); err != nil {
			return false
		}

		if _, err := conn.Write(msg[0:length]); err != nil {
			return false
		}

		receive := make([]byte, EchoReplyHeadLen+length)
		if _, err := conn.Read(receive); err != nil {
			return false
		}
		return true
	} else {
		log2.Info("[IcmpCheck]:", host)
		size := 32
		var seq int16 = 1
		const EchoRequestHeadLen = 8
		const EchoReplyHeadLen = 20

		startTime := time.Now()
		conn, err := net.DialTimeout("ip4:icmp", host, 2*time.Second)
		if err != nil {
			log2.Warn("[IcmpCheck]", err)
			return false
		}
		defer conn.Close()
		id0, id1 := genIdentifier(host)

		msg := make([]byte, size+EchoRequestHeadLen)
		msg[0] = 8
		msg[1] = 0
		msg[2] = 0
		msg[3] = 0
		msg[4], msg[5] = id0, id1
		msg[6], msg[7] = genSequence(seq)

		length := size + EchoRequestHeadLen

		check := checkSum(msg[0:length])
		msg[2] = byte(check >> 8)
		msg[3] = byte(check & 255)

		if err := conn.SetDeadline(startTime.Add(5 * time.Second)); err != nil {
			return false
		}

		if _, err := conn.Write(msg[0:length]); err != nil {
			return false
		}

		receive := make([]byte, EchoReplyHeadLen+length)
		if _, err := conn.Read(receive); err != nil {
			return false
		}
		return true
	}
}

func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	answer := uint16(^sum)
	return answer
}

func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

func genIdentifier(host string) (byte, byte) {
	return host[0], host[1]
}
