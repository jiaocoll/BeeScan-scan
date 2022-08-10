package getipbydomain

import (
	log2 "BeeScan-scan/pkg/log"
	"net"
	"net/http"
	"strings"
)

/*
创建人员：云深不知处
创建时间：2022/1/6
程序功能：获取真实ip
*/

var localNetworks = []string{"10.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"172.17.0.0/12",
	"172.18.0.0/12",
	"172.19.0.0/12",
	"172.20.0.0/12",
	"172.21.0.0/12",
	"172.22.0.0/12",
	"172.23.0.0/12",
	"172.24.0.0/12",
	"172.25.0.0/12",
	"172.26.0.0/12",
	"172.27.0.0/12",
	"172.28.0.0/12",
	"172.29.0.0/12",
	"172.30.0.0/12",
	"172.31.0.0/12",
	"192.168.0.0/16"}

// ClientIP 尽最大努力实现获取客户端 IP 的算法。
// 解析 X-Real-IP 和 X-Forwarded-For 以便于反向代理（nginx 或 haproxy）可以正常工作。
func ClientIP(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	ip := strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
	if ip != "" {
		return ip
	}

	ip = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	if ip != "" {
		return ip
	}

	if ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return ip
	}

	return ""
}

// ClientPublicIP 尽最大努力实现获取客户端公网 IP 的算法。
// 解析 X-Real-IP 和 X-Forwarded-For 以便于反向代理（nginx 或 haproxy）可以正常工作。
func ClientPublicIP(r *http.Request) string {
	var ip string
	for _, ip = range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		ip = strings.TrimSpace(ip)
		IP := net.ParseIP(ip)
		if ip != "" && !IP.IsPrivate() {
			return ip
		}
	}

	ip = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	IP := net.ParseIP(ip)
	if ip != "" && !IP.IsPrivate() {
		return ip
	}

	if ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		IP := net.ParseIP(ip)
		if !IP.IsPrivate() {
			return ip
		}
	}
	return ""
}

// GetIPbyDomain 通过域名获取IP地址
func GetIPbyDomain(domain string) (string, error) {
	addr, err := net.ResolveIPAddr("ip", domain)
	if err != nil {
		log2.Warn("[GetIPbyDomain]:", err)
	}
	if addr != nil {
		if addr.IP.IsPrivate() != true {
			return addr.IP.String(), nil
		}
	}
	return "", err
}
