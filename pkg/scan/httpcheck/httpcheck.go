package httpcheck

import (
	log2 "BeeScan-scan/pkg/log"
	"github.com/valyala/fasthttp"
	"time"
)

/*
创建人员：云深不知处
创建时间：2022/1/7
程序功能：http检测主机是否存在
*/

// HttpCheck HTTP检测主机存活
func HttpCheck(domain string, port string, ip string) bool {
	var url string
	log2.Info("[HttpCheck]:", ip)
	if domain != "" {
		if port == "80" {
			url = "http://" + domain
		} else {
			url = "http://" + domain + ":" + port
		}
	} else {
		if port == "80" {
			url = "http://" + ip
		} else {
			url = "http://" + ip + ":" + port
		}
	}
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.Header.SetMethod("GET")
	req.SetRequestURI(url)
	err := fasthttp.DoTimeout(req, nil, 2*time.Second)
	if err != nil {
		log2.Warn("[HttpCheck]:", err)
		return false
	} else {
		return true
	}

}
