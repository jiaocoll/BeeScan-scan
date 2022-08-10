package runner

import (
	"BeeScan-scan/pkg/config"
	"BeeScan-scan/pkg/db"
	"BeeScan-scan/pkg/httpx"
	"BeeScan-scan/pkg/job"
	log2 "BeeScan-scan/pkg/log"
	"BeeScan-scan/pkg/result"
	"BeeScan-scan/pkg/scan/cdncheck"
	"BeeScan-scan/pkg/scan/fringerprint"
	"BeeScan-scan/pkg/scan/getipbydomain"
	"BeeScan-scan/pkg/scan/gonmap"
	"BeeScan-scan/pkg/scan/httpcheck"
	"BeeScan-scan/pkg/scan/icmp"
	"BeeScan-scan/pkg/scan/ipinfo"
	"BeeScan-scan/pkg/scan/tcp"
	"BeeScan-scan/pkg/util"
	"fmt"
	redis2 "github.com/go-redis/redis"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"net"
	"net/url"
	"strings"
	"time"
)

/*
创建人员：云深不知处
创建时间：2022/1/30
程序功能：运行实例
*/

type Runner struct {
	Ip       string
	Port     string
	Domain   string
	Protocol string
	Ht       *httpx.HTTPX
	Hm       *hybrid.HybridMap
	Fofa     *fringerprint.FofaPrints
	Output   *result.Output
}

// NewRunner 创建runner实例
func NewRunner(ip string, port string, domain string, protocol string, FofaPrints *fringerprint.FofaPrints) (*Runner, error) {
	runner := &Runner{
		Ip:       ip,
		Port:     port,
		Domain:   domain,
		Protocol: protocol,
		Output:   &result.Output{},
	}
	if hm, err := hybrid.New(hybrid.DefaultDiskOptions); err != nil {
		runner.Hm = nil
	} else {
		runner.Hm = hm
	}

	// http
	HttpOptions := &httpx.HTTPOptions{
		Timeout:          3 * time.Second,
		RetryMax:         3,
		FollowRedirects:  true,
		Unsafe:           false,
		DefaultUserAgent: httpx.GetRadnomUserAgent(),
	}
	ht, err := httpx.NewHttpx(HttpOptions)
	if err != nil {
		return nil, err
	}
	runner.Ht = ht
	runner.Fofa = FofaPrints
	return runner, nil

}

// http请求
func (r *Runner) do(fullUrl string) (*httpx.Response, error) {
	req, err := r.Ht.NewRequest("GET", fullUrl)

	if err != nil {
		return &httpx.Response{}, err
	}
	resp, err2 := r.Ht.Do(req)
	return resp, err2
}

// Request 指纹识别
func (r *Runner) Request() result.FingerResult {
	var resp *httpx.Response
	var fullUrl string
	if r.Ht != nil && r.Hm != nil {
		if r.Ht.Dialer != nil {
			r.Close()
		}
	}
	log2.Info("[HttpRequest]:", r.Ip)

	retried := false
	protocol := httpx.HTTPS
retry:
	if r.Domain != "" && r.Port != "80" {
		fullUrl = fmt.Sprintf("%s://%s:%s", protocol, r.Domain, r.Port)
	} else if r.Ip != "" && r.Port != "80" {
		fullUrl = fmt.Sprintf("%s://%s:%s", protocol, r.Ip, r.Port)
	} else if r.Domain != "" && r.Port == "80" {
		fullUrl = fmt.Sprintf("%s://%s", protocol, r.Domain)
	} else if r.Ip != "" && r.Port == "80" {
		fullUrl = fmt.Sprintf("%s://%s", protocol, r.Ip)
	}
	timeStart := time.Now()

	resp = &httpx.Response{}
	var err error
	resp, err = r.do(fullUrl)
	if err != nil {
		if !retried {
			if protocol == httpx.HTTPS {
				protocol = httpx.HTTP
			} else {
				protocol = httpx.HTTPS
			}
			retried = true
			goto retry
		}
	}

	builder := &strings.Builder{}
	builder.WriteString(fullUrl)

	var title string
	if resp != nil {
		title = resp.Title
	}

	p, err := url.Parse(fullUrl)
	var ip string
	var ipArray []string
	if err != nil {
		ip = ""
	} else {
		hostname := p.Hostname()
		ip = r.Ht.Dialer.GetDialedIP(hostname)
		// ip为空，看看p.host是不是ip
		if ip == "" {
			address := net.ParseIP(hostname)
			if address != nil {
				ip = address.String()
			}
		}
	}
	dnsData, err := r.Ht.Dialer.GetDNSData(p.Host)
	if dnsData != nil && err == nil {
		ipArray = append(ipArray, dnsData.CNAME...)
		ipArray = append(ipArray, dnsData.A...)
		ipArray = append(ipArray, dnsData.AAAA...)
	}
	cname := strings.Join(ipArray, ",")

	// CDN检测
	cdn, err := r.Ht.CDNCheck(resp, r.Ip, cname)
	if err != nil {
		log2.Warn("[CDNCheck]:", err)
	}

	// 指纹处理
	fofaResults, err := r.Fofa.Matcher(resp, r.Output.Servers, r.Port)
	if err != nil {
		log2.Warn("[FOFAFinger]:", err)
	}
	var webbanner result.FingerResult
	if resp != nil {
		if resp.TLSData != nil {
			webbanner = result.FingerResult{
				Title:         title,
				TLSData:       resp.TLSData,
				ContentLength: resp.ContentLength,
				StatusCode:    resp.StatusCode,
				ResponseTime:  time.Since(timeStart).String(),
				Str:           builder.String(),
				Header:        resp.HeaderStr,
				FirstLine:     resp.FirstLine,
				Headers:       resp.Headers,
				DataStr:       resp.DataStr,
				Fingers:       fofaResults,
				CDN:           cdn,
			}
		} else {
			tlsdata := &httpx.TLSData{
				DNSNames:           nil,
				EmailAddresses:     nil,
				CommonName:         nil,
				Organization:       nil,
				IssuerCommonName:   nil,
				IssuerOrg:          nil,
				OrganizationalUnit: nil,
				Issuer:             nil,
				Subject:            nil,
			}
			webbanner = result.FingerResult{
				Title:         title,
				TLSData:       tlsdata,
				ContentLength: resp.ContentLength,
				StatusCode:    resp.StatusCode,
				ResponseTime:  time.Since(timeStart).String(),
				Str:           builder.String(),
				Header:        resp.HeaderStr,
				FirstLine:     resp.FirstLine,
				Headers:       resp.Headers,
				DataStr:       resp.DataStr,
				Fingers:       fofaResults,
				CDN:           cdn,
			}
		}
	} else {
		webbanner = result.FingerResult{}
	}
	return webbanner
}

func (r *Runner) Close() {
	r.Ht.Dialer.Close()
	_ = r.Hm.Close()
}

// Handlejob 任务处理
func Handlejob(c *redis2.Client, queue *job.Queue, taskstate *job.TaskState) {
	var targets []string
	// 查看消息队列，取出任务
	lenval := c.LLen(config.GlobalConfig.NodeConfig.NodeQueue)
	qlen := lenval.Val()
	if qlen > 0 { // 若队列不空
		for i := 1; i <= int(qlen); i++ {
			tmpjob := db.RecvJob(c)
			st := strings.Replace(tmpjob[1], "\"", "", -1)
			tmptargets := strings.Split(st, ",")
			taskstate.Tasks = len(tmptargets) - 1
			for k, v := range tmptargets {
				if k == 0 {
					taskstate.Name = v
				}
				if k != 0 && v != "" {
					targets = append(targets, v)
				}
			}
			log2.Info("[targets]:", targets)
		}
		for _, t := range targets {
			job.Push(queue, t) //将任务目标加入到任务队列中
		}
	}
}

// HandleTargets 生成扫描实例
func HandleTargets(queue *job.Queue, fofaPrints *fringerprint.FofaPrints) []*Runner {
	var targets []string
	var runners []*Runner
	for i := 0; i <= queue.Length; i++ {
		targets = append(targets, job.Pop(queue))
	}
	if len(targets) > 0 {
		for _, v := range targets {
			if !strings.Contains(v, "http") {
				target := strings.Split(v, ":")
				if len(target) > 0 {
					tmptarget := util.TargetsHandle(target[0]) //目标处理，若是c段地址，则返回一个ip段，若是单个ip，则直接返回单个ip切片，若是域名或url地址，则返回域名
					if len(target) == 3 && target[1] == "U" {
						for _, t := range tmptarget {
							var runner2 *Runner
							var err1 error
							if strings.Contains(t, "com") || strings.Contains(t, "cn") {
								ip, err := getipbydomain.GetIPbyDomain(t)
								if err == nil {
									runner2, err1 = NewRunner(ip, target[2], t, "udp", fofaPrints)
								}
							} else {
								runner2, err1 = NewRunner(t, target[2], "", "udp", fofaPrints)
							}
							if err1 != nil {
								log2.Error("[HandleTargets]:", err1)
							}
							if runner2 != nil {
								runners = append(runners, runner2)
							}
						}
					} else {
						for _, t := range tmptarget {
							var runner2 *Runner
							var err1 error
							if strings.Contains(t, "com") || strings.Contains(t, "cn") {
								ip, err := getipbydomain.GetIPbyDomain(t)
								if err == nil {
									runner2, err1 = NewRunner(ip, target[1], t, "tcp", fofaPrints)
								}
							} else {
								runner2, err1 = NewRunner(t, target[1], "", "tcp", fofaPrints)
							}
							if err1 != nil {
								log2.Error("[HandleTargets]:", err1)
							}
							if runner2 != nil {
								runners = append(runners, runner2)
							}
						}
					}

				}
			} else if strings.Contains(v, "https") {
				vtarget := v[8:]
				target := strings.Split(vtarget, ":")
				if len(v) > 0 {
					tmptarget := util.TargetsHandle(v) //目标处理，若是c段地址，则返回一个ip段，若是单个ip，则直接返回单个ip切片，若是域名或url地址，则返回域名
					if len(target) == 3 && target[1] == "U" {
						for _, t := range tmptarget {
							var runner2 *Runner
							var err1 error
							if strings.Contains(t, "com") || strings.Contains(t, "cn") {
								ip, err := getipbydomain.GetIPbyDomain(t)
								if err == nil {
									runner2, err1 = NewRunner(ip, target[1], t, "udp", fofaPrints)
								}
							} else {
								runner2, err1 = NewRunner(t, target[1], "", "udp", fofaPrints)
							}
							if err1 != nil {
								log2.Error("[HandleTargets]:", err1)
							}
							if runner2 != nil {
								runners = append(runners, runner2)
							}
						}
					} else {
						for _, t := range tmptarget {
							var runner2 *Runner
							var err1 error
							if strings.Contains(t, "com") || strings.Contains(t, "cn") {
								ip, err := getipbydomain.GetIPbyDomain(t)
								if err == nil {
									runner2, err1 = NewRunner(ip, target[1], t, "tcp", fofaPrints)
								}
							} else {
								runner2, err1 = NewRunner(t, target[1], "", "tcp", fofaPrints)
							}
							if err1 != nil {
								log2.Error("[HandleTargets]:", err1)
							}
							if runner2 != nil {
								runners = append(runners, runner2)
							}
						}
					}

				}
			} else if strings.Contains(v, "http") {
				vtarget := v[7:]
				target := strings.Split(vtarget, ":")
				if len(v) > 0 {
					tmptarget := util.TargetsHandle(v) //目标处理，若是c段地址，则返回一个ip段，若是单个ip，则直接返回单个ip切片，若是域名或url地址，则返回域名
					if len(target) == 3 && target[1] == "U" {
						for _, t := range tmptarget {
							var runner2 *Runner
							var err1 error
							if strings.Contains(t, "com") || strings.Contains(t, "cn") {
								ip, err := getipbydomain.GetIPbyDomain(t)
								if err == nil {
									runner2, err1 = NewRunner(ip, target[1], t, "udp", fofaPrints)
								}
							} else {
								runner2, err1 = NewRunner(t, target[1], "", "udp", fofaPrints)
							}
							if err1 != nil {
								log2.Error("[HandleTargets]:", err1)
							}
							if runner2 != nil {
								runners = append(runners, runner2)
							}
						}
					} else {
						for _, t := range tmptarget {
							var runner2 *Runner
							var err1 error
							if strings.Contains(t, "com") || strings.Contains(t, "cn") {
								ip, err := getipbydomain.GetIPbyDomain(t)
								if err == nil {
									runner2, err1 = NewRunner(ip, target[1], t, "tcp", fofaPrints)
								}

							} else {
								runner2, err1 = NewRunner(t, target[1], "", "tcp", fofaPrints)
							}
							if err1 != nil {
								log2.Error("[HandleTargets]:", err1)
							}
							if runner2 != nil {
								runners = append(runners, runner2)
							}
						}
					}
				}
			}

		}
	}
	if len(runners) > 0 {
		return runners
	}
	return nil
}

// Scan 扫描函数
func Scan(target *Runner, GoNmap *gonmap.VScan, region *ipinfo.Ip2Region) *result.Output {
	// 域名存在与否
	if target.Domain != "" {
		// 主机存活探测
		if icmp.IcmpCheckAlive(target.Domain, target.Ip) || httpcheck.HttpCheck(target.Domain, target.Port, target.Ip) || tcp.TcpCheckAlive(target.Ip, target.Port) {

			// 普通端口探测
			nmapbanner, err := gonmap.GoNmapScan(GoNmap, target.Ip, target.Port, target.Protocol)
			if nmapbanner != nil {
				target.Output.Servers = nmapbanner
			}
			if strings.Contains(target.Output.Servers.Banner, "HTTP") {
				target.Output.Servers.Name = "http"
				target.Output.Servername = "http"
			} else {
				target.Output.Servername = nmapbanner.Name

			}
			// web端口探测
			webresult := result.FingerResult{}
			if target.Output.Servername == "http" {
				webresult = target.Request()
			}
			target.Output.Webbanner = webresult
			target.Output.Ip = target.Ip
			target.Output.Port = target.Port
			target.Output.Protocol = strings.ToUpper(target.Protocol)
			target.Output.Domain = target.Domain

			if webresult.Header != "" {
				target.Output.Banner = target.Output.Webbanner.Header
			} else {
				target.Output.Banner = nmapbanner.Banner
			}
			// ip信息查询
			info, err := ipinfo.GetIpinfo(region, target.Ip)
			if err != nil {
				log2.Warn("[GetIPInfo]:", err)
			}
			target.Output.City = info.City
			target.Output.Region = info.Region
			target.Output.ISP = info.ISP
			target.Output.CityId = info.CityId
			target.Output.Province = info.Province
			target.Output.Country = info.Country
			target.Output.TargetId = target.Ip + "-" + target.Port + "-" + target.Domain
			if target.Output.Port == "80" {
				target.Output.Target = "http://" + target.Domain
			} else {
				target.Output.Target = "http://" + target.Domain + ":" + target.Output.Port
			}
			target.Output.LastTime = time.Now().Format("2006-01-02 15:04:05")
			return target.Output
		} else {
			return nil
		}
	} else {
		if cdncheck.IPCDNCheck(target.Ip) != true { //判断IP是否存在CDN

			// 主机存活探测
			if icmp.IcmpCheckAlive("", target.Ip) || httpcheck.HttpCheck(target.Domain, target.Port, target.Ip) || tcp.TcpCheckAlive(target.Ip, target.Port) {

				// 普通端口探测
				nmapbanner, err := gonmap.GoNmapScan(GoNmap, target.Ip, target.Port, target.Protocol)
				if nmapbanner != nil {
					target.Output.Servers = nmapbanner
				}
				if strings.Contains(target.Output.Servers.Banner, "HTTP") {
					target.Output.Servers.Name = "http"
					target.Output.Servername = "http"
				} else {
					target.Output.Servername = nmapbanner.Name
				}
				// web端口探测
				webresult := result.FingerResult{}
				if target.Output.Servername == "http" {
					webresult = target.Request()
				}
				target.Output.Webbanner = webresult
				target.Output.Ip = target.Ip
				target.Output.Port = target.Port
				target.Output.Protocol = strings.ToUpper(target.Protocol)
				target.Output.Domain = ""

				if webresult.Header != "" {
					target.Output.Banner = target.Output.Webbanner.Header
				} else {
					target.Output.Banner = nmapbanner.Banner
				}
				// ip信息查询
				info, err := ipinfo.GetIpinfo(region, target.Ip)
				if err != nil {
					log2.Warn("[GetIPInfo]:", err)
				}
				target.Output.City = info.City
				target.Output.Region = info.Region
				target.Output.ISP = info.ISP
				target.Output.CityId = info.CityId
				target.Output.Province = info.Province
				target.Output.Country = info.Country
				target.Output.TargetId = target.Ip + "-" + target.Port + "-" + target.Domain
				if target.Output.Port == "80" {
					target.Output.Target = "http://www." + target.Ip
				} else {
					target.Output.Target = "http://www." + target.Ip + ":" + target.Port
				}
				target.Output.LastTime = time.Now().Format("2006-01-02 15:04:05")
				return target.Output
			} else {
				return nil
			}
		}
	}
	return nil
}
