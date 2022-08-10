package gowapp

import (
	"BeeScan-scan/pkg/job"
	log2 "BeeScan-scan/pkg/log"
	"BeeScan-scan/pkg/result"
	"embed"
	"fmt"
	gowap "github.com/jiaocoll/GoWapp/pkg/core"
	"os"
)

/*
创建人员：云深不知处
创建时间：2022/1/14
程序功能：Wappalyzer模块
*/

type TargetInfo struct {
	Urls         []Urls         `json:"urls"`
	Technologies []Technologies `json:"technologies"`
}
type Urls struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}
type Categories struct {
	ID   int    `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}
type Technologies struct {
	Slug       string       `json:"slug"`
	Name       string       `json:"name"`
	Confidence int          `json:"confidence"`
	Version    string       `json:"version"`
	Icon       string       `json:"icon"`
	Website    string       `json:"website"`
	Cpe        string       `json:"cpe"`
	Categories []Categories `json:"categories"`
}

func GowappConfig() *gowap.Config {
	//Create a Config object and customize it
	wapconfig := gowap.NewConfig()
	//Timeout in seconds for fetching the url
	wapconfig.TimeoutSeconds = 5
	//Timeout in seconds for loading the page
	wapconfig.LoadingTimeoutSeconds = 6
	//Don't analyze page when depth superior to this number. Default (0) means no recursivity (only first page will be analyzed)
	wapconfig.MaxDepth = 1
	//Max number of pages to visit. Exit when reached
	wapconfig.MaxVisitedLinks = 5
	//Delay in ms between requests
	wapconfig.MsDelayBetweenRequests = 200
	//Choose scraper between rod (default) and colly
	wapconfig.Scraper = "rod"
	//Override the user-agent string
	wapconfig.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"
	//Output as a JSON string
	wapconfig.JSON = false
	return wapconfig
}

func GowappInit(f embed.FS) (*gowap.Wappalyzer, error) {
	wapconfig := GowappConfig()
	wapp, err := gowap.Init(wapconfig, f)
	if err != nil {
		log2.Error("[GoWappInit]:", err)
		os.Exit(1)
	}
	return wapp, nil
}

// GoWapp Wappalyzer识别模块
func GoWapp(r *result.Output, wapp *gowap.Wappalyzer, nodestate *job.NodeState, taskstate *job.TaskState) *gowap.Output {
	if r.Webbanner.Header != "" {
		if r != nil {
			if r.Ip != "" {
				log2.Info("[GoWapp]:", r.Ip)
			} else if r.Ip == "" && r.Domain != "" {
				log2.Info("[GoWapp]:", r.Domain)
			}
		}
		var fullUrl string
		targetinfo := &gowap.Output{}
		protocol := "http"
		if r.Domain != "" && r.Port != "80" {
			fullUrl = fmt.Sprintf("%s://%s:%s", protocol, r.Domain, r.Port)
		} else if r.Ip != "" && r.Port != "80" {
			fullUrl = fmt.Sprintf("%s://%s:%s", protocol, r.Ip, r.Port)
		} else if r.Domain != "" && r.Port == "80" {
			fullUrl = fmt.Sprintf("%s://%s", protocol, r.Domain)
		} else if r.Ip != "" && r.Port == "80" {
			fullUrl = fmt.Sprintf("%s://%s", protocol, r.Ip)
		}
		res, _ := wapp.Analyze(fullUrl)
		if res != nil {
			targetinfo = res.(*gowap.Output)
		}
		nodestate.Running--
		taskstate.Running--
		nodestate.Finished++
		taskstate.Finished++
		if r.Ip != "" {
			log2.Info("[Scanned]:", r.Ip)
		} else if r.Domain != "" {
			log2.Info("[Scanned]:", r.Domain)
		}
		return targetinfo
	}
	return nil
}
