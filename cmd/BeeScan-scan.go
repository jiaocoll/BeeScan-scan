package main

import (
	"BeeScan-scan/internal/runner"
	"BeeScan-scan/pkg/banner"
	"BeeScan-scan/pkg/config"
	"BeeScan-scan/pkg/db"
	"BeeScan-scan/pkg/job"
	log2 "BeeScan-scan/pkg/log"
	"BeeScan-scan/pkg/node"
	"BeeScan-scan/pkg/result"
	"BeeScan-scan/pkg/scan/fringerprint"
	"BeeScan-scan/pkg/scan/gonmap"
	"BeeScan-scan/pkg/scan/gowapp"
	"BeeScan-scan/pkg/scan/ipinfo"
	"BeeScan-scan/pkg/util"
	"BeeScan-scan/pkg/worker"
	"context"
	"embed"
	"fmt"
	"github.com/fatih/color"
	redis2 "github.com/go-redis/redis"
	gowap "github.com/jiaocoll/GoWapp/pkg/core"
	"github.com/olivere/elastic/v7"
	"github.com/panjf2000/ants/v2"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/ratelimit"
	"time"
)

/*
创建人员：云深不知处
创建时间：2022/1/3
程序功能：主函数
*/

//go:embed nmap-probes wapp.json goby.json ip2region.db
var f embed.FS

var (
	queue      *job.Queue
	jobs       chan *runner.Runner
	results    chan *result.Output
	tmpresults chan *result.Output
	conn       *redis2.Client
	nodestate  *job.NodeState
	taskstate  *job.TaskState
	region     *ipinfo.Ip2Region
	wg         sizedwaitgroup.SizedWaitGroup
	wapp       *gowap.Wappalyzer
	esclient   *elastic.Client
	fofaPrints *fringerprint.FofaPrints
	GoNmap     *gonmap.VScan
	rl         ratelimit.Limiter
	p          *ants.PoolWithFunc
)

func init() {
	banner.Banner()
	_, _ = fmt.Fprintln(color.Output, color.HiMagentaString("Initializing......"))
	config.Setup()
	log2.Setup()
	jobs = make(chan *runner.Runner, 1000)
	tmpresults = make(chan *result.Output, 1000)
	results = make(chan *result.Output, 1000)
	GoNmap = gonmap.GoNmapInit(f)
	wapp, _ = gowapp.GowappInit(f)
	fofaPrints = fringerprint.FOFAInit(f)
	region = ipinfo.IpInfoInit(f)
	conn = db.InitRedis()
	esclient = db.ElasticSearchInit()                                //初始化redis连接
	node.NodeRegister(conn, config.GlobalConfig.NodeConfig.NodeName) //节点注册
	queue = job.NewQueue()
	nodestate = &job.NodeState{
		Tasks:     0,
		Running:   0,
		Finished:  0,
		State:     "Free",
		StartTime: time.Now().Format("2006-01-02 15:04:05"),
	}
	taskstate = &job.TaskState{
		Name:      "",
		TargetNum: 0,
		Tasks:     0,
		Running:   0,
		Finished:  0,
		LastTime:  time.Time{},
	}
	rl = ratelimit.New(config.GlobalConfig.WorkerConfig.Thread)
	wg = sizedwaitgroup.New(config.GlobalConfig.WorkerConfig.WorkerNumber)
	p = worker.WorkerInit(nodestate, taskstate, &wg, rl, conn, GoNmap, region, tmpresults)
	_, _ = fmt.Fprintln(color.Output, color.HiMagentaString("Initialized!"))
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 扫描节点状态更新
	go func() {
		for true {
			if nodestate.State == "Running" {
				log2.InfoOutput("[Tasks]:", nodestate.Tasks, "[Running]:", nodestate.Running, "[Finished]:", nodestate.Finished)
			}
			node.NodeUpdate(conn, config.GlobalConfig.NodeConfig.NodeName, nodestate)
			node.TaskUpdate(conn, taskstate)
			time.Sleep(5 * time.Second)
		}
	}()

	// 处理消息队列任务
	go func() {
		for true {
			runner.Handlejob(conn, queue, taskstate)
			var runners []*runner.Runner
			if queue.Length > 0 { //判断队列长度
				// 任务实例集合
				runners = runner.HandleTargets(queue, fofaPrints)
			}

			if len(runners) > 0 {
				// 添加任务到任务队列
				for _, v := range runners {
					jobs <- v
					nodestate.Tasks++
				}
				runners = nil
			}
			time.Sleep(5 * time.Second)
		}
	}()

	go func() {
		for true {
			if len(jobs) > 0 {
				nodestate.State = "Running"
				for i := 0; i < len(jobs); i++ {
					j := <-jobs
					wg.Add()
					_ = p.Invoke(j)
				}
				wg.Wait()
			}
			time.Sleep(5 * time.Second)
		}
	}()

	// Gowapp扫描模块，单独进行扫描，防止rod模块多线程出现panic
	go func() {
		for true {
			if len(tmpresults) > 0 {
				for i := 0; i < len(tmpresults); i++ {
					tmpres := <-tmpresults
					if tmpres != nil {
						if tmpres.Banner != "" || tmpres.Servername == "http" {
							tmpres.Wappalyzer = gowapp.GoWapp(tmpres, wapp)
							time.Sleep(500 * time.Millisecond)
							results <- tmpres
						}
					}
				}
			}
			time.Sleep(5 * time.Second)
		}
	}()

	go func() {
		for true {
			if len(results) > 0 {
				// 遍历结果，写入数据库
				for i := 0; i < len(results); i++ {
					res := <-results
					if res != nil {
						if res.Target != "" {
							db.EsAdd(esclient, res)
						}
					}
				}
			}
		}
	}()

	// 写入日志到es数据库
	go func() {
		for true {
			if util.MinSub(db.QueryLogByID(esclient, config.GlobalConfig.NodeConfig.NodeName))%30 == 0 && util.MinSub(db.QueryLogByID(esclient, config.GlobalConfig.NodeConfig.NodeName)) > 0 {
				db.ESLogAdd(esclient, "BeeScanLogs.log")
			}
			time.Sleep(30 * time.Second)
		}
	}()

	// 扫描节点状态更新
	//node.NodeUpdate(conn, config.GlobalConfig.NodeConfig.NodeName, nodestate)
	go func() {
		for true {
			if len(jobs) == 0 {
				log2.InfoOutput("[ConnectCheck]")
				nodestate.State = "Free"
				taskstate.Name = ""
				taskstate.Running = 0
				taskstate.Finished = 0
				// 节点每运行15天会定时重新扫描es数据库中一定时长的目标
				if util.DaySub(nodestate.StartTime) > 15 && util.DaySub(nodestate.StartTime)%15 == 0 {
					RegularTargets := db.EsScanRegular(esclient)
					RegularTargets = util.Removesamesip(RegularTargets)
					if RegularTargets != nil {
						log2.Info("[targets]:", RegularTargets)
						for _, v := range RegularTargets {
							job.Push(queue, v)
						}
					}
				}
				time.Sleep(10 * time.Second)
			}
		}
	}()
	<-ctx.Done()
}
