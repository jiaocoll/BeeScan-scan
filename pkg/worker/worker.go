package worker

import (
	"BeeScan-scan/internal/runner"
	"BeeScan-scan/pkg/config"
	"BeeScan-scan/pkg/job"
	log2 "BeeScan-scan/pkg/log"
	"BeeScan-scan/pkg/result"
	"BeeScan-scan/pkg/scan/gonmap"
	"BeeScan-scan/pkg/scan/ipinfo"
	redis2 "github.com/go-redis/redis"
	"github.com/panjf2000/ants/v2"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/ratelimit"
)

/*
创建人员：云深不知处
创建时间：2022/1/4
程序功能：任务池
*/

func WorkerInit(nodestate *job.NodeState, taskstate *job.TaskState, wg *sizedwaitgroup.SizedWaitGroup, rl ratelimit.Limiter, conn *redis2.Client, GoNmap *gonmap.VScan, region *ipinfo.Ip2Region, tmpresults chan *result.Output) *ants.PoolWithFunc {
	p, _ := ants.NewPoolWithFunc(config.GlobalConfig.WorkerConfig.WorkerNumber, func(j interface{}) {
		if j != nil {
			if j.(*runner.Runner) != nil {
				if j.(*runner.Runner).Ip != "" || j.(*runner.Runner).Domain != "" {
					nodestate.Running++
					taskstate.Running++
					rl.Take()
					if j.(*runner.Runner).Ip != "" {
						log2.Info("[Scanning]:", j.(*runner.Runner).Ip)
					} else if j.(*runner.Runner).Domain != "" {
						log2.Info("[Scanning]:", j.(*runner.Runner).Domain)
					}

					tmpresult := runner.Scan(j.(*runner.Runner), GoNmap, region) // 执行扫描
					if tmpresult != nil {
						tmpresults <- tmpresult
					} else {
						nodestate.Running--
						nodestate.Finished++
						taskstate.Running--
						taskstate.Finished++
					}

					defer wg.Done()
				}
			}
		}
	})
	return p
}
