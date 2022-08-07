package config

/*
创建人员：云深不知处
创建时间：2022/1/13
程序功能：默认配置
*/

var defaultYamlByte = []byte(`
# 节点配置
NodeConfig:
  # 节点名称配置
  NodeName: BeeScan_node_1

# 任务池配置
WorkerConfig:
  #任务池数量
  WorkerNumber: 10
  # 速率配置(每秒最多运行任务数)
  Thread: 6

# Log配置
LogConfig:
  # 每个日志文件保存的最大尺寸 单位：M
  max_size: 50
  # 日志文件最多保存多少个备份
  max_backups: 1
  # 文件最多保存多少天
  max_age: 7
  # 是否压缩
  compress: false

# 数据库配置
DBConfig:
  # Redis配置
  redis:
    host: "127.0.0.1"
    password: ""
    port: "6379"
    database: ""
  # Elasticsearch配置
  Elasticsearch:
    host: "127.0.0.1"
    port: "9200"
    username: ""
    password: ""
    index: "beescan"
`)
