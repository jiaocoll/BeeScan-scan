package config

import (
	"BeeScan-scan/pkg/util"
	"bytes"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/viper"
	"go.uber.org/zap/zapcore"
	"os"
	"path"
	"path/filepath"
	"time"
)

/*
创建人员：云深不知处
创建时间：2022/1/13
程序功能：配置模块
*/
var GlobalConfig *Config

type Redis struct {
	Host     string
	Password string
	Port     string
	User     string
	Database int
}

type Elasticsearch struct {
	Host     string
	Password string
	Port     string
	Username string
	Index    string
}

type LogConfig struct {
	MaxSize    int
	MaxBackups int
	MaxAge     int
	Compress   bool
}

type DBConfig struct {
	Redis         Redis
	Elasticsearch Elasticsearch
}

type NodeConfig struct {
	NodeName  string
	NodeQueue string
}

type DicConfig struct {
	Dic_user string
	Dic_pwd  string
}

type WorkerConfig struct {
	WorkerNumber int
	Thread       int
}

type Config struct {
	NodeConfig   NodeConfig
	DicConfig    DicConfig
	WorkerConfig WorkerConfig
	LogConfig    LogConfig
	DBConfig     DBConfig
}

func (config *Config) LogMaxSize() int {
	return config.LogConfig.MaxSize
}

// 加载配置
func Setup() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		_, _ = fmt.Fprintln(color.Output, color.HiRedString("[ERRO]"), "["+time.Now().Format("2006-01-02 15:04:05")+"]", "[Config_Setup]:fail to get current path", err)
		os.Exit(1)
	}
	// 配置文件
	configFile := path.Join(dir, "config.yaml")

	if !util.FileExist(configFile) {
		WriteYamlConfig()
	}
	ReadYamlConfig(configFile)
}

func (cfg *Config) Level() zapcore.Level {
	return zapcore.DebugLevel
}

func (cfg *Config) MaxLogSize() int {
	return cfg.LogConfig.MaxSize
}

func (cfg *Config) LogPath() string {
	return ""
}

func (cfg *Config) InfoOutput() string {
	return ""
}

func (cfg *Config) ErrorOutput() string {
	return ""
}

func (cfg *Config) DebugOutput() string {
	return ""
}

func ReadYamlConfig(configFile string) {
	// 加载config
	viper.SetConfigType("yaml")
	viper.SetConfigFile(configFile)

	err := viper.ReadInConfig()
	if err != nil {
		_, _ = fmt.Fprintln(color.Output, color.HiRedString("[ERRO]"), "["+time.Now().Format("2006-01-02 15:04:05")+"]", "[Config_Setup]:", "fail to read 'config.yaml", err)
		os.Exit(1)
	}
	err = viper.Unmarshal(&GlobalConfig)
	if err != nil {
		_, _ = fmt.Fprintln(color.Output, color.HiRedString("[ERRO]"), "["+time.Now().Format("2006-01-02 15:04:05")+"]", "[Config_Setup]:", "fail to parse 'config.yaml', check format", err)
		os.Exit(1)
	}
	GlobalConfig.NodeConfig.NodeQueue = GlobalConfig.NodeConfig.NodeName + "_queue"
}

func WriteYamlConfig() {
	// 生成默认config
	viper.SetConfigType("yaml")
	err := viper.ReadConfig(bytes.NewBuffer(defaultYamlByte))
	if err != nil {
		_, _ = fmt.Fprintln(color.Output, color.HiRedString("[ERRO]"), "["+time.Now().Format("2006-01-02 15:04:05")+"]", "[Config_Setup]:", "fail to read default config bytes:", err)
	}

	f, err := os.Create("config.yaml")
	if err != nil {
		_, _ = fmt.Fprintln(color.Output, color.HiRedString("[ERRO]"), "["+time.Now().Format("2006-01-02 15:04:05")+"]", "[Config_Setup]:", "fail to write config yaml", err)
		os.Exit(1)
	}
	_, err = f.Write(defaultYamlByte)
	if err != nil {
		_, _ = fmt.Fprintln(color.Output, color.HiRedString("[ERRO]"), "["+time.Now().Format("2006-01-02 15:04:05")+"]", "[Config_Setup]:", err)
	}
}
