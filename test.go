package main

import (
	"fmt"
	"strings"
)

/*
创建人员：云深不知处
创建时间：2022/1/4
程序功能：测试
*/

func main() {
	onetarget := "127.0.0.1:U:8080"
	target := strings.Split(onetarget, ":")
	fmt.Println(len(target))
	if strings.Contains(target[1], "U") {
		tmp := strings.Split(target[1], ":")
		port := tmp[1]
		fmt.Println(port)
	}
}
