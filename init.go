package main

import (
	"log"
	"os"
	"path/filepath"
)

func init() {
	// 设置日志格式
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// 确保环境变量存在
	ensureEnvVars()

	// 初始化存储目录
	initStorageDir()
}

func ensureEnvVars() {
	// 检查必要的环境变量
	vars := map[string]string{
		"SERVER_PORT":        "2888",
		"PUBLIC_IP":          "", // 不设置默认值，必须在 docker-compose.yml 中指定
		"IMAGE_STORAGE_PATH": "/data/images",
	}

	for key, defaultValue := range vars {
		if os.Getenv(key) == "" {
			if key == "PUBLIC_IP" {
				log.Fatalf("[FATAL] 必须设置 PUBLIC_IP 环境变量")
			}
			log.Printf("[WARN] 环境变量 %s 未设置，使用默认值: %s", key, defaultValue)
			os.Setenv(key, defaultValue)
		}
	}
}

func initStorageDir() {
	imagePath := os.Getenv("IMAGE_STORAGE_PATH")
	if imagePath == "" {
		imagePath = filepath.Join("/data", "images")
	}

	// 创建目录
	if err := os.MkdirAll(imagePath, 0777); err != nil {
		log.Fatalf("[FATAL] 创建图片存储目录失败: %v", err)
	}

	// 设置目录权限
	if err := os.Chmod(imagePath, 0777); err != nil {
		log.Printf("[WARN] 修改目录权限失败: %v", err)
	}

	// 创建 .keep 文件确保目录存在
	keepFile := filepath.Join(imagePath, ".keep")
	if _, err := os.Stat(keepFile); os.IsNotExist(err) {
		if file, err := os.Create(keepFile); err == nil {
			file.Close()
		}
	}

	log.Printf("[INFO] 图片存储目录初始化完成: %s", imagePath)
}
