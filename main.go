// 群组聊天服务器（纯去中心化，单进程单群组）。
//
// 核心原则：
//   - 每个群组服务器独立管理自己的成员密码（bcrypt 哈希，cost=12），不依赖任何中心服务器；
//   - 密码仅用于验证“操作者是否是该 userId 的持有者”；
//   - 服务器只负责存储和转发加密数据，不解密任何内容；
//   - 全部数据基于文件系统存储（不使用数据库），根目录由 -dir 指定（默认 ./data）；
//   - 成员加入需要管理员手动批准。
//
// 启动命令示例：
//
//	go run main.go -port=8443 -dir=./data -admin=alice -admin-pass=your_password
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"groupchat/handlers"
	"groupchat/storage"
)

// loggingMiddleware 简单的访问日志中间件（记录方法、路径、来源与耗时）
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s <- %s（耗时 %v）", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

// printSetPasswordHint 在终端打印管理员自行设置密码的操作指引。
// 对应初始化流程：提供了 -admin 但未提供 -admin-pass 的场景，
// 管理员需通过 /members/set-password 自行设置密码（首次设置无需旧密码）。
func printSetPasswordHint(port int, admin string) {
	fmt.Println("==============================================================")
	fmt.Printf("  Alarm: Admin %s haven't set a password yet.\n", admin)
	fmt.Println("  Admins, set your passwords immediately through /members/set-password.")
	fmt.Println("  Old psw not required for first modification, cannot be blank & ≥6 digits, e.g.:")
	fmt.Println()
	fmt.Printf("  curl -X POST http://(domain):%d/members/set-password \\\n", port)
	fmt.Println("       -H \"Content-Type: application/json\" \\")
	fmt.Printf("       -H \"X-User-Id: %s\" -H \"X-Password: \" \\\n", admin)
	fmt.Printf("       -d '{\"userId\":\"%s\",\"newPassword\":\"Your psw (≥6 digits)\"}'\n", admin)
	fmt.Println("==============================================================")
}

func main() {
	// ── 启动参数解析 ──
	port := flag.Int("port", 8443, "port")
	dir := flag.String("dir", "./data", "data path")
	admin := flag.String("admin", "", "admin userId")
	adminPass := flag.String("admin-pass", "", "admin psw")
	name := flag.String("name", "Untitled Group", "group name(optional, stoarged in serverinfo/name.txt)")
	flag.Parse()

	// -admin-pass 必须与 -admin 一起使用
	if *adminPass != "" && *admin == "" {
		fmt.Fprintln(os.Stderr, "Error: -admin-pass should be used with -admin")
		os.Exit(1)
	}

	// ── 初始化存储：自动创建完整目录结构（目录权限 0700）──
	store, err := storage.NewStore(*dir)
	if err != nil {
		log.Fatalf("Data path init failed: %v", err)
	}
	defer store.Close() // 程序退出前关闭聊天日志文件句柄

	// ── 首次启动初始化：群组信息 + 初始管理员 + 管理员密码哈希 ──
	if err := store.Init(*admin, *adminPass, *name); err != nil {
		log.Fatalf("Server data init failed: %v", err)
	}

	// 提供了 -admin 但未提供 -admin-pass：在终端打印密码设置指引
	if *admin != "" && *adminPass == "" {
		if has, err := store.HasPassword(*admin); err == nil && !has {
			printSetPasswordHint(*port, *admin)
		}
	}

	// ── 注册全部路由并启动 HTTP 服务 ──
	mux := http.NewServeMux()
	handlers.New(store).Register(mux)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 15 * time.Second, // 防止慢速连接长期占用
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("Group chat server started: port %d, data path %s", *port, store.Dir())
	log.Printf("Start command example: go run main.go -port=%d -dir=%s -admin=alice -admin-pass=your_password", *port, *dir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP service exception quit: %v", err)
	}
}
