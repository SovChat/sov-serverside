// Package handlers 实现群组聊天服务器的全部 HTTP 接口。
//
// 身份验证方式（无 Cookie、无 Session、无中心认证服务）：
//   - 请求头 X-User-Id：操作者 userId
//   - 请求头 X-Password：操作者密码（明文比对 bcrypt 哈希，生产环境应置于 HTTPS 反代之后）
//
// 防暴力破解：同一 userId 连续验证失败 5 次后，服务器延迟 5 秒再响应。
package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"groupchat/storage"
)

// ---------- 常量 ----------

const (
	// maxJSONBodyBytes JSON 请求体大小上限（超大加密内容应改走 /files/upload 接口）
	maxJSONBodyBytes = 4 << 20 // 4MB
	// maxUploadBodyBytes 文件上传请求体大小上限
	maxUploadBodyBytes = 1 << 30 // 1GB
	// maxConsecutiveFailures 同一 userId 允许的连续验证失败次数阈值
	maxConsecutiveFailures = 5
	// bruteForceDelay 达到失败阈值后的响应延迟
	bruteForceDelay = 5 * time.Second
)

// Handler 封装全部 HTTP 接口处理逻辑
type Handler struct {
	store   *storage.Store // 文件存储层
	limiter *loginLimiter  // 登录防暴力破解器
}

// New 创建 Handler
func New(store *storage.Store) *Handler {
	return &Handler{store: store, limiter: newLoginLimiter()}
}

// Register 将全部路由注册到 mux。
// 使用 Go 1.22+ 的 "METHOD /path" 路由模式：路径匹配但方法不符时自动返回 405。
func (h *Handler) Register(mux *http.ServeMux) {
	// 服务器信息（无需验证）
	mux.HandleFunc("GET /health", h.handleHealth)

	// 成员管理
	mux.HandleFunc("POST /members/apply", h.handleMemberApply)        // 无需验证
	mux.HandleFunc("POST /members/approve", h.handleMemberApprove)    // 需验证 + 管理员
	mux.HandleFunc("POST /members/reject", h.handleMemberReject)      // 需验证 + 管理员
	mux.HandleFunc("GET /members/list", h.handleMemberList)           // 无需验证
	mux.HandleFunc("GET /members/pending", h.handleMemberPending)     // 需验证 + 管理员
	mux.HandleFunc("POST /members/leave", h.handleMemberLeave)        // 需验证
	mux.HandleFunc("POST /members/set-password", h.handleSetPassword) // 需验证

	// 聊天消息（全部需验证）
	mux.HandleFunc("POST /chat/send", h.handleChatSend)
	mux.HandleFunc("GET /chat/messages", h.handleChatMessages)

	// 文件管理（全部需验证）
	mux.HandleFunc("POST /files/upload", h.handleFileUpload)
	mux.HandleFunc("POST /files/upload-key", h.handleFileUploadKey)
	mux.HandleFunc("GET /files/download", h.handleFileDownload)
}

// ---------- 通用响应工具 ----------

// writeJSON 输出 JSON 响应
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError 输出统一错误格式：{"success":false,"error":"..."}
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"success": false, "error": msg})
}

// writeOK 输出 {"success":true}，可通过 extra 携带额外字段
func writeOK(w http.ResponseWriter, extra map[string]any) {
	if extra == nil {
		extra = map[string]any{}
	}
	extra["success"] = true
	writeJSON(w, http.StatusOK, extra)
}

// writeStoreError 将 storage 层错误映射为对应的 HTTP 状态码响应
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrForbidden):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, storage.ErrPathTraversal):
		// 路径遍历攻击：按铁律返回 400 Bad Request
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, storage.ErrNotPending), errors.Is(err, storage.ErrNotMember):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, storage.ErrUserExists), errors.Is(err, storage.ErrAlreadyApplied),
		errors.Is(err, storage.ErrInvalidUserID), errors.Is(err, storage.ErrInvalidDate),
		errors.Is(err, storage.ErrInvalidFileID), errors.Is(err, storage.ErrEmptyPassword):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		log.Printf("Server interior error: %v", err)
		writeError(w, http.StatusInternalServerError, "Server interior error")
	}
}

// ---------- 登录防暴力破解 ----------

// loginLimiter 记录每个 userId 的连续验证失败次数：
// 连续失败达到 5 次后，需要延迟 5 秒再响应；验证成功后计数清零。
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string]int
}

// newLoginLimiter 创建防暴力破解器
func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: make(map[string]int)}
}

// recordFailure 记录一次验证失败，返回是否达到“需要延迟响应”的阈值
func (l *loginLimiter) recordFailure(userId string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	// 防御恶意伪造大量 userId 导致 map 无限增长：超过上限时重置计数表
	if len(l.failures) > 100000 {
		l.failures = make(map[string]int)
	}
	l.failures[userId]++
	return l.failures[userId] >= maxConsecutiveFailures
}

// reset 验证成功后清除该用户的失败计数
func (l *loginLimiter) reset(userId string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, userId)
}

// ---------- 身份验证 ----------

// verifyOperator 校验 userId+password（与 bcrypt 哈希比对），内置防暴力破解延迟。
// 验证成功返回 true；失败时已写出 401/500 响应并返回 false。
func (h *Handler) verifyOperator(w http.ResponseWriter, userId, password, failMsg string) bool {
	ok, err := h.store.VerifyPassword(userId, password)
	if err != nil {
		log.Printf("Interior error occured while verifying psw: userId=%s err=%v", userId, err)
		writeError(w, http.StatusInternalServerError, "Server interior error")
		return false
	}
	if !ok {
		// 防暴力破解铁律：同一 userId 连续失败 5 次后，延迟 5 秒再响应
		if h.limiter.recordFailure(userId) {
			log.Printf("userId=%s Continuous verifying failed %d times, delay %v to react", userId, maxConsecutiveFailures, bruteForceDelay)
			time.Sleep(bruteForceDelay)
		}
		writeError(w, http.StatusUnauthorized, failMsg)
		return false
	}
	h.limiter.reset(userId) // 验证成功，清零失败计数
	return true
}

// authenticate 从请求头提取并验证 X-User-Id / X-Password。
// 成功返回操作者 userId；失败时已写出错误响应并返回 ("", false)。
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	userId := r.Header.Get("X-User-Id")
	if userId == "" {
		writeError(w, http.StatusUnauthorized, "Lack X-User-Id header")
		return "", false
	}
	if !storage.ValidUserID(userId) {
		writeError(w, http.StatusBadRequest, "X-User-Id format illegal")
		return "", false
	}
	if !h.verifyOperator(w, userId, r.Header.Get("X-Password"), "Auth failed: userId or psw wrong") {
		return "", false
	}
	return userId, true
}

// requireMember 校验操作者是本群正式成员，否则写出 403 并返回 false
func (h *Handler) requireMember(w http.ResponseWriter, userId string) bool {
	isMember, err := h.store.IsMember(userId)
	if err != nil {
		writeStoreError(w, err)
		return false
	}
	if !isMember {
		writeError(w, http.StatusForbidden, "Only members can process this")
		return false
	}
	return true
}

// decodeJSONBody 解析 JSON 请求体（限制大小，防止恶意超大请求体）
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "Not legal JSON: "+err.Error())
		return false
	}
	return true
}

// ---------- 服务器信息 ----------

// handleHealth GET /health（无需验证）：返回服务器状态
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	info, err := h.store.Health()
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// ---------- 成员管理 ----------

// applyRequest POST /members/apply 请求体
type applyRequest struct {
	UserID    string `json:"userId"`
	PublicKey string `json:"publicKey"`
}

// handleMemberApply POST /members/apply（无需验证）：提交入群申请
func (h *Handler) handleMemberApply(w http.ResponseWriter, r *http.Request) {
	var req applyRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "userId cannot be blank")
		return
	}
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "publicKey cannot be blank")
		return
	}
	if len(req.PublicKey) > 8192 {
		writeError(w, http.StatusBadRequest, "publicKey too long (≤8192 characters)")
		return
	}
	// 公钥按 Opaque 字符串原样存储，服务器不做任何解码或解析
	if err := h.store.Apply(req.UserID, req.PublicKey); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Request submitted, waiting for admin to approve"})
}

// userIDRequest 仅含 userId 的通用请求体（approve/reject/leave）
type userIDRequest struct {
	UserID string `json:"userId"`
}

// handleMemberApprove POST /members/approve（需验证 + 管理员）：批准入群申请
func (h *Handler) handleMemberApprove(w http.ResponseWriter, r *http.Request) {
	operator, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req userIDRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "userId cannot be blank")
		return
	}
	// 管理员权限校验与文件操作在 storage 层同一把锁内原子完成
	if err := h.store.Approve(operator, req.UserID); err != nil {
		writeStoreError(w, err)
		return
	}
	writeOK(w, nil)
}

// handleMemberReject POST /members/reject（需验证 + 管理员）：拒绝入群申请
func (h *Handler) handleMemberReject(w http.ResponseWriter, r *http.Request) {
	operator, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req userIDRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "userId cannot be blank")
		return
	}
	if err := h.store.Reject(operator, req.UserID); err != nil {
		writeStoreError(w, err)
		return
	}
	writeOK(w, nil)
}

// handleMemberList GET /members/list（无需验证，公钥是公开信息）：返回成员列表
func (h *Handler) handleMemberList(w http.ResponseWriter, r *http.Request) {
	members, err := h.store.ListMembers()
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

// handleMemberPending GET /members/pending（需验证 + 管理员）：返回待审批列表
func (h *Handler) handleMemberPending(w http.ResponseWriter, r *http.Request) {
	operator, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	pending, err := h.store.PendingList(operator)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": pending})
}

// handleMemberLeave POST /members/leave（需验证）：退出群组
func (h *Handler) handleMemberLeave(w http.ResponseWriter, r *http.Request) {
	operator, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req userIDRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	// 铁律：只能退出自己的账号（防止借用 leave 接口移除他人）
	if req.UserID == "" || req.UserID != operator {
		writeError(w, http.StatusForbidden, "You can only quit your own account: userId must be the same with X-User-Id")
		return
	}
	// 从 members.txt 移除；若在 admins.txt 中则一并移除（storage 层原子完成）
	if err := h.store.Leave(req.UserID); err != nil {
		writeStoreError(w, err)
		return
	}
	writeOK(w, nil)
}

// setPasswordRequest POST /members/set-password 请求体
type setPasswordRequest struct {
	UserID      string `json:"userId"`
	NewPassword string `json:"newPassword"`
}

// handleSetPassword POST /members/set-password（需验证）。
// 歧义消除规则（严格按需求实现）：
//   - X-User-Id == body.userId：视为“本人修改密码”，必须验证 X-Password 为该用户的旧密码；
//     （特例：该用户从未设置过密码时视为首次引导设置，无需旧密码。为覆盖
//     “-admin 启动但未提供 -admin-pass”的引导流程，首次设置仅对管理员账号开放，
//     防止任意账号被抢先注册密码。）
//   - X-User-Id != body.userId：视为“管理员代设密码”，必须验证操作者是管理员，
//     直接更新目标 userId 的密码，无需提供旧密码。
//
// 成功写入 bcrypt 哈希（cost=12）后返回 {"success":true}。
func (h *Handler) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	// 注意：此接口不能直接复用 authenticate——两种情形的验证规则不同，
	// 且首次引导设置时目标用户尚无密码可验证，因此手动处理请求头。
	userId := r.Header.Get("X-User-Id")
	if userId == "" {
		writeError(w, http.StatusUnauthorized, "Lack X-User-Id header")
		return
	}
	if !storage.ValidUserID(userId) {
		writeError(w, http.StatusBadRequest, "X-User-Id format illegal")
		return
	}
	var req setPasswordRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "userId cannot be blank")
		return
	}
	if !storage.ValidUserID(req.UserID) {
		writeError(w, http.StatusBadRequest, storage.ErrInvalidUserID.Error())
		return
	}

	if userId == req.UserID {
		// ── 情形一：本人修改密码 ──
		has, err := h.store.HasPassword(req.UserID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if has {
			// 已有旧密码：必须验证 X-Password 是旧密码（含防暴力破解延迟）
			if !h.verifyOperator(w, userId, r.Header.Get("X-Password"), "Auth failed: old psw wrong") {
				return
			}
		} else {
			// 首次引导设置（如 -admin 未带 -admin-pass 的初始管理员）：
			// 无旧密码可验证，但仅允许管理员账号自行引导，防止任意账号被抢注密码
			isAdmin, err := h.store.IsAdmin(req.UserID)
			if err != nil {
				writeStoreError(w, err)
				return
			}
			if !isAdmin {
				writeError(w, http.StatusForbidden, "Psw for this account not set yet, ask admins.")
				return
			}
		}
	} else {
		// ── 情形二：管理员代设密码 ──
		// 先验证操作者本人的密码，再确认其管理员身份；目标用户无需提供旧密码
		if !h.verifyOperator(w, userId, r.Header.Get("X-Password"), "Auth failed: userId or psw wrong") {
			return
		}
		isAdmin, err := h.store.IsAdmin(userId)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if !isAdmin {
			writeError(w, http.StatusForbidden, "Only admins can set psws for others.")
			return
		}
	}

	// 密码规则铁律：不能为空，长度至少 6 位
	if err := storage.ValidatePassword(req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// bcrypt 哈希（cost=12）并写入 passwords/{userId}.hash
	if err := h.store.SetPassword(req.UserID, req.NewPassword); err != nil {
		writeStoreError(w, err)
		return
	}
	writeOK(w, nil)
}

// ---------- 聊天消息 ----------

// chatSendRequest POST /chat/send 请求体。
// ciphertext 与 encryptedKeys 均为客户端加密产物，服务器按 Opaque 字符串处理。
type chatSendRequest struct {
	SenderID      string            `json:"senderId"`
	Ciphertext    string            `json:"ciphertext"`
	EncryptedKeys map[string]string `json:"encryptedKeys"`
}

// handleChatSend POST /chat/send（需验证 + 成员）：追加一条加密聊天消息到当天日志
func (h *Handler) handleChatSend(w http.ResponseWriter, r *http.Request) {
	operator, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req chatSendRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	// 铁律：senderId 必须与请求头 X-User-Id 一致
	if req.SenderID == "" || req.SenderID != operator {
		writeError(w, http.StatusForbidden, "senderId must be the same with header X-User-Id")
		return
	}
	// 发送者必须是正式成员
	if !h.requireMember(w, req.SenderID) {
		return
	}
	if req.Ciphertext == "" {
		writeError(w, http.StatusBadRequest, "ciphertext cannot be blank")
		return
	}
	// ciphertext 与 encryptedKeys 均按 Opaque 字符串处理：只序列化并落盘，绝不解码
	if err := h.store.AppendChatMessage(req.SenderID, req.Ciphertext, req.EncryptedKeys); err != nil {
		writeStoreError(w, err)
		return
	}
	writeOK(w, nil)
}

// handleChatMessages GET /chat/messages（需验证 + 成员）：按行返回聊天记录。
// 查询参数：date（可选，默认当天，格式 YYYY-MM-DD）、
// since（可选，Unix 秒；只返回时间戳 >= since 的消息行，避免同秒消息丢失，客户端可按行去重）。
func (h *Handler) handleChatMessages(w http.ResponseWriter, r *http.Request) {
	operator, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !h.requireMember(w, operator) {
		return
	}
	// date 参数（可选，默认当天）
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	if date == "" {
		date = time.Now().Format("2006-01-02")
	}
	// since 参数（可选）
	var since int64
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		var err error
		since, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be int Unix time (sec)")
			return
		}
	}
	messages, err := h.store.ReadChatMessages(date, since)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": messages})
}

// ---------- 文件管理 ----------

// handleFileUpload POST /files/upload（需验证 + 成员）：multipart 表单上传加密文件主体。
// 表单字段：file（二进制文件）、fileId（客户端生成的文件标识，缺省时服务器生成 UUID 兜底）、
// date（可选，默认当天）。
func (h *Handler) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	h.handleFileUploadCommon(w, r, ".enc")
}

// handleFileUploadKey POST /files/upload-key（需验证 + 成员）：multipart 表单上传加密文件密钥副本。
// 表单字段：keysFile（二进制）、fileId（必填，应与文件主体上传时一致）、date（可选）。
func (h *Handler) handleFileUploadKey(w http.ResponseWriter, r *http.Request) {
	h.handleFileUploadCommon(w, r, ".keys")
}

// handleFileUploadCommon /files/upload 与 /files/upload-key 的公共实现。
// ext=".enc" 对应文件主体接口（返回 path 字段），ext=".keys" 对应密钥副本接口。
func (h *Handler) handleFileUploadCommon(w http.ResponseWriter, r *http.Request, ext string) {
	operator, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	// 只有正式成员才能上传
	if !h.requireMember(w, operator) {
		return
	}

	// 限制上传体积，防止恶意超大请求
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBodyBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "Parse multipart table failed: "+err.Error())
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll() // 及时清理落盘的表单临时文件
		}
	}()

	// 文件字段：文件主体为 file，密钥副本为 keysFile
	field := "file"
	if ext == ".keys" {
		field = "keysFile"
	}
	file, _, err := r.FormFile(field)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Lack chart file field"+field)
		return
	}
	defer file.Close()

	// date 参数（可选，默认当天）
	date := strings.TrimSpace(r.FormValue("date"))
	if date == "" {
		date = time.Now().Format("2006-01-02")
	}
	// fileId 由客户端生成；仅文件主体接口允许缺省并由服务器生成 UUID 兜底
	fileId := strings.TrimSpace(r.FormValue("fileId"))
	if fileId == "" {
		if ext == ".keys" {
			writeError(w, http.StatusBadRequest, "fileId cannot be blank")
			return
		}
		fileId = uuid.NewString()
	}

	// 密钥副本内容为逐行 “userId:encryptedKey” 的密钥副本，按 Opaque 字节流原样存储
	var relPath string
	if ext == ".enc" {
		relPath, err = h.store.SaveEncryptedFile(date, fileId, file)
	} else {
		relPath, err = h.store.SaveFileKeys(date, fileId, file)
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if ext == ".enc" {
		writeOK(w, map[string]any{"path": relPath})
		return
	}
	writeOK(w, nil)
}

// handleFileDownload GET /files/download（需验证 + 成员）：下载加密文件。
// 查询参数 path 形如 files/2026-08-28/abc123.enc，必须通过严格的路径遍历校验
// （不以 files/ 开头、或 Clean+Abs 后不在 {data}/files/ 之下的一律返回 400）。
func (h *Handler) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	operator, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	// 只有正式成员才能下载
	if !h.requireMember(w, operator) {
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		writeError(w, http.StatusBadRequest, "Lack path arguments")
		return
	}

	absPath, f, info, err := h.store.OpenDownloadFile(path)
	if err != nil {
		if errors.Is(err, storage.ErrPathTraversal) {
			// 路径遍历攻击：铁律要求返回 400 Bad Request
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "File doesn't exist")
			return
		}
		writeStoreError(w, err)
		return
	}
	defer f.Close()

	// 以附件（attachment）形式返回二进制内容
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(absPath)))
	http.ServeContent(w, r, "", info.ModTime(), f)
}

