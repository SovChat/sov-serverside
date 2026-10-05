// Package handlers 的账号与登录实现：注册、登录、登出、会话校验。
//
// 会话机制（无 Cookie、无中心认证服务）：
//   - /auth/register 与 /auth/login 成功后下发一个随机会话令牌（32 字节 crypto/rand，base64url）；
//   - 客户端在后续请求中携带 Authorization: Bearer <token>；
//   - 令牌与过期时间保存在服务器内存中，进程重启即全部失效（账号与密码哈希已落盘，不受影响）；
//   - 其余接口同时兼容旧的 X-User-Id + X-Password 方式，便于脚本调用与灰度迁移。
//
// 注册入群规则（「只有公开频道注册即入群」）：
//   - 公开频道（visibility.txt = public）：注册即写入 members.txt，注册完即可发言；
//   - 私有群组：注册仅创建账号，并自动登记待审批申请，管理员批准前不能发言。
package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"groupchat/storage"
)

// ---------- 常量 ----------

const (
	// sessionTTL 会话有效期（自签发起计）
	sessionTTL = 7 * 24 * time.Hour
	// maxSessions 会话表容量上限，防止恶意刷令牌导致内存无限增长
	maxSessions = 100000
	// authFailedMsg 登录失败统一文案：账号不存在与密码错误返回同一句话，避免用户名枚举
	authFailedMsg = "Auth failed: userId or psw wrong"
)

// ---------- 会话存储 ----------

// session 一条登录会话
type session struct {
	UserID    string
	ExpiresAt time.Time
}

// sessionStore 内存会话表（并发安全）
type sessionStore struct {
	mu   sync.Mutex
	data map[string]session
}

// newSessionStore 创建会话表
func newSessionStore() *sessionStore {
	return &sessionStore{data: make(map[string]session)}
}

// newSessionToken 生成随机会话令牌（32 字节 crypto/rand，base64url 无填充）
func newSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// create 为 userId 建立会话，返回令牌与过期时间
func (st *sessionStore) create(userId string) (string, time.Time, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().Add(sessionTTL)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.gcLocked()
	if len(st.data) >= maxSessions {
		return "", time.Time{}, errors.New("session table is full")
	}
	st.data[token] = session{UserID: userId, ExpiresAt: expiresAt}
	return token, expiresAt, nil
}

// lookup 校验令牌并返回其所属 userId
func (st *sessionStore) lookup(token string) (string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.data[token]
	if !ok {
		return "", false
	}
	if time.Now().After(s.ExpiresAt) {
		delete(st.data, token)
		return "", false
	}
	return s.UserID, true
}

// revoke 吊销单个令牌（登出）
func (st *sessionStore) revoke(token string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.data, token)
}

// revokeUser 吊销某用户的全部会话；keepToken 指定的令牌除外（传空表示全部吊销）
func (st *sessionStore) revokeUser(userId, keepToken string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for token, s := range st.data {
		if s.UserID == userId && token != keepToken {
			delete(st.data, token)
		}
	}
}

// gcLocked 清理过期会话（调用方需持有 st.mu）
func (st *sessionStore) gcLocked() {
	now := time.Now()
	for token, s := range st.data {
		if now.After(s.ExpiresAt) {
			delete(st.data, token)
		}
	}
}

// bearerToken 从 Authorization: Bearer <token> 请求头中提取令牌；格式不符时返回空串
func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// ---------- 响应组装 ----------

// authPayload 组装注册/登录/会话校验成功后返回的数据。
// token 为空表示不附带会话字段（GET /auth/me 复用）。
func (h *Handler) authPayload(userId, token string, expiresAt time.Time) (map[string]any, error) {
	acc, found, err := h.store.GetAccount(userId)
	if err != nil {
		return nil, err
	}
	if !found {
		// 兼容「-admin 启动」建立、尚未登记到账号表的账号
		acc = storage.AccountInfo{UserID: userId, DisplayName: userId}
	}
	role, err := h.store.GetRole(userId)
	if err != nil {
		return nil, err
	}
	isMember, err := h.store.IsMember(userId)
	if err != nil {
		return nil, err
	}
	health, err := h.store.Health()
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"success":  true,
		"user":     acc,
		"role":     role,
		"isAdmin":  role == storage.RoleAdmin,
		"isMod":    role == storage.RoleMod,
		"isMember": isMember,
		"group":    health,
	}
	if token != "" {
		payload["token"] = token
		payload["expiresAt"] = expiresAt.Unix()
	}
	return payload, nil
}

// ---------- 注册 ----------

// registerRequest POST /auth/register 请求体
type registerRequest struct {
	UserID      string `json:"userId"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName"`
}

// handleAuthRegister POST /auth/register（无需验证）：注册账号并立即下发登录会话。
//
// 入群规则见包注释：公开频道注册即入群（joined=true），
// 私有群组仅创建账号并自动提交审批申请（pending=true）。
func (h *Handler) handleAuthRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	// 已被封禁的来源 IP 直接拒绝（403）
	if !h.rejectBannedIP(w, r) {
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "userId cannot be blank")
		return
	}
	if !storage.ValidUserID(req.UserID) {
		writeError(w, http.StatusBadRequest, storage.ErrInvalidUserID.Error())
		return
	}
	if err := storage.ValidatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := storage.ValidateDisplayName(req.DisplayName); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	acc, joined, pending, err := h.store.CreateAccount(req.UserID, req.Password, req.DisplayName)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// 注册成功：记录最近来源 IP（供后续 banip 使用）
	h.noteLastIP(r, acc.UserID)
	// 注册成功即登录：直接建立会话，前端无需再发一次登录请求
	token, expiresAt, err := h.sessions.create(acc.UserID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	payload, err := h.authPayload(acc.UserID, token, expiresAt)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	payload["joined"] = joined
	payload["pending"] = pending
	if pending {
		payload["message"] = "Account created, waiting for admins to approve your joining request"
	} else {
		payload["message"] = "Account created, welcome"
	}
	writeJSON(w, http.StatusOK, payload)
}

// ---------- 登录 ----------

// loginRequest POST /auth/login 请求体
type loginRequest struct {
	UserID   string `json:"userId"`
	Password string `json:"password"`
}

// handleAuthLogin POST /auth/login（无需验证）：校验账号密码并下发会话令牌。
func (h *Handler) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	// 已被封禁的来源 IP 直接拒绝（403）
	if !h.rejectBannedIP(w, r) {
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "userId cannot be blank")
		return
	}
	if !storage.ValidUserID(req.UserID) {
		writeError(w, http.StatusBadRequest, storage.ErrInvalidUserID.Error())
		return
	}
	has, err := h.store.HasPassword(req.UserID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !has {
		// 账号不存在或从未设置密码：与密码错误同样处理（防枚举），并计入防暴力破解
		if h.limiter.recordFailure(req.UserID) {
			time.Sleep(bruteForceDelay)
		}
		writeError(w, http.StatusUnauthorized, authFailedMsg)
		return
	}
	if !h.verifyOperator(w, req.UserID, req.Password, authFailedMsg) {
		return
	}
	// 登录成功：记录最近来源 IP（供后续 banip 使用）
	h.noteLastIP(r, req.UserID)
	token, expiresAt, err := h.sessions.create(req.UserID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	payload, err := h.authPayload(req.UserID, token, expiresAt)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

// ---------- 会话校验 / 登出 ----------

// handleAuthMe GET /auth/me：返回当前身份（账号、管理员/成员身份、群组概况）。
func (h *Handler) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	userId, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	payload, err := h.authPayload(userId, "", time.Time{})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

// handleAuthLogout POST /auth/logout：吊销当前会话令牌。
// 幂等：令牌缺失或已失效都按成功处理，客户端可放心用于本地登出清理。
func (h *Handler) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if token := bearerToken(r); token != "" {
		h.sessions.revoke(token)
	}
	writeOK(w, nil)
}
