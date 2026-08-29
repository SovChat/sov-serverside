// Package storage 实现群组聊天服务器的文件存储层。
//
// 设计原则：
//   - 全部数据基于文件系统存储，不使用任何数据库；
//   - 一个 Store 实例对应一个群组（一个服务器进程只服务一个群组）；
//   - 服务器只存储和转发加密数据：公钥/密文/加密密钥均按 Opaque 字符串处理，绝不解码；
//   - 所有文件读写均通过全局互斥锁保护，防止并发写入导致文件损坏；
//   - 目录权限 0700、文件权限 0600，仅所有者可读写。
package storage

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// ---------- 常量 ----------

const (
	// BcryptCost bcrypt 哈希计算成本（安全铁律：cost=12）
	BcryptCost = 12
	// dateLayout 日期格式（YYYY-MM-DD），用于目录名与记录中的日期字段
	dateLayout = "2006-01-02"
	// maxChatLineBytes 读取聊天日志时单行允许的最大字节数（密文可能很长）
	maxChatLineBytes = 16 << 20 // 16MB
)

// ---------- 错误定义 ----------

// 预定义错误：handlers 层据此映射对应的 HTTP 状态码
var (
	ErrInvalidUserID  = errors.New("userId illegal: only letters, numbers, underlines and hyphens allowed, length 1-64.")
	ErrInvalidDate    = errors.New("date illegal: should be in YYYY-MM-DD format.")
	ErrInvalidFileID  = errors.New("fileId illegal: only letters, numbers, sentence marks, underlines and hyphens allowed, length 1-128.")
	ErrEmptyPassword  = errors.New("psw cannot be blank and must be ≥6 digits.")
	ErrUserExists     = errors.New("The userId is already a member.")
	ErrAlreadyApplied = errors.New("The userId have requested yet, please wait for admins to approve.")
	ErrNotPending     = errors.New("The userId is not in the pending list.")
	ErrNotMember      = errors.New("The userId is not a member.")
	ErrForbidden      = errors.New("No access processing: admin required.")
	ErrPathTraversal  = errors.New("Path illegal: path traversal attack detected.")
)

// ---------- 格式校验 ----------

// userIDPattern userId 合法格式。
// 严格限制字符集可保证 userId 能安全地用作文件名（如 passwords/{userId}.hash），防止路径注入。
var userIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// fileIDPattern fileId 合法格式（客户端生成的文件标识，用作存储文件名的一部分）
var fileIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// datePattern 日期合法格式（YYYY-MM-DD）
var datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// ValidUserID 判断 userId 是否符合格式要求（供 handlers 层做前置校验）
func ValidUserID(userId string) bool {
	return userIDPattern.MatchString(userId)
}

// ValidatePassword 校验密码规则（安全铁律）：密码不能为空，长度至少 6 位
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < 6 {
		return ErrEmptyPassword
	}
	return nil
}

// ValidateDate 校验日期字符串（同时校验格式与真实有效性，如 2026-13-99 会被拒绝）
func ValidateDate(date string) error {
	if !datePattern.MatchString(date) {
		return ErrInvalidDate
	}
	if _, err := time.ParseInLocation(dateLayout, date, time.Local); err != nil {
		return ErrInvalidDate
	}
	return nil
}

// ValidateFileID 校验 fileId（fileId 会拼入存储路径，必须杜绝路径遍历）
func ValidateFileID(fileId string) error {
	if !fileIDPattern.MatchString(fileId) || fileId == "." || fileId == ".." {
		return ErrInvalidFileID
	}
	return nil
}

// ---------- 数据结构 ----------

// MemberInfo 正式成员信息（members.txt 一行：userId|加入日期|公钥）
type MemberInfo struct {
	UserID     string `json:"userId"`
	PublicKey  string `json:"publicKey"`
	JoinedDate string `json:"joinedDate"`
}

// PendingInfo 待审批成员信息（unverified_members.txt 一行：userId|申请日期|公钥）
type PendingInfo struct {
	UserID      string `json:"userId"`
	RequestDate string `json:"requestDate"`
}

// HealthStatus GET /health 返回的服务器状态信息
type HealthStatus struct {
	Status      string `json:"status"`
	Name        string `json:"name"`
	MemberCount int    `json:"memberCount"`
}

// ---------- 存储主体 ----------

// Store 群组服务器的文件存储管理器（一个实例对应一个群组的数据目录）
type Store struct {
	mu sync.Mutex // 全局互斥锁：所有文件读写操作必须持锁进行，防止并发损坏

	dir      string // 数据根目录（绝对路径）
	filesDir string // {dir}/files 的绝对路径（下载路径校验基准）

	chatFile *os.File // 当前正在写入的聊天日志句柄（按天缓存，避免每次请求都 OpenFile）
	chatDate string   // chatFile 对应的日期（YYYY-MM-DD）
}

// NewStore 创建 Store 并自动创建完整目录结构（目录权限 0700）
func NewStore(dir string) (*Store, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("Data path parsing failed: %w", err)
	}
	// 启动时自动创建的目录结构（与需求中的目录树一致）
	subDirs := []string{
		"serverinfo/passwords", // bcrypt 密码哈希（cost=12）
		"serverpersons",        // admins.txt / members.txt / unverified_members.txt
		"memberprofiles",       // 用户头像 {userId}.png（预留，可后续实现）
		"chat",                 // 聊天记录 {YYYY-MM-DD}.log（按天分割）
		"files",                // 加密文件 {YYYY-MM-DD}/{fileId}.enc|.keys
	}
	for _, sub := range subDirs {
		if err := os.MkdirAll(filepath.Join(absDir, sub), 0700); err != nil {
			return nil, fmt.Errorf("Path creation %s failed: %w", sub, err)
		}
	}
	return &Store{
		dir:      absDir,
		filesDir: filepath.Join(absDir, "files"),
	}, nil
}

// Dir 返回数据根目录的绝对路径
func (s *Store) Dir() string { return s.dir }

// Close 释放存储层持有的资源（当前聊天日志句柄），程序退出前调用
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.chatFile != nil {
		err := s.chatFile.Close()
		s.chatFile = nil
		return err
	}
	return nil
}

// ---------- 内部路径方法（假定调用方已持有 s.mu）----------

func (s *Store) nameFilePath() string {
	return filepath.Join(s.dir, "serverinfo", "name.txt")
}

func (s *Store) createdDatePath() string {
	return filepath.Join(s.dir, "serverinfo", "created_date.txt")
}

func (s *Store) founderPath() string {
	return filepath.Join(s.dir, "serverinfo", "founder.txt")
}

// passwordPath 返回某用户的密码哈希文件路径：serverinfo/passwords/{userId}.hash。
// userId 已通过 ValidUserID 校验（不含路径分隔符），可安全拼接。
func (s *Store) passwordPath(userId string) string {
	return filepath.Join(s.dir, "serverinfo", "passwords", userId+".hash")
}

func (s *Store) adminsPath() string {
	return filepath.Join(s.dir, "serverpersons", "admins.txt")
}

func (s *Store) membersPath() string {
	return filepath.Join(s.dir, "serverpersons", "members.txt")
}

func (s *Store) unverifiedPath() string {
	return filepath.Join(s.dir, "serverpersons", "unverified_members.txt")
}

// ---------- 通用文件工具 ----------

// readLines 读取文本文件全部非空行；文件不存在时返回 (nil, nil)
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	// 聊天日志单行可能包含很长的密文，放宽 Scanner 的单行长度上限
	sc.Buffer(make([]byte, 0, 64*1024), maxChatLineBytes)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

// appendLine 以追加模式写入一行（文件权限 0600，不存在则自动创建）
func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

// rewriteLines 用给定的全部行覆盖写文件。
// 采用“临时文件 + rename”的原子写法，进程中途崩溃也不会损坏原文件。
func rewriteLines(path string, lines []string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	w := bufio.NewWriter(tmp)
	for _, l := range lines {
		if _, err := w.WriteString(l + "\n"); err != nil {
			return fail(err)
		}
	}
	if err := w.Flush(); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(0600); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// writeFileIfMissing 文件不存在时写入内容；已存在则跳过（避免重启覆盖已有数据）
func writeFileIfMissing(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

// parseMemberLine 解析成员行：userId|日期|公钥（公钥允许为空）。
// members.txt 与 unverified_members.txt 行结构相同，日期字段含义由调用方解释。
func parseMemberLine(line string) (MemberInfo, bool) {
	parts := strings.SplitN(line, "|", 3)
	if len(parts) != 3 || parts[0] == "" {
		return MemberInfo{}, false
	}
	return MemberInfo{UserID: parts[0], JoinedDate: parts[1], PublicKey: parts[2]}, true
}

// ---------- 初始化 ----------

// Init 首次启动初始化：
//  1. 写入群组名称与创建日期（已存在则跳过，避免重启覆盖）；
//  2. 若指定初始管理员：写入 founder.txt、admins.txt（第一行，即群主）与 members.txt；
//  3. 若提供管理员密码：立即生成 bcrypt 哈希（cost=12）写入 passwords/{admin}.hash；
//     若未提供密码：由 main 在终端打印提示，引导管理员通过 /members/set-password 自行设置。
func (s *Store) Init(admin, adminPass, groupName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	today := time.Now().Format(dateLayout)

	// 1. 群组基本信息
	if err := writeFileIfMissing(s.nameFilePath(), groupName+"\n"); err != nil {
		return fmt.Errorf("Write name.txt failed: %w", err)
	}
	if err := writeFileIfMissing(s.createdDatePath(), today+"\n"); err != nil {
		return fmt.Errorf("Write created_date.txt failed: %w", err)
	}

	// 未指定初始管理员：仅完成基础初始化
	if admin == "" {
		return nil
	}
	if !ValidUserID(admin) {
		return ErrInvalidUserID
	}

	// 2. 创建者与初始管理员
	if err := writeFileIfMissing(s.founderPath(), admin+"\n"); err != nil {
		return fmt.Errorf("Write founder.txt failed: %w", err)
	}
	// admins.txt：首次创建时管理员为第一行（群主）；已存在则不改动
	if _, err := os.Stat(s.adminsPath()); os.IsNotExist(err) {
		if err := os.WriteFile(s.adminsPath(), []byte(admin+"\n"), 0600); err != nil {
			return fmt.Errorf("Write admins.txt failed: %w", err)
		}
	}
	// members.txt：创建者本人即为成员（公钥暂为空）
	lines, err := readLines(s.membersPath())
	if err != nil {
		return err
	}
	isMember := false
	for _, l := range lines {
		if m, ok := parseMemberLine(l); ok && m.UserID == admin {
			isMember = true
			break
		}
	}
	if !isMember {
		if err := appendLine(s.membersPath(), admin+"|"+today+"|"); err != nil {
			return fmt.Errorf("Write members.txt failed: %w", err)
		}
	}

	// 3. 管理员密码（提供 -admin-pass 时立即生成 bcrypt 哈希；否则由 main 打印指引）
	if adminPass == "" {
		return nil
	}
	if err := ValidatePassword(adminPass); err != nil {
		return err
	}
	if _, err := os.Stat(s.passwordPath(admin)); os.IsNotExist(err) {
		// 哈希已存在时不覆盖，避免重启时用启动参数意外重置密码
		if err := s.savePasswordHashLocked(admin, adminPass); err != nil {
			return err
		}
	}
	return nil
}

// savePasswordHashLocked 对密码做 bcrypt 哈希（cost=12）并写入
// serverinfo/passwords/{userId}.hash（文件权限 0600）。调用方需持有 s.mu。
func (s *Store) savePasswordHashLocked(userId, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return fmt.Errorf("Generate bcrypt hash failed: %w", err)
	}
	return os.WriteFile(s.passwordPath(userId), hash, 0600)
}

// ---------- 身份验证 ----------

// VerifyPassword 验证某用户的密码是否正确。
// 返回 (true, nil) 表示验证通过；(false, nil) 表示密码错误或该用户尚未设置密码。
func (s *Store) VerifyPassword(userId, password string) (bool, error) {
	if !ValidUserID(userId) {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyPasswordLocked(userId, password)
}

// verifyPasswordLocked 读取 bcrypt 哈希并比对（调用方需持有 s.mu）
func (s *Store) verifyPasswordLocked(userId, password string) (bool, error) {
	hash, err := os.ReadFile(s.passwordPath(userId))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // 该用户尚未设置密码
		}
		return false, err
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil // 密码不匹配
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// HasPassword 判断某用户是否已设置过密码（用于 /members/set-password 的首次引导设置场景）
func (s *Store) HasPassword(userId string) (bool, error) {
	if !ValidUserID(userId) {
		return false, ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := os.Stat(s.passwordPath(userId))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// SetPassword 设置/更新指定用户的密码（身份与权限校验由 handlers 层完成后调用）：
// 对新密码做 bcrypt 哈希（cost=12）并写入 passwords/{userId}.hash。
func (s *Store) SetPassword(userId, newPassword string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.savePasswordHashLocked(userId, newPassword)
}

// IsAdmin 判断某用户是否为管理员（admins.txt 中的任意一行，第一行为群主）
func (s *Store) IsAdmin(userId string) (bool, error) {
	if !ValidUserID(userId) {
		return false, ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isAdminLocked(userId)
}

// isAdminLocked（调用方需持有 s.mu）
func (s *Store) isAdminLocked(userId string) (bool, error) {
	lines, err := readLines(s.adminsPath())
	if err != nil {
		return false, err
	}
	for _, l := range lines {
		if l == userId {
			return true, nil
		}
	}
	return false, nil
}

// IsMember 判断某用户是否为正式成员
func (s *Store) IsMember(userId string) (bool, error) {
	if !ValidUserID(userId) {
		return false, ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isMemberLocked(userId)
}

// isMemberLocked（调用方需持有 s.mu）。
// userId 字符集不含 '|'，用 "userId|" 前缀匹配即可准确定位成员行。
func (s *Store) isMemberLocked(userId string) (bool, error) {
	lines, err := readLines(s.membersPath())
	if err != nil {
		return false, err
	}
	for _, l := range lines {
		if strings.HasPrefix(l, userId+"|") {
			return true, nil
		}
	}
	return false, nil
}

// ---------- 成员管理 ----------

// Apply 提交入群申请（无需身份验证）。
// userId 已是正式成员或已在待审批列表中时返回错误。
func (s *Store) Apply(userId, publicKey string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// 已是正式成员 → 拒绝
	if ok, err := s.isMemberLocked(userId); err != nil {
		return err
	} else if ok {
		return ErrUserExists
	}
	// 已在待审批列表 → 拒绝
	lines, err := readLines(s.unverifiedPath())
	if err != nil {
		return err
	}
	for _, l := range lines {
		if m, ok := parseMemberLine(l); ok && m.UserID == userId {
			return ErrAlreadyApplied
		}
	}
	// 写入待审批列表，格式：userId|申请日期|公钥
	return appendLine(s.unverifiedPath(), userId+"|"+time.Now().Format(dateLayout)+"|"+publicKey)
}

// Approve 管理员批准入群申请：
// 从 unverified_members.txt 移除该 userId，并按 userId|加入日期|公钥 追加到 members.txt。
func (s *Store) Approve(operatorId, userId string) error {
	return s.moveFromPending(operatorId, userId, true)
}

// Reject 管理员拒绝入群申请：仅从 unverified_members.txt 移除该 userId。
func (s *Store) Reject(operatorId, userId string) error {
	return s.moveFromPending(operatorId, userId, false)
}

// moveFromPending Approve/Reject 的公共实现（approve=true 时转入正式成员列表）。
// 权限校验与文件修改在同一把锁内原子完成。
func (s *Store) moveFromPending(operatorId, userId string, approve bool) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// 权限铁律：修改成员列表的操作必须是管理员
	if ok, err := s.isAdminLocked(operatorId); err != nil {
		return err
	} else if !ok {
		return ErrForbidden
	}

	// 从待审批列表查找并移除该 userId
	lines, err := readLines(s.unverifiedPath())
	if err != nil {
		return err
	}
	var target MemberInfo
	found := false
	var remaining []string
	for _, l := range lines {
		if !found {
			if m, ok := parseMemberLine(l); ok && m.UserID == userId {
				target = m
				found = true
				continue
			}
		}
		remaining = append(remaining, l)
	}
	if !found {
		return ErrNotPending
	}
	if err := rewriteLines(s.unverifiedPath(), remaining); err != nil {
		return err
	}
	// 批准时追加到正式成员列表，加入日期为批准当天（保留申请时提交的公钥）
	if approve {
		return appendLine(s.membersPath(), userId+"|"+time.Now().Format(dateLayout)+"|"+target.PublicKey)
	}
	return nil
}

// Leave 成员退出群组：从 members.txt 移除；若在 admins.txt 中则一并移除。
// （操作者只能为自己退出，handlers 层已校验 body.userId == header X-User-Id）
func (s *Store) Leave(userId string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// 从正式成员列表移除
	lines, err := readLines(s.membersPath())
	if err != nil {
		return err
	}
	found := false
	var remaining []string
	for _, l := range lines {
		if m, ok := parseMemberLine(l); ok && m.UserID == userId {
			found = true
			continue
		}
		remaining = append(remaining, l)
	}
	if !found {
		return ErrNotMember
	}
	if err := rewriteLines(s.membersPath(), remaining); err != nil {
		return err
	}

	// 若该用户是管理员，同时从 admins.txt 移除
	adminLines, err := readLines(s.adminsPath())
	if err != nil {
		return err
	}
	adminChanged := false
	var adminRemaining []string
	for _, l := range adminLines {
		if l == userId {
			adminChanged = true
			continue
		}
		adminRemaining = append(adminRemaining, l)
	}
	if adminChanged {
		return rewriteLines(s.adminsPath(), adminRemaining)
	}
	return nil
}

// ListMembers 返回全部正式成员列表（公钥是公开信息，无需验证）
func (s *Store) ListMembers() ([]MemberInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memberLinesLocked()
}

// memberLinesLocked 读取并解析全部正式成员行（调用方需持有 s.mu）
func (s *Store) memberLinesLocked() ([]MemberInfo, error) {
	lines, err := readLines(s.membersPath())
	if err != nil {
		return nil, err
	}
	members := make([]MemberInfo, 0, len(lines))
	for _, l := range lines {
		if m, ok := parseMemberLine(l); ok {
			members = append(members, m)
		}
	}
	return members, nil
}

// PendingList 返回待审批成员列表（权限铁律：仅管理员可查看）
func (s *Store) PendingList(operatorId string) ([]PendingInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok, err := s.isAdminLocked(operatorId); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrForbidden
	}
	lines, err := readLines(s.unverifiedPath())
	if err != nil {
		return nil, err
	}
	pending := make([]PendingInfo, 0, len(lines))
	for _, l := range lines {
		if m, ok := parseMemberLine(l); ok {
			pending = append(pending, PendingInfo{UserID: m.UserID, RequestDate: m.JoinedDate})
		}
	}
	return pending, nil
}

// ---------- 服务器信息 ----------

// Health 返回 GET /health 所需的服务器状态（无需验证）：
// {"status":"ok","name":"群组名","memberCount":人数}
func (s *Store) Health() (HealthStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := "Untitled Group"
	if b, err := os.ReadFile(s.nameFilePath()); err == nil {
		if n := strings.TrimSpace(string(b)); n != "" {
			name = n
		}
	}
	members, err := s.memberLinesLocked()
	if err != nil {
		return HealthStatus{}, err
	}
	return HealthStatus{Status: "ok", Name: name, MemberCount: len(members)}, nil
}

// ---------- 聊天消息 ----------

// AppendChatMessage 追加一条聊天消息到当天的日志文件 chat/{YYYY-MM-DD}.log。
// 行格式：timestamp|senderId|ciphertext|encryptedKeysJson
// 其中 timestamp 为服务器接收时刻的 Unix 秒；ciphertext 与 encryptedKeys
// 均为 Opaque 字符串，服务器只做 JSON 序列化与落盘，绝不解码、不解析内容。
func (s *Store) AppendChatMessage(senderId, ciphertext string, encryptedKeys map[string]string) error {
	// 序列化加密密钥表（{"userId":"encryptedKey", ...}），作为行尾的 JSON 字段
	if encryptedKeys == nil {
		encryptedKeys = map[string]string{}
	}
	keysJSON, err := json.Marshal(encryptedKeys)
	if err != nil {
		return fmt.Errorf("Serialize encryptedKeys failed: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 确保日志句柄对应当天日期（跨天自动切换新文件）
	if err := s.ensureChatFileLocked(); err != nil {
		return err
	}
	line := fmt.Sprintf("%d|%s|%s|%s\n", time.Now().Unix(), senderId, ciphertext, keysJSON)
	_, err = io.WriteString(s.chatFile, line)
	return err
}

// ensureChatFileLocked 确保当前聊天日志句柄对应当天日期（调用方需持有 s.mu）。
// 使用日期缓存：同一天内直接复用已打开的文件句柄，避免每次请求都执行 OpenFile；
// 跨天时关闭旧句柄并自动创建/打开新一天的日志文件（权限 0600，追加写）。
func (s *Store) ensureChatFileLocked() error {
	today := time.Now().Format(dateLayout)
	if s.chatFile != nil && s.chatDate == today {
		return nil // 日期未变，直接复用已打开的句柄
	}
	if s.chatFile != nil {
		_ = s.chatFile.Close() // 跨天：关闭昨天的日志文件
		s.chatFile = nil
	}
	f, err := os.OpenFile(filepath.Join(s.dir, "chat", today+".log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("Open chatting log %s failed: %w", today, err)
	}
	s.chatFile = f
	s.chatDate = today
	return nil
}

// ReadChatMessages 读取指定日期的聊天记录行（文件不存在时返回空列表）。
// since > 0 时只返回“时间戳 >= since”的消息行，否则返回全部行。
func (s *Store) ReadChatMessages(date string, since int64) ([]string, error) {
	// date 会拼入文件路径，必须先严格校验格式，杜绝路径遍历
	if err := ValidateDate(date); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lines, err := readLines(filepath.Join(s.dir, "chat", date+".log"))
	if err != nil {
		return nil, err
	}
	if since <= 0 {
		if lines == nil {
			lines = []string{} // 保证 JSON 输出为 [] 而不是 null
		}
		return lines, nil
	}
	result := make([]string, 0, len(lines))
	for _, l := range lines {
		if ts, ok := parseLineTimestamp(l); !ok || ts >= since {
			result = append(result, l)
		}
	}
	return result, nil
}

// parseLineTimestamp 从日志行首解析 Unix 时间戳（行格式：timestamp|senderId|...）
func parseLineTimestamp(line string) (int64, bool) {
	idx := strings.Index(line, "|")
	if idx <= 0 {
		return 0, false
	}
	ts, err := strconv.ParseInt(line[:idx], 10, 64)
	if err != nil {
		return 0, false
	}
	return ts, true
}

// ---------- 加密文件存储 ----------

// SaveEncryptedFile 保存加密文件主体到 files/{date}/{fileId}.enc，
// 返回相对路径（如 files/2026-08-28/abc123.enc）。
func (s *Store) SaveEncryptedFile(date, fileId string, r io.Reader) (string, error) {
	return s.saveUploadFile(date, fileId, ".enc", r)
}

// SaveFileKeys 保存加密文件密钥副本到 files/{date}/{fileId}.keys。
// 内容为逐行 “userId:encryptedKey” 的密钥副本，按 Opaque 字节流原样存储。
func (s *Store) SaveFileKeys(date, fileId string, r io.Reader) (string, error) {
	return s.saveUploadFile(date, fileId, ".keys", r)
}

// saveUploadFile 上传保存的公共实现（date 与 fileId 均会拼入存储路径，必须先严格校验）。
// 目录 0700、文件 0600；先完成格式校验，再持全局锁写入，防止并发写坏文件。
func (s *Store) saveUploadFile(date, fileId, ext string, r io.Reader) (string, error) {
	if err := ValidateDate(date); err != nil {
		return "", err
	}
	if err := ValidateFileID(fileId); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Join(s.dir, "files", date)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(filepath.Join(dir, fileId+ext),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return "files/" + date + "/" + fileId + ext, nil
}

// ResolveFilesPath 下载路径校验（【路径铁律】）：
//  1. path 必须以 "files/" 开头；
//  2. 经过 filepath.Clean 与 filepath.Abs 处理后，其绝对路径必须严格位于
//     {data目录}/files/ 之下；任何形式的路径遍历（如 ../）都返回 ErrPathTraversal，
//     由 handlers 层映射为 400 Bad Request。
func (s *Store) ResolveFilesPath(path string) (string, error) {
	// 规则 1：必须以 files/ 开头（同时拒绝绝对路径、空路径等情况）
	if !strings.HasPrefix(path, "files/") {
		return "", ErrPathTraversal
	}
	// 规则 2：Clean 消除 ..、重复分隔符等，再取绝对路径做前缀校验
	cleaned := filepath.Clean(path)
	abs, err := filepath.Abs(filepath.Join(s.dir, cleaned))
	if err != nil {
		return "", ErrPathTraversal
	}
	// 前缀必须精确到 {data}/files/ + 分隔符：既拒绝越出 files 目录的遍历，
	// 也拒绝 path 本身就是 files 目录（必须严格位于其下），还排除 filesXXX 同级目录混淆
	if !strings.HasPrefix(abs, s.filesDir+string(filepath.Separator)) {
		return "", ErrPathTraversal
	}
	return abs, nil
}

// OpenDownloadFile 校验并打开待下载文件，返回（绝对路径, 文件句柄, 文件信息）。
// 调用方负责在使用完毕后关闭文件句柄。
func (s *Store) OpenDownloadFile(path string) (string, *os.File, os.FileInfo, error) {
	abs, err := s.ResolveFilesPath(path)
	if err != nil {
		return "", nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(abs)
	if err != nil {
		return "", nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return "", nil, nil, err
	}
	return abs, f, info, nil
}

