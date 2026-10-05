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
	// maxDisplayNameRunes 显示名（displayName）允许的最大字符数
	maxDisplayNameRunes = 32
	// visibilityPublic visibility.txt 中表示「公开频道」的取值
	visibilityPublic = "public"
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
	ErrModOnAdmin     = errors.New("No access processing: mods cannot act on admins.")
	ErrInvalidRole    = errors.New(`role illegal: only "admin", "mod" or "none" is allowed.`)
	// ErrLastAdmin 降级/移除最后一个管理员时返回（铁律：服务器必须始终保有管理员）
	ErrLastAdmin = errors.New("Cannot demote the last remaining admin.")
	// ErrInvalidIP IP 地址格式非法
	ErrInvalidIP = errors.New("IP address format is illegal.")
	// ErrNoIPFound 目标用户从未记录过来源 IP（banip 需要 IP 时）
	ErrNoIPFound     = errors.New("No known IP recorded for this user.")
	ErrPathTraversal = errors.New("Path illegal: path traversal attack detected.")

	// 账号（注册 / 登录）相关错误
	ErrAccountExists      = errors.New("The userId is already registered.")
	ErrAccountNotFound    = errors.New("The userId haven't registered yet.")
	ErrInvalidDisplayName = errors.New("displayName illegal: max 32 characters, no control characters or line breaks.")
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

// ValidateDisplayName 校验显示名：允许为空（落库时回退为 userId），
// 最长 maxDisplayNameRunes 个字符，且不得含控制字符或换行（防止写入账号文件时破坏行结构）。
func ValidateDisplayName(name string) error {
	if name == "" {
		return nil
	}
	if utf8.RuneCountInString(name) > maxDisplayNameRunes {
		return ErrInvalidDisplayName
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidDisplayName
		}
	}
	return nil
}

// ---------- 数据结构 ----------

// MemberInfo 正式成员信息（members.txt 一行：userId|加入日期|公钥）。
// DisplayName 不落 members.txt，而是由 accounts.txt 关联出来的展示字段（可能为空）。
type MemberInfo struct {
	UserID      string `json:"userId"`
	PublicKey   string `json:"publicKey"`
	JoinedDate  string `json:"joinedDate"`
	DisplayName string `json:"displayName"`
}

// PendingInfo 待审批成员信息（unverified_members.txt 一行：userId|申请日期|公钥）
type PendingInfo struct {
	UserID      string `json:"userId"`
	RequestDate string `json:"requestDate"`
}

// AccountInfo 账号信息（serverinfo/accounts.txt 一行一个 JSON 对象）。
// 密码不在本结构中：bcrypt 哈希单独存放在 serverinfo/passwords/{userId}.hash。
type AccountInfo struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
	CreatedAt   string `json:"createdAt"`
}

// HealthStatus GET /health 返回的服务器状态信息。
// Public 表示本群组是否为公开频道：公开频道允许「注册即入群」，私有群组仍需管理员审批。
type HealthStatus struct {
	Status      string `json:"status"`
	Name        string `json:"name"`
	MemberCount int    `json:"memberCount"`
	Public      bool   `json:"public"`
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
		"serverpersons",        // roles.txt / members.txt / unverified_members.txt
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

// accountsPath 账号表路径：serverinfo/accounts.txt（一行一个 JSON 账号对象）
func (s *Store) accountsPath() string {
	return filepath.Join(s.dir, "serverinfo", "accounts.txt")
}

// visibilityPath 群组可见性路径：serverinfo/visibility.txt（public / private）
func (s *Store) visibilityPath() string {
	return filepath.Join(s.dir, "serverinfo", "visibility.txt")
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
//  2. 若指定初始管理员：写入 founder.txt、roles.txt（admin 角色，即群主）与 members.txt；
//  3. 若提供管理员密码：立即生成 bcrypt 哈希（cost=12）写入 passwords/{admin}.hash，
//     并同步建立账号记录（accounts.txt），使初始管理员可以直接登录；
//     若未提供密码：由 main 在终端打印提示，引导管理员通过 /members/set-password 自行设置。
//  4. 写入群组可见性 serverinfo/visibility.txt（public=注册即入群 / private=需管理员审批），
//     已存在则跳过，避免重启覆盖。
func (s *Store) Init(admin, adminPass, groupName string, public bool) error {
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
	// 群组可见性：公开频道允许「注册即入群」，私有群组仍需管理员审批
	visibility := "private"
	if public {
		visibility = visibilityPublic
	}
	if err := writeFileIfMissing(s.visibilityPath(), visibility+"\n"); err != nil {
		return fmt.Errorf("Write visibility.txt failed: %w", err)
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
	// roles.txt：首次创建时管理员为第一条 admin 记录（群主）；已存在则不改动。
	// （旧版写入 admins.txt，现由 roles.txt 承担；旧数据在首次访问时自动迁移）
	if _, err := os.Stat(s.rolesPath()); os.IsNotExist(err) {
		if err := os.WriteFile(s.rolesPath(), []byte(RoleAdmin+"|"+admin+"\n"), 0600); err != nil {
			return fmt.Errorf("Write roles.txt failed: %w", err)
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
	if has, err := s.hasPasswordLocked(admin); err != nil {
		return err
	} else if !has {
		// 哈希已存在时不覆盖，避免重启时用启动参数意外重置密码
		if err := s.savePasswordHashLocked(admin, adminPass); err != nil {
			return err
		}
	}
	// 同步建立账号记录，使初始管理员可以直接通过 /auth/login 登录
	return s.ensureAccountLocked(admin, admin)
}

// ensureAccountLocked 账号记录不存在时补写一条（调用方需持有 s.mu）。
// 用于把「-admin 启动」创建的初始管理员纳入账号表（displayName 缺省为 userId）。
func (s *Store) ensureAccountLocked(userId, displayName string) error {
	if _, ok, err := s.accountLocked(userId); err != nil {
		return err
	} else if ok {
		return nil
	}
	acc := AccountInfo{UserID: userId, DisplayName: displayName, CreatedAt: time.Now().Format(dateLayout)}
	line, err := json.Marshal(acc)
	if err != nil {
		return fmt.Errorf("Serialize account failed: %w", err)
	}
	return appendLine(s.accountsPath(), string(line))
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

// isAdminLocked 判断某用户是否为 admin 角色（roles.txt，旧 admins.txt 自动迁移；
// 调用方需持有 s.mu）
func (s *Store) isAdminLocked(userId string) (bool, error) {
	role, err := s.getRoleLocked(userId)
	if err != nil {
		return false, err
	}
	return role == RoleAdmin, nil
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

	// 权限铁律：修改成员列表的操作必须是版主及以上（admin 或 mod）
	if ok, err := s.isModOrAboveLocked(operatorId); err != nil {
		return err
	} else if !ok {
		return ErrForbidden
	}
	// 版主不能操作管理员：目标 userId 是 admin 角色时，操作者也必须是 admin
	if tRole, err := s.getRoleLocked(userId); err != nil {
		return err
	} else if tRole == RoleAdmin {
		if oRole, err := s.getRoleLocked(operatorId); err != nil {
			return err
		} else if oRole != RoleAdmin {
			return ErrModOnAdmin
		}
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

	// 若该用户是旧版 admins.txt 中的管理员，同时移除（兼容未迁移数据；迁移后此文件不再被读取）
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
		if err := rewriteLines(s.adminsPath(), adminRemaining); err != nil {
			return err
		}
	}

	// 同时从角色表 roles.txt 移除该用户的角色记录
	roleEntries, err := s.loadRolesLocked()
	if err != nil {
		return err
	}
	roleChanged := false
	roleRemaining := make([]RoleEntry, 0, len(roleEntries))
	for _, e := range roleEntries {
		if e.UserID == userId {
			roleChanged = true
			continue
		}
		roleRemaining = append(roleRemaining, e)
	}
	if roleChanged {
		return s.saveRolesLocked(roleRemaining)
	}
	return nil
}

// ListMembers 返回全部正式成员列表（公钥是公开信息，无需验证）
func (s *Store) ListMembers() ([]MemberInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memberLinesLocked()
}

// memberLinesLocked 读取并解析全部正式成员行（调用方需持有 s.mu）。
// 同时关联 accounts.txt，为成员补上展示用 displayName（账号不存在时为空）。
func (s *Store) memberLinesLocked() ([]MemberInfo, error) {
	lines, err := readLines(s.membersPath())
	if err != nil {
		return nil, err
	}
	displayNames := map[string]string{}
	if accountLines, err := readLines(s.accountsPath()); err == nil {
		for _, l := range accountLines {
			if a, ok := parseAccountLine(l); ok {
				displayNames[a.UserID] = a.DisplayName
			}
		}
	}
	members := make([]MemberInfo, 0, len(lines))
	for _, l := range lines {
		if m, ok := parseMemberLine(l); ok {
			m.DisplayName = displayNames[m.UserID]
			members = append(members, m)
		}
	}
	return members, nil
}

// PendingList 返回待审批成员列表（权限铁律：仅版主及以上可查看）
func (s *Store) PendingList(operatorId string) ([]PendingInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok, err := s.isModOrAboveLocked(operatorId); err != nil {
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

// ---------- 账号（注册 / 登录） ----------

// parseAccountLine 解析账号行（JSON Lines 格式）；格式非法的行直接忽略
func parseAccountLine(line string) (AccountInfo, bool) {
	var a AccountInfo
	if err := json.Unmarshal([]byte(line), &a); err != nil {
		return AccountInfo{}, false
	}
	if a.UserID == "" {
		return AccountInfo{}, false
	}
	return a, true
}

// accountLocked 在账号表中查找某 userId（调用方需持有 s.mu）
func (s *Store) accountLocked(userId string) (AccountInfo, bool, error) {
	lines, err := readLines(s.accountsPath())
	if err != nil {
		return AccountInfo{}, false, err
	}
	for _, l := range lines {
		if a, ok := parseAccountLine(l); ok && a.UserID == userId {
			return a, true, nil
		}
	}
	return AccountInfo{}, false, nil
}

// GetAccount 查询账号信息；第二个返回值表示账号记录是否存在。
func (s *Store) GetAccount(userId string) (AccountInfo, bool, error) {
	if !ValidUserID(userId) {
		return AccountInfo{}, false, ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accountLocked(userId)
}

// hasPasswordLocked 判断密码哈希文件是否已存在（调用方需持有 s.mu）
func (s *Store) hasPasswordLocked(userId string) (bool, error) {
	_, err := os.Stat(s.passwordPath(userId))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// findPendingLocked 判断 userId 是否已在待审批列表中（调用方需持有 s.mu）
func (s *Store) findPendingLocked(userId string) (bool, error) {
	lines, err := readLines(s.unverifiedPath())
	if err != nil {
		return false, err
	}
	for _, l := range lines {
		if m, ok := parseMemberLine(l); ok && m.UserID == userId {
			return true, nil
		}
	}
	return false, nil
}

// appendPendingLocked 把 userId 登记到待审批列表（已存在则跳过；调用方需持有 s.mu）
func (s *Store) appendPendingLocked(userId string) error {
	exists, err := s.findPendingLocked(userId)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return appendLine(s.unverifiedPath(), userId+"|"+time.Now().Format(dateLayout)+"|")
}

// isPublicLocked 读取群组可见性（调用方需持有 s.mu）。
// visibility.txt 缺失（升级前的旧数据目录）时按「私有」处理，
// 避免历史群组在升级后意外开放自助入群。
func (s *Store) isPublicLocked() (bool, error) {
	b, err := os.ReadFile(s.visibilityPath())
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(string(b)) == visibilityPublic, nil
}

// IsPublic 返回本群组是否为公开频道（公开频道允许注册即入群）
func (s *Store) IsPublic() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isPublicLocked()
}

// CreateAccount 注册新账号：写入 bcrypt 密码哈希（cost=12）并在 accounts.txt 追加账号记录。
//
// 入群规则（「只有公开频道注册即入群」）：
//   - 公开频道（visibility.txt = public）：注册即写入 members.txt 成为正式成员，返回 joined=true；
//   - 私有群组：仅创建账号，并自动登记一条待审批申请，返回 pending=true，需管理员审批后才能发言。
//
// 返回 (账号信息, 是否已直接入群, 是否进入待审批, error)。
func (s *Store) CreateAccount(userId, password, displayName string) (AccountInfo, bool, bool, error) {
	if !ValidUserID(userId) {
		return AccountInfo{}, false, false, ErrInvalidUserID
	}
	if err := ValidatePassword(password); err != nil {
		return AccountInfo{}, false, false, err
	}
	if err := ValidateDisplayName(displayName); err != nil {
		return AccountInfo{}, false, false, err
	}
	if displayName == "" {
		displayName = userId
	}
	acc := AccountInfo{
		UserID:      userId,
		DisplayName: displayName,
		CreatedAt:   time.Now().Format(dateLayout),
	}
	line, err := json.Marshal(acc)
	if err != nil {
		return AccountInfo{}, false, false, fmt.Errorf("Serialize account failed: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 账号唯一性：账号表与密码哈希文件任一已存在都视为已注册
	// （后者覆盖「-admin 启动时已建好密码但还没有账号记录」的初始管理员场景）
	if _, ok, err := s.accountLocked(userId); err != nil {
		return AccountInfo{}, false, false, err
	} else if ok {
		return AccountInfo{}, false, false, ErrAccountExists
	}
	if has, err := s.hasPasswordLocked(userId); err != nil {
		return AccountInfo{}, false, false, err
	} else if has {
		return AccountInfo{}, false, false, ErrAccountExists
	}

	// 1. 密码哈希落盘
	if err := s.savePasswordHashLocked(userId, password); err != nil {
		return AccountInfo{}, false, false, err
	}
	// 2. 账号记录落盘
	if err := appendLine(s.accountsPath(), string(line)); err != nil {
		return AccountInfo{}, false, false, err
	}
	// 3. 入群策略：仅公开频道注册即入群
	public, err := s.isPublicLocked()
	if err != nil {
		return acc, false, false, err
	}
	if !public {
		if err := s.appendPendingLocked(userId); err != nil {
			return acc, false, false, err
		}
		return acc, false, true, nil
	}
	isMember, err := s.isMemberLocked(userId)
	if err != nil {
		return acc, false, false, err
	}
	if !isMember {
		if err := appendLine(s.membersPath(), userId+"|"+acc.CreatedAt+"|"); err != nil {
			return acc, false, false, err
		}
	}
	return acc, true, false, nil
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
	public, err := s.isPublicLocked()
	if err != nil {
		return HealthStatus{}, err
	}
	return HealthStatus{Status: "ok", Name: name, MemberCount: len(members), Public: public}, nil
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
