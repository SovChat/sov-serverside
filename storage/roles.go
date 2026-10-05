// Package storage 的两级角色模型：admin（最高权限）与 mod（版主）。
//
// 存储文件：serverpersons/roles.txt，每行一条 "role|userId"：
//
//	admin|alice
//	admin|bob
//	mod|carol
//
// 兼容策略：roles.txt 不存在而旧版 admins.txt 存在时，首次访问自动迁移
// （旧管理员全部映射为 admin 角色并原子写入 roles.txt）。迁移完成后
// roles.txt 成为唯一事实来源，admins.txt 仅作为遗留文件不再被读取。
package storage

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

// 角色取值（GetRole 的返回值之一，空串表示无角色）
const (
	RoleAdmin = "admin"
	RoleMod   = "mod"
	// RoleNone 表示"移除角色"（SetRole 的目标取值，不作为存储行出现）
	RoleNone = "none"
)

// RoleEntry roles.txt 中的一条角色记录（ListRoles 的返回元素，预留管理面板使用）
type RoleEntry struct {
	Role   string `json:"role"`
	UserID string `json:"userId"`
}

// rolesPath 角色表路径：serverpersons/roles.txt
func (s *Store) rolesPath() string {
	return filepath.Join(s.dir, "serverpersons", "roles.txt")
}

// parseRoleLine 解析角色行 "role|userId"；role 必须是 admin 或 mod，格式非法的行直接忽略
func parseRoleLine(line string) (RoleEntry, bool) {
	parts := strings.SplitN(line, "|", 2)
	if len(parts) != 2 || parts[1] == "" {
		return RoleEntry{}, false
	}
	if parts[0] != RoleAdmin && parts[0] != RoleMod {
		return RoleEntry{}, false
	}
	return RoleEntry{Role: parts[0], UserID: parts[1]}, true
}

// loadRolesLocked 读取全部角色记录（调用方需持有 s.mu）。
// roles.txt 不存在而旧版 admins.txt 存在时，自动执行一次性迁移。
func (s *Store) loadRolesLocked() ([]RoleEntry, error) {
	if _, err := os.Stat(s.rolesPath()); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return s.migrateAdminsLocked()
	}
	lines, err := readLines(s.rolesPath())
	if err != nil {
		return nil, err
	}
	entries := make([]RoleEntry, 0, len(lines))
	for _, l := range lines {
		if e, ok := parseRoleLine(l); ok {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// migrateAdminsLocked 旧版 admins.txt → roles.txt 的一次性自动迁移
// （调用方需持有 s.mu）：每个旧管理员映射为一条 admin 记录并原子写入 roles.txt。
func (s *Store) migrateAdminsLocked() ([]RoleEntry, error) {
	adminLines, err := readLines(s.adminsPath())
	if err != nil {
		return nil, err
	}
	entries := make([]RoleEntry, 0, len(adminLines))
	for _, l := range adminLines {
		if !ValidUserID(l) {
			continue // 跳过脏行，避免把损坏数据当作 userId 迁移
		}
		entries = append(entries, RoleEntry{Role: RoleAdmin, UserID: l})
	}
	if len(entries) == 0 {
		return nil, nil // 既无 roles.txt 也无有效 admins.txt：无任何角色
	}
	if err := s.saveRolesLocked(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// saveRolesLocked 原子覆盖写角色表（临时文件 + rename，权限 0600）。调用方需持有 s.mu。
func (s *Store) saveRolesLocked(entries []RoleEntry) error {
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		lines = append(lines, e.Role+"|"+e.UserID)
	}
	return rewriteLines(s.rolesPath(), lines)
}

// getRoleLocked 查询某用户的角色（调用方需持有 s.mu）；无任何角色时返回 ""
func (s *Store) getRoleLocked(userId string) (string, error) {
	entries, err := s.loadRolesLocked()
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.UserID == userId {
			return e.Role, nil
		}
	}
	return "", nil
}

// GetRole 返回某用户的角色："admin"、"mod" 或 ""（无角色）
func (s *Store) GetRole(userId string) (string, error) {
	if !ValidUserID(userId) {
		return "", ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getRoleLocked(userId)
}

// IsModOrAbove 判断某用户是否拥有版主及以上角色（admin 或 mod 均为 true）
func (s *Store) IsModOrAbove(userId string) (bool, error) {
	if !ValidUserID(userId) {
		return false, ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isModOrAboveLocked(userId)
}

// isModOrAboveLocked（调用方需持有 s.mu）
func (s *Store) isModOrAboveLocked(userId string) (bool, error) {
	role, err := s.getRoleLocked(userId)
	if err != nil {
		return false, err
	}
	return role == RoleAdmin || role == RoleMod, nil
}

// ListRoles 返回全部角色记录（预留：管理面板展示用）
func (s *Store) ListRoles() ([]RoleEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.loadRolesLocked()
	if err != nil {
		return nil, err
	}
	if entries == nil {
		entries = []RoleEntry{} // 保证 JSON 输出为 [] 而不是 null
	}
	return entries, nil
}

// SetRole 设置某用户的角色（权限校验由 handlers 层完成后调用）。
// role 取值：RoleAdmin / RoleMod / RoleNone（移除角色）。
// 铁律（同锁内原子完成）：降级或移除 admin 角色时，若目标已是最后一个管理员则拒绝；
// admin 角色的变更仅限本方法，调用方（handlers 层）需自行确保操作者具备相应权限。
func (s *Store) SetRole(userId, role string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	if role != RoleAdmin && role != RoleMod && role != RoleNone {
		return ErrInvalidRole
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.loadRolesLocked()
	if err != nil {
		return err
	}
	changed := false
	targetFound := false
	out := make([]RoleEntry, 0, len(entries)+1)
	for _, e := range entries {
		if e.UserID == userId {
			targetFound = true
			// 降级/移除管理员：最后一个管理员不可被剥夺
			if e.Role == RoleAdmin && role != RoleAdmin {
				admins := 0
				for _, other := range entries {
					if other.Role == RoleAdmin {
						admins++
					}
				}
				if admins <= 1 {
					return ErrLastAdmin
				}
			}
			if e.Role != role {
				changed = true
				if role == RoleNone {
					continue // 移除角色：丢弃该行
				}
				out = append(out, RoleEntry{Role: role, UserID: userId})
				continue
			}
		}
		out = append(out, e)
	}
	if !targetFound && role != RoleNone {
		out = append(out, RoleEntry{Role: role, UserID: userId})
		changed = true
	}
	if !changed {
		return nil // 无实际变化，避免无意义落盘
	}
	return s.saveRolesLocked(out)
}

// removeRoleLocked 移除某用户的全部角色记录（无记录时视为成功）。调用方需持有 s.mu。
// 用于踢出/封禁等场景的角色清理。
func (s *Store) removeRoleLocked(userId string) error {
	entries, err := s.loadRolesLocked()
	if err != nil {
		return err
	}
	changed := false
	out := make([]RoleEntry, 0, len(entries))
	for _, e := range entries {
		if e.UserID == userId {
			changed = true
			continue
		}
		out = append(out, e)
	}
	if !changed {
		return nil
	}
	return s.saveRolesLocked(out)
}

// RemoveRole 移除某用户的全部角色记录（无记录时视为成功）。
// 用于踢出/封禁等场景的角色清理。
func (s *Store) RemoveRole(userId string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeRoleLocked(userId)
}

// ---------- 根管理员（创始人）判定与移交 ----------

// firstAdminLocked 返回角色表中第一条 admin 记录（即根管理员 / 创始人）。
// 调用方需持有 s.mu。无任何管理员时返回 ("", false)。
func (s *Store) firstAdminLocked() (string, bool) {
	entries, err := s.loadRolesLocked()
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if e.Role == RoleAdmin {
			return e.UserID, true
		}
	}
	return "", false
}

// IsRootAdmin 判断某用户是否为根管理员（roles.txt 第一条 admin 记录 / 创始人）
func (s *Store) IsRootAdmin(userId string) (bool, error) {
	if !ValidUserID(userId) {
		return false, ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	root, ok := s.firstAdminLocked()
	return ok && root == userId, nil
}

// TransferRootAdmin 根管理员移交：target 升为 admin（置于表首），原根管理员降为 mod。
// 仅当前根管理员可发起（handlers 层前置校验，此处同锁内再校验一次）。
func (s *Store) TransferRootAdmin(from, target string) error {
	if !ValidUserID(from) || !ValidUserID(target) {
		return ErrInvalidUserID
	}
	if from == target {
		return ErrInvalidUserID // 自移交无意义，直接拒绝
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	root, ok := s.firstAdminLocked()
	if !ok || root != from {
		return ErrForbidden // 仅根管理员可移交
	}
	entries, err := s.loadRolesLocked()
	if err != nil {
		return err
	}
	// 目标升为 admin：已有记录改写角色，否则插到表首（保证其成为新的第一管理员）
	targetFound := false
	out := make([]RoleEntry, 0, len(entries)+1)
	for _, e := range entries {
		if e.UserID == target {
			targetFound = true
			out = append(out, RoleEntry{Role: RoleAdmin, UserID: target})
			continue
		}
		out = append(out, e)
	}
	if !targetFound {
		out = append([]RoleEntry{{Role: RoleAdmin, UserID: target}}, out...)
	}
	// 原根管理员降为 mod
	for i := range out {
		if out[i].UserID == from {
			out[i].Role = RoleMod
		}
	}
	return s.saveRolesLocked(out)
}

// ---------- 封禁与最近来源 IP ----------

// lastIPsPath 最近来源 IP 表路径：serverpersons/last_ips.txt（一行一条 userId|ip）
func (s *Store) lastIPsPath() string {
	return filepath.Join(s.dir, "serverpersons", "last_ips.txt")
}

// bannedUsersPath 被封禁账号表路径：serverpersons/banned_users.txt（一行一个 userId）
func (s *Store) bannedUsersPath() string {
	return filepath.Join(s.dir, "serverpersons", "banned_users.txt")
}

// bannedIPsPath 被封禁 IP 表路径：serverpersons/banned_ips.txt（一行一个 IP）
func (s *Store) bannedIPsPath() string {
	return filepath.Join(s.dir, "serverpersons", "banned_ips.txt")
}

// RecordLastIP 记录用户最近一次来源 IP（同一用户只保留最新一条，原子覆盖写）
func (s *Store) RecordLastIP(userId, ip string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	if strings.TrimSpace(ip) == "" {
		return ErrInvalidIP
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lines, err := readLines(s.lastIPsPath())
	if err != nil {
		return err
	}
	out := make([]string, 0, len(lines)+1)
	for _, l := range lines {
		parts := strings.SplitN(l, "|", 2)
		if len(parts) == 2 && parts[0] == userId {
			continue // 旧记录被新记录取代
		}
		out = append(out, l)
	}
	out = append(out, userId+"|"+ip)
	return rewriteLines(s.lastIPsPath(), out)
}

// LastKnownIP 返回用户最近一次记录的来源 IP；从未记录过时返回 ErrNoIPFound
func (s *Store) LastKnownIP(userId string) (string, error) {
	if !ValidUserID(userId) {
		return "", ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lines, err := readLines(s.lastIPsPath())
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		parts := strings.SplitN(l, "|", 2)
		if len(parts) == 2 && parts[0] == userId {
			return parts[1], nil
		}
	}
	return "", ErrNoIPFound
}

// IsUserBanned 判断某账号是否已被封禁
func (s *Store) IsUserBanned(userId string) (bool, error) {
	if !ValidUserID(userId) {
		return false, ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lines, err := readLines(s.bannedUsersPath())
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

// IsIPBanned 判断某 IP 是否已被封禁
func (s *Store) IsIPBanned(ip string) (bool, error) {
	if strings.TrimSpace(ip) == "" {
		return false, ErrInvalidIP
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isIPBannedLocked(ip)
}

// isIPBannedLocked 判断 IP 是否已在封禁表（调用方需持有 s.mu）
func (s *Store) isIPBannedLocked(ip string) (bool, error) {
	lines, err := readLines(s.bannedIPsPath())
	if err != nil {
		return false, err
	}
	for _, l := range lines {
		if l == ip {
			return true, nil
		}
	}
	return false, nil
}

// removeMemberLocked 从 members.txt 移除一行（调用方需持有 s.mu）。
// 目标是管理员角色时拒绝（mod 不能对 admin 执行治理命令）；不在成员表中返回 ErrNotMember。
func (s *Store) removeMemberLocked(userId string) error {
	role, err := s.getRoleLocked(userId)
	if err != nil {
		return err
	}
	if role == RoleAdmin {
		return ErrModOnAdmin
	}
	lines, err := readLines(s.membersPath())
	if err != nil {
		return err
	}
	found := false
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if m, ok := parseMemberLine(l); ok && m.UserID == userId {
			found = true
			continue
		}
		out = append(out, l)
	}
	if !found {
		return ErrNotMember
	}
	return rewriteLines(s.membersPath(), out)
}

// RemoveMember 踢出成员：仅从 members.txt 移除（不写封禁表）
func (s *Store) RemoveMember(userId string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeMemberLocked(userId)
}

// BanUser 封禁账号：写入 banned_users.txt；目标仍是成员时同锁内一并移除。
// 目标已被踢出 / 待审批（不在成员表）也允许封禁（防止二次加入），仅 admin 角色拒绝。
func (s *Store) BanUser(userId string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	role, err := s.getRoleLocked(userId)
	if err != nil {
		return err
	}
	if role == RoleAdmin {
		return ErrModOnAdmin
	}
	// 仍是成员则一并移除；不在成员表（已踢出 / 待审批）不算失败
	member, err := s.isMemberLocked(userId)
	if err != nil {
		return err
	}
	if member {
		if err := s.removeMemberLocked(userId); err != nil {
			return err
		}
	}
	// 同步清掉残留角色（如 mod），避免被封禁账号复登后仍持有版主权限
	if err := s.removeRoleLocked(userId); err != nil {
		return err
	}
	return appendLine(s.bannedUsersPath(), userId)
}

// BanUserIP 封禁用户最近一次记录的来源 IP（不改动成员表；从未记录过 IP 时返回 ErrNoIPFound）
func (s *Store) BanUserIP(userId string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	role, err := s.getRoleLocked(userId)
	if err != nil {
		return err
	}
	if role == RoleAdmin {
		return ErrModOnAdmin
	}
	lines, err := readLines(s.lastIPsPath())
	if err != nil {
		return err
	}
	ip := ""
	for _, l := range lines {
		parts := strings.SplitN(l, "|", 2)
		if len(parts) == 2 && parts[0] == userId {
			ip = parts[1]
			break
		}
	}
	if strings.TrimSpace(ip) == "" {
		return ErrNoIPFound
	}
	banned, err := s.isIPBannedLocked(ip)
	if err != nil {
		return err
	}
	if banned {
		return nil // 已封禁，幂等成功
	}
	return appendLine(s.bannedIPsPath(), ip)
}

// ForgiveUser 解封账号：从 banned_users.txt 移除（不在表中视为成功，幂等）
func (s *Store) ForgiveUser(userId string) error {
	if !ValidUserID(userId) {
		return ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lines, err := readLines(s.bannedUsersPath())
	if err != nil {
		return err
	}
	out := make([]string, 0, len(lines))
	changed := false
	for _, l := range lines {
		if l == userId {
			changed = true
			continue
		}
		out = append(out, l)
	}
	if !changed {
		return nil
	}
	return rewriteLines(s.bannedUsersPath(), out)
}

// ForgiveIP 解封 IP：从 banned_ips.txt 移除（IP 格式非法返回 400；不在表中视为成功）
func (s *Store) ForgiveIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return ErrInvalidIP
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lines, err := readLines(s.bannedIPsPath())
	if err != nil {
		return err
	}
	out := make([]string, 0, len(lines))
	changed := false
	for _, l := range lines {
		if l == ip {
			changed = true
			continue
		}
		out = append(out, l)
	}
	if !changed {
		return nil
	}
	return rewriteLines(s.bannedIPsPath(), out)
}
