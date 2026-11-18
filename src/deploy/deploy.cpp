#include "lexhelper/deploy.hpp"
#include "lexhelper/core.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <bcrypt.h>
#include "full_security_query.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace lexhelper {
namespace {
namespace fs = std::filesystem;
using Bytes = std::vector<std::byte>;
constexpr std::uint64_t max_file_size = 64ULL * 1024 * 1024;
constexpr std::size_t max_manifest_size = 1024 * 1024;
constexpr SECURITY_INFORMATION security_parts = OWNER_SECURITY_INFORMATION |
    GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
constexpr WORD inheritance_bits = SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED |
    SE_DACL_AUTO_INHERIT_REQ | SE_SACL_PROTECTED | SE_SACL_AUTO_INHERITED | SE_SACL_AUTO_INHERIT_REQ;
constexpr std::uint32_t full_security_marker = 0x32445346; // FSD2: complete BACKUP_SECURITY_INFORMATION
constexpr DWORD supported_attributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
    FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL |
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
constexpr std::array<const wchar_t*, 2> file_names{L"ChsWubi.lex", L"ChsWubiNew.lex"};
constexpr std::array<const wchar_t*, 2> payload_names{L"original-0.bin", L"original-1.bin"};

std::string utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!count) throw std::runtime_error("无效 UTF-16 路径");
    std::string result(static_cast<std::size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), result.data(), count, nullptr, nullptr);
    return result;
}

[[noreturn]] void error(const std::string& text) { throw std::runtime_error(text); }
[[noreturn]] void win_error(const std::string& action, const fs::path& path, DWORD code = GetLastError()) {
    error(action + "：" + utf8(path.wstring()) + " (Win32=" + std::to_string(code) + ")");
}

std::string hex32(DWORD value) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string result = "0x00000000";
    for (unsigned i = 0; i < 8; ++i) { result[9 - i] = digits[value & 15]; value >>= 4; }
    return result;
}

class Handle {
    HANDLE value_{INVALID_HANDLE_VALUE};
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { reset(); value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE); }
        return *this;
    }
    void reset() noexcept { if (valid()) CloseHandle(value_); value_ = INVALID_HANDLE_VALUE; }
    [[nodiscard]] HANDLE get() const { return value_; }
    [[nodiscard]] bool valid() const { return value_ != INVALID_HANDLE_VALUE && value_ != nullptr; }
};

struct LocalFreeDeleter { void operator()(void* p) const { if (p) LocalFree(p); } };
using LocalPtr = std::unique_ptr<void, LocalFreeDeleter>;

Bytes current_user_sid() {
    HANDLE raw{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) win_error("读取用户令牌失败", {});
    Handle token(raw);
    DWORD length{};
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &length);
    if (!length || length > 65536) error("用户令牌长度无效");
    Bytes data(length);
    if (!GetTokenInformation(token.get(), TokenUser, data.data(), length, &length))
        win_error("读取用户 SID 失败", {});
    const auto sid = reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid;
    Bytes result(GetLengthSid(sid));
    if (!CopySid(static_cast<DWORD>(result.size()), result.data(), sid)) win_error("复制 SID 失败", {});
    return result;
}

bool well_known(PSID sid, WELL_KNOWN_SID_TYPE type) {
    return sid && IsWellKnownSid(sid, type) != FALSE;
}

bool is_admin() {
    std::array<std::byte, SECURITY_MAX_SID_SIZE> sid{};
    DWORD length = static_cast<DWORD>(sid.size());
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid.data(), &length))
        win_error("创建管理员 SID 失败", {});
    BOOL member{};
    if (!CheckTokenMembership(nullptr, sid.data(), &member)) win_error("检查管理员身份失败", {});
    return member != FALSE;
}

// Privileges are enabled only for a demonstrated access failure or a known
// owner-assignment requirement, on a private thread token.
// No ownership take-over and no process-wide privilege / ACL changes are performed.
class Privileges {
    Handle previous_;
    Handle token_;
    bool active_{};
public:
    ~Privileges() {
        if (active_ && !SetThreadToken(nullptr, previous_.valid() ? previous_.get() : nullptr)) {
            // A privileged thread must never return to unrelated application work.
            RaiseFailFastException(nullptr, nullptr, 0);
            TerminateProcess(GetCurrentProcess(), ERROR_PRIVILEGE_NOT_HELD);
        }
    }
    void enable_names(bool system_mode, std::initializer_list<const wchar_t*> names) {
        if (!system_mode) error("模拟部署权限不足；不会提权或放宽 ACL");
        if (!token_.valid()) {
            HANDLE raw{};
            if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
                                 TRUE, &raw)) previous_ = Handle(raw);
            else if (GetLastError() != ERROR_NO_TOKEN) win_error("读取线程令牌失败", {});
            Handle process;
            HANDLE base = previous_.get();
            if (!previous_.valid()) {
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &raw))
                    win_error("读取进程令牌失败", {});
                process = Handle(raw); base = process.get();
            }
            if (!DuplicateTokenEx(base, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                                  nullptr, SecurityImpersonation, TokenImpersonation, &raw))
                win_error("创建最小范围部署令牌失败", {});
            token_ = Handle(raw);
        }
        for (const wchar_t* name : names) {
            TOKEN_PRIVILEGES p{}; p.PrivilegeCount = 1;
            if (!LookupPrivilegeValueW(nullptr, name, &p.Privileges[0].Luid))
                win_error("查询临时部署权限失败", name);
            p.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            SetLastError(ERROR_SUCCESS);
            if (!AdjustTokenPrivileges(token_.get(), FALSE, &p, 0, nullptr, nullptr) ||
                GetLastError() != ERROR_SUCCESS) win_error("令牌缺少所需部署权限", name);
        }
        if (!active_) {
            if (!SetThreadToken(nullptr, token_.get())) win_error("启用临时线程权限失败", {});
            active_ = true;
        }
    }
    void security(bool system_mode) { enable_names(system_mode, {SE_SECURITY_NAME}); }
    void relabel(bool system_mode) { enable_names(system_mode, {SE_RELABEL_NAME}); }
};

// Diagnostics describe the EFFECTIVE token, not just the process token. Do not
// print SID, descriptor, or unrelated user configuration. A diagnostic failure
// is reported inline and must never replace the original I/O error.
std::string security_token_diagnostic() {
    HANDLE raw{};
    bool thread = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw) != FALSE;
    if (!thread) {
        const auto code = GetLastError();
        if (code != ERROR_NO_TOKEN) return "token_query_Win32=" + std::to_string(code);
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
            return "process_token_query_Win32=" + std::to_string(GetLastError());
    }
    Handle token(raw);
    DWORD length{};
    if (GetTokenInformation(token.get(), TokenPrivileges, nullptr, 0, &length) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || length < sizeof(DWORD) || length > 65536)
        return "token_privileges_length_Win32=" + std::to_string(GetLastError());
    Bytes data(length);
    if (!GetTokenInformation(token.get(), TokenPrivileges, data.data(), length, &length))
        return "token_privileges_Win32=" + std::to_string(GetLastError());
    const auto privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(data.data());
    if (length < offsetof(TOKEN_PRIVILEGES, Privileges) || privileges->PrivilegeCount >
        (length - offsetof(TOKEN_PRIVILEGES, Privileges)) / sizeof(LUID_AND_ATTRIBUTES))
        return "token_privileges_invalid_length";
    std::string result = thread ? "effective_token=thread" : "effective_token=process";
    for (const wchar_t* name : {SE_SECURITY_NAME, SE_BACKUP_NAME, SE_RESTORE_NAME}) {
        LUID id{};
        if (!LookupPrivilegeValueW(nullptr, name, &id)) {
            result += "; privilege_lookup_Win32=" + std::to_string(GetLastError());
            continue;
        }
        const char* state = "absent";
        for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
            const auto& p = privileges->Privileges[i];
            if (p.Luid.LowPart == id.LowPart && p.Luid.HighPart == id.HighPart)
                state = (p.Attributes & SE_PRIVILEGE_ENABLED) ? "enabled" : "disabled";
        }
        result += "; " + utf8(name) + "=" + state;
    }
    return result;
}

std::string safe_security_token_diagnostic() noexcept {
    try { return security_token_diagnostic(); }
    catch (...) { return "token_diagnostic_unavailable"; }
}

struct Security {
    LocalPtr descriptor;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE};
    explicit Security(bool system) {
        std::wstring owner = L"BA";
        if (!system) {
            auto sid = current_user_sid();
            LPWSTR text{};
            if (!ConvertSidToStringSidW(sid.data(), &text)) win_error("转换 SID 失败", {});
            LocalPtr holder(text); owner = text;
        }
        const auto sddl = L"O:" + owner + L"G:" + owner +
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" +
            (system ? std::wstring{} : L"(A;OICI;FA;;;" + owner + L")");
        PSECURITY_DESCRIPTOR sd{};
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                                   &sd, nullptr))
            win_error("创建受保护备份 ACL 失败", {});
        descriptor.reset(sd); attributes.lpSecurityDescriptor = sd;
    }
};

bool same_path(const fs::path& a, const fs::path& b) {
    return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
}

fs::path checked_path(const fs::path& input) {
    const auto text = input.wstring();
    if (text.size() < 3 || text.size() > 30000 || text[1] != L':' || text[2] != L'\\' ||
        !((text[0] >= L'A' && text[0] <= L'Z') || (text[0] >= L'a' && text[0] <= L'z')) ||
        text.find(L'\0') != std::wstring::npos || text.find(L'/') != std::wstring::npos)
        error("仅接受绝对本地盘符路径（不接受 UNC、设备路径或相对路径）");
    (void)utf8(text); // Refuse unpaired UTF-16 before I/O and before error-path formatting.
    fs::path result = input;
    for (const auto& part : input.relative_path()) {
        const auto name = part.wstring();
        if (name.empty()) continue;
        if (name == L"." || name == L".." || name.back() == L'.' || name.back() == L' ' ||
            name.find_first_of(L"<>:\"|?*") != std::wstring::npos ||
            std::any_of(name.begin(), name.end(), [](wchar_t c) { return c < 32; }))
            error("拒绝路径穿越、ADS 或不规范路径组件");
    }
    // Avoid Win32 device-name normalization and path truncation surprises.
    if (text.size() > 240) error("部署路径超过保守安全上限 240 个 UTF-16 单元");
    result = result.lexically_normal();
    if (result.filename().empty()) result = result.parent_path();
    return result;
}

bool within(const fs::path& path, const fs::path& directory) {
    auto p = path.wstring(), d = directory.wstring();
    if (!d.empty() && d.back() != L'\\') d.push_back(L'\\');
    return same_path(path, directory) || (p.size() >= d.size() &&
        CompareStringOrdinal(p.data(), static_cast<int>(d.size()), d.data(),
                             static_cast<int>(d.size()), TRUE) == CSTR_EQUAL);
}

BY_HANDLE_FILE_INFORMATION information(HANDLE handle, const fs::path& path) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) win_error("读取文件身份失败", path);
    return info;
}

Bytes get_security(HANDLE handle, const fs::path& path) {
    DWORD length{};
    GetKernelObjectSecurity(handle, security_parts, nullptr, 0, &length);
    if (!length || length > 65536) win_error("安全描述符长度无效", path);
    Bytes data(length);
    if (!GetKernelObjectSecurity(handle, security_parts,
            reinterpret_cast<PSECURITY_DESCRIPTOR>(data.data()), length, &length))
        win_error("读取所有者/DACL 失败", path);
    return data;
}

void validate_sd(const Bytes& bytes) {
    if (bytes.size() < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || bytes.size() > 65536)
        error("备份安全描述符长度无效");
    SECURITY_DESCRIPTOR_RELATIVE sd{};
    std::memcpy(&sd, bytes.data(), sizeof(sd));
    constexpr WORD valid_control = SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_PRESENT |
        SE_DACL_DEFAULTED | SE_SACL_PRESENT | SE_SACL_DEFAULTED | inheritance_bits | SE_SELF_RELATIVE;
    if (sd.Revision != SECURITY_DESCRIPTOR_REVISION || sd.Sbz1 || !(sd.Control & SE_SELF_RELATIVE) ||
        (sd.Control & ~valid_control) || !(sd.Control & SE_DACL_PRESENT) ||
        !sd.Dacl || !sd.Owner || !sd.Group || (sd.Sacl && !(sd.Control & SE_SACL_PRESENT)))
        error("备份安全描述符 schema 无效（不支持空 DACL/额外控制位）");
    std::vector<std::pair<std::size_t, std::size_t>> regions;
    auto check_sid = [&](DWORD offset) -> std::size_t {
        if (offset % 4 || offset < sizeof(sd) || offset > bytes.size() || bytes.size() - offset < 8)
            error("SID 偏移越界");
        const auto p = reinterpret_cast<const unsigned char*>(bytes.data() + offset);
        const auto length = 8U + 4U * p[1];
        if (p[0] != SID_REVISION || p[1] > SID_MAX_SUB_AUTHORITIES || length > bytes.size() - offset)
            error("SID 长度无效");
        return length;
    };
    regions.emplace_back(sd.Owner, sd.Owner + check_sid(sd.Owner));
    if (sd.Group != sd.Owner) regions.emplace_back(sd.Group, sd.Group + check_sid(sd.Group));
    auto check_acl = [&](DWORD offset, bool sacl) {
        if (!offset) return;
        if (offset % 4 || offset < sizeof(sd) || offset > bytes.size() || bytes.size() - offset < sizeof(ACL))
            error("ACL 偏移越界");
        ACL acl{}; std::memcpy(&acl, bytes.data() + offset, sizeof(acl));
        if ((acl.AclRevision != ACL_REVISION && acl.AclRevision != ACL_REVISION_DS) || acl.Sbz1 || acl.Sbz2 ||
            acl.AclSize % 4 || acl.AclSize < sizeof(ACL) || acl.AclSize > bytes.size() - offset)
            error("ACL 长度/版本越界");
        regions.emplace_back(offset, offset + acl.AclSize);
        std::size_t pos = offset + sizeof(ACL); unsigned labels{};
        for (unsigned i = 0; i < acl.AceCount; ++i) {
            if (pos > offset + acl.AclSize || offset + acl.AclSize - pos < sizeof(ACE_HEADER)) error("ACE 头越界");
            ACE_HEADER ace{}; std::memcpy(&ace, bytes.data() + pos, sizeof(ace));
            if (ace.AceSize < 16 || ace.AceSize % 4 || ace.AceSize > offset + acl.AclSize - pos) error("ACE 长度越界");
            const bool audit = sacl && ace.AceType == SYSTEM_AUDIT_ACE_TYPE;
            const bool label = sacl && ace.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE;
            if ((!sacl && ace.AceType != ACCESS_ALLOWED_ACE_TYPE && ace.AceType != ACCESS_DENIED_ACE_TYPE) ||
                (sacl && !audit && !label) || (ace.AceFlags & ~(audit ? 0xdf : 0x1f)))
                error("不支持的 ACL ACE（拒绝对象/条件/回调/资源属性 ACE）");
            const auto sid_offset = pos + offsetof(ACCESS_ALLOWED_ACE, SidStart);
            const auto length = check_sid(static_cast<DWORD>(sid_offset));
            if (length != ace.AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart)) error("ACE SID 长度不匹配");
            if (label) {
                DWORD mask{}; std::memcpy(&mask, bytes.data() + pos + sizeof(ACE_HEADER), sizeof(mask));
                const SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
                const auto p = reinterpret_cast<const unsigned char*>(bytes.data() + sid_offset);
                if (++labels != 1 || p[1] != 1 || std::memcmp(p + 2, &authority, sizeof(authority)) ||
                    (mask & ~SYSTEM_MANDATORY_LABEL_VALID_MASK)) error("强制完整性 label SID/掩码无效");
            }
            pos += ace.AceSize;
        }
        if (!IsValidAcl(reinterpret_cast<PACL>(const_cast<std::byte*>(bytes.data()) + offset))) error("ACL 无效");
    };
    check_acl(sd.Dacl, false); check_acl(sd.Sacl, true);
    std::sort(regions.begin(), regions.end());
    for (std::size_t i = 1; i < regions.size(); ++i)
        if (regions[i].first < regions[i - 1].second) error("安全描述符字段重叠");
    if (!IsValidSecurityDescriptor(const_cast<std::byte*>(bytes.data())))
        error("备份安全描述符无效");
}

bool security_equal(const Bytes& left, const Bytes& right) {
    validate_sd(left); validate_sd(right);
    auto view = [](const Bytes& data) { return reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(data.data()); };
    const auto a = view(left), b = view(right);
    auto sid = [](const Bytes& data, DWORD offset) { return const_cast<std::byte*>(data.data()) + offset; };
    const auto acl_a = reinterpret_cast<const ACL*>(left.data() + a->Dacl);
    const auto acl_b = reinterpret_cast<const ACL*>(right.data() + b->Dacl);
    return EqualSid(sid(left, a->Owner), sid(right, b->Owner)) &&
        EqualSid(sid(left, a->Group), sid(right, b->Group)) &&
        ((a->Control ^ b->Control) & (inheritance_bits | SE_SACL_PRESENT | SE_SACL_DEFAULTED)) == 0 &&
        acl_a->AclSize == acl_b->AclSize && std::memcmp(acl_a, acl_b, acl_a->AclSize) == 0 &&
        ((!a->Sacl && !b->Sacl) || (a->Sacl && b->Sacl &&
         reinterpret_cast<const ACL*>(left.data() + a->Sacl)->AclSize == reinterpret_cast<const ACL*>(right.data() + b->Sacl)->AclSize &&
         std::memcmp(left.data() + a->Sacl, right.data() + b->Sacl,
                     reinterpret_cast<const ACL*>(left.data() + a->Sacl)->AclSize) == 0));
}

void require_trusted(HANDLE handle, const fs::path& path, bool system,
                     bool require_protected = true, bool allow_installer = false) {
    auto data = get_security(handle, path); validate_sd(data);
    const auto sd = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(data.data());
    if (require_protected && !(sd->Control & SE_DACL_PROTECTED))
        error("备份/互斥对象 DACL 未受继承保护：" + utf8(path.wstring()));
    auto user = current_user_sid();
    PSID installer_raw{};
    if (allow_installer && !ConvertStringSidToSidW(
        L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &installer_raw))
        win_error("创建 TrustedInstaller SID 失败", path);
    LocalPtr installer(installer_raw);
    auto trusted = [&](PSID sid) {
        return well_known(sid, WinLocalSystemSid) || well_known(sid, WinBuiltinAdministratorsSid) ||
               (installer_raw && EqualSid(sid, installer_raw)) ||
               (!system && EqualSid(sid, user.data()));
    };
    if (!trusted(data.data() + sd->Owner)) error("备份/互斥对象所有者不可信：" + utf8(path.wstring()));
    const auto acl = reinterpret_cast<ACL*>(data.data() + sd->Dacl);
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* raw{};
        if (!GetAce(acl, i, &raw)) error("读取备份 DACL ACE 失败");
        const auto header = static_cast<ACE_HEADER*>(raw);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) error("备份 DACL 含不支持的 ACE");
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if (header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8) error("备份 ACE 无效");
        auto sid = reinterpret_cast<PSID>(&ace->SidStart);
        const auto size = 8U + 4U * static_cast<SID*>(sid)->SubAuthorityCount;
        if (size > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart) || !IsValidSid(sid))
            error("备份 ACE SID 越界");
        constexpr DWORD mutation = GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER |
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD;
        if ((ace->Mask & mutation) && !trusted(sid))
            error("备份目录/文件允许非可信身份修改，拒绝使用：" + utf8(path.wstring()));
    }
}

// Native relative names are exactly one checked component. There is no full-path
// fallback: a directory's old DOS name must never redirect I/O to a new object.
std::wstring leaf_name(const fs::path& leaf) {
    const auto name = leaf.wstring();
    if (name.empty() || name == L"." || name == L".." || name.size() > 240 ||
        name.find_first_of(L"\\/:<>\"|?*") != name.npos || name.back() == L'.' || name.back() == L' ' ||
        std::any_of(name.begin(), name.end(), [](wchar_t c) { return c < 32; }))
        error("对象相对 I/O 只接受单个规范文件名");
    (void)utf8(name);
    auto stem = name.substr(0, name.find(L'.'));
    std::transform(stem.begin(), stem.end(), stem.begin(), [](wchar_t c) -> wchar_t {
        return c >= L'a' && c <= L'z' ? static_cast<wchar_t>(c - 32) : c;
    });
    if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" || stem == L"CONIN$" || stem == L"CONOUT$" ||
        (stem.size() == 4 && (stem.starts_with(L"COM") || stem.starts_with(L"LPT")) &&
         ((stem[3] >= L'1' && stem[3] <= L'9') || stem[3] == L'¹' || stem[3] == L'²' || stem[3] == L'³')))
        error("拒绝 DOS 设备名称");
    return name;
}

struct NativeApi {
    decltype(&::NtCreateFile) create{};
    decltype(&::RtlNtStatusToDosError) dos_error{};
    using SetInformation = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    SetInformation set_information{};
    decltype(&::NtQueryObject) query_object{};
    using QuerySecurity = NTSTATUS(NTAPI*)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG);
    QuerySecurity query_security{};
    NativeApi() {
        const auto module = GetModuleHandleW(L"ntdll.dll"); // Borrow the loaded system module, never search a DLL path.
        if (!module) win_error("获取系统 ntdll 失败", {});
        create = reinterpret_cast<decltype(create)>(GetProcAddress(module, "NtCreateFile"));
        dos_error = reinterpret_cast<decltype(dos_error)>(GetProcAddress(module, "RtlNtStatusToDosError"));
        set_information = reinterpret_cast<SetInformation>(GetProcAddress(module, "NtSetInformationFile"));
        query_object = reinterpret_cast<decltype(query_object)>(GetProcAddress(module, "NtQueryObject"));
        query_security = reinterpret_cast<QuerySecurity>(GetProcAddress(module, "NtQuerySecurityObject"));
        if (!create || !dos_error || !set_information) error("缺少目录对象相对 I/O 接口；拒绝不安全的路径回退");
    }
    [[noreturn]] void fail(const std::string& action, const fs::path& path, NTSTATUS status) const {
        error(action + "：" + utf8(path.wstring()) + " (NTSTATUS=" +
            std::to_string(static_cast<std::uint32_t>(status)) + ", Win32=" + std::to_string(dos_error(status)) + ")");
    }
};
const NativeApi& native_api() { static const NativeApi api; return api; }

struct NativeFile {
    Handle handle;
    ULONG_PTR result{};
    NTSTATUS status{};
    DWORD code() const { return status < 0 ? native_api().dos_error(status) : ERROR_SUCCESS; }
};
NativeFile relative_file(HANDLE parent, const fs::path& leaf, DWORD access, DWORD share,
                         ULONG disposition, bool directory, PSECURITY_DESCRIPTOR security = nullptr) {
    const auto name = leaf_name(leaf);
    UNICODE_STRING text{};
    text.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t)); text.MaximumLength = text.Length;
    text.Buffer = const_cast<wchar_t*>(name.data());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes); attributes.RootDirectory = parent; attributes.ObjectName = &text;
    attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE; attributes.SecurityDescriptor = security;
    IO_STATUS_BLOCK io{}; HANDLE raw{};
    const auto status = native_api().create(&raw, access | SYNCHRONIZE, &attributes, &io, nullptr,
        FILE_ATTRIBUTE_NORMAL, share, disposition, (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE) |
        FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    Handle handle(status >= 0 ? raw : INVALID_HANDLE_VALUE);
    if (status >= 0 && !handle.valid()) error("Native I/O 未返回有效句柄");
    if (status >= 0 && disposition == FILE_CREATE && io.Information != FILE_CREATED)
        error("Native I/O 未确认唯一创建；拒绝写入或删除未知对象");
    return {std::move(handle), io.Information, status};
}

// Handles pin directory *objects*, not their names. Every later lookup/creation
// and rename destination is relative to these objects, including backup children.
struct PinnedDirectory {
    fs::path path;
    std::vector<Handle> ancestors;
    PinnedDirectory(const fs::path& input, bool create = false, bool system = false) : path(checked_path(input)) {
        Security security(system);
        auto current = path.root_path();
        constexpr DWORD access = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
        constexpr DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        Handle root(CreateFileW(current.c_str(), access, sharing, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!root.valid()) win_error("打开卷根目录失败", current);
        check_directory(root.get(), current); ancestors.push_back(std::move(root));
        for (const auto& part : path.relative_path()) {
            const auto name = leaf_name(part); current /= name;
            auto opened = relative_file(get(), name, access, sharing, create ? FILE_OPEN_IF : FILE_OPEN,
                true, security.attributes.lpSecurityDescriptor);
            if (!opened.handle.valid()) native_api().fail("对象相对打开/创建目录失败", current, opened.status);
            check_directory(opened.handle.get(), current); ancestors.push_back(std::move(opened.handle));
        }
        check_location();
    }
    // The caller retains the already verified parent object throughout this child lifetime.
    PinnedDirectory(const PinnedDirectory& parent, const fs::path& leaf, Handle child)
        : path(checked_path(parent.path / leaf_name(leaf))) {
        check_directory(child.get(), path); ancestors.push_back(std::move(child)); check_location();
    }
    static void check_directory(HANDLE handle, const fs::path& diagnostic) {
        const auto info = information(handle, diagnostic);
        if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            error("拒绝目录联接/重解析点：" + utf8(diagnostic.wstring()));
        if (GetFileType(handle) != FILE_TYPE_DISK) error("目录不是磁盘对象");
    }
    void check_location() const {
        check_directory(get(), path);
        std::array<wchar_t, 32768> resolved{};
        const auto n = GetFinalPathNameByHandleW(get(), resolved.data(), static_cast<DWORD>(resolved.size()),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (!n || n >= resolved.size() || !same_path(resolved.data(), fs::path(L"\\\\?\\" + path.wstring())))
            error("已绑定目录被改名/路径已变化；拒绝继续：" + utf8(path.wstring()));
    }
    HANDLE get() const { return ancestors.back().get(); }
};

void require_backup_attributes(const PinnedDirectory& directory) {
    const auto attributes = information(directory.get(), directory.path).dwFileAttributes;
    if (attributes & ~(supported_attributes | FILE_ATTRIBUTE_DIRECTORY))
        error("备份目录含不支持的可继承属性（压缩/加密等）；不改变目录设置，目标未修改：" + utf8(directory.path.wstring()));
}

struct Identity {
    std::uint32_t volume{};
    std::uint64_t file{};
    bool operator==(const Identity&) const = default;
};
Identity identity(HANDLE handle, const fs::path& path) {
    auto i = information(handle, path);
    return {i.dwVolumeSerialNumber, (std::uint64_t(i.nFileIndexHigh) << 32) | i.nFileIndexLow};
}

void require_ntfs(HANDLE handle, const fs::path& path) {
    std::array<wchar_t, 32> name{};
    if (!GetVolumeInformationByHandleW(handle, nullptr, 0, nullptr, nullptr, nullptr,
                                      name.data(), static_cast<DWORD>(name.size())))
        win_error("查询受控目录文件系统失败", path);
    if (_wcsicmp(name.data(), L"NTFS") != 0)
        error("部署仅支持本地 NTFS（需要可靠 ACL、文件身份及删除语义）：" + utf8(path.wstring()));
}

struct SaclSnapshot {
    WORD control{};
    Bytes acl;
    bool operator==(const SaclSnapshot&) const = default;
};
thread_local std::vector<fs::path> simulated_targets;
thread_local std::vector<std::pair<Identity, SaclSnapshot>> simulated_sacls;

bool simulated(const fs::path& path, bool system) {
    if (system) return false;
    return std::any_of(simulated_targets.begin(), simulated_targets.end(), [&](const auto& target) {
        return same_path(path.parent_path(), target) &&
            (same_path(path.filename(), file_names[0]) || same_path(path.filename(), file_names[1]));
    });
}
struct Observation {
    Identity target;
    deploy_testing::Observer callback{};
    void* context{};
};
thread_local Observation observation;
thread_local bool observing{};
void observe(const PinnedDirectory& target, bool system, deploy_testing::ObservationPoint point, const fs::path& subject) {
    if (system || observing || !observation.callback || !simulated(target.path / file_names[0], false) ||
        identity(target.get(), target.path) != observation.target) return;
    struct Guard { Guard() { observing = true; } ~Guard() { observing = false; } } guard;
    observation.callback(point, subject, observation.context);
}
SaclSnapshot sacl_part(const Bytes& data) {
    validate_sd(data);
    const auto sd = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(data.data());
    SaclSnapshot result;
    result.control = sd->Control & (SE_SACL_PRESENT | SE_SACL_DEFAULTED | SE_SACL_PROTECTED |
                                    SE_SACL_AUTO_INHERITED | SE_SACL_AUTO_INHERIT_REQ);
    if (sd->Sacl) {
        const auto acl = reinterpret_cast<const ACL*>(data.data() + sd->Sacl);
        result.acl.assign(data.begin() + sd->Sacl, data.begin() + sd->Sacl + acl->AclSize);
    }
    return result;
}
void store_sacl(HANDLE handle, const fs::path& path, SaclSnapshot sacl) {
    const auto id = identity(handle, path);
    for (auto& item : simulated_sacls) if (item.first == id) { item.second = std::move(sacl); return; }
    simulated_sacls.emplace_back(id, std::move(sacl));
}
Bytes combine_sacl(const Bytes& base, const SaclSnapshot& sacl) {
    validate_sd(base);
    const auto sd = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(base.data());
    auto p = const_cast<std::byte*>(base.data());
    SECURITY_DESCRIPTOR absolute{};
    if (!InitializeSecurityDescriptor(&absolute, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(&absolute, p + sd->Owner, (sd->Control & SE_OWNER_DEFAULTED) != 0) ||
        !SetSecurityDescriptorGroup(&absolute, p + sd->Group, (sd->Control & SE_GROUP_DEFAULTED) != 0) ||
        !SetSecurityDescriptorDacl(&absolute, TRUE, reinterpret_cast<PACL>(p + sd->Dacl), (sd->Control & SE_DACL_DEFAULTED) != 0) ||
        !SetSecurityDescriptorSacl(&absolute, (sacl.control & SE_SACL_PRESENT) != 0,
            sacl.acl.empty() ? nullptr : reinterpret_cast<PACL>(const_cast<std::byte*>(sacl.acl.data())),
            (sacl.control & SE_SACL_DEFAULTED) != 0) ||
        !SetSecurityDescriptorControl(&absolute, inheritance_bits, (sd->Control &
            (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ)) | (sacl.control & inheritance_bits)))
        win_error("构造完整模拟安全描述符失败", {});
    DWORD length{}; MakeSelfRelativeSD(&absolute, nullptr, &length);
    if (!length || length > 65536) error("完整安全描述符长度无效");
    Bytes result(length);
    if (!MakeSelfRelativeSD(&absolute, reinterpret_cast<PSECURITY_DESCRIPTOR>(result.data()), &length))
        win_error("序列化完整模拟安全描述符失败", {});
    validate_sd(result); return result;
}
void fault(deploy_testing::FailurePoint point, bool system);
Bytes get_full_security(HANDLE handle, const fs::path& path, bool system, const char* phase) {
    fault(deploy_testing::FailurePoint::full_security_read, system);
    if (simulated(path, system)) {
        const auto id = identity(handle, path);
        SaclSnapshot sacl;
        for (const auto& item : simulated_sacls) if (item.first == id) { sacl = item.second; break; }
        return combine_sacl(get_security(handle, path), sacl);
    }
    const auto& api = native_api();
    const std::string context = std::string("phase=") + phase + "; SecurityInfo=" +
        hex32(deploy_detail::full_security_information);
    if (!api.query_object)
        win_error("完整安全读取[handle_access]缺少 NtQueryObject；" + context, path, ERROR_PROC_NOT_FOUND);
    PUBLIC_OBJECT_BASIC_INFORMATION info{}; ULONG length{};
    const auto access_status = api.query_object(handle, ObjectBasicInformation, &info, sizeof(info), &length);
    if (access_status < 0) api.fail("完整安全读取[handle_access]；" + context, path, access_status);
    const auto detail = context + "; GrantedAccess=" + hex32(info.GrantedAccess) +
        "; RequiredAccess=" + hex32(deploy_detail::full_security_access);
    auto queried = deploy_detail::query_full_security(info.GrantedAccess,
        [&](SECURITY_INFORMATION flags) {
            deploy_detail::SecurityQueryAttempt attempt;
            PSECURITY_DESCRIPTOR raw{};
            attempt.code = GetSecurityInfo(handle, SE_FILE_OBJECT, flags, nullptr, nullptr, nullptr, nullptr, &raw);
            LocalPtr holder(raw);
            if (attempt.code != ERROR_SUCCESS) return attempt; // Never inspect failed output.
            if (!raw) { attempt.code = ERROR_INVALID_SECURITY_DESCR; return attempt; }
            const auto size = GetSecurityDescriptorLength(raw);
            if (size < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || size > 65536) {
                attempt.code = ERROR_INVALID_SECURITY_DESCR; return attempt;
            }
            attempt.descriptor.resize(size);
            std::memcpy(attempt.descriptor.data(), raw, size);
            return attempt;
        },
        [&](SECURITY_INFORMATION flags) {
            deploy_detail::SecurityQueryAttempt attempt;
            if (!api.query_security) { attempt.code = ERROR_PROC_NOT_FOUND; return attempt; }
            // NTFS's documented upper bound. One call, no sizing race, path
            // reopen, privilege retry, or reduction of requested information.
            attempt.descriptor.resize(65536);
            ULONG needed{};
            attempt.native_status = api.query_security(handle, flags,
                reinterpret_cast<PSECURITY_DESCRIPTOR>(attempt.descriptor.data()),
                static_cast<ULONG>(attempt.descriptor.size()), &needed);
            attempt.has_native_status = true;
            if (attempt.native_status < 0) {
                attempt.code = api.dos_error(attempt.native_status);
                attempt.descriptor.clear(); return attempt;
            }
            if (needed < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || needed > attempt.descriptor.size()) {
                attempt.code = ERROR_INVALID_SECURITY_DESCR; attempt.descriptor.clear(); return attempt;
            }
            attempt.descriptor.resize(needed);
            return attempt;
        });
    if (!queried.access_complete)
        win_error("完整安全读取[handle_access]句柄实际权限不完整；需在打开前获得权限，不在旧句柄上提权；" +
            detail + "; " + safe_security_token_diagnostic(), path, ERROR_ACCESS_DENIED);
    const auto& final = queried.final_attempt();
    if (final.code != ERROR_SUCCESS) {
        std::string failure = "完整安全读取[GetSecurityInfo] Win32=" + std::to_string(queried.primary.code);
        if (queried.native_attempted) {
            failure += "; 完整安全读取[NtQuerySecurityObject] Win32=" + std::to_string(final.code);
            if (final.has_native_status) failure += "; NTSTATUS=" + hex32(static_cast<DWORD>(final.native_status));
        }
        win_error(failure + "; " + detail + "; " + safe_security_token_diagnostic(), path, final.code);
    }
    // The same bounded schema validates both full-query paths. Do not merge
    // partial projections or substitute an absent/NULL SACL after a failed read.
    try { validate_sd(final.descriptor); }
    catch (const std::exception& ex) {
        error(std::string("完整安全读取[validate_descriptor]；") + detail + "; API=" +
            (queried.native_attempted ? "NtQuerySecurityObject" : "GetSecurityInfo") +
            "; GetSecurityInfo_Win32=" + std::to_string(queried.primary.code) +
            "；" + utf8(path.wstring()) + "；" + ex.what());
    }
    return std::move(queried.native_attempted ? queried.native.descriptor : queried.primary.descriptor);
}

bool higher_integrity_label(const Bytes& data) {
    validate_sd(data);
    const auto sd = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(data.data());
    if (!sd->Sacl) return false;
    const auto acl = reinterpret_cast<const ACL*>(data.data() + sd->Sacl);
    DWORD wanted{};
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* raw{}; if (!GetAce(const_cast<ACL*>(acl), i, &raw)) error("读取 label ACE 失败");
        if (static_cast<ACE_HEADER*>(raw)->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
            auto sid = reinterpret_cast<SID*>(&static_cast<SYSTEM_MANDATORY_LABEL_ACE*>(raw)->SidStart);
            wanted = sid->SubAuthority[0];
        }
    }
    if (!wanted) return false;
    HANDLE raw{};
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        if (GetLastError() != ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
            win_error("查询当前完整性令牌失败", {});
    }
    Handle token(raw); DWORD length{};
    GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &length);
    if (!length || length > 65536) error("完整性令牌长度无效");
    Bytes bytes(length);
    if (!GetTokenInformation(token.get(), TokenIntegrityLevel, bytes.data(), length, &length))
        win_error("查询当前完整性级别失败", {});
    const auto sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(bytes.data())->Label.Sid;
    if (!IsValidSid(sid) || !*GetSidSubAuthorityCount(sid)) error("当前完整性 SID 无效");
    return wanted > *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
}

bool owner_assignable_without_restore(PSID owner) {
    HANDLE raw{};
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        if (GetLastError() != ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
            win_error("查询可分配所有者失败", {});
    }
    Handle token(raw);
    auto info = [&](TOKEN_INFORMATION_CLASS type) {
        DWORD length{}; GetTokenInformation(token.get(), type, nullptr, 0, &length);
        if (!length || length > 65536) error("所有者令牌长度超过安全上限");
        Bytes result(length);
        if (!GetTokenInformation(token.get(), type, result.data(), length, &length)) win_error("查询所有者令牌失败", {});
        return result;
    };
    auto user = info(TokenUser);
    if (EqualSid(owner, reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid)) return true;
    auto groups = info(TokenGroups);
    const auto list = reinterpret_cast<TOKEN_GROUPS*>(groups.data());
    for (DWORD i = 0; i < list->GroupCount; ++i)
        if ((list->Groups[i].Attributes & SE_GROUP_OWNER) && !(list->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) &&
            EqualSid(owner, list->Groups[i].Sid)) return true;
    return false;
}

class Mutex {
    Handle handle_;
    bool held_{};
public:
    Mutex(Identity id, bool system) {
        const auto name = L"Global\\LexHelper.Deploy." + std::to_wstring(id.volume) + L"." + std::to_wstring(id.file);
        Security security(system);
        handle_ = Handle(CreateMutexW(&security.attributes, FALSE, name.c_str()));
        if (!handle_.valid()) win_error("无法创建/打开部署互斥锁", name);
        require_trusted(handle_.get(), name, system);
        const auto result = WaitForSingleObject(handle_.get(), 0);
        held_ = result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
        if (result == WAIT_ABANDONED) {
            ReleaseMutex(handle_.get()); held_ = false;
            error("检测到上次部署异常中断；请先核对备份与目标状态，拒绝自动继续");
        }
        if (!held_) error("另一个进程正在部署/备份/恢复（未等待、未修改文件）");
    }
    ~Mutex() { if (held_) ReleaseMutex(handle_.get()); }
};

std::array<std::byte, 32> sha256(std::span<const std::byte> input) {
    std::array<std::byte, 32> result{};
    if (input.size() > std::numeric_limits<ULONG>::max() || BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(input.data())), static_cast<ULONG>(input.size()),
        reinterpret_cast<PUCHAR>(result.data()), static_cast<ULONG>(result.size())) < 0)
        error("SHA-256 计算失败");
    return result;
}

Bytes read_bytes(HANDLE handle, const fs::path& path, std::uint64_t limit = max_file_size) {
    LARGE_INTEGER size{}, start{};
    if (!GetFileSizeEx(handle, &size)) win_error("读取文件长度失败", path);
    if (size.QuadPart < 0 || std::uint64_t(size.QuadPart) > limit)
        error("文件超出安全长度上限：" + utf8(path.wstring()));
    if (!SetFilePointerEx(handle, start, nullptr, FILE_BEGIN)) win_error("定位读取失败", path);
    Bytes bytes(static_cast<std::size_t>(size.QuadPart));
    std::size_t position{};
    while (position < bytes.size()) {
        DWORD count{};
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - position, 1024 * 1024));
        if (!ReadFile(handle, bytes.data() + position, chunk, &count, nullptr)) win_error("读取文件失败", path);
        if (count != chunk) error("读取短于预期：" + utf8(path.wstring()) + " (" + std::to_string(count) + "/" + std::to_string(chunk) + ")");
        position += count;
    }
    return bytes;
}

void require_single_stream(HANDLE handle, const fs::path& path) {
    Bytes storage(65536);
    if (!GetFileInformationByHandleEx(handle, FileStreamInfo, storage.data(), static_cast<DWORD>(storage.size()))) {
        if (GetLastError() == ERROR_HANDLE_EOF) return; // An empty unnamed stream may not be enumerated.
        win_error("无法安全枚举文件数据流", path);
    }
    std::size_t offset{};
    for (;;) {
        constexpr auto header = offsetof(FILE_STREAM_INFO, StreamName);
        if (offset > storage.size() || storage.size() - offset < header) error("文件数据流列表越界");
        const auto stream = reinterpret_cast<const FILE_STREAM_INFO*>(storage.data() + offset);
        if (stream->StreamNameLength % sizeof(wchar_t) || stream->StreamNameLength > storage.size() - offset - header)
            error("文件数据流名称越界");
        const std::wstring name(stream->StreamName, stream->StreamNameLength / sizeof(wchar_t));
        if (name != L"::$DATA") error("拒绝未备份的命名数据流/ADS：" + utf8(path.wstring()));
        if (!stream->NextEntryOffset) break;
        if (stream->NextEntryOffset < header || stream->NextEntryOffset % alignof(FILE_STREAM_INFO) ||
            stream->NextEntryOffset > storage.size() - offset) error("文件数据流偏移越界");
        offset += stream->NextEntryOffset;
    }
}

Handle open_regular(const PinnedDirectory& parent, const fs::path& leaf, DWORD access, bool optional, Privileges& privileges,
                    bool system, bool trusted = false, bool controlled_target = false, DWORD share_override = MAXDWORD) {
    const auto path = parent.path / leaf_name(leaf); // diagnostics / fake SACL routing only
    if (controlled_target && !simulated(path, system)) access |= ACCESS_SYSTEM_SECURITY;
    const bool audit_access = (access & ACCESS_SYSTEM_SECURITY) != 0;
    // Mutation excludes readers as well: no new IME reader may observe a partial stream.
    const DWORD sharing = share_override != MAXDWORD ? share_override : ((access & (FILE_WRITE_DATA | DELETE)) ? 0 : FILE_SHARE_READ);
    NativeFile opened;
    std::string failures;
    auto open = [&] {
        opened = relative_file(parent.get(), leaf, access | FILE_READ_ATTRIBUTES, sharing, FILE_OPEN, false);
        if (!opened.handle.valid()) failures += "; NtCreateFile_NTSTATUS=" + hex32(static_cast<DWORD>(opened.status)) +
            "/Win32=" + std::to_string(opened.code());
        return std::move(opened.handle);
    };
    auto diagnostic = [&] {
        return std::string("完整安全/文件访问[file_open]；RequestedAccess=") +
            hex32(access | FILE_READ_ATTRIBUTES | SYNCHRONIZE) + failures + "; " + safe_security_token_diagnostic();
    };
    auto request_privilege = [&](auto request) {
        try { request(); }
        catch (const std::exception& ex) {
            error(std::string(ex.what()) + "\n" + diagnostic() + "；访问文件：" + utf8(path.wstring()));
        }
    };
    Handle handle = open();
    if (!handle.valid()) {
        auto code = opened.code();
        if (optional && code == ERROR_FILE_NOT_FOUND) return {};
        if (audit_access && (code == ERROR_ACCESS_DENIED || code == ERROR_PRIVILEGE_NOT_HELD)) {
            request_privilege([&] { privileges.security(system); }); handle = open(); code = opened.code();
        }
        if (!handle.valid() && code == ERROR_ACCESS_DENIED && system) {
            if (access & (DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES)) {
                request_privilege([&] { privileges.enable_names(system, {SE_RESTORE_NAME}); }); handle = open();
            }
            if (!handle.valid() && opened.code() == ERROR_ACCESS_DENIED) {
                request_privilege([&] { privileges.enable_names(system, {SE_BACKUP_NAME}); }); handle = open();
            }
        }
        if (!handle.valid()) native_api().fail(diagnostic(), path, opened.status);
    }
    const auto info = information(handle.get(), path);
    if (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) ||
        info.nNumberOfLinks == 0 || (!controlled_target && info.nNumberOfLinks != 1))
        error("拒绝目录、重解析点或多硬链接文件：" + utf8(path.wstring()));
    if (info.dwFileAttributes & ~supported_attributes)
        error("不支持的文件属性（压缩/稀疏/加密等），拒绝部署：" + utf8(path.wstring()));
    require_single_stream(handle.get(), path);
    if (trusted) require_trusted(handle.get(), path, system);
    return handle;
}

struct State {
    bool present{};
    std::uint64_t size{};
    std::array<std::byte, 32> hash{};
    Bytes security;
    FILE_BASIC_INFO basic{};
    Bytes bytes;
};

State snapshot(HANDLE handle, const fs::path& path, bool system, const char* phase) {
    State state;
    if (handle == INVALID_HANDLE_VALUE || !handle) return state;
    state.present = true;
    state.bytes = read_bytes(handle, path); state.size = state.bytes.size(); state.hash = sha256(state.bytes);
    state.security = get_full_security(handle, path, system, phase); validate_sd(state.security);
    if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &state.basic, sizeof(state.basic)))
        win_error("读取文件属性失败", path);
    return state;
}

bool equivalent(const State& a, const State& b) {
    return a.present == b.present && (!a.present || (a.size == b.size && a.hash == b.hash &&
        a.basic.FileAttributes == b.basic.FileAttributes && security_equal(a.security, b.security)));
}

struct Files {
    std::array<Handle, 2> handles;
    std::array<State, 2> states;
    Files(const PinnedDirectory& target, bool writable, Privileges& privileges, bool system) {
        for (std::size_t i = 0; i < 2; ++i) {
            DWORD access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL;
            if (writable) access |= DELETE;
            handles[i] = open_regular(target, file_names[i], access, true, privileges, system, false, true);
            if (system && handles[i].valid()) require_trusted(handles[i].get(), target.path / file_names[i], true, false, true);
            states[i] = snapshot(handles[i].get(), target.path / file_names[i], system, "source_snapshot");
        }
        if (!states[0].present) error("目标缺少 ChsWubi.lex，拒绝向未知目录部署");
    }
};

void write_all(HANDLE handle, const Bytes& bytes, const fs::path& path) {
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN)) win_error("定位写入失败", path);
    std::size_t position{};
    while (position < bytes.size()) {
        DWORD count{};
        auto chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - position, 1024 * 1024));
        if (!WriteFile(handle, bytes.data() + position, chunk, &count, nullptr)) win_error("写入失败", path);
        if (count != chunk) error("写入短于预期：" + utf8(path.wstring()) + " (" + std::to_string(count) + "/" + std::to_string(chunk) + ")");
        position += count;
    }
    if (!SetEndOfFile(handle) || !FlushFileBuffers(handle)) win_error("截断/落盘失败", path);
    if (sha256(read_bytes(handle, path)) != sha256(bytes)) error("写后 SHA-256 校验失败：" + utf8(path.wstring()));
}

void set_security(HANDLE handle, const State& state, const fs::path& path, Privileges& privileges, bool system) {
    const auto before = get_full_security(handle, path, system, "stage_before_security_apply");
    if (security_equal(before, state.security)) return;
    const bool changed_sacl = sacl_part(before) != sacl_part(state.security);
    const auto old = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(before.data());
    const auto sd = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(state.security.data());
    const bool fake = simulated(path, system);
    auto previous = const_cast<std::byte*>(before.data());
    auto wanted = const_cast<std::byte*>(state.security.data());
    SECURITY_INFORMATION parts{};
    if (!EqualSid(previous + old->Owner, wanted + sd->Owner)) parts |= OWNER_SECURITY_INFORMATION;
    if (!EqualSid(previous + old->Group, wanted + sd->Group)) parts |= GROUP_SECURITY_INFORMATION;
    const auto old_acl = reinterpret_cast<const ACL*>(previous + old->Dacl);
    const auto new_acl = reinterpret_cast<const ACL*>(wanted + sd->Dacl);
    constexpr WORD dacl_inheritance = SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ;
    if (((old->Control ^ sd->Control) & dacl_inheritance) || old_acl->AclSize != new_acl->AclSize ||
        std::memcmp(old_acl, new_acl, old_acl->AclSize) != 0)
        parts |= DACL_SECURITY_INFORMATION | ((sd->Control & SE_DACL_PROTECTED) ?
            PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
    if (!fake && changed_sacl)
        parts |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | ((sd->Control & SE_SACL_PROTECTED) ?
            PROTECTED_SACL_SECURITY_INFORMATION : UNPROTECTED_SACL_SECURITY_INFORMATION);
    // SetSecurityInfo is an automatic-inheritance API: even a protected DACL can
    // acquire SE_DACL_AUTO_INHERITED when rewritten. Do not touch an already exact
    // native DACL just to change another component (including a simulated SACL).
    auto apply = [&] {
        if (!parts) return DWORD{ERROR_SUCCESS};
        return SetSecurityInfo(handle, SE_FILE_OBJECT, parts,
            (parts & OWNER_SECURITY_INFORMATION) ? wanted + sd->Owner : nullptr,
            (parts & GROUP_SECURITY_INFORMATION) ? wanted + sd->Group : nullptr,
            (parts & DACL_SECURITY_INFORMATION) ? reinterpret_cast<PACL>(wanted + sd->Dacl) : nullptr,
            (parts & SACL_SECURITY_INFORMATION) && sd->Sacl ? reinterpret_cast<PACL>(wanted + sd->Sacl) : nullptr);
    };
    auto status = apply();
    if (status != ERROR_SUCCESS) {
        if (!system || (status != ERROR_ACCESS_DENIED && status != ERROR_PRIVILEGE_NOT_HELD &&
                        status != ERROR_INVALID_OWNER && status != ERROR_INVALID_PRIMARY_GROUP))
            win_error("恢复完整安全元数据失败", path, status);
        privileges.enable_names(system, {SE_RESTORE_NAME});
        status = apply();
        if ((status == ERROR_ACCESS_DENIED || status == ERROR_PRIVILEGE_NOT_HELD) && higher_integrity_label(state.security)) {
            privileges.relabel(system); status = apply();
        }
        if (status != ERROR_SUCCESS) win_error("恢复完整安全元数据失败", path, status);
    }
    if (fake) store_sacl(handle, path, sacl_part(state.security));
    if (changed_sacl) fault(deploy_testing::FailurePoint::after_sacl_restore, system);
    if (!security_equal(get_full_security(handle, path, system, "stage_security_verify"), state.security))
        error("完整 Owner/DACL/SACL/label 及保护/继承控制位写后校验失败：" + utf8(path.wstring()));
}

thread_local deploy_testing::FailurePoint failure_point = deploy_testing::FailurePoint::none;
thread_local bool fail_rollback = false;
void fault(deploy_testing::FailurePoint point, bool system) {
    if (!system && failure_point == point) {
        failure_point = deploy_testing::FailurePoint::none;
        error("模拟部署故障注入（尚未报告成功）");
    }
}

// A fixed binary schema: no manifest-supplied names or filesystem paths are ever used.
struct Writer {
    Bytes data;
    void u32(std::uint32_t value) { for (unsigned i = 0; i < 4; ++i) data.push_back(std::byte((value >> (i * 8)) & 255)); }
    void u64(std::uint64_t value) { u32(static_cast<std::uint32_t>(value)); u32(static_cast<std::uint32_t>(value >> 32)); }
    void raw(std::span<const std::byte> value) { data.insert(data.end(), value.begin(), value.end()); }
    void state(const State& value) {
        u32(value.present ? 1 : 0);
        if (!value.present) return;
        u64(value.size); raw(value.hash);
        u32(value.basic.FileAttributes);
        for (const auto t : {value.basic.CreationTime, value.basic.LastAccessTime, value.basic.LastWriteTime, value.basic.ChangeTime})
            u64(static_cast<std::uint64_t>(t.QuadPart));
        u32(full_security_marker);
        u32(static_cast<std::uint32_t>(value.security.size())); raw(value.security);
    }
};

struct Reader {
    const Bytes& data; std::size_t position{};
    std::span<const std::byte> take(std::size_t n) {
        if (position > data.size() || n > data.size() - position) error("备份清单截断/长度越界");
        auto result = std::span(data).subspan(position, n); position += n; return result;
    }
    std::uint32_t u32() {
        auto bytes = take(4); std::uint32_t v{};
        for (unsigned i = 0; i < 4; ++i) v |= std::uint32_t(std::to_integer<unsigned>(bytes[i])) << (i * 8);
        return v;
    }
    std::uint64_t u64() { auto lo = u32(); return lo | (std::uint64_t(u32()) << 32); }
    State state() {
        State value; const auto flag = u32();
        if (flag > 1) error("备份存在性标记无效");
        value.present = flag != 0; if (!value.present) return value;
        value.size = u64(); if (value.size > max_file_size) error("备份文件大小超过上限");
        auto hash = take(value.hash.size()); std::copy(hash.begin(), hash.end(), value.hash.begin());
        value.basic.FileAttributes = u32();
        if (!value.basic.FileAttributes || value.basic.FileAttributes & ~supported_attributes)
            error("备份文件属性无效");
        for (auto* t : {&value.basic.CreationTime, &value.basic.LastAccessTime, &value.basic.LastWriteTime, &value.basic.ChangeTime}) {
            const auto time = u64(); if (time > std::uint64_t(std::numeric_limits<LONGLONG>::max())) error("备份时间无效");
            t->QuadPart = static_cast<LONGLONG>(time);
        }
        if (u32() != full_security_marker) error("备份未证明已完整采集 SACL/label");
        const auto length = u32(); if (length > 65536) error("安全描述符过长");
        const auto sd = take(length); value.security.assign(sd.begin(), sd.end()); validate_sd(value.security);
        return value;
    }
};

constexpr std::uint32_t magic = 0x4248584c; // LXHB
struct Manifest {
    Identity target;
    bool system{};
    std::array<State, 2> original;
    std::array<State, 2> expected;
    Bytes serialize() const {
        Writer writer; writer.u32(magic); writer.u32(2); writer.u32(system ? 1 : 0);
        writer.u32(target.volume); writer.u64(target.file);
        for (const auto& s : original) writer.state(s);
        for (const auto& s : expected) writer.state(s);
        const auto digest = sha256(writer.data); writer.raw(digest); return writer.data;
    }
    static Manifest parse(const Bytes& bytes) {
        if (bytes.size() < 56 || bytes.size() > max_manifest_size) error("备份清单长度无效");
        const auto body = std::span(bytes).first(bytes.size() - 32);
        const auto digest = sha256(body);
        if (!std::equal(digest.begin(), digest.end(), bytes.end() - 32)) error("备份清单 SHA-256 不匹配");
        Reader r{bytes};
        if (r.u32() != magic || r.u32() != 2) error("不支持的备份清单 schema（仅接受完整元数据 v2，拒绝旧 v1）");
        Manifest m; auto mode = r.u32(); if (mode > 1) error("备份模式无效"); m.system = mode != 0;
        m.target.volume = r.u32(); m.target.file = r.u64();
        for (auto& s : m.original) s = r.state();
        for (auto& s : m.expected) s = r.state();
        if (r.position != bytes.size() - 32 || !m.original[0].present || !m.expected[0].present)
            error("备份清单尾部/主文件存在性无效");
        return m;
    }
};

struct VerifiedBackup {
    PinnedDirectory directory;
    Manifest manifest;
    std::array<Handle, 3> files; // Retain restore-readable files, excluding writes/deletes until the operation ends.
};

VerifiedBackup load_backup(PinnedDirectory directory, Identity target, bool system, Privileges& privileges) {
    directory.check_location();
    require_backup_attributes(directory);
    require_trusted(directory.get(), directory.path, system);
    VerifiedBackup result{std::move(directory), {}, {}};
    auto& pinned = result.directory;
    result.files[2] = open_regular(pinned, L"manifest.lhb", FILE_READ_DATA | READ_CONTROL, false, privileges, system, true);
    result.manifest = Manifest::parse(read_bytes(result.files[2].get(), pinned.path / L"manifest.lhb", max_manifest_size));
    auto& manifest = result.manifest;
    if (manifest.target != target || manifest.system != system)
        error("备份不属于当前目标目录身份/运行模式（目录被重建也不接受）");
    for (std::size_t i = 0; i < 2; ++i) {
        result.files[i] = open_regular(pinned, payload_names[i], FILE_READ_DATA | READ_CONTROL, true, privileges, system, true);
        auto& handle = result.files[i];
        if (handle.valid() != manifest.original[i].present) error("备份载荷存在性与清单不符");
        if (handle.valid()) {
            auto bytes = read_bytes(handle.get(), pinned.path / payload_names[i]);
            if (bytes.size() != manifest.original[i].size || sha256(bytes) != manifest.original[i].hash)
                error("备份内容 SHA-256/大小不匹配；目标未修改");
            manifest.original[i].bytes = std::move(bytes);
        }
    }
    return result;
}

void create_backup_file(const PinnedDirectory& directory, const fs::path& name, const Bytes& bytes, Security& security) {
    auto opened = relative_file(directory.get(), name, FILE_WRITE_DATA | FILE_READ_DATA | READ_CONTROL,
        0, FILE_CREATE, false, security.attributes.lpSecurityDescriptor);
    if (!opened.handle.valid()) native_api().fail("创建不可覆盖备份文件失败", directory.path / name, opened.status);
    write_all(opened.handle.get(), bytes, directory.path / name);
}

VerifiedBackup persist_backup(const PinnedDirectory& root, const PinnedDirectory& target,
                              const Manifest& manifest, Privileges& privileges) {
    root.check_location(); require_backup_attributes(root);
    const auto manifest_bytes = manifest.serialize();
    (void)Manifest::parse(manifest_bytes); // Never install with a self-produced but unrestorable backup.
    Security security(manifest.system);
    std::optional<PinnedDirectory> pinned;
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        std::array<unsigned char, 16> random{};
        if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            error("生成备份唯一标识失败");
        constexpr wchar_t digits[] = L"0123456789abcdef";
        std::wstring name = L"backup-";
        for (const auto byte : random) { name += digits[byte >> 4]; name += digits[byte & 15]; }
        auto opened = relative_file(root.get(), name, FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, true, security.attributes.lpSecurityDescriptor);
        if (opened.handle.valid()) { pinned.emplace(root, name, std::move(opened.handle)); break; }
        if (opened.code() != ERROR_ALREADY_EXISTS && opened.code() != ERROR_FILE_EXISTS)
            native_api().fail("创建唯一备份目录失败", root.path / name, opened.status);
    }
    if (!pinned) error("无法分配唯一备份目录");
    const auto directory = pinned->path;
    try {
        observe(target, manifest.system, deploy_testing::ObservationPoint::backup_directory_created, directory);
        require_backup_attributes(*pinned);
        require_trusted(pinned->get(), directory, manifest.system);
        observe(target, manifest.system, deploy_testing::ObservationPoint::backup_directory_ready, directory);
        for (std::size_t i = 0; i < 2; ++i)
            if (manifest.original[i].present) create_backup_file(*pinned, payload_names[i], manifest.original[i].bytes, security);
        // The manifest is written last; a failed preparation can never be accepted as complete.
        create_backup_file(*pinned, L"manifest.lhb", manifest_bytes, security);
        observe(target, manifest.system, deploy_testing::ObservationPoint::backup_files_written, directory);
        // Validate actual on-disk attributes/streams/ACL/link count and all payloads
        // using the SAME reader as restore, not merely the intended manifest bytes.
        auto verified = load_backup(std::move(*pinned), manifest.target, manifest.system, privileges);
        if (verified.manifest.serialize() != manifest_bytes) error("落盘备份清单与待保存状态不一致");
        observe(target, manifest.system, deploy_testing::ObservationPoint::backup_validated, directory);
        root.check_location(); verified.directory.check_location();
        return verified;
    } catch (const std::exception& ex) {
        error(std::string(ex.what()) + "；未完成备份保留于 " + utf8(directory.wstring()) + "，目标尚未修改");
    }
}

struct Context {
    DeployOptions options;
    Privileges privileges; // destroyed after every file handle and before returning to the caller
    PinnedDirectory target;
    Identity id;
    Mutex mutex;
    PinnedDirectory root;
    explicit Context(const DeployOptions& opt) : options(opt), target(opt.target_directory),
        id(identity(target.get(), target.path)), mutex(id, opt.system_mode),
        root(opt.backup_root, true, opt.system_mode) {
        require_ntfs(target.get(), target.path);
        require_ntfs(root.get(), root.path);
        require_backup_attributes(root);
        require_trusted(root.get(), root.path, opt.system_mode);
        if (opt.system_mode) {
            require_trusted(target.get(), target.path, true, false, true);
            // The application-owned parent must not be a user-created ProgramData squatter.
            if (root.ancestors.size() < 2) error("备份根目录层级无效");
            require_trusted(root.ancestors[root.ancestors.size() - 2].get(), root.path.parent_path(), true);
        }
        observe(target, opt.system_mode, deploy_testing::ObservationPoint::directories_bound, target.path);
    }
    void check_locations() const { target.check_location(); root.check_location(); }
};

fs::path sibling_name(const fs::path& target, const wchar_t* role) {
    std::array<unsigned char, 16> random{};
    if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        error("生成事务制品名称失败");
    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring name = L"LexHelper-"; name += role; name += L"-";
    for (auto b : random) { name += hex[b >> 4]; name += hex[b & 15]; }
    return checked_path(target / (name + L".tmp"));
}

void require_absent(const PinnedDirectory& parent, const fs::path& leaf) {
    auto opened = relative_file(parent.get(), leaf, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, false);
    if (opened.handle.valid() || opened.code() != ERROR_FILE_NOT_FOUND)
        error("拒绝覆盖/删除新出现的未知目录项：" + utf8((parent.path / leaf).wstring()));
}

void require_owned_name(const PinnedDirectory& parent, HANDLE handle, const fs::path& leaf) {
    auto opened = relative_file(parent.get(), leaf, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, false);
    if (!opened.handle.valid()) native_api().fail("核对对象相对目录项失败", parent.path / leaf, opened.status);
    if (identity(opened.handle.get(), parent.path / leaf) != identity(handle, parent.path / leaf))
        error("已绑定目录中的目录项身份与持有句柄不一致：" + utf8((parent.path / leaf).wstring()));
}

void rename_owned(const PinnedDirectory& parent, HANDLE handle, const fs::path& from, const fs::path& to) {
    require_owned_name(parent, handle, from);
    const auto text = leaf_name(to);
    const auto length = text.size() * sizeof(wchar_t);
    // SDK winternl.h omits this WDK-documented structure/class. Use its public
    // Native layout explicitly, without any Win32 full-path conversion.
    struct RenameInformation { BOOLEAN ReplaceIfExists; HANDLE RootDirectory; ULONG FileNameLength; WCHAR FileName[1]; };
    static_assert(offsetof(RenameInformation, FileName) == 20 && sizeof(void*) == 8);
    Bytes buffer(sizeof(RenameInformation) + length);
    auto info = reinterpret_cast<RenameInformation*>(buffer.data());
    info->ReplaceIfExists = FALSE; info->RootDirectory = parent.get();
    info->FileNameLength = static_cast<DWORD>(length);
    std::memcpy(info->FileName, text.data(), length);
    IO_STATUS_BLOCK io{};
    constexpr auto rename_class = static_cast<FILE_INFORMATION_CLASS>(10); // FileRenameInformation
    const auto status = native_api().set_information(handle, &io, info, static_cast<ULONG>(buffer.size()), rename_class);
    if (status < 0) native_api().fail("目录对象相对重命名失败（不覆盖）", parent.path / to, status);
}

void disposition_owned(HANDLE handle, const fs::path& path, bool remove) {
    // Never clear READONLY on an old multi-linked object: even attributes are shared
    // with WinSxS. Non-POSIX delete-pending is reversible until the handle closes.
    FILE_DISPOSITION_INFO_EX info{};
    info.Flags = remove ? FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE : 0;
    if (!SetFileInformationByHandle(handle, FileDispositionInfoEx, &info, sizeof(info)))
        win_error(remove ? "标记受控旁路目录项待删除失败" : "撤销旁路目录项待删除失败", path);
}

struct Replacement {
    std::array<Handle, 2> staged;
    std::array<fs::path, 2> stage_paths;
    std::array<bool, 2> installed{}, created{};
};

void prepare_stage(Context& c, Replacement& tx, std::size_t i, const State& desired) {
    if (!desired.present) return;
    const auto logical = c.target.path / file_names[i];
    tx.stage_paths[i] = sibling_name(c.target.path, L"stage");
    const bool fake = simulated(logical, c.options.system_mode);
    // Create the native object with the exact owner/group/DACL/control state.
    // The fake backend substitutes only SACL/label; replacing the entire native
    // descriptor with a generic private DACL used to force a later DACL rewrite,
    // converting a valid legacy protected 0x9004 descriptor to 0x9404.
    const auto creation_security = fake ? combine_sacl(desired.security, {}) : desired.security;
    const auto sd = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(desired.security.data());
    if (!fake && !owner_assignable_without_restore(const_cast<std::byte*>(desired.security.data()) + sd->Owner))
        c.privileges.enable_names(c.options.system_mode, {SE_RESTORE_NAME});
    DWORD access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
        READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE | (fake ? 0 : ACCESS_SYSTEM_SECURITY);
    NativeFile opened;
    auto create = [&] {
        opened = relative_file(c.target.get(), tx.stage_paths[i].filename(), access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, false,
            const_cast<std::byte*>(creation_security.data()));
        return std::move(opened.handle);
    };
    tx.staged[i] = create();
    DWORD creation_error = opened.code();
    if (!tx.staged[i].valid() && !fake && c.options.system_mode &&
        (creation_error == ERROR_ACCESS_DENIED || creation_error == ERROR_PRIVILEGE_NOT_HELD ||
         creation_error == ERROR_INVALID_OWNER || creation_error == ERROR_INVALID_PRIMARY_GROUP)) {
        c.privileges.enable_names(c.options.system_mode, {SE_RESTORE_NAME});
        tx.staged[i] = create();
        creation_error = opened.code();
        if (!tx.staged[i].valid() &&
            (creation_error == ERROR_ACCESS_DENIED || creation_error == ERROR_PRIVILEGE_NOT_HELD) &&
            higher_integrity_label(desired.security)) {
            // Only a demonstrated write-up failure can justify SeRelabelPrivilege.
            c.privileges.relabel(c.options.system_mode); tx.staged[i] = create();
            creation_error = opened.code();
        }
    }
    if (!tx.staged[i].valid()) native_api().fail("创建唯一完整元数据暂存制品失败，目标未修改", tx.stage_paths[i], opened.status);
    tx.created[i] = true;
    if (fake) store_sacl(tx.staged[i].get(), logical, {});
    write_all(tx.staged[i].get(), desired.bytes, tx.stage_paths[i]);
    fault(deploy_testing::FailurePoint::before_security_restore, c.options.system_mode);
    set_security(tx.staged[i].get(), desired, logical, c.privileges, c.options.system_mode);
    const auto id = identity(tx.staged[i].get(), tx.stage_paths[i]);
    // Retain a second, metadata-only file object before closing the writer. A
    // WRITE_DATA file object can cause NTFS to set ARCHIVE during cleanup after
    // rename. There is no unpinned staging gap: both handles refer to the same ID.
    // System staging DACL and parent ACL have already excluded untrusted mutation.
    auto metadata = open_regular(c.target, tx.stage_paths[i].filename(), FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
        READ_CONTROL | DELETE | (fake ? 0 : ACCESS_SYSTEM_SECURITY),
        false, c.privileges, c.options.system_mode, false, false, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    if (identity(metadata.get(), tx.stage_paths[i]) != id) error("暂存制品身份被替换，目标未修改");
    if (!FlushFileBuffers(tx.staged[i].get())) win_error("暂存数据/安全元数据落盘失败", tx.stage_paths[i]);
    tx.staged[i] = std::move(metadata);
    auto basic = desired.basic;
    if (!SetFileInformationByHandle(tx.staged[i].get(), FileBasicInfo, &basic, sizeof(basic)))
        win_error("暂存制品最终属性设置失败", tx.stage_paths[i]);
    if (!equivalent(snapshot(tx.staged[i].get(), logical, c.options.system_mode, "prepared_stage_snapshot"), desired))
        error("暂存制品完整内容/安全元数据校验失败：" + utf8(tx.stage_paths[i].wstring()));
}

void execute_transaction(Context& c, Files& files, const std::array<State, 2>& desired, const VerifiedBackup& backup) {
    Replacement tx, undo;
    std::array<bool, 2> touched{}, pending_undo{}, rolled_back{};
    auto unlink_exact = [&](Handle& handle, const fs::path& path) {
        require_owned_name(c.target, handle.get(), path.filename());
        FILE_DISPOSITION_INFO_EX info{};
        info.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
                     FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        if (!SetFileInformationByHandle(handle.get(), FileDispositionInfoEx, &info, sizeof(info)))
            win_error("无法仅移除已固定的 CHS 目录项（未写共享实体）", path);
        handle.reset(); // POSIX removes this opened link when this file object closes.
    };
    auto final_attributes = [&](HANDLE handle, const State& state, const fs::path& path) {
        auto basic = state.basic;
        if (!SetFileInformationByHandle(handle, FileBasicInfo, &basic, sizeof(basic)))
            win_error("恢复新建目录项的最终属性失败", path);
    };
    try {
        fault(deploy_testing::FailurePoint::after_backup, c.options.system_mode);
        // Prepare both forward and rollback objects before removing any CHS link.
        // The original inode is never renamed or written: even rename can cause
        // NTFS to mark its shared ARCHIVE attribute. Rollback restores content and
        // full security, not the old WinSxS hard-link topology.
        for (std::size_t i = 0; i < 2; ++i) {
            prepare_stage(c, tx, i, desired[i]);
            prepare_stage(c, undo, i, files.states[i]);
        }
        observe(c.target, c.options.system_mode, deploy_testing::ObservationPoint::stages_prepared, c.target.path);
        c.check_locations(); backup.directory.check_location();
        for (std::size_t i = 0; i < 2; ++i) {
            const auto path = c.target.path / file_names[i];
            if (files.handles[i].valid()) {
                unlink_exact(files.handles[i], path); touched[i] = true;
            } else require_absent(c.target, path.filename());
            if (i == 0) observe(c.target, c.options.system_mode, deploy_testing::ObservationPoint::primary_unlinked, c.target.path);
            fault(i == 0 ? deploy_testing::FailurePoint::after_primary_unlink :
                          deploy_testing::FailurePoint::after_new_unlink, c.options.system_mode);
            if (desired[i].present) {
                rename_owned(c.target, tx.staged[i].get(), tx.stage_paths[i].filename(), path.filename()); tx.installed[i] = true;
                touched[i] = true;
                final_attributes(tx.staged[i].get(), desired[i], path);
            } else require_absent(c.target, path.filename());
            if (i == 0) observe(c.target, c.options.system_mode, deploy_testing::ObservationPoint::primary_installed, c.target.path);
            fault(i == 0 ? deploy_testing::FailurePoint::after_primary_write :
                          deploy_testing::FailurePoint::after_new_disabled, c.options.system_mode);
        }
        for (std::size_t i = 0; i < 2; ++i) {
            const auto path = c.target.path / file_names[i];
            if (desired[i].present) {
                require_owned_name(c.target, tx.staged[i].get(), path.filename());
                if (!equivalent(snapshot(tx.staged[i].get(), path, c.options.system_mode, "committed_target_snapshot"), desired[i]))
                    error("目录项提交后完整状态不匹配");
            } else require_absent(c.target, path.filename());
        }
        c.check_locations(); backup.directory.check_location();
        // No original source inode is disposed here. Only our independently
        // allocated unused rollback copies are marked pending, reversibly.
        for (std::size_t i = 0; i < 2; ++i) if (undo.staged[i].valid()) {
            disposition_owned(undo.staged[i].get(), undo.stage_paths[i], true); pending_undo[i] = true;
            if (i == 0) fault(deploy_testing::FailurePoint::after_first_cleanup_mark, c.options.system_mode);
        }
        for (std::size_t i = 0; i < 2; ++i) if (pending_undo[i]) undo.staged[i].reset();
        return;
    } catch (const std::exception& ex) {
        const std::string original_error = ex.what();
        std::string rollback_errors;
        const bool injected = !c.options.system_mode && std::exchange(fail_rollback, false);
        for (std::size_t i = 0; i < 2; ++i) {
            const auto path = c.target.path / file_names[i];
            try {
                if (pending_undo[i]) {
                    disposition_owned(undo.staged[i].get(), undo.stage_paths[i], false); pending_undo[i] = false;
                }
                if (injected && i == 0) error("模拟回滚失败");
                if (touched[i]) {
                    if (tx.installed[i]) { unlink_exact(tx.staged[i], path); tx.installed[i] = false; }
                    if (files.states[i].present) {
                        rename_owned(c.target, undo.staged[i].get(), undo.stage_paths[i].filename(), path.filename()); undo.installed[i] = true;
                        final_attributes(undo.staged[i].get(), files.states[i], path);
                    } else require_absent(c.target, path.filename());
                }
                if (files.states[i].present) {
                    const auto handle = touched[i] ? undo.staged[i].get() : files.handles[i].get();
                    require_owned_name(c.target, handle, path.filename());
                    if (!equivalent(snapshot(handle, path, c.options.system_mode, "rollback_snapshot"), files.states[i]))
                        error("原对象内容/完整安全元数据回滚校验失败");
                } else require_absent(c.target, path.filename());
                rolled_back[i] = true;
            } catch (const std::exception& rollback) {
                rollback_errors += "\n" + utf8(path.wstring()) + "：" + rollback.what() +
                    "；受保护恢复副本=" + utf8(undo.stage_paths[i].wstring());
            }
        }
        std::string artifacts;
        for (std::size_t i = 0; i < 2; ++i) for (const auto* item : {&tx, &undo})
            if (!item->stage_paths[i].empty() && !item->created[i])
                artifacts += "\n未能确认创建的制品路径（不按路径删除未知对象）：" + utf8(item->stage_paths[i].wstring());
        for (std::size_t i = 0; i < 2; ++i) for (auto* item : {&tx, &undo})
            if (item->staged[i].valid() && !item->installed[i] && (item != &undo || rolled_back[i] || !touched[i])) {
                try { disposition_owned(item->staged[i].get(), item->stage_paths[i], true); item->staged[i].reset(); }
                catch (const std::exception& cleanup) { artifacts += "\n暂存制品保留：" + utf8(item->stage_paths[i].wstring()) + "；" + cleanup.what(); }
            }
        error(original_error + "\n备份/恢复点：" + utf8(backup.directory.path.wstring()) + "\n目标：" + utf8(c.target.path.wstring()) +
            (rollback_errors.empty() ? "\n已校验回滚到操作前的内容、存在性及完整安全元数据。" :
             "\n警告：回滚不完整，绝非全部恢复！请勿继续安装；需人工核对/恢复：" + rollback_errors) + artifacts);
    }
}

} // namespace

namespace deploy_testing {
void inject_failure(FailurePoint point, bool rollback_failure) noexcept {
    failure_point = point; fail_rollback = rollback_failure;
}
void enable_security_simulation(const fs::path& target_directory) {
    const auto target = checked_path(target_directory);
    const fs::path base = L"D:\\temp\\aiRunner\\opencode";
    if (!within(target, base)) error("完整安全元数据模拟仅接受专用 D 盘测试目录");
    const auto relative = target.lexically_relative(base);
    const auto first = relative.begin()->wstring();
    const bool test_root = first.size() == 55 && first.starts_with(L"LexHelper-deploy-tests-") &&
        first.substr(23).find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    const std::wstring fix_prefix = L"LexHelper-fix-backup-";
    const bool fix_root = first.size() == fix_prefix.size() + 47 && first.starts_with(fix_prefix) &&
        first.substr(fix_prefix.size(), 14).find_first_not_of(L"0123456789") == std::wstring::npos &&
        first[fix_prefix.size() + 14] == L'-' && first.substr(fix_prefix.size() + 15).find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    if (!test_root && !fix_root) error("安全元数据模拟要求唯一、规范命名的 D 盘测试/备份修复沙箱");
    PinnedDirectory pin(target);
    auto security = get_security(pin.get(), target);
    const auto sd = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(security.data());
    auto user = current_user_sid();
    if (!EqualSid(security.data() + sd->Owner, user.data())) error("只能注册当前用户拥有的测试目录");
    if (!simulated(target / file_names[0], false)) simulated_targets.push_back(target);
}
void set_simulated_sacl(const fs::path& file, std::span<const std::byte> descriptor) {
    const auto path = checked_path(file);
    if (!simulated(path, false)) error("目标未显式注册为测试沙箱");
    Bytes data(descriptor.begin(), descriptor.end()); validate_sd(data);
    PinnedDirectory pin(path.parent_path()); Privileges privileges;
    auto handle = open_regular(pin, path.filename(), FILE_READ_DATA | READ_CONTROL, false, privileges, false, false, true);
    store_sacl(handle.get(), path, sacl_part(data));
}
std::vector<std::byte> simulated_security(const fs::path& file) {
    const auto path = checked_path(file);
    if (!simulated(path, false)) error("目标未显式注册为测试沙箱");
    PinnedDirectory pin(path.parent_path()); Privileges privileges;
    auto handle = open_regular(pin, path.filename(), FILE_READ_DATA | READ_CONTROL, false, privileges, false, false, true);
    return get_full_security(handle.get(), path, false, "simulation_read");
}
void set_observer(const fs::path& registered_target, Observer callback, void* context) {
    if (!callback) { observation = {}; return; }
    const auto target = checked_path(registered_target);
    if (!simulated(target / file_names[0], false)) error("观察点只接受已显式注册的 D 盘模拟目录");
    PinnedDirectory pin(target);
    auto security = get_security(pin.get(), target);
    const auto sd = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(security.data());
    auto user = current_user_sid();
    if (!EqualSid(security.data() + sd->Owner, user.data())) error("观察点目录必须由当前用户拥有");
    observation = {identity(pin.get(), target), callback, context};
}
}

fs::path system_lex_directory() {
    std::array<wchar_t, 32768> windows{};
    const auto n = GetSystemWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
    if (!n || n >= windows.size()) win_error("获取 Windows 系统目录失败", {});
    return checked_path(fs::path(windows.data()) / L"InputMethod" / L"CHS");
}

fs::path default_backup_root() {
    PWSTR raw{};
    const auto hr = SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &raw);
    if (FAILED(hr)) error("获取 ProgramData 失败，HRESULT=" + std::to_string(hr));
    struct Free { void operator()(wchar_t* p) const { CoTaskMemFree(p); } };
    std::unique_ptr<wchar_t, Free> holder(raw);
    return checked_path(fs::path(raw) / L"LexHelper" / L"Backups");
}

Deployer::Deployer(DeployOptions options) : options_(std::move(options)) {
    options_.target_directory = checked_path(options_.target_directory);
    options_.backup_root = checked_path(options_.backup_root);
    const auto system = system_lex_directory();
    if (options_.system_mode) {
        if (!same_path(options_.target_directory, system) || !same_path(options_.backup_root, default_backup_root()))
            error("系统模式只允许 Windows API 指定的词库目录及默认受保护备份目录");
        if (!is_admin()) error("真实系统部署必须由用户明确确认并以管理员身份运行");
    } else if (within(options_.target_directory, fs::path(system.root_path()) /
                   system.relative_path().begin()->native())) {
        // Simulation must never reach the Windows tree, even when run elevated.
        error("模拟模式禁止 Windows 目录；真实部署必须显式启用 system_mode");
    }
    if (within(options_.target_directory, options_.backup_root) || within(options_.backup_root, options_.target_directory))
        error("备份根目录与目标目录不得重叠");
}

fs::path Deployer::backup() {
    Context c(options_);
    Files files(c.target, false, c.privileges, options_.system_mode);
    auto saved = persist_backup(c.root, c.target, {c.id, options_.system_mode, files.states, files.states}, c.privileges);
    c.check_locations();
    return saved.directory.path;
}

fs::path Deployer::install(const fs::path& generated_lex) {
    const auto source = checked_path(generated_lex);
    if (within(source, options_.target_directory) || within(source, options_.backup_root))
        error("输入 lex 不得位于受控目标/备份目录（拒绝输入输出 alias）");
    PinnedDirectory source_parent(source.parent_path());
    Context c(options_);
    observe(c.target, options_.system_mode, deploy_testing::ObservationPoint::source_bound, source_parent.path);
    auto input = open_regular(source_parent, source.filename(), FILE_READ_DATA | READ_CONTROL, false, c.privileges, false);
    auto bytes = read_bytes(input.get(), source);
    const auto entries = read_lex(bytes);
    if (entries.empty()) error("拒绝安装空码表");
    Files files(c.target, true, c.privileges, options_.system_mode);
    auto desired = files.states;
    desired[0].bytes = std::move(bytes); desired[0].size = desired[0].bytes.size(); desired[0].hash = sha256(desired[0].bytes);
    desired[1] = {};
    auto backup = persist_backup(c.root, c.target, {c.id, options_.system_mode, files.states, desired}, c.privileges);
    source_parent.check_location(); c.check_locations(); backup.directory.check_location();
    execute_transaction(c, files, desired, backup);
    return backup.directory.path;
}

void Deployer::restore(const fs::path& backup_directory) {
    const auto directory = checked_path(backup_directory);
    if (!same_path(directory.parent_path(), options_.backup_root) || directory.filename().wstring().size() != 39 ||
        directory.filename().wstring().substr(0, 7) != L"backup-" ||
        directory.filename().wstring().substr(7).find_first_not_of(L"0123456789abcdef") != std::wstring::npos)
        error("仅接受当前备份根目录内、本程序唯一命名的直接子目录");
    Context c(options_);
    // Keep the selected backup directory pinned until the full transaction is finished.
    auto opened = relative_file(c.root.get(), directory.filename(), FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, true);
    if (!opened.handle.valid()) native_api().fail("打开选定备份目录失败", directory, opened.status);
    PinnedDirectory selected_directory(c.root, directory.filename(), std::move(opened.handle));
    observe(c.target, options_.system_mode, deploy_testing::ObservationPoint::selected_backup_bound, directory);
    auto selected = load_backup(std::move(selected_directory), c.id, options_.system_mode, c.privileges);
    auto& manifest = selected.manifest;
    Files files(c.target, true, c.privileges, options_.system_mode);
    bool is_original = true, is_expected = true;
    for (std::size_t i = 0; i < 2; ++i) {
        is_original = is_original && equivalent(files.states[i], manifest.original[i]);
        is_expected = is_expected && equivalent(files.states[i], manifest.expected[i]);
    }
    if (!is_original && !is_expected)
        error("当前内容/存在性/权限不匹配备份的原态或预期部署态；拒绝覆盖/删除无关新文件");
    auto recovery = persist_backup(c.root, c.target, {c.id, options_.system_mode, files.states, manifest.original}, c.privileges);
    c.check_locations(); selected.directory.check_location(); recovery.directory.check_location();
    execute_transaction(c, files, manifest.original, recovery);
}

} // namespace lexhelper
