// Explicit, separately authorized diagnostic; NOT the application / Deployer.
// Include the real implementation without hooks or linking lexhelper_deploy.
#include "../src/deploy/deploy.cpp"
#include <iostream>
#include <string_view>

namespace native_probe {
using lexhelper::Handle;
using lexhelper::Bytes;
namespace fs = std::filesystem;
constexpr std::wstring_view prefix = L"D:\\temp\\aiRunner\\opencode\\LexHelper-admin-fullsecurity-";
constexpr DWORD full_access = READ_CONTROL | ACCESS_SYSTEM_SECURITY | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
constexpr DWORD low_access = READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
constexpr DWORD directory_access = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
constexpr ULONG open_by_id = 0x00002000;

void check(bool ok, const char* what) { if (!ok) throw std::runtime_error(what); }
void wincheck(BOOL ok, const char* what) {
    if (!ok) throw std::runtime_error(std::string(what) + "; Win32=" + std::to_string(GetLastError()));
}
[[noreturn]] void unsafe_token() noexcept {
    RaiseFailFastException(nullptr, nullptr, 0);
    TerminateProcess(GetCurrentProcess(), ERROR_PRIVILEGE_NOT_HELD);
    std::terminate();
}
bool allowed_root(std::wstring_view text) {
    // Deliberately exact casing, separators, lowercase hex; no normalization.
    return text.size() == prefix.size() + 32 && text.starts_with(prefix) &&
        std::all_of(text.begin() + prefix.size(), text.end(), [](wchar_t c) {
            return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
        });
}
enum class Mode { invalid, self_test, diagnose };
Mode parse(const std::vector<std::wstring_view>& args) {
    if (args.size() == 1 && args[0] == L"--self-test") return Mode::self_test;
    if (args.size() == 3 && args[0] == L"--diagnose" && args[1] == L"--root" && allowed_root(args[2]))
        return Mode::diagnose;
    return Mode::invalid;
}
std::wstring random_leaf() {
    std::array<unsigned char, 16> bytes{};
    check(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0,
        "random generator failed");
    std::wstring text = L"fixture-";
    for (auto b : bytes) { text += L"0123456789abcdef"[b >> 4]; text += L"0123456789abcdef"[b & 15]; }
    return text;
}

// Compare the ENTIRE privilege list and TokenId, not only the three named bits.
struct Token {
    bool thread{};
    LUID id{};
    Bytes privileges;
    bool operator==(const Token& b) const {
        return thread == b.thread && id.LowPart == b.id.LowPart && id.HighPart == b.id.HighPart && privileges == b.privileges;
    }
};
Token read_token(HANDLE h, bool thread) {
    Token t; t.thread = thread;
    TOKEN_STATISTICS statistics{}; DWORD n{};
    wincheck(GetTokenInformation(h, TokenStatistics, &statistics, sizeof(statistics), &n), "TokenStatistics");
    check(n == sizeof(statistics), "TokenStatistics size"); t.id = statistics.TokenId;
    SetLastError(ERROR_SUCCESS);
    check(!GetTokenInformation(h, TokenPrivileges, nullptr, 0, &n) && GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
        n >= offsetof(TOKEN_PRIVILEGES, Privileges) && n <= 65536, "TokenPrivileges sizing");
    t.privileges.resize(n);
    wincheck(GetTokenInformation(h, TokenPrivileges, t.privileges.data(), n, &n), "TokenPrivileges");
    check(n <= t.privileges.size() && n >= offsetof(TOKEN_PRIVILEGES, Privileges), "TokenPrivileges result size");
    t.privileges.resize(n);
    const auto p = reinterpret_cast<const TOKEN_PRIVILEGES*>(t.privileges.data());
    check(p->PrivilegeCount <= (n - offsetof(TOKEN_PRIVILEGES, Privileges)) / sizeof(LUID_AND_ATTRIBUTES), "TokenPrivileges count");
    return t;
}
Token process_token() {
    HANDLE raw{}; wincheck(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "OpenProcessToken query");
    Handle h(raw); return read_token(h.get(), false);
}
Token effective_token() {
    HANDLE raw{};
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) { Handle h(raw); return read_token(h.get(), true); }
    check(GetLastError() == ERROR_NO_TOKEN, "OpenThreadToken query failed"); return process_token();
}
LUID privilege_id(const wchar_t* name) {
    LUID id{}; wincheck(LookupPrivilegeValueW(nullptr, name, &id), "LookupPrivilegeValue"); return id;
}
bool same_id(LUID a, LUID b) { return a.LowPart == b.LowPart && a.HighPart == b.HighPart; }
std::optional<DWORD> privilege(const Token& t, const wchar_t* name) {
    const auto id = privilege_id(name);
    const auto p = reinterpret_cast<const TOKEN_PRIVILEGES*>(t.privileges.data());
    for (DWORD i = 0; i != p->PrivilegeCount; ++i) if (same_id(p->Privileges[i].Luid, id)) return p->Privileges[i].Attributes;
    return std::nullopt;
}
std::string token_text(const Token& t) {
    std::string text = std::string(t.thread ? "thread" : "process") + "; TokenId=" +
        lexhelper::hex32(static_cast<DWORD>(t.id.HighPart)) + ":" + lexhelper::hex32(t.id.LowPart) + "; privileges=";
    const auto p = reinterpret_cast<const TOKEN_PRIVILEGES*>(t.privileges.data());
    for (DWORD i = 0; i != p->PrivilegeCount; ++i) {
        const auto& v = p->Privileges[i];
        text += "[" + lexhelper::hex32(static_cast<DWORD>(v.Luid.HighPart)) + ":" + lexhelper::hex32(v.Luid.LowPart) +
            "=" + lexhelper::hex32(v.Attributes) + "]";
    }
    for (const auto name : {SE_SECURITY_NAME, SE_BACKUP_NAME, SE_RESTORE_NAME}) {
        const auto state = privilege(t, name);
        text += "; " + lexhelper::utf8(name) + "=" + (!state ? "absent" : ((*state & SE_PRIVILEGE_ENABLED) ? "enabled" : "disabled"));
    }
    return text;
}
void verify_restore(const Token& effective, const Token& process) noexcept {
    try { if (effective_token() == effective && process_token() == process) return; } catch (...) {}
    unsafe_token(); // An uncertain privileged context cannot return normally.
}
struct TokenInvariant {
    Token effective{effective_token()}, process{process_token()};
    ~TokenInvariant() { verify_restore(effective, process); }
};
bool elevated() {
    HANDLE raw{}; wincheck(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "OpenProcessToken elevation");
    Handle h(raw); TOKEN_ELEVATION e{}; DWORD n{};
    wincheck(GetTokenInformation(h.get(), TokenElevation, &e, sizeof(e), &n), "TokenElevation");
    check(n == sizeof(e), "TokenElevation size");
    return e.TokenIsElevated != 0 && lexhelper::is_admin();
}

struct Object {
    Handle h;
    fs::path path; // Diagnostic only; never used to reopen a child.
    lexhelper::Identity id;
    bool directory{};
};
BY_HANDLE_FILE_INFORMATION inspect(HANDLE h, bool directory, const fs::path& path) {
    BY_HANDLE_FILE_INFORMATION i{};
    wincheck(GetFileInformationByHandle(h, &i), "GetFileInformationByHandle");
    check(GetFileType(h) == FILE_TYPE_DISK, "not a disk object");
    constexpr DWORD common = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY;
    check(!(i.dwFileAttributes & ~(common | (directory ? FILE_ATTRIBUTE_DIRECTORY : 0))) &&
        !!(i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory, "unsupported attributes / reparse / wrong object type");
    check(directory || i.nNumberOfLinks == 1, "fixture/report has unexpected hard links");
    std::array<wchar_t, 1024> actual{};
    const auto n = GetFinalPathNameByHandleW(h, actual.data(), static_cast<DWORD>(actual.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    check(n && n < actual.size() && lexhelper::same_path(actual.data(), fs::path(L"\\\\?\\" + path.wstring())),
        "bound object location changed / not exact D: location");
    return i;
}
Object object(Handle h, const fs::path& path, bool directory) {
    const auto i = inspect(h.get(), directory, path);
    return {std::move(h), path, {i.dwVolumeSerialNumber, (std::uint64_t(i.nFileIndexHigh) << 32) | i.nFileIndexLow}, directory};
}
void verify(const Object& o) {
    const auto i = inspect(o.h.get(), o.directory, o.path);
    check(o.id == lexhelper::Identity{i.dwVolumeSerialNumber, (std::uint64_t(i.nFileIndexHigh) << 32) | i.nFileIndexLow},
        "bound object identity changed");
}
// No FILE_OPEN_IF, overwrite, delete, rename, security-update or string fallback.
Handle relative(HANDLE parent, std::wstring_view leaf, DWORD access, ULONG disposition, bool directory,
    PSECURITY_DESCRIPTOR sd = nullptr) {
    const auto name = lexhelper::leaf_name(fs::path(leaf));
    UNICODE_STRING text{}; text.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    text.MaximumLength = text.Length; text.Buffer = const_cast<wchar_t*>(name.data());
    OBJECT_ATTRIBUTES oa{}; oa.Length = sizeof(oa); oa.RootDirectory = parent; oa.ObjectName = &text;
    oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE; oa.SecurityDescriptor = sd;
    IO_STATUS_BLOCK io{}; HANDLE raw{};
    const auto status = lexhelper::native_api().create(&raw, access, &oa, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, disposition, (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE) |
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    Handle result(raw);
    if (status != 0) throw std::runtime_error("relative NtCreateFile; NTSTATUS=" + lexhelper::hex32(static_cast<DWORD>(status)) +
        "; Win32=" + std::to_string(lexhelper::native_api().dos_error(status)));
    check(result.valid() && io.Status == 0 && io.Information == (disposition == FILE_CREATE ? FILE_CREATED : FILE_OPENED),
        "relative NtCreateFile completion contract");
    return result;
}
void empty_root(HANDLE root) {
    using QueryDirectory = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
        FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
    const auto query = reinterpret_cast<QueryDirectory>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile"));
    check(query != nullptr, "NtQueryDirectoryFile unavailable");
    struct Name { ULONG next, index, bytes; WCHAR text[1]; };
    alignas(8) std::array<std::byte, 1024> buffer{};
    for (unsigned count = 0; count != 4; ++count) {
        IO_STATUS_BLOCK io{};
        const auto status = query(root, nullptr, nullptr, nullptr, &io, buffer.data(), static_cast<ULONG>(buffer.size()),
            static_cast<FILE_INFORMATION_CLASS>(12), TRUE, nullptr, count == 0);
        if (status == static_cast<NTSTATUS>(0x80000006UL)) return; // STATUS_NO_MORE_FILES
        check(status == 0 && io.Status == 0 && io.Information >= offsetof(Name, text) && io.Information <= buffer.size(),
            "root enumeration failed");
        const auto entry = reinterpret_cast<const Name*>(buffer.data());
        check(entry->next == 0 && !(entry->bytes % sizeof(wchar_t)) && entry->bytes <= io.Information - offsetof(Name, text),
            "root enumeration length invalid");
        const std::wstring_view name(entry->text, entry->bytes / sizeof(wchar_t));
        check(name == L"." || name == L"..", "root is not empty; refusing unknown/pre-existing object");
    }
    throw std::runtime_error("root enumeration did not terminate");
}
class Boundary {
    std::vector<Object> directories_;
public:
    explicit Boundary(const fs::path& path) {
        check(allowed_root(path.wstring()), "root syntax rejected");
        check(GetDriveTypeW(L"D:\\") == DRIVE_FIXED, "D: is not a fixed local drive");
        Handle drive(CreateFileW(L"D:\\", directory_access, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        wincheck(drive.valid(), "open D: root");
        directories_.push_back(object(std::move(drive), L"D:\\", true));
        lexhelper::require_ntfs(get(), L"D:\\");
        auto current = path.root_path();
        for (const auto& part : path.relative_path()) {
            current /= part;
            const bool target = lexhelper::same_path(current, path);
            auto h = relative(get(), part.wstring(), directory_access | (target ? FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY : 0), FILE_OPEN, true);
            directories_.push_back(object(std::move(h), current, true));
            check(directories_.back().id.volume == directories_.front().id.volume, "directory changed volume");
        }
        // Parent pre-created root must have this user's owner SID and a protected,
        // supported DACL with no mutation grants to identities other than user/SY/BA.
        auto sd = lexhelper::get_security(get(), path); lexhelper::validate_sd(sd);
        const auto relative_sd = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(sd.data());
        const auto user = lexhelper::current_user_sid();
        check(EqualSid(sd.data() + relative_sd->Owner, const_cast<std::byte*>(user.data())) != FALSE, "root owner is not current user");
        lexhelper::require_trusted(get(), path, false, true);
        check_all(); empty_root(get());
    }
    HANDLE get() const { return directories_.back().h.get(); }
    const fs::path& path() const { return directories_.back().path; }
    void check_all() const { for (const auto& d : directories_) verify(d); }
    Object make(std::wstring_view leaf, bool directory) const {
        check_all(); lexhelper::Security security(false);
        auto h = relative(get(), leaf, directory ? directory_access | FILE_ADD_FILE :
            FILE_READ_DATA | FILE_WRITE_DATA | low_access, FILE_CREATE, directory, security.attributes.lpSecurityDescriptor);
        auto made = object(std::move(h), path() / leaf, directory);
        check(made.id.volume == directories_.front().id.volume, "new object changed volume");
        return made;
    }
};
void write(HANDLE h, std::string_view text) {
    check(text.size() <= 65536, "log line too large"); DWORD done{};
    wincheck(WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &done, nullptr), "WriteFile");
    check(done == text.size(), "short WriteFile"); wincheck(FlushFileBuffers(h), "FlushFileBuffers");
}
class Report {
    const Boundary& boundary_;
    Object file_;
public:
    explicit Report(const Boundary& boundary) : boundary_(boundary), file_(boundary.make(L"diagnostic.log", false)) {}
    void line(const std::string& text) {
        boundary_.check_all(); verify(file_); write(file_.h.get(), text + "\r\n");
    }
};
Object fixture(const Boundary& boundary, const Object& directory) {
    boundary.check_all(); verify(directory); lexhelper::Security security(false);
    auto h = relative(directory.h.get(), L"fixture.bin", FILE_READ_DATA | FILE_WRITE_DATA | low_access,
        FILE_CREATE, false, security.attributes.lpSecurityDescriptor);
    auto made = object(std::move(h), directory.path / L"fixture.bin", false);
    check(made.id.volume == directory.id.volume, "fixture changed volume");
    write(made.h.get(), "LexHelper native full-security diagnostic fixture\r\n"); return made;
}

// The held CREATE_NEW fixture prevents deletion, hard-link replacement and name
// reuse. Further read-only handles open its binary file ID, NOT its old filename.
// RootDirectory is the held directory object on the same already verified volume.
Handle open_fixture(const Object& directory, const Object& file, DWORD access, bool backup, Report& report) {
    verify(directory); verify(file);
    auto id = file.id.file;
    UNICODE_STRING binary{}; binary.Length = sizeof(id); binary.MaximumLength = sizeof(id);
    binary.Buffer = reinterpret_cast<PWSTR>(&id);
    OBJECT_ATTRIBUTES oa{}; oa.Length = sizeof(oa); oa.RootDirectory = directory.h.get(); oa.ObjectName = &binary;
    oa.Attributes = OBJ_DONT_REPARSE;
    IO_STATUS_BLOCK io{}; HANDLE raw{};
    const auto options = open_by_id | FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT |
        (backup ? FILE_OPEN_FOR_BACKUP_INTENT : 0);
    const auto status = lexhelper::native_api().create(&raw, access, &oa, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, options, nullptr, 0);
    Handle h(raw);
    report.line("OPEN method=NtCreateFile_by_fixture_ID; RequestedAccess=" + lexhelper::hex32(access) +
        "; CreateOptions=" + lexhelper::hex32(options) + "; backup_intent=" + std::to_string(backup) +
        "; NTSTATUS=" + lexhelper::hex32(static_cast<DWORD>(status)) + "; Win32=" +
        std::to_string(status == 0 ? 0 : lexhelper::native_api().dos_error(status)));
    if (status < 0) { check(!h.valid(), "failed Native open returned unexpected handle"); return {}; }
    check(status == 0 && h.valid() && io.Status == 0 && io.Information == FILE_OPENED, "fixture Native open completion contract");
    auto opened = object(std::move(h), file.path, false);
    check(opened.id == file.id, "query handle not the held fixture");
    // Object is movable; do not reopen by name to recover ownership.
    return std::move(opened.h);
}

struct Descriptor {
    bool valid{};
    DWORD length{}, control{};
    std::string error;
};
Descriptor describe(Bytes& bytes) {
    Descriptor d; d.length = static_cast<DWORD>(bytes.size());
    if (bytes.size() < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || bytes.size() > 65536) { d.error = "length_out_of_bounds"; return d; }
    // Validate relative offsets/lengths BEFORE calling any API that dereferences
    // the SD. This also rejects unsupported ACEs, overlap and partial O/G/D.
    try { lexhelper::validate_sd(bytes); }
    catch (const std::exception& ex) { d.error = ex.what(); return d; }
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision{};
    if (!GetSecurityDescriptorControl(bytes.data(), &control, &revision)) {
        d.error = "GetSecurityDescriptorControl_Win32=" + std::to_string(GetLastError()); return d;
    }
    if (revision != SECURITY_DESCRIPTOR_REVISION || !(control & SE_SELF_RELATIVE) ||
        GetSecurityDescriptorLength(bytes.data()) != bytes.size()) { d.error = "descriptor_length_or_revision_mismatch"; return d; }
    d.control = control; d.valid = true; return d;
}
std::string descriptor_text(const Descriptor& d) {
    return "; sd_length=" + std::to_string(d.length) + "; sd_valid=" + std::to_string(d.valid) +
        "; control=" + lexhelper::hex32(d.control) + (d.error.empty() ? "" : "; sd_error=" + d.error);
}
struct Matrix {
    unsigned unavailable{}, query_failures{}, full_native{}, differences{}, production_success{};
};
void queries(HANDLE h, const Object& file, Report& report, Matrix& matrix) {
    const auto& api = lexhelper::native_api();
    check(api.query_object && api.query_security, "required Native query interface unavailable");
    PUBLIC_OBJECT_BASIC_INFORMATION info{}; ULONG n{};
    const auto status = api.query_object(h, ObjectBasicInformation, &info, sizeof(info), &n);
    report.line("HANDLE NtQueryObject_NTSTATUS=" + lexhelper::hex32(static_cast<DWORD>(status)) + "; Win32=" +
        std::to_string(status == 0 ? 0 : api.dos_error(status)) + "; returned_length=" + std::to_string(n) +
        "; GrantedAccess=" + lexhelper::hex32(info.GrantedAccess));
    check(status == 0 && n == sizeof(info), "NtQueryObject did not verify GrantedAccess");
    for (const SECURITY_INFORMATION flags : {0x7UL, 0x1fUL, 0x10000UL, 0x1001fUL}) {
        PSECURITY_DESCRIPTOR raw{};
        const DWORD code = GetSecurityInfo(h, SE_FILE_OBJECT, flags, nullptr, nullptr, nullptr, nullptr, &raw);
        lexhelper::LocalPtr allocated(raw); Descriptor win; Bytes win_bytes;
        if (code == ERROR_SUCCESS && raw) {
            // Windows owns this LocalAlloc result; bound length before copying.
            const auto length = GetSecurityDescriptorLength(raw);
            if (length >= sizeof(SECURITY_DESCRIPTOR_RELATIVE) && length <= 65536) {
                win_bytes.resize(length); std::memcpy(win_bytes.data(), raw, length); win = describe(win_bytes);
            } else { win.length = length; win.error = "length_out_of_bounds"; }
        } else win.error = code ? "API_failed" : "API_success_null_descriptor";
        report.line("QUERY API=GetSecurityInfo; flags=" + lexhelper::hex32(flags) + "; Win32=" + std::to_string(code) + descriptor_text(win));
        Bytes bytes(65536); ULONG needed{};
        const auto nt = api.query_security(h, flags, bytes.data(), static_cast<ULONG>(bytes.size()), &needed);
        Descriptor native; native.length = needed;
        if (nt == 0 && needed >= sizeof(SECURITY_DESCRIPTOR_RELATIVE) && needed <= bytes.size()) {
            bytes.resize(needed); native = describe(bytes);
        } else native.error = nt ? "API_failed" : "length_out_of_bounds";
        report.line("QUERY API=NtQuerySecurityObject; flags=" + lexhelper::hex32(flags) + "; NTSTATUS=" +
            lexhelper::hex32(static_cast<DWORD>(nt)) + "; Win32=" + std::to_string(nt == 0 ? 0 : api.dos_error(nt)) + descriptor_text(native));
        if (!code && win.valid && !nt && native.valid)
            report.line("PAIR both_valid=1; flags=" + lexhelper::hex32(flags) + "; bytes_equal=" + std::to_string(win_bytes == bytes));
        if (code || !win.valid) ++matrix.query_failures;
        if (nt || !native.valid) ++matrix.query_failures;
        if (flags == BACKUP_SECURITY_INFORMATION && nt == 0 && native.valid) ++matrix.full_native;
        if ((code == ERROR_ACCESS_DENIED || code == ERROR_PRIVILEGE_NOT_HELD) && nt == 0 && native.valid) {
            ++matrix.differences;
            report.line("OBSERVATION GetSecurityInfo_denied_Nt_success=1; flags=" + lexhelper::hex32(flags));
        }
    }
    try {
        // Real production helper, real handle and bytes; no simulated_targets,
        // no source macros, no Deployer and no application system_mode action.
        auto bytes = lexhelper::get_full_security(h, file.path, false, "native_probe");
        const auto sd = describe(bytes);
        report.line("PRODUCTION get_full_security=returned" + descriptor_text(sd));
        if (sd.valid) ++matrix.production_success; else ++matrix.query_failures;
    } catch (const std::exception& ex) {
        ++matrix.query_failures; report.line(std::string("PRODUCTION get_full_security=error; ") + ex.what());
    }
}

// Only manipulate the token freshly duplicated and installed by the REAL
// production Privileges scope. Never adjust the baseline or process token.
Handle private_token(const Token& before) {
    const auto active = effective_token();
    check(active.thread && !same_id(active.id, before.id), "private copy token not installed");
    HANDLE raw{}; wincheck(OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, &raw), "open private token");
    Handle h(raw); check(same_id(read_token(h.get(), true).id, active.id), "wrong private token handle"); return h;
}
void disable(HANDLE private_copy, const wchar_t* name) {
    const auto token = read_token(private_copy, true);
    if (!privilege(token, name)) return;
    TOKEN_PRIVILEGES p{}; p.PrivilegeCount = 1; p.Privileges[0].Luid = privilege_id(name);
    SetLastError(ERROR_SUCCESS);
    wincheck(AdjustTokenPrivileges(private_copy, FALSE, &p, 0, nullptr, nullptr), "disable private privilege");
    check(GetLastError() == ERROR_SUCCESS, "disable private privilege not assigned");
    const auto after = privilege(read_token(private_copy, true), name);
    check(after && !(*after & SE_PRIVILEGE_ENABLED), "private privilege did not disable");
}
struct Row { const char* name; unsigned enabled; bool backup, disable_security_after_open; DWORD access; };
void row(const Row& r, const Boundary& boundary, const Object& directory, const Object& file, Report& report, Matrix& matrix) {
    TokenInvariant invariant; // survives nested Privileges destruction, including exceptions.
    report.line(std::string("ROW BEGIN ") + r.name);
    report.line("TOKEN before_effective=" + token_text(invariant.effective));
    report.line("TOKEN before_process=" + token_text(invariant.process));
    const std::array<const wchar_t*, 3> names{SE_SECURITY_NAME, SE_BACKUP_NAME, SE_RESTORE_NAME};
    bool available = true;
    for (unsigned i = 0; i != names.size(); ++i) if ((r.enabled & (1u << i)) && !privilege(invariant.effective, names[i])) {
        available = false; report.line("not_available=" + lexhelper::utf8(names[i]));
    }
    if (available) {
        try {
            lexhelper::Privileges privileges;
            Handle copy;
            if (r.enabled) {
                privileges.enable_names(true, {}); // actual existing private-copy implementation
                copy = private_token(invariant.effective);
                for (auto name : names) disable(copy.get(), name);
                if (r.enabled & 1) privileges.enable_names(true, {SE_SECURITY_NAME});
                if (r.enabled & 2) privileges.enable_names(true, {SE_BACKUP_NAME});
                if (r.enabled & 4) privileges.enable_names(true, {SE_RESTORE_NAME});
                const auto active = effective_token();
                for (unsigned i = 0; i != names.size(); ++i) {
                    const auto state = privilege(active, names[i]);
                    check((state && (*state & SE_PRIVILEGE_ENABLED)) == !!(r.enabled & (1u << i)), "private privilege combination mismatch");
                }
                check(process_token() == invariant.process, "process token changed while private token active");
            }
            report.line("TOKEN at_open=" + token_text(effective_token()));
            boundary.check_all();
            auto h = open_fixture(directory, file, r.access, r.backup, report);
            if (h.valid()) {
                if (r.disable_security_after_open) disable(copy.get(), SE_SECURITY_NAME);
                report.line("TOKEN at_query=" + token_text(effective_token()));
                check(process_token() == invariant.process, "process token changed during query");
                queries(h.get(), file, report, matrix);
            } else { ++matrix.unavailable; report.line("not_verified=queries; reason=fixture_open_failed"); }
        } catch (const std::exception& ex) {
            // Ordinary API/privilege failures are evidence, not a successful row.
            ++matrix.unavailable; report.line(std::string("not_verified=row; error=") + ex.what());
        }
    } else { ++matrix.unavailable; report.line("not_verified=row; reason=required_privilege_not_available"); }
    verify_restore(invariant.effective, invariant.process);
    report.line("TOKEN after_effective=" + token_text(effective_token()));
    report.line("TOKEN after_process=" + token_text(process_token()));
    report.line(std::string("ROW END ") + r.name + "; token_restored=1; process_unchanged=1");
}

int diagnose(const fs::path& path) {
    // Refuse BEFORE creating or even binding a root. No fallback matrix labelled
    // privileged when elevation cannot be established.
    if (!elevated()) { std::cerr << "REFUSED not_elevated; no filesystem objects created\n"; return 3; }
    TokenInvariant invariant;
    Boundary boundary(path);
    Report report(boundary);
    try {
        report.line("BEGIN LexHelper native full-security diagnostic v1; elevated=1; application_system_mode=NOT_USED");
        report.line("CONTRACT new_fixture_only=1; root_precreated_owner_verified=1; all_writes_bound=1; no_cleanup=1");
        const auto leaf = random_leaf();
        auto directory = boundary.make(leaf, true);
        report.line("FIXTURE relative_directory=" + lexhelper::utf8(leaf) + "; relative_file=fixture.bin; report=diagnostic.log");
        auto file = fixture(boundary, directory);
        Matrix matrix;
        const Row rows[]{
            {"original_low_handle", 0, false, false, low_access},
            {"original_full_no_backup_intent", 0, false, false, full_access},
            {"original_full_handle", 0, true, false, full_access},
            {"security_full_no_backup_intent", 1, false, false, full_access},
            {"security_full_backup_intent", 1, true, false, full_access},
            {"security_open_then_security_disabled", 1, true, true, full_access},
            {"backup_only_no_backup_intent", 2, false, false, full_access},
            {"backup_only_backup_intent", 2, true, false, full_access},
            {"security_backup_no_backup_intent", 3, false, false, full_access},
            {"security_backup_backup_intent", 3, true, false, full_access},
            {"security_backup_open_then_security_disabled", 3, true, true, full_access},
            {"security_restore_no_backup_intent", 5, false, false, full_access},
            {"security_restore_backup_intent", 5, true, false, full_access},
            {"security_restore_open_then_security_disabled", 5, true, true, full_access},
            {"security_backup_restore_backup_intent", 7, true, false, full_access}
        };
        for (const auto& r : rows) row(r, boundary, directory, file, report, matrix);
        verify_restore(invariant.effective, invariant.process);
        report.line("SUMMARY matrix_completed=1; token_restored=1; process_unchanged=1; full_native_success=" +
            std::string(matrix.full_native ? "observed" : "not_observed") + "; full_native_success_count=" + std::to_string(matrix.full_native) +
            "; GetSecurityInfo_denied_Nt_success_count=" + std::to_string(matrix.differences) +
            "; production_success_count=" + std::to_string(matrix.production_success) + "; query_failure_count=" +
            std::to_string(matrix.query_failures) + "; not_verified_count=" + std::to_string(matrix.unavailable));
        report.line("END exit=0; matrix_completed_only=1; field_problem_fixed=NOT_VERIFIED; system_install=NOT_PERFORMED");
        std::cout << "matrix_completed only; inspect root/diagnostic.log; fixture retained\n";
        return 0;
    } catch (const std::exception& ex) {
        verify_restore(invariant.effective, invariant.process);
        report.line(std::string("ERROR ") + ex.what());
        report.line("END exit=4; matrix_completed=0; field_problem_fixed=NOT_VERIFIED; objects_retained=1");
        return 4;
    }
}
int self_test() {
    unsigned checks{};
    auto test = [&](bool value) { ++checks; check(value, "self-test assertion failed"); };
    const std::wstring root = std::wstring(prefix) + std::wstring(32, L'a');
    test(allowed_root(root));
    for (const auto& bad : {std::wstring{}, root + L"\\", root + L"\\x", root + L":x", root + L".",
        root.substr(0, root.size() - 1), L"C:" + root.substr(2), L"d:" + root.substr(2), L"\\\\?\\" + root,
        root + std::wstring(1, L'\0'), std::wstring(prefix) + std::wstring(32, L'A'),
        std::wstring(prefix) + std::wstring(31, L'a') + L"g", L"D:\\temp\\aiRunner\\opencode\\..\\" + root}) test(!allowed_root(bad));
    test(parse({}) == Mode::invalid); test(parse({L"--self-test"}) == Mode::self_test);
    test(parse({L"--diagnose", L"--root", root}) == Mode::diagnose);
    test(parse({L"--diagnose", L"--root", root, L"extra"}) == Mode::invalid);
    test(parse({L"--root", root, L"--diagnose"}) == Mode::invalid);
    test(parse({L"--self-test", L"--root", root}) == Mode::invalid);
    Bytes tiny(19); test(!describe(tiny).valid);
    Bytes huge(65537); test(!describe(huge).valid);
    PSECURITY_DESCRIPTOR raw{};
    wincheck(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:BAD:P(A;;FA;;;SY)", SDDL_REVISION_1, &raw, nullptr), "self-test SD");
    lexhelper::LocalPtr sd(raw); Bytes bytes(GetSecurityDescriptorLength(raw)); std::memcpy(bytes.data(), raw, bytes.size());
    test(describe(bytes).valid);
    reinterpret_cast<SECURITY_DESCRIPTOR_RELATIVE*>(bytes.data())->Owner = 65532; test(!describe(bytes).valid);
    TokenInvariant invariant; test(!invariant.effective.privileges.empty()); test(!invariant.process.privileges.empty());
    verify_restore(invariant.effective, invariant.process);
    std::cout << "SELF_TEST checks=" << checks << "; passed; filesystem_writes=0; privileged_matrix=NOT_VERIFIED\n";
    return 0;
}
} // namespace native_probe

int wmain(int argc, wchar_t** argv) {
    try {
        std::vector<std::wstring_view> args;
        for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
        const auto mode = native_probe::parse(args);
        if (mode == native_probe::Mode::self_test) return native_probe::self_test();
        if (mode == native_probe::Mode::diagnose) return native_probe::diagnose(std::filesystem::path(args[2]));
        std::cerr << "REFUSED arguments; use --self-test OR --diagnose --root <exact approved D: root>\n";
        return 2;
    } catch (const std::exception& ex) {
        std::cerr << "REFUSED/ERROR " << ex.what() << "; matrix_completed=0; privileged_success=NOT_VERIFIED\n";
        return 4;
    } catch (...) { std::cerr << "ERROR unknown; matrix_completed=0\n"; return 4; }
}
