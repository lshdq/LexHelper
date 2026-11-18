// TC-001..005. Independent regression, not the developer's private harness.
// Only this EXE redirects these source-level calls; no DLL patching, public
// production hooks, or successful fake file opens. With no scoped scenario,
// every query/open reaches Windows. Synthetic SDs never get applied to a file.
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace full_security_test {
using Bytes = std::vector<std::byte>;
using QuerySecurity = NTSTATUS(NTAPI*)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG);
struct Scenario {
    HANDLE expected{};
    DWORD granted{READ_CONTROL | ACCESS_SYSTEM_SECURITY};
    DWORD primary_code{ERROR_ACCESS_DENIED};
    NTSTATUS object_status{}, native_status{};
    Bytes primary_sd, native_sd;
    std::optional<DWORD> primary_length;
    std::optional<ULONG> native_length;
    bool null_primary{}, contract_ok{true};
    unsigned objects{}, primaries{}, natives{};
    PSECURITY_DESCRIPTOR allocated_primary{};
};
thread_local Scenario* scenario{};
bool missing_native{}, missing_object{};
thread_local unsigned observed_creates{};
thread_local bool observe_creates{};
thread_local bool create_contract_ok{true};
thread_local HANDLE expected_parent{};
thread_local DWORD expected_access{};
decltype(&NtCreateFile) real_create{};
decltype(&NtQueryObject) real_object{};
QuerySecurity real_security{};

DWORD WINAPI get_security_info(HANDLE h, SE_OBJECT_TYPE type, SECURITY_INFORMATION flags,
    PSID* owner, PSID* group, PACL* dacl, PACL* sacl, PSECURITY_DESCRIPTOR* out) {
    if (!scenario) return ::GetSecurityInfo(h, type, flags, owner, group, dacl, sacl, out);
    auto& s = *scenario; ++s.primaries;
    s.contract_ok &= h == s.expected && flags == BACKUP_SECURITY_INFORMATION && type == SE_FILE_OBJECT &&
        !owner && !group && !dacl && !sacl && out;
    if (out) *out = nullptr;
    if (s.primary_code || s.null_primary) return s.primary_code;
    auto raw = LocalAlloc(LMEM_FIXED, s.primary_sd.size());
    if (!raw) return ERROR_OUTOFMEMORY;
    std::memcpy(raw, s.primary_sd.data(), s.primary_sd.size());
    s.allocated_primary = raw; *out = raw;
    return ERROR_SUCCESS;
}
DWORD WINAPI descriptor_length(PSECURITY_DESCRIPTOR sd) {
    if (scenario && sd == scenario->allocated_primary)
        return scenario->primary_length.value_or(static_cast<DWORD>(scenario->primary_sd.size()));
    return ::GetSecurityDescriptorLength(sd);
}
NTSTATUS NTAPI query_object(HANDLE h, OBJECT_INFORMATION_CLASS cls, PVOID out, ULONG size, PULONG needed) {
    if (!scenario) return real_object(h, cls, out, size, needed);
    auto& s = *scenario; ++s.objects;
    s.contract_ok &= h == s.expected && cls == ObjectBasicInformation && size == sizeof(PUBLIC_OBJECT_BASIC_INFORMATION);
    if (s.object_status < 0) return s.object_status;
    PUBLIC_OBJECT_BASIC_INFORMATION info{}; info.GrantedAccess = s.granted;
    std::memcpy(out, &info, sizeof(info)); *needed = sizeof(info);
    return s.object_status;
}
NTSTATUS NTAPI query_security(HANDLE h, SECURITY_INFORMATION flags, PSECURITY_DESCRIPTOR out, ULONG size, PULONG needed) {
    if (!scenario) return real_security(h, flags, out, size, needed);
    auto& s = *scenario; ++s.natives;
    s.contract_ok &= h == s.expected && flags == BACKUP_SECURITY_INFORMATION && size == 65536 && out && needed;
    if (s.native_status < 0) return s.native_status;
    if (s.native_sd.size() <= size) std::memcpy(out, s.native_sd.data(), s.native_sd.size());
    *needed = s.native_length.value_or(static_cast<ULONG>(s.native_sd.size()));
    return s.native_status;
}
NTSTATUS NTAPI create_file(PHANDLE out, ACCESS_MASK access, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK io,
    PLARGE_INTEGER allocation, ULONG attributes, ULONG share, ULONG disposition, ULONG options, PVOID ea, ULONG ea_size) {
    if (observe_creates) {
        ++observed_creates;
        create_contract_ok &= oa && oa->RootDirectory == expected_parent && access == expected_access &&
            (options & FILE_OPEN_FOR_BACKUP_INTENT) && disposition == FILE_OPEN;
    }
    return real_create(out, access, oa, io, allocation, attributes, share, disposition, options, ea, ea_size);
}
FARPROC WINAPI get_proc_address(HMODULE module, LPCSTR name) {
    const auto found = ::GetProcAddress(module, name);
    if (!std::strcmp(name, "NtQueryObject")) {
        real_object = reinterpret_cast<decltype(real_object)>(found);
        return missing_object || !found ? nullptr : reinterpret_cast<FARPROC>(&query_object);
    }
    if (!std::strcmp(name, "NtQuerySecurityObject")) {
        real_security = reinterpret_cast<QuerySecurity>(found);
        return missing_native || !found ? nullptr : reinterpret_cast<FARPROC>(&query_security);
    }
    if (!std::strcmp(name, "NtCreateFile")) {
        real_create = reinterpret_cast<decltype(real_create)>(found);
        return !found ? nullptr : reinterpret_cast<FARPROC>(&create_file);
    }
    return found;
}
struct ScopedScenario {
    explicit ScopedScenario(Scenario& s) { if (scenario) throw std::runtime_error("nested scenario"); scenario = &s; }
    ~ScopedScenario() { scenario = nullptr; }
    ScopedScenario(const ScopedScenario&) = delete;
    ScopedScenario& operator=(const ScopedScenario&) = delete;
};
} // namespace full_security_test

// Headers have already been read: these macros change only the included
// implementation's call sites, never Windows declarations or another target.
#define GetSecurityInfo full_security_test::get_security_info
#define GetSecurityDescriptorLength full_security_test::descriptor_length
#define GetProcAddress full_security_test::get_proc_address
#include "../src/deploy/deploy.cpp"
#undef GetProcAddress
#undef GetSecurityDescriptorLength
#undef GetSecurityInfo

namespace full_security_test {
namespace fs = std::filesystem;
unsigned checks{}, groups{}, failed{}, skips{};
void require(bool ok, const char* message) {
    ++checks; if (!ok) throw std::runtime_error(message);
}
template<class F> std::string rejects(F&& f) {
    try { f(); } catch (const std::exception& ex) { ++checks; return ex.what(); }
    throw std::runtime_error("operation unexpectedly succeeded");
}
void contains(const std::string& text, const std::string& part) {
    require(text.find(part) != text.npos, ("missing diagnostic: " + part + " in " + text).c_str());
}
void skip(const char* message) { ++skips; std::cout << "SKIP: " << message << '\n'; }
template<class F> void group(const char* name, F&& f) {
    ++groups;
    try { f(); std::cout << "GROUP PASS: " << name << '\n'; }
    catch (const std::exception& ex) { ++failed; std::cerr << "GROUP FAIL: " << name << ": " << ex.what() << '\n'; }
}
Bytes descriptor(const wchar_t* sacl = L"S:P(AU;SAFA;FR;;;WD)(ML;;NW;;;ME)") {
    const auto text = std::wstring(L"O:SYG:BAD:P(A;;FA;;;SY)(A;;FR;;;WD)") + sacl;
    PSECURITY_DESCRIPTOR sd{};
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(), SDDL_REVISION_1, &sd, nullptr) != FALSE,
        "construct independent synthetic SD");
    lexhelper::LocalPtr holder(sd);
    Bytes bytes(::GetSecurityDescriptorLength(sd)); std::memcpy(bytes.data(), sd, bytes.size());
    return bytes;
}
void assert_full_bytes(const Bytes& actual, const Bytes& expected) {
    // Byte equality (not the production semantic comparer) protects every field,
    // control flag, SID, audit ACE and label in the supplied synthetic response.
    require(actual == expected, "full response changed / truncated / replaced with NULL SACL");
    lexhelper::validate_sd(actual);
}

struct Token {
    bool thread{}; LUID id{}; Bytes privileges;
    bool operator==(const Token& b) const {
        return thread == b.thread && id.LowPart == b.id.LowPart && id.HighPart == b.id.HighPart && privileges == b.privileges;
    }
};
Token read_token(HANDLE handle, bool thread) {
    Token t; t.thread = thread;
    DWORD n{}; GetTokenInformation(handle, TokenPrivileges, nullptr, 0, &n);
    require(n >= sizeof(DWORD) && n < 65536, "token length");
    t.privileges.resize(n);
    require(GetTokenInformation(handle, TokenPrivileges, t.privileges.data(), n, &n) != FALSE, "read privileges");
    TOKEN_STATISTICS stats{};
    require(GetTokenInformation(handle, TokenStatistics, &stats, sizeof(stats), &n) != FALSE, "read TokenId");
    t.id = stats.TokenId; return t;
}
Token process_token() {
    HANDLE raw{}; require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw) != FALSE, "open process token");
    lexhelper::Handle h(raw); return read_token(h.get(), false);
}
Token effective_token() {
    HANDLE raw{};
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        lexhelper::Handle h(raw); return read_token(h.get(), true);
    }
    require(GetLastError() == ERROR_NO_TOKEN, "unexpected OpenThreadToken error");
    return process_token();
}
bool holds(const Token& t, const wchar_t* name, bool enabled_only = false) {
    LUID id{}; require(LookupPrivilegeValueW(nullptr, name, &id) != FALSE, "lookup privilege");
    const auto p = reinterpret_cast<const TOKEN_PRIVILEGES*>(t.privileges.data());
    for (DWORD i = 0; i < p->PrivilegeCount; ++i)
        if (p->Privileges[i].Luid.LowPart == id.LowPart && p->Privileges[i].Luid.HighPart == id.HighPart)
            return !enabled_only || (p->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED);
    return false;
}
struct RestoreThread {
    lexhelper::Handle previous;
    RestoreThread() {
        HANDLE raw{};
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, TRUE, &raw))
            previous = lexhelper::Handle(raw);
        else require(GetLastError() == ERROR_NO_TOKEN, "capture original thread token");
    }
    ~RestoreThread() {
        if (!SetThreadToken(nullptr, previous.valid() ? previous.get() : nullptr)) std::terminate();
    }
};
void verify_tokens(const Token& effective, const Token& process) {
    require(effective_token() == effective, "effective TokenId / privileges not restored");
    require(process_token() == process, "process TokenId / privileges changed");
}
void token_lifecycle(bool existing, HANDLE fixture_handle, const fs::path& fixture_path) {
    RestoreThread outer;
    require(SetThreadToken(nullptr, nullptr) != FALSE, "clear test thread token");
    const auto process = process_token();
    if (!holds(process, SE_CHANGE_NOTIFY_NAME)) { skip("SeChangeNotify absent; legal private-token lifecycle unavailable"); return; }
    lexhelper::Handle owned;
    if (existing) {
        HANDLE source{}, copy{};
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &source) != FALSE, "open source");
        lexhelper::Handle base(source);
        require(DuplicateTokenEx(base.get(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
            nullptr, SecurityImpersonation, TokenImpersonation, &copy) != FALSE, "duplicate test token");
        owned = lexhelper::Handle(copy);
        TOKEN_PRIVILEGES p{}; p.PrivilegeCount = 1;
        require(LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &p.Privileges[0].Luid) != FALSE, "lookup notify");
        SetLastError(ERROR_SUCCESS);
        require(AdjustTokenPrivileges(owned.get(), FALSE, &p, 0, nullptr, nullptr) && GetLastError() == ERROR_SUCCESS,
            "disable notify on own private token");
        require(SetThreadToken(nullptr, owned.get()) != FALSE, "set existing private token");
    }
    const auto baseline = effective_token();
    require(baseline.thread == existing, "wrong lifecycle starting context");
    if (existing) require(!holds(baseline, SE_CHANGE_NOTIFY_NAME, true), "test token must start notify disabled");
    for (bool unwind : {false, true}) {
        bool caught{};
        try {
            lexhelper::Privileges temporary;
            temporary.enable_names(true, {SE_CHANGE_NOTIFY_NAME});
            const auto active = effective_token();
            require(active.thread && !(active == baseline) && holds(active, SE_CHANGE_NOTIFY_NAME, true),
                "temporary privilege must be enabled on distinct thread token");
            const auto diagnostic = lexhelper::security_token_diagnostic();
            contains(diagnostic, "effective_token=thread");
            // A real production full-query refusal, not just an artificial
            // exception, must unwind the active privilege scope as well.
            if (unwind) {
                lexhelper::get_full_security(fixture_handle, fixture_path, false, "thread_token_probe");
                throw std::logic_error("low handle query unexpectedly succeeded");
            }
        } catch (const std::runtime_error& ex) {
            if (!unwind) throw;
            contains(ex.what(), "phase=thread_token_probe");
            contains(ex.what(), "[handle_access]");
            contains(ex.what(), "effective_token=thread");
            caught = true;
        }
        require(caught == unwind, "exception scenario not reached");
        verify_tokens(baseline, process);
    }
    // Do not enable SeSecurity if the runner owns it: that needs explicit opt-in.
    if (!holds(baseline, SE_SECURITY_NAME)) {
        for (bool activate_first : {false, true}) {
            const auto text = rejects([&] {
                lexhelper::Privileges temporary;
                if (activate_first) temporary.enable_names(true, {SE_CHANGE_NOTIFY_NAME});
                temporary.security(true);
            });
            contains(text, "Win32=1300"); contains(text, "SeSecurityPrivilege");
            verify_tokens(baseline, process);
        }
    } else skip("missing-SeSecurity failure cases: runner owns privilege; not enabled by this test");
}

void checked_directory(const fs::path& path) {
    auto current = path.root_path();
    auto check = [&] {
        const auto a = GetFileAttributesW(current.c_str());
        require(a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT),
            "fixture ancestor missing / reparse");
    };
    check(); for (const auto& part : path.relative_path()) { current /= part; check(); }
}
fs::path sandbox() {
    // TEMP must be inside the caller's approved D: task directory; no C: fallback.
    const fs::path approved = L"D:\\temp\\aiRunner\\opencode";
    checked_directory(approved);
    const auto base = fs::temp_directory_path();
    require(base.is_absolute() && lexhelper::within(base, approved) && !lexhelper::same_path(base, approved),
        "TEMP must be a task-specific descendant of approved D: root");
    checked_directory(base);
    std::array<unsigned char, 16> id{};
    require(BCryptGenRandom(nullptr, id.data(), static_cast<ULONG>(id.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
        "fixture randomness");
    std::wstring leaf = L"LexHelper-test-fullsecurity-fixture-";
    for (auto b : id) { leaf += L"0123456789abcdef"[b >> 4]; leaf += L"0123456789abcdef"[b & 15]; }
    const auto path = base / leaf;
    require(CreateDirectoryW(path.c_str(), nullptr) != FALSE, "CREATE_NEW fixture directory");
    checked_directory(path); return path;
}
lexhelper::Handle fixture(const fs::path& path) {
    lexhelper::Handle made(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(made.valid(), "CREATE_NEW fixture file");
    const char payload[] = "full-security-independent-fixture"; DWORD n{};
    require(WriteFile(made.get(), payload, sizeof(payload), &n, nullptr) && n == sizeof(payload), "write fixture");
    made.reset();
    lexhelper::Handle result(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(result.valid(), "open low-rights fixture"); return result;
}
void no_query_change(const Token& before, const Token& process, const Scenario& s, unsigned primary, unsigned native) {
    require(s.objects == 1 && s.primaries == primary && s.natives == native, "query attempt count / unbounded retry");
    require(s.contract_ok, "wrong handle / flags / buffer / object information class");
    verify_tokens(before, process);
}
void diagnostic_contract(const std::string& text) {
    contains(text, "phase=independent_test"); contains(text, "SecurityInfo=0x00010000");
    contains(text, "GrantedAccess="); contains(text, "RequiredAccess=0x01020000");
    require(text.find("S-1-") == text.npos && text.find("O:SY") == text.npos, "diagnostic leaked SID / descriptor");
}
Bytes query(HANDLE h, const fs::path& path) { return lexhelper::get_full_security(h, path, false, "independent_test"); }

void native_low_handle(HANDLE h, const fs::path& path) {
    const auto before = effective_token(), process = process_token();
    PSECURITY_DESCRIPTOR sd{};
    require(::GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &sd) == ERROR_SUCCESS, "real ordinary O/G/D query must succeed");
    { lexhelper::LocalPtr holder(sd); require(sd != nullptr && IsValidSecurityDescriptor(sd), "real ordinary descriptor invalid"); }
    sd = nullptr;
    const auto full_code = ::GetSecurityInfo(h, SE_FILE_OBJECT, BACKUP_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &sd);
    { lexhelper::LocalPtr holder(sd); require(full_code == ERROR_ACCESS_DENIED, "real low-rights BACKUP must fail, not complete success"); }
    const auto native = reinterpret_cast<QuerySecurity>(::GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySecurityObject"));
    require(native != nullptr, "real native query export unavailable on this test host");
    Bytes buffer(65536); ULONG needed{};
    const auto native_status = native(h, BACKUP_SECURITY_INFORMATION,
        reinterpret_cast<PSECURITY_DESCRIPTOR>(buffer.data()), static_cast<ULONG>(buffer.size()), &needed);
    require(native_status == static_cast<NTSTATUS>(0xC0000022UL), "Native BACKUP must not bypass low handle authorization");
    const auto text = rejects([&] { query(h, path); });
    contains(text, "[handle_access]"); contains(text, "Win32=5"); diagnostic_contract(text);
    contains(text, "effective_token=");
    std::cout << "NATIVE: ordinary O/G/D=0; BACKUP=" << full_code << "; native BACKUP NTSTATUS=0xC0000022; production preflight=" << text << '\n';
    verify_tokens(before, process);
}
void native_audit_open(const fs::path& root, const fs::path& path) {
    const auto before = effective_token(), process = process_token();
    if (holds(before, SE_SECURITY_NAME) || holds(before, SE_BACKUP_NAME) || holds(before, SE_RESTORE_NAME)) {
        skip("ordinary audit-open refusal: runner owns security/backup/restore privilege; no implicit privileged test"); return;
    }
    lexhelper::PinnedDirectory parent(root);
    // controlled_target=false but audit is explicit. system=false must still
    // reach the retry's simulation permission gate, not skip it or activate a
    // private token. No SACL simulation is registered for this native fixture.
    for (bool system : {false, true}) {
        observed_creates = 0; create_contract_ok = true;
        expected_parent = parent.get(); expected_access = READ_CONTROL | ACCESS_SYSTEM_SECURITY | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        struct Observe { Observe() { observe_creates = true; } ~Observe() { observe_creates = false; } } observer;
        const auto text = rejects([&] {
            lexhelper::Privileges temporary;
            lexhelper::open_regular(parent, path.filename(), READ_CONTROL | ACCESS_SYSTEM_SECURITY, false,
                temporary, system, false, false);
        });
        contains(text, "[file_open]"); contains(text, "NtCreateFile_NTSTATUS=0xC0000061/Win32=1314");
        contains(text, "RequestedAccess=0x01120080"); contains(text, "effective_token=");
        contains(text, system ? "令牌缺少所需部署权限" : "模拟部署权限不足；不会提权或放宽 ACL");
        if (system) { contains(text, "SeSecurityPrivilege"); contains(text, "Win32=1300"); }
        require(observed_creates == 1 && create_contract_ok, "audit branch bypassed, retried after privilege failure or changed open contract");
        verify_tokens(before, process);
        std::cout << "NATIVE: explicit audit controlled_target=false system=" << system << "; " << text << '\n';
    }
}

void synthetic_matrix(HANDLE h, const fs::path& path) {
    const auto before = effective_token(), process = process_token();
    const auto full = descriptor();
    group("synthetic-actual-mask-preflight", [&] {
        for (DWORD rights : {DWORD(0), DWORD(READ_CONTROL), DWORD(ACCESS_SYSTEM_SECURITY)}) {
            Scenario s; s.expected = h; s.granted = rights; ScopedScenario scope(s);
            const auto text = rejects([&] { query(h, path); });
            contains(text, "[handle_access]"); contains(text, "Win32=5"); diagnostic_contract(text);
            no_query_change(before, process, s, 0, 0);
        }
    });
    group("synthetic-primary-full-success-no-native", [&] {
        // Valid absent, NULL, empty, audit+label SACL are distinct successful
        // API responses, never substitutes for a failed full read.
        for (const wchar_t* sacl : {L"", L"S:NO_ACCESS_CONTROL", L"S:P", L"S:P(AU;SAFA;FR;;;WD)(ML;;NW;;;ME)"}) {
            Scenario s; s.expected = h; s.primary_code = ERROR_SUCCESS; s.primary_sd = descriptor(sacl);
            ScopedScenario scope(s); assert_full_bytes(query(h, path), s.primary_sd);
            no_query_change(before, process, s, 1, 0);
        }
    });
    group("synthetic-permission-only-same-handle-BACKUP", [&] {
        for (DWORD denied : {DWORD(ERROR_ACCESS_DENIED), DWORD(ERROR_PRIVILEGE_NOT_HELD)})
            for (const wchar_t* sacl : {L"", L"S:NO_ACCESS_CONTROL", L"S:P", L"S:P(AU;SAFA;FR;;;WD)(ML;;NW;;;ME)"}) {
            Scenario s; s.expected = h; s.primary_code = denied; s.native_sd = descriptor(sacl); ScopedScenario scope(s);
            assert_full_bytes(query(h, path), s.native_sd); no_query_change(before, process, s, 1, 1);
        }
    });
    group("synthetic-nonpermission-error-no-native", [&] {
        for (DWORD code : {DWORD(ERROR_INVALID_HANDLE), DWORD(ERROR_INVALID_PARAMETER), DWORD(ERROR_INVALID_SECURITY_DESCR)}) {
            Scenario s; s.expected = h; s.primary_code = code; ScopedScenario scope(s);
            const auto text = rejects([&] { query(h, path); });
            contains(text, "[GetSecurityInfo] Win32=" + std::to_string(code)); diagnostic_contract(text);
            require(text.find("[NtQuerySecurityObject]") == text.npos, "unexpected native error after nonpermission failure");
            no_query_change(before, process, s, 1, 0);
        }
    });
    group("synthetic-native-failure-merged-errors", [&] {
        struct Failure { ULONG status; DWORD code; const char* hex; };
        const Failure failures[]{{0xC0000022UL, ERROR_ACCESS_DENIED, "0xC0000022"},
            {0xC0000061UL, ERROR_PRIVILEGE_NOT_HELD, "0xC0000061"},
            {0xC0000023UL, ERROR_INSUFFICIENT_BUFFER, "0xC0000023"}};
        for (DWORD primary : {DWORD(5), DWORD(1314)}) for (const auto& failure : failures) {
            Scenario s; s.expected = h; s.primary_code = primary; s.native_status = static_cast<NTSTATUS>(failure.status);
            ScopedScenario scope(s); const auto text = rejects([&] { query(h, path); });
            contains(text, "[GetSecurityInfo] Win32=" + std::to_string(primary));
            contains(text, "[NtQuerySecurityObject] Win32=" + std::to_string(failure.code));
            contains(text, "NTSTATUS=" + std::string(failure.hex)); diagnostic_contract(text);
            no_query_change(before, process, s, 1, 1);
        }
    });
    group("synthetic-native-length-bounds", [&] {
        for (ULONG length : {0UL, 19UL, 65537UL}) {
            Scenario s; s.expected = h; s.native_sd = full; s.native_length = length; ScopedScenario scope(s);
            const auto text = rejects([&] { query(h, path); });
            contains(text, "[GetSecurityInfo] Win32=5"); contains(text, "[NtQuerySecurityObject] Win32=1338");
            no_query_change(before, process, s, 1, 1);
        }
        for (ULONG length : {20UL, static_cast<ULONG>(full.size() - 4)}) {
            Scenario s; s.expected = h; s.native_sd = full; s.native_length = length; ScopedScenario scope(s);
            const auto text = rejects([&] { query(h, path); });
            contains(text, "[validate_descriptor]"); contains(text, "API=NtQuerySecurityObject");
            no_query_change(before, process, s, 1, 1);
        }
        // Boundary 65536 still has to pass schema, not a blanket size rejection.
        Scenario s; s.expected = h; s.native_sd = full; s.native_sd.resize(65536);
        ScopedScenario scope(s); assert_full_bytes(query(h, path), s.native_sd);
        no_query_change(before, process, s, 1, 1);
    });
    group("synthetic-primary-null-and-length-bounds", [&] {
        for (DWORD length : {0UL, 19UL, 65537UL}) {
            Scenario s; s.expected = h; s.primary_code = 0; s.primary_sd = full; s.primary_length = length;
            ScopedScenario scope(s); const auto text = rejects([&] { query(h, path); });
            contains(text, "[GetSecurityInfo] Win32=1338"); no_query_change(before, process, s, 1, 0);
        }
        Scenario s; s.expected = h; s.primary_code = 0; s.null_primary = true; ScopedScenario scope(s);
        contains(rejects([&] { query(h, path); }), "[GetSecurityInfo] Win32=1338");
        no_query_change(before, process, s, 1, 0);
    });
    group("synthetic-successful-API-bad-SD-rejected-no-extra-fallback", [&] {
        for (bool native : {false, true}) for (unsigned corruption = 0; corruption != 7; ++corruption) {
            auto bad = full; auto sd = reinterpret_cast<SECURITY_DESCRIPTOR_RELATIVE*>(bad.data());
            switch (corruption) {
            case 0: sd->Owner = 0; break;
            case 1: sd->Dacl = 0; break;
            case 2: sd->Sacl = 65532; break;
            case 3: sd->Control |= SE_RM_CONTROL_VALID; break;
            case 4: sd->Group = sd->Dacl; break;
            case 5: reinterpret_cast<ACL*>(bad.data() + sd->Sacl)->AclSize = 65532; break;
            case 6: reinterpret_cast<ACE_HEADER*>(bad.data() + sd->Sacl + sizeof(ACL))->AceType = SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE; break;
            }
            Scenario s; s.expected = h; s.primary_code = native ? 5 : 0; s.primary_sd = bad; s.native_sd = bad;
            ScopedScenario scope(s); const auto text = rejects([&] { query(h, path); });
            contains(text, "[validate_descriptor]"); contains(text, native ? "API=NtQuerySecurityObject" : "API=GetSecurityInfo");
            contains(text, native ? "GetSecurityInfo_Win32=5" : "GetSecurityInfo_Win32=0"); diagnostic_contract(text);
            no_query_change(before, process, s, 1, native ? 1 : 0);
        }
    });
    group("synthetic-object-query-failure-stops-both-APIs", [&] {
        Scenario s; s.expected = h; s.object_status = static_cast<NTSTATUS>(0xC0000008UL); ScopedScenario scope(s);
        const auto text = rejects([&] { query(h, path); });
        contains(text, "[handle_access]"); contains(text, "Win32=6"); contains(text, "phase=independent_test");
        no_query_change(before, process, s, 0, 0);
    });
}
} // namespace full_security_test

int wmain(int argc, wchar_t** argv) {
    using namespace full_security_test;
    try {
        if (argc == 2 && std::wstring(argv[1]) == L"--missing-native") missing_native = true;
        else if (argc == 2 && std::wstring(argv[1]) == L"--missing-object") missing_object = true;
        else if (argc != 1) return 2;
        const auto root = sandbox(), path = root / L"ChsWubi.lex";
        std::cout << "Sandbox: " << root.string() << '\n';
        auto h = fixture(path);
        const auto initial = effective_token(), process = process_token();
        if (missing_native || missing_object) {
            group(missing_native ? "synthetic-missing-native-interface" : "synthetic-missing-object-interface", [&] {
                Scenario s; s.expected = h.get(); ScopedScenario scope(s);
                const auto text = rejects([&] { query(h.get(), path); });
                contains(text, "Win32=127"); contains(text, "phase=independent_test");
                if (missing_native) {
                    contains(text, "[GetSecurityInfo] Win32=5"); contains(text, "[NtQuerySecurityObject] Win32=127");
                    no_query_change(initial, process, s, 1, 0);
                } else {
                    contains(text, "[handle_access]"); contains(text, "NtQueryObject");
                    require(!s.objects && !s.primaries && !s.natives, "missing-object API must stop all queries");
                }
                std::cout << "SYNTHETIC missing API: " << text << '\n';
            });
        } else {
            group("native-low-handle-ordinary-success-full-refusal", [&] { native_low_handle(h.get(), path); });
            group("native-audit-open-explicit-mask-not-controlled-source", [&] { native_audit_open(root, path); });
            group("native-private-token-originally-no-thread", [&] { token_lifecycle(false, h.get(), path); });
            group("native-private-token-originally-existing-thread", [&] { token_lifecycle(true, h.get(), path); });
            skip("SeSecurity complete native success, native audit/control roundtrip and native compatibility success: not authorized/runner lacks required privileges");
            synthetic_matrix(h.get(), path);
        }
        verify_tokens(initial, process);
        std::cout << "GROUPS: " << (groups - failed) << '/' << groups << "; CHECKS: " << checks << "; SKIPS: " << skips
                  << "; native privileged success NOT VERIFIED; sandbox retained for boundary-checked cleanup\n";
        return failed ? 1 : 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL: " << ex.what() << '\n'; return 1; }
}
