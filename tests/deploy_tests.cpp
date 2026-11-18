#include "lexhelper/deploy.hpp"
#include "lexhelper/core.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>
#include <aclapi.h>
#include <sddl.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
namespace fs = std::filesystem;
using Bytes = std::vector<std::byte>;
constexpr SECURITY_INFORMATION parts = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
int checks = 0;
unsigned observed_last_access_changes{}, observed_change_time_changes{};
void require(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
template<class F> std::string rejects(F&& operation) {
    try { operation(); } catch (const std::exception& ex) { ++checks; return ex.what(); }
    throw std::runtime_error("operation unexpectedly succeeded");
}
struct Handle {
    HANDLE h{INVALID_HANDLE_VALUE};
    explicit Handle(HANDLE value) : h(value) {}
    ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
Bytes load(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    require(bool(stream), "open test data failed");
    const auto size = fs::file_size(path);
    require(size < 4 * 1024 * 1024, "unexpected fixture length");
    Bytes data(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    require(bool(stream), "read test data failed");
    return data;
}
void save(const fs::path& path, const Bytes& data) {
    HANDLE raw = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (raw == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND)
        raw = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                          CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    Handle handle(raw); require(handle.h != INVALID_HANDLE_VALUE, "open fixture output failed");
    DWORD written{};
    require(WriteFile(handle.h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) != FALSE &&
             written == data.size() && SetEndOfFile(handle.h) != FALSE, "write fixture failed");
}
void save_new_secure(const fs::path& path, const Bytes& data, const Bytes& descriptor) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), const_cast<std::byte*>(descriptor.data()), FALSE};
    Handle h(CreateFileW(path.c_str(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    require(h.h != INVALID_HANDLE_VALUE, "create secure fixture payload failed");
    DWORD count{};
    require(WriteFile(h.h, data.data(), static_cast<DWORD>(data.size()), &count, nullptr) && count == data.size(),
            "write secure fixture payload failed");
}
Bytes security(const fs::path& path) {
    DWORD count{}; GetFileSecurityW(path.c_str(), parts, nullptr, 0, &count);
    require(count > 0 && count < 65536, "security length failed");
    Bytes result(count);
    require(GetFileSecurityW(path.c_str(), parts, reinterpret_cast<PSECURITY_DESCRIPTOR>(result.data()),
                             count, &count) != FALSE, "get security failed");
    return result;
}
bool same_security(const Bytes& a, const Bytes& b) {
    const auto sa = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(a.data());
    const auto sb = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(b.data());
    auto sid = [](const Bytes& bytes, DWORD offset) { return const_cast<std::byte*>(bytes.data()) + offset; };
    const auto aa = reinterpret_cast<const ACL*>(a.data() + sa->Dacl);
    const auto ab = reinterpret_cast<const ACL*>(b.data() + sb->Dacl);
    // Compare semantic security rather than self-relative offset/padding layout.
    constexpr WORD control = SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ |
        SE_SACL_PRESENT | SE_SACL_DEFAULTED | SE_SACL_PROTECTED | SE_SACL_AUTO_INHERITED | SE_SACL_AUTO_INHERIT_REQ;
    return EqualSid(sid(a, sa->Owner), sid(b, sb->Owner)) && EqualSid(sid(a, sa->Group), sid(b, sb->Group)) &&
        ((sa->Control ^ sb->Control) & control) == 0 &&
        aa->AclSize == ab->AclSize && std::memcmp(aa, ab, aa->AclSize) == 0 &&
        ((!sa->Sacl && !sb->Sacl) || (sa->Sacl && sb->Sacl &&
         reinterpret_cast<const ACL*>(a.data() + sa->Sacl)->AclSize == reinterpret_cast<const ACL*>(b.data() + sb->Sacl)->AclSize &&
         std::memcmp(a.data() + sa->Sacl, b.data() + sb->Sacl,
             reinterpret_cast<const ACL*>(a.data() + sa->Sacl)->AclSize) == 0));
}
Bytes sacl_descriptor(const std::wstring& sacl) {
    PSECURITY_DESCRIPTOR raw{};
    const auto text = L"O:SYG:SYD:P(A;;FA;;;SY)" + sacl;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(), SDDL_REVISION_1, &raw, nullptr) != FALSE,
            "synthetic full security descriptor failed");
    const auto length = GetSecurityDescriptorLength(raw);
    Bytes result(length); std::memcpy(result.data(), raw, length); LocalFree(raw); return result;
}
void apply_security(const fs::path& path, const Bytes& data) {
    auto sd = reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(data.data()));
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision{};
    require(GetSecurityDescriptorControl(sd, &control, &revision) != FALSE, "read descriptor control failed");
    const auto info = parts | ((control & SE_DACL_PROTECTED) ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
    auto relative = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(data.data());
    auto base = const_cast<std::byte*>(data.data());
    auto name = path.wstring();
    require(SetNamedSecurityInfoW(name.data(), SE_FILE_OBJECT, info,
            base + relative->Owner, base + relative->Group, reinterpret_cast<PACL>(base + relative->Dacl), nullptr)
                == ERROR_SUCCESS, "restore test descriptor failed");
}
void dacl(const fs::path& path, const wchar_t* sddl) {
    PSECURITY_DESCRIPTOR sd{};
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr) != FALSE,
            "create test DACL failed");
    const BOOL ok = SetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd); require(ok != FALSE, "apply test DACL failed");
}
std::vector<fs::path> backups(const fs::path& root) {
    std::vector<fs::path> result;
    if (fs::exists(root)) for (const auto& item : fs::directory_iterator(root))
        if (item.is_directory() && item.path().filename().wstring().starts_with(L"backup-")) result.push_back(item.path());
    return result;
}
Bytes token_privileges(HANDLE token) {
    DWORD length{}; GetTokenInformation(token, TokenPrivileges, nullptr, 0, &length);
    require(length >= sizeof(DWORD) && length < 65536, "token privilege length invalid");
    Bytes result(length);
    require(GetTokenInformation(token, TokenPrivileges, result.data(), length, &length) != FALSE, "read token privileges failed");
    return result;
}
struct TokenState {
    Bytes process_privileges, thread_privileges;
    bool has_thread{}; DWORD thread_low{}; LONG thread_high{};
    bool operator==(const TokenState&) const = default;
};
TokenState capture_tokens() {
    HANDLE raw{};
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw) != FALSE, "capture process token failed");
    Handle process(raw); TokenState result; result.process_privileges = token_privileges(process.h);
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        Handle thread(raw); result.has_thread = true; result.thread_privileges = token_privileges(thread.h);
        TOKEN_STATISTICS stats{}; DWORD length{};
        require(GetTokenInformation(thread.h, TokenStatistics, &stats, sizeof(stats), &length) != FALSE, "capture thread token identity failed");
        result.thread_low = stats.TokenId.LowPart; result.thread_high = stats.TokenId.HighPart;
    } else require(GetLastError() == ERROR_NO_TOKEN, "unexpected thread token query failure");
    return result;
}

struct Fixture {
    fs::path root, target, backup_root, generated;
    Bytes original = lexhelper::write_lex({{"a", u"工", 0}, {"b", u"子", 0}});
    Bytes secondary = lexhelper::write_lex({{"c", u"又", 0}});
    Bytes replacement = lexhelper::write_lex({{"a", u"我", 0}, {"ab", u"新世纪", 0}});
    Bytes primary_sd, secondary_sd, primary_full, secondary_full;
    bool has_new;
    Fixture(const fs::path& base, const std::wstring& name, bool new_file)
        : root(base / name), target(root / L"模拟词库"), backup_root(root / L"备份"),
          generated(root / L"新世纪.lex"), has_new(new_file) {
        fs::create_directories(target);
        save(target / L"ChsWubi.lex", original);
        require(SetFileAttributesW((target / L"ChsWubi.lex").c_str(), FILE_ATTRIBUTE_HIDDEN) != FALSE,
                "set fixture attributes failed");
        if (has_new) save(target / L"ChsWubiNew.lex", secondary);
        save(target / L"unrelated.keep", Bytes{std::byte{42}});
        save(generated, replacement);
        lexhelper::deploy_testing::enable_security_simulation(target);
        primary_sd = security(target / L"ChsWubi.lex");
        if (has_new) secondary_sd = security(target / L"ChsWubiNew.lex");
        remember_full_security();
    }
    void remember_full_security() {
        primary_full = lexhelper::deploy_testing::simulated_security(target / L"ChsWubi.lex");
        if (has_new) secondary_full = lexhelper::deploy_testing::simulated_security(target / L"ChsWubiNew.lex");
    }
    lexhelper::Deployer deployer() const { return lexhelper::Deployer({target, backup_root, false}); }
    void original_state() const {
        require(load(target / L"ChsWubi.lex") == original, "primary not rolled back");
        require(same_security(security(target / L"ChsWubi.lex"), primary_sd), "primary security changed");
        require(same_security(lexhelper::deploy_testing::simulated_security(target / L"ChsWubi.lex"), primary_full),
                "primary full SACL/label/control changed");
        require((GetFileAttributesW((target / L"ChsWubi.lex").c_str()) & FILE_ATTRIBUTE_HIDDEN) != 0,
                "primary attributes changed");
        require(fs::exists(target / L"ChsWubiNew.lex") == has_new, "secondary existence changed");
        if (has_new) {
            require(load(target / L"ChsWubiNew.lex") == secondary, "secondary bytes changed");
            require(same_security(security(target / L"ChsWubiNew.lex"), secondary_sd), "secondary security changed");
            require(same_security(lexhelper::deploy_testing::simulated_security(target / L"ChsWubiNew.lex"), secondary_full),
                    "secondary full SACL/label/control changed");
        }
        require(load(target / L"unrelated.keep") == Bytes{std::byte{42}}, "unrelated file changed");
    }
    void installed_state() const {
        require(load(target / L"ChsWubi.lex") == replacement, "replacement mismatch");
        require(!fs::exists(target / L"ChsWubiNew.lex"), "secondary not disabled");
        require(same_security(security(target / L"ChsWubi.lex"), primary_sd), "installed primary security changed");
        require(same_security(lexhelper::deploy_testing::simulated_security(target / L"ChsWubi.lex"), primary_full),
                "installed primary SACL/label changed");
    }
};

// TC-008: independent Win32 observations, not just the deployment state comparer.
FILE_BASIC_INFO basic_info(const fs::path& path) {
    Handle h(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    FILE_BASIC_INFO result{};
    require(h.h != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(h.h, FileBasicInfo, &result, sizeof(result)),
            "independent file metadata query failed");
    return result;
}
Bytes native_label(const fs::path& path) {
    auto name = path.wstring(); PSECURITY_DESCRIPTOR raw{};
    require(GetNamedSecurityInfoW(name.data(), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                nullptr, nullptr, nullptr, nullptr, &raw) == ERROR_SUCCESS, "unprivileged native label read failed");
    const auto length = GetSecurityDescriptorLength(raw);
    Bytes result(length); std::memcpy(result.data(), raw, length); LocalFree(raw); return result;
}
struct Sentinel {
    fs::path path;
    Bytes bytes, sd, full, label;
    FILE_BASIC_INFO basic{};
    BY_HANDLE_FILE_INFORMATION identity{};
    Sentinel(const fs::path& source, const fs::path& directory) : path(directory / source.filename()) {
        fs::create_directories(directory);
        lexhelper::deploy_testing::enable_security_simulation(directory);
        require(CreateHardLinkW(path.c_str(), source.c_str(), nullptr) != FALSE, "create independent sentinel failed");
        // Reset fixture timestamps before observing: opening/creating a hard link is not part of deployment.
        Handle h(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
        require(h.h != INVALID_HANDLE_VALUE, "open sentinel timestamps failed");
        FILETIME c{0x11110000, 0x01d90000}, a{0x22220000, 0x01d90000}, w{0x33330000, 0x01d90000};
        require(SetFileTime(h.h, &c, &a, &w) != FALSE, "set known sentinel timestamps failed");
        require(GetFileInformationByHandle(h.h, &identity) != FALSE, "sentinel identity failed");
        bytes = load(path); sd = security(path); full = lexhelper::deploy_testing::simulated_security(path);
        label = native_label(path); basic = basic_info(path);
    }
    void unchanged() const {
        require(load(path) == bytes, "shared sentinel bytes changed");
        require(same_security(security(path), sd), "shared sentinel native Owner/Group/DACL changed");
        require(same_security(lexhelper::deploy_testing::simulated_security(path), full), "shared sentinel simulated SACL changed");
        require(native_label(path) == label, "shared sentinel native label changed");
        const auto now = basic_info(path);
        require(now.FileAttributes == basic.FileAttributes, "shared sentinel attributes (including ARCHIVE) changed");
        require(now.CreationTime.QuadPart == basic.CreationTime.QuadPart, "shared sentinel creation time changed");
        require(now.LastWriteTime.QuadPart == basic.LastWriteTime.QuadPart, "shared sentinel write time changed");
        // NTFS may update LastAccessTime for reads and ChangeTime/link count for directory-entry removal.
        // These observations are logged explicitly, not falsely asserted as preserved metadata.
        if (now.LastAccessTime.QuadPart != basic.LastAccessTime.QuadPart) ++observed_last_access_changes;
        if (now.ChangeTime.QuadPart != basic.ChangeTime.QuadPart) ++observed_change_time_changes;
        Handle h(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, 0, nullptr));
        BY_HANDLE_FILE_INFORMATION after{};
        require(h.h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(h.h, &after), "sentinel post identity failed");
        require(after.dwVolumeSerialNumber == identity.dwVolumeSerialNumber &&
                after.nFileIndexHigh == identity.nFileIndexHigh && after.nFileIndexLow == identity.nFileIndexLow,
                "sentinel object was replaced");
    }
};

std::uint32_t u32(const Bytes& bytes, std::size_t at) {
    std::uint32_t result{};
    for (unsigned i = 0; i < 4; ++i) result |= std::uint32_t(std::to_integer<unsigned>(bytes.at(at + i))) << (8 * i);
    return result;
}
void put32(Bytes& bytes, std::size_t at, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes.at(at + i) = std::byte((value >> (8 * i)) & 255);
}
std::array<std::size_t, 4> state_offsets(const Bytes& manifest) {
    std::array<std::size_t, 4> offsets{}; std::size_t p = 24;
    for (auto& offset : offsets) {
        offset = p; p += u32(manifest, p) ? 88 + u32(manifest, p + 84) : 4;
        require(p <= manifest.size() - 32, "test schema walker exceeded manifest");
    }
    require(p == manifest.size() - 32, "test schema walker tail mismatch");
    return offsets;
}

void roundtrip(const fs::path& base, bool new_file) {
    Fixture f(base, new_file ? L"往返-有New" : L"往返-无New", new_file);
    auto d = f.deployer();
    const auto b1 = d.backup(), b2 = d.backup();
    require(b1 != b2 && fs::exists(b1 / L"manifest.lhb") && fs::exists(b2 / L"manifest.lhb"), "backups not unique");
    f.original_state();
    const auto installed = d.install(f.generated);
    f.installed_state();
    rejects([&] { d.restore(b1); }); // A backup-only snapshot does not authorize unrelated changes.
    f.installed_state();
    d.restore(installed);
    f.original_state();
    d.restore(installed); // Idempotent restore is still preceded by an independent recovery point.
    f.original_state();
    require(backups(f.backup_root).size() == 5, "restore did not create recovery points");
    require(load(installed / L"original-0.bin") == f.original, "history overwritten");
}

void failure_paths(const fs::path& base) {
    using P = lexhelper::deploy_testing::FailurePoint;
    const std::array points{P::after_backup, P::after_primary_write, P::after_new_disabled, P::before_security_restore};
    unsigned n{};
    for (const bool secondary : {false, true}) for (const auto point : points) {
        Fixture f(base, L"注入-" + std::to_wstring(++n), secondary);
        auto d = f.deployer();
        lexhelper::deploy_testing::inject_failure(point);
        const auto message = rejects([&] { (void)d.install(f.generated); });
        require(message.find("manifest") == std::string::npos, "failed before intended injection");
        require(message.find("Win32=") == std::string::npos, "unexpected OS error during rollback");
        require(message.find("已校验回滚") != std::string::npos, "rollback was not verified complete");
        f.original_state(); require(backups(f.backup_root).size() == 1, "failure recovery backup missing");
    }
    for (const auto point : points) {
        Fixture f(base, L"恢复注入-" + std::to_wstring(++n), true);
        auto d = f.deployer(); const auto backup = d.install(f.generated);
        lexhelper::deploy_testing::inject_failure(point);
        rejects([&] { d.restore(backup); });
        f.installed_state();
        require(backups(f.backup_root).size() == 2, "restore recovery point missing");
        d.restore(backup); f.original_state();
    }
    Fixture f(base, L"回滚自身失败", false);
    auto d = f.deployer();
    lexhelper::deploy_testing::inject_failure(P::after_primary_write, true);
    const auto message = rejects([&] { (void)d.install(f.generated); });
    require(message.find("ChsWubi.lex") != std::string::npos && message.find("backup-") != std::string::npos,
            "rollback failure omits concrete recovery paths");
    require(message.find("Win32=") == std::string::npos, "unexpected rollback OS error");
    require(message.find("回滚不完整") != std::string::npos && message.find("已校验回滚") == std::string::npos,
            "rollback failure incorrectly claims complete recovery");
    f.installed_state();
    const auto recovery = backups(f.backup_root);
    require(recovery.size() == 1, "recovery backup missing");
    d.restore(recovery.front()); f.original_state();
}

void refresh_digest(Bytes& manifest) {
    require(manifest.size() > 32, "manifest too small");
    require(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(manifest.data()), static_cast<ULONG>(manifest.size() - 32),
        reinterpret_cast<PUCHAR>(manifest.data() + manifest.size() - 32), 32) >= 0, "hash failed");
}
void corrupt_backups(const fs::path& base) {
    Fixture f(base, L"坏备份", true); auto d = f.deployer();
    const auto b = d.install(f.generated);
    const auto original_payload = load(b / L"original-1.bin");
    auto payload = original_payload; payload.back() ^= std::byte{1}; save(b / L"original-1.bin", payload);
    const auto count = backups(f.backup_root).size();
    rejects([&] { d.restore(b); }); f.installed_state();
    require(backups(f.backup_root).size() == count, "bad backup created recovery point");
    save(b / L"original-1.bin", original_payload);
    const auto clean = load(b / L"manifest.lhb");
    auto corrupt = clean; corrupt[0] ^= std::byte{1}; save(b / L"manifest.lhb", corrupt);
    rejects([&] { d.restore(b); }); f.installed_state();
    corrupt = clean; corrupt.resize(31); save(b / L"manifest.lhb", corrupt);
    rejects([&] { d.restore(b); }); f.installed_state();
    corrupt = clean;
    // First state's self-relative SD owner offset is intentionally outside the bounded blob.
    require(corrupt.size() > 120, "manifest schema unexpectedly changed");
    for (unsigned i = 116; i < 120; ++i) corrupt[i] = std::byte{255};
    refresh_digest(corrupt); save(b / L"manifest.lhb", corrupt);
    rejects([&] { d.restore(b); }); f.installed_state();
    save(b / L"manifest.lhb", clean);
    const auto protected_sd = security(b);
    dacl(b, L"D:P(A;OICI;FA;;;WD)");
    rejects([&] { d.restore(b); }); f.installed_state();
    apply_security(b, protected_sd);
    d.restore(b); f.original_state();
}

void unsafe_paths(const fs::path& base) {
    Fixture f(base, L"不安全路径", true); auto d = f.deployer();
    rejects([&] { (void)d.install(f.target / L"ChsWubi.lex"); }); f.original_state();
    rejects([&] { lexhelper::Deployer x({f.target / L".." / L"模拟词库", f.backup_root, false}); });
    rejects([&] { lexhelper::Deployer x({L"relative", f.backup_root, false}); });
    rejects([&] { lexhelper::Deployer x({f.target.wstring() + L".", f.backup_root, false}); });
    rejects([&] { lexhelper::Deployer x({f.target.wstring() + L":stream", f.backup_root, false}); });
    rejects([&] { lexhelper::Deployer x({f.target.wstring() + wchar_t(0xd800), f.backup_root, false}); });
    rejects([&] { lexhelper::Deployer x({f.target, f.target / L"backup", false}); });
    // Independent automated runs never invoke system_mode=true, including constructors.
    // Constructor-only check: never opens or changes the real Windows target.
    rejects([&] { lexhelper::Deployer x({lexhelper::system_lex_directory(), f.backup_root, false}); });
    const auto hardlink = f.root / L"硬链接.lex";
    require(CreateHardLinkW(hardlink.c_str(), f.generated.c_str(), nullptr) != FALSE, "create hardlink failed");
    rejects([&] { (void)d.install(hardlink); }); f.original_state();
    require(DeleteFileW(hardlink.c_str()) != FALSE, "delete test hardlink failed");
    const auto ads = fs::path(f.generated.wstring() + L":test-stream");
    save(ads, Bytes{std::byte{13}});
    rejects([&] { (void)d.install(f.generated); }); f.original_state();
    require(DeleteFileW(ads.c_str()) != FALSE, "remove own ADS failed");
    auto invalid = f.replacement; invalid[0] ^= std::byte{255}; save(f.generated, invalid);
    rejects([&] { (void)d.install(f.generated); }); f.original_state();
    save(f.generated, f.replacement);
    const auto b = d.install(f.generated);
    save(f.target / L"ChsWubiNew.lex", Bytes{std::byte{12}});
    rejects([&] { d.restore(b); });
    require(load(f.target / L"ChsWubiNew.lex") == Bytes{std::byte{12}}, "unrelated new file deleted");
    require(DeleteFileW((f.target / L"ChsWubiNew.lex").c_str()) != FALSE, "remove own unexpected fixture failed");
    d.restore(b); f.original_state();
    rejects([&] { d.restore(b / L".." / b.filename()); }); f.original_state();
    const auto other_install = d.install(f.generated);
    save(f.target / L"ChsWubi.lex", f.secondary);
    rejects([&] { d.restore(other_install); });
    require(load(f.target / L"ChsWubi.lex") == f.secondary, "unrelated changed primary overwritten");
    save(f.target / L"ChsWubi.lex", f.replacement);
    require(SetFileAttributesW((f.target / L"ChsWubi.lex").c_str(), FILE_ATTRIBUTE_HIDDEN) != FALSE,
            "restore known fixture attributes failed");
    d.restore(other_install); f.original_state();
    Fixture another(base, L"不同目标身份", true);
    rejects([&] { another.deployer().restore(b); }); another.original_state();
}

void exclusive_and_permissions(const fs::path& base) {
    Fixture f(base, L"独占与权限", true); auto d = f.deployer();
    for (const wchar_t* name : {L"ChsWubi.lex", L"ChsWubiNew.lex"}) {
        {
            Handle held(CreateFileW((f.target / name).c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr));
            require(held.h != INVALID_HANDLE_VALUE, "open exclusive test handle failed");
            rejects([&] { (void)d.backup(); });
            rejects([&] { (void)d.install(f.generated); });
        }
        f.original_state();
    }
    const auto sd = security(f.target / L"ChsWubi.lex");
    // Directory-entry replacement does not need write-data access to the old file.
    // Deny required backup reads instead; simulation must never bypass this ACL.
    dacl(f.target / L"ChsWubi.lex", L"D:P(D;;0x1;;;WD)(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)");
    rejects([&] { (void)d.install(f.generated); });
    apply_security(f.target / L"ChsWubi.lex", sd); f.original_state();
    const auto root_sd = security(f.backup_root);
    dacl(f.backup_root, L"D:P(A;OICI;FA;;;WD)");
    rejects([&] { (void)d.backup(); });
    apply_security(f.backup_root, root_sd); f.original_state();
}

void mutex_contention(const fs::path& base) {
    Fixture f(base, L"跨线程互斥", false); auto d = f.deployer();
    Handle directory(CreateFileW(f.target.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    require(GetFileInformationByHandle(directory.h, &info) != FALSE, "directory identity failed");
    const auto id = (std::uint64_t(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    const auto name = L"Global\\LexHelper.Deploy." + std::to_wstring(info.dwVolumeSerialNumber) + L"." + std::to_wstring(id);
    const auto sd = security(f.target);
    PSID owner{}; BOOL defaulted{};
    require(GetSecurityDescriptorOwner(reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(sd.data())),
                                       &owner, &defaulted) != FALSE, "owner lookup failed");
    // Use the current token SID, not a possibly inherited directory owner.
    HANDLE raw{}; require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw) != FALSE, "token open failed");
    Handle token(raw); DWORD size{}; GetTokenInformation(token.h, TokenUser, nullptr, 0, &size);
    Bytes token_data(size); require(GetTokenInformation(token.h, TokenUser, token_data.data(), size, &size) != FALSE,
                                    "token user failed");
    LPWSTR sid{};
    require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(token_data.data())->User.Sid, &sid) != FALSE,
            "SID string failed");
    const auto sddl = L"O:" + std::wstring(sid) + L"G:" + sid + L"D:P(A;;GA;;;" + sid + L")(A;;GA;;;SY)(A;;GA;;;BA)";
    LocalFree(sid); PSECURITY_DESCRIPTOR mutex_sd{};
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &mutex_sd, nullptr) != FALSE,
            "mutex descriptor failed");
    SECURITY_ATTRIBUTES sa{sizeof(sa), mutex_sd, FALSE};
    Handle held(CreateMutexW(&sa, TRUE, name.c_str())); LocalFree(mutex_sd);
    require(held.h != nullptr, "test mutex creation failed");
    std::string rejection;
    std::thread worker([&] { try { (void)d.backup(); } catch (const std::exception& ex) { rejection = ex.what(); } });
    worker.join(); require(!rejection.empty(), "concurrent deployment not rejected");
    require(!fs::exists(f.backup_root), "contended operation wrote a backup");
    require(ReleaseMutex(held.h) != FALSE, "test mutex release failed");
    require(!d.backup().empty(), "operation failed after mutex release"); f.original_state();

    // A real second process holds the same global mutex; the deployer must not wait forever.
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, (name + L".ready").c_str()));
    Handle release(CreateEventW(nullptr, TRUE, FALSE, (name + L".release").c_str()));
    require(ready.h && release.h, "child synchronization events failed");
    std::array<wchar_t, 32768> exe{};
    require(GetModuleFileNameW(nullptr, exe.data(), static_cast<DWORD>(exe.size())) != 0, "test exe path failed");
    std::wstring command = L"\"" + std::wstring(exe.data()) + L"\" --hold-mutex \"" + name + L"\"";
    STARTUPINFOW startup{sizeof(startup)}; PROCESS_INFORMATION process{};
    require(CreateProcessW(exe.data(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                           f.root.c_str(), &startup, &process) != FALSE, "start mutex test child failed");
    Handle child(process.hProcess), child_thread(process.hThread);
    const auto ready_result = WaitForSingleObject(ready.h, 10000);
    const auto before = backups(f.backup_root).size();
    std::string child_rejection;
    if (ready_result == WAIT_OBJECT_0) {
        try { (void)d.install(f.generated); } catch (const std::exception& ex) { child_rejection = ex.what(); }
    }
    SetEvent(release.h);
    const auto stopped = WaitForSingleObject(child.h, 15000);
    DWORD exit_code{}; GetExitCodeProcess(child.h, &exit_code);
    require(ready_result == WAIT_OBJECT_0 && stopped == WAIT_OBJECT_0 && exit_code == 0, "mutex test child failed/timed out");
    require(!child_rejection.empty(), "cross-process installation not rejected");
    require(backups(f.backup_root).size() == before, "contended installation wrote a backup");
    f.original_state();
}

int hold_mutex_child(const std::wstring& name) {
    Handle mutex(OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, name.c_str()));
    Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, (name + L".ready").c_str()));
    Handle release(OpenEventW(SYNCHRONIZE, FALSE, (name + L".release").c_str()));
    if (!mutex.h || !ready.h || !release.h || WaitForSingleObject(mutex.h, 10000) != WAIT_OBJECT_0) return 2;
    SetEvent(ready.h);
    const auto result = WaitForSingleObject(release.h, 10000);
    ReleaseMutex(mutex.h);
    return result == WAIT_OBJECT_0 ? 0 : 3;
}

void junction_test(const fs::path& base) {
    Fixture f(base, L"目录联接", false);
    const auto link = f.root / L"联接";
    require(CreateDirectoryW(link.c_str(), nullptr) != FALSE, "junction directory failed");
    {
        Handle h(CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        require(h.h != INVALID_HANDLE_VALUE, "junction handle failed");
        const auto substitute = L"\\??\\" + f.target.wstring(), print = f.target.wstring();
        struct MountHeader { DWORD tag; WORD data_length; WORD reserved; WORD sub_offset;
            WORD sub_length; WORD print_offset; WORD print_length; };
        MountHeader header{}; header.tag = IO_REPARSE_TAG_MOUNT_POINT;
        header.sub_length = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
        header.print_offset = header.sub_length + sizeof(wchar_t);
        header.print_length = static_cast<WORD>(print.size() * sizeof(wchar_t));
        header.data_length = static_cast<WORD>(8 + header.print_offset + header.print_length + sizeof(wchar_t));
        Bytes data(8 + header.data_length);
        std::memcpy(data.data(), &header, sizeof(header));
        std::memcpy(data.data() + sizeof(header), substitute.c_str(), header.sub_length + sizeof(wchar_t));
        std::memcpy(data.data() + sizeof(header) + header.print_offset, print.c_str(), header.print_length + sizeof(wchar_t));
        DWORD returned{};
        require(DeviceIoControl(h.h, FSCTL_SET_REPARSE_POINT, data.data(), static_cast<DWORD>(data.size()),
                                nullptr, 0, &returned, nullptr) != FALSE, "junction creation failed");
    }
    try {
        lexhelper::Deployer d({link, f.backup_root, false});
        rejects([&] { (void)d.backup(); });
        rejects([&] { (void)d.install(f.generated); });
        f.original_state();
    } catch (...) { RemoveDirectoryW(link.c_str()); throw; }
    require(RemoveDirectoryW(link.c_str()) != FALSE, "remove own junction failed");
    require(fs::exists(f.target / L"ChsWubi.lex"), "junction removal followed target");
}

void complete_security_tests(const fs::path& base) {
    using namespace lexhelper::deploy_testing;
    const std::array<std::wstring, 5> sacls{
        L"", L"S:NO_ACCESS_CONTROL", L"S:P", L"S:PAI(AU;SAFA;0x2;;;WD)(ML;;NW;;;LW)",
        L"S:AIAR(AU;SA;FR;;;WD)(ML;;NWNRNX;;;ME)"};
    unsigned index{};
    for (const auto& text : sacls) {
        Fixture f(base, L"完整安全元数据-" + std::to_wstring(++index), true);
        set_simulated_sacl(f.target / L"ChsWubi.lex", sacl_descriptor(text));
        set_simulated_sacl(f.target / L"ChsWubiNew.lex", sacl_descriptor(text));
        f.remember_full_security();
        auto d = f.deployer(); const auto b = d.install(f.generated); f.installed_state();
        d.restore(b); f.original_state(); d.restore(b); f.original_state();
        // Permission failure while reading *complete* metadata is pre-mutation.
        const auto count = backups(f.backup_root).size();
        inject_failure(FailurePoint::full_security_read);
        rejects([&] { (void)d.install(f.generated); });
        require(backups(f.backup_root).size() == count, "partial metadata was accepted into a backup");
        f.original_state();
    }
    Fixture f(base, L"SACL回滚与损坏", true);
    set_simulated_sacl(f.target / L"ChsWubiNew.lex", sacl_descriptor(sacls[3])); f.remember_full_security();
    auto d = f.deployer(); const auto b = d.install(f.generated);
    inject_failure(FailurePoint::after_sacl_restore);
    rejects([&] { d.restore(b); }); f.installed_state();
    d.restore(b); f.original_state();
    const auto c = d.install(f.generated);
    const auto clean = load(c / L"manifest.lhb");
    auto write_u32 = [](Bytes& bytes, std::size_t at, std::uint32_t value) {
        for (unsigned n = 0; n < 4; ++n) bytes[at + n] = std::byte((value >> (8 * n)) & 255);
    };
    // Schema 2 begins first SD at byte 112; walk its length to the second SD.
    auto read_u32 = [](const Bytes& bytes, std::size_t at) {
        std::uint32_t value{}; for (unsigned n = 0; n < 4; ++n)
            value |= std::uint32_t(std::to_integer<unsigned>(bytes.at(at + n))) << (8 * n); return value;
    };
    require(read_u32(clean, 4) == 2 && read_u32(clean, 104) == 0x32445346, "full-security schema marker missing");
    const auto second_sd = std::size_t(112) + read_u32(clean, 108) + 88;
    require(second_sd + 20 < clean.size(), "second descriptor offset invalid");
    const auto sacl = second_sd + read_u32(clean, second_sd + 12);
    require(sacl + 24 < clean.size(), "synthetic SACL not serialized");
    const auto label = sacl + 8 + std::to_integer<unsigned>(clean[sacl + 10]) +
        (std::to_integer<unsigned>(clean[sacl + 11]) << 8);
    for (unsigned variant = 0; variant < 11; ++variant) {
        auto corrupt = clean;
        if (variant == 0) write_u32(corrupt, 4, 1); // Old partial schema is not restorable.
        if (variant == 1) write_u32(corrupt, second_sd + 12, 0xfffffff0);
        if (variant == 2) corrupt[sacl + 8] = std::byte{SYSTEM_AUDIT_CALLBACK_ACE_TYPE};
        if (variant == 3) { corrupt[sacl + 10] = std::byte{4}; corrupt[sacl + 11] = std::byte{0}; }
        if (variant == 4) corrupt[sacl + 8 + 8 + 1] = std::byte{255};
        if (variant == 5) write_u32(corrupt, second_sd + 12, read_u32(corrupt, second_sd + 16)); // Overlap SACL/DACL.
        if (variant == 6) corrupt[label + 8 + 7] = std::byte{5}; // Not SECURITY_MANDATORY_LABEL_AUTHORITY.
        if (variant == 7) write_u32(corrupt, label + 4, 0x80000001);
        if (variant == 8) { corrupt[sacl + 4] = std::byte{255}; corrupt[sacl + 5] = std::byte{255}; }
        if (variant == 9) corrupt[label + 8 + 1] = std::byte{2};
        if (variant == 10) corrupt[label] = std::byte{SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE};
        refresh_digest(corrupt); save(c / L"manifest.lhb", corrupt);
        const auto count = backups(f.backup_root).size();
        rejects([&] { d.restore(c); }); f.installed_state();
        require(backups(f.backup_root).size() == count, "corrupt SACL created a restore point");
    }
    save(c / L"manifest.lhb", clean); d.restore(c); f.original_state();

    // Ordinary permissions must not degrade a complete snapshot into DACL-only.
    // Do not enable or disable any real privilege for this negative test.
    const auto before_tokens = capture_tokens();
    const auto native = f.root / L"未注册模拟后端";
    fs::create_directory(native); save(native / L"ChsWubi.lex", f.original);
    LUID security_luid{};
    require(LookupPrivilegeValueW(nullptr, SE_SECURITY_NAME, &security_luid) != FALSE, "lookup security privilege failed");
    bool enabled{};
    const auto tp = reinterpret_cast<const TOKEN_PRIVILEGES*>(before_tokens.process_privileges.data());
    for (DWORD i = 0; i < tp->PrivilegeCount; ++i)
        if (tp->Privileges[i].Luid.LowPart == security_luid.LowPart && tp->Privileges[i].Luid.HighPart == security_luid.HighPart)
            enabled = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
    if (!enabled && !before_tokens.has_thread) {
        auto native_deployer = lexhelper::Deployer({native, f.root / L"原生权限拒绝备份", false});
        rejects([&] { (void)native_deployer.install(f.generated); });
        require(load(native / L"ChsWubi.lex") == f.original, "incomplete native SACL read modified the target");
    } else std::cout << "SKIP: native permission-refusal probe (caller already has a privileged/impersonating token)\n";
    require(capture_tokens() == before_tokens, "simulation changed process privileges or caller thread token");
}

void hardlink_sentinel_tests(const fs::path& base) {
    using namespace lexhelper::deploy_testing;
    const std::array points{FailurePoint::none, FailurePoint::after_backup,
        FailurePoint::before_security_restore, FailurePoint::after_sacl_restore,
        FailurePoint::after_primary_write, FailurePoint::after_new_disabled,
        FailurePoint::after_primary_unlink, FailurePoint::after_new_unlink, FailurePoint::after_first_cleanup_mark};
    unsigned count{};
    for (const bool has_new : {false, true}) for (const auto point : points) {
        Fixture f(base, L"WinSxS硬链接哨兵-" + std::to_wstring(++count), has_new);
        set_simulated_sacl(f.target / L"ChsWubi.lex", sacl_descriptor(L"S:PAI(AU;SAFA;FR;;;WD)(ML;;NW;;;ME)"));
        if (has_new) set_simulated_sacl(f.target / L"ChsWubiNew.lex", sacl_descriptor(L"S:P(AU;SA;0x2;;;WD)(ML;;NW;;;LW)"));
        f.remember_full_security();
        const auto sentinel = f.root / L"WinSxS-sentinel";
        fs::create_directory(sentinel); enable_security_simulation(sentinel);
        for (const auto* name : {L"ChsWubi.lex", L"ChsWubiNew.lex"})
            if (fs::exists(f.target / name)) require(CreateHardLinkW((sentinel / name).c_str(), (f.target / name).c_str(), nullptr) != FALSE,
                    "create WinSxS sentinel link failed");
        require(SetFileAttributesW((f.target / L"ChsWubi.lex").c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY) != FALSE,
                "set shared readonly sentinel attributes failed");
        const auto primary_attrs = GetFileAttributesW((sentinel / L"ChsWubi.lex").c_str());
        auto unchanged = [&] {
            require(load(sentinel / L"ChsWubi.lex") == f.original, "WinSxS primary stream was modified");
            if (has_new) require(load(sentinel / L"ChsWubiNew.lex") == f.secondary, "WinSxS New stream was modified");
            require(GetFileAttributesW((sentinel / L"ChsWubi.lex").c_str()) == primary_attrs, "shared old attributes modified");
            require(same_security(simulated_security(sentinel / L"ChsWubi.lex"), f.primary_full), "shared primary security modified");
            if (has_new) require(same_security(simulated_security(sentinel / L"ChsWubiNew.lex"), f.secondary_full), "shared New security modified");
        };
        auto d = f.deployer();
        const auto standalone = d.backup(); require(fs::exists(standalone / L"original-0.bin"), "multi-link backup failed");
        inject_failure(point);
        if (point == FailurePoint::none) {
            const auto b = d.install(f.generated); f.installed_state(); unchanged();
            d.restore(b); f.original_state(); unchanged();
            inject_failure(FailurePoint::after_primary_write);
            rejects([&] { (void)d.install(f.generated); }); f.original_state(); unchanged();
            const auto b2 = d.install(f.generated); unchanged();
            inject_failure(FailurePoint::after_new_disabled);
            rejects([&] { d.restore(b2); }); f.installed_state(); unchanged();
            d.restore(b2); f.original_state(); unchanged();
        } else {
            rejects([&] { (void)d.install(f.generated); }); f.original_state(); unchanged();
        }
        for (const auto& entry : fs::directory_iterator(f.target))
            require(!entry.path().filename().wstring().starts_with(L"LexHelper-"), "successful rollback/commit leaked a sidecar");
    }
}

void independent_hardlink_matrix(const fs::path& base) {
    using namespace lexhelper::deploy_testing;
    const std::array points{FailurePoint::after_backup, FailurePoint::after_primary_write,
        FailurePoint::after_new_disabled, FailurePoint::before_security_restore, FailurePoint::full_security_read,
        FailurePoint::after_sacl_restore, FailurePoint::after_primary_unlink, FailurePoint::after_new_unlink,
        FailurePoint::after_first_cleanup_mark};
    unsigned sequence{};
    for (const bool has_new : {false, true}) for (const bool restoring : {false, true}) for (const auto point : points) {
        Fixture f(base, L"独立哨兵矩阵-" + std::to_wstring(++sequence), has_new);
        set_simulated_sacl(f.target / L"ChsWubi.lex", sacl_descriptor(L"S:PAIAR(AU;SAFA;FR;;;WD)(ML;;NWNRNX;;;ME)"));
        if (has_new) set_simulated_sacl(f.target / L"ChsWubiNew.lex", sacl_descriptor(L"S:AI(AU;SA;0x2;;;WD)(ML;;NW;;;LW)"));
        f.remember_full_security();
        require(SetFileAttributesW((f.target / L"ChsWubi.lex").c_str(),
                    FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
                "clear primary ARCHIVE before shared-object test failed");
        if (has_new) require(SetFileAttributesW((f.target / L"ChsWubiNew.lex").c_str(),
                    FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
                "clear New ARCHIVE before shared-object test failed");
        std::vector<Sentinel> original;
        original.emplace_back(f.target / L"ChsWubi.lex", f.root / L"original-sentinel");
        if (has_new) original.emplace_back(f.target / L"ChsWubiNew.lex", f.root / L"original-sentinel");
        auto unchanged = [&] { for (const auto& s : original) s.unchanged(); };
        auto d = f.deployer();
        fs::path backup;
        std::vector<Sentinel> installed;
        if (restoring) {
            backup = d.install(f.generated); f.installed_state(); unchanged();
            installed.emplace_back(f.target / L"ChsWubi.lex", f.root / L"installed-sentinel");
        }
        const auto before = backups(f.backup_root).size();
        inject_failure(point);
        const auto message = rejects([&] { if (restoring) d.restore(backup); else (void)d.install(f.generated); });
        require(message.find("模拟部署故障注入") != std::string::npos, "matrix did not reach its intended failure hook");
        require(backups(f.backup_root).size() == before + (point == FailurePoint::full_security_read ? 0 : 1),
                "matrix preflight/recovery-point count mismatch");
        if (point != FailurePoint::full_security_read)
            require(message.find("已校验回滚") != std::string::npos && message.find("回滚不完整") == std::string::npos,
                    "matrix rollback status inaccurate");
        if (restoring) f.installed_state(); else f.original_state();
        unchanged(); for (const auto& s : installed) s.unchanged();
        for (const auto& item : fs::directory_iterator(f.target))
            require(!item.path().filename().wstring().starts_with(L"LexHelper-"), "matrix rollback leaked owned staging object");
        if (!restoring) backup = d.install(f.generated);
        unchanged();
        d.restore(backup); f.original_state(); unchanged();
        for (const auto& s : installed) s.unchanged();
        const auto restored = basic_info(f.target / L"ChsWubi.lex");
        require(restored.CreationTime.QuadPart == original.front().basic.CreationTime.QuadPart &&
                restored.LastWriteTime.QuadPart == original.front().basic.LastWriteTime.QuadPart,
                "restore did not preserve supported creation/write timestamps");
    }

    Fixture f(base, L"恢复混合态-回滚失败", true);
    set_simulated_sacl(f.target / L"ChsWubi.lex", sacl_descriptor(L"S:P(AU;SAFA;FR;;;WD)(ML;;NW;;;ME)"));
    f.remember_full_security();
    Sentinel old_primary(f.target / L"ChsWubi.lex", f.root / L"original-sentinel");
    Sentinel old_new(f.target / L"ChsWubiNew.lex", f.root / L"original-sentinel");
    auto d = f.deployer(); const auto backup = d.install(f.generated);
    Sentinel installed(f.target / L"ChsWubi.lex", f.root / L"installed-sentinel");
    inject_failure(FailurePoint::after_first_cleanup_mark, true);
    const auto message = rejects([&] { d.restore(backup); });
    require(message.find("回滚不完整") != std::string::npos && message.find("已校验回滚") == std::string::npos &&
            message.find("受保护恢复副本=") != std::string::npos && message.find("backup-") != std::string::npos &&
            message.find("ChsWubi.lex") != std::string::npos, "restore rollback failure omitted accurate recovery paths");
    require(load(f.target / L"ChsWubi.lex") == f.original && !fs::exists(f.target / L"ChsWubiNew.lex"),
            "restore rollback failure concrete mixed state differs from injection semantics");
    old_primary.unchanged(); old_new.unchanged(); installed.unchanged();
    require(backups(f.backup_root).size() == 2, "failed restore did not retain the pre-restore recovery point");
    unsigned retained{};
    for (const auto& item : fs::directory_iterator(f.target))
        if (item.path().filename().wstring().starts_with(L"LexHelper-")) {
            ++retained; require(load(item.path()) == f.replacement, "retained rollback copy has incorrect bytes");
        }
    require(retained == 1, "restore rollback failure did not retain its independent recovery copy");
    rejects([&] { d.restore(backup); }); // Neither known whole state: refuse to overwrite a mixed/unknown state.
    old_primary.unchanged(); old_new.unchanged(); installed.unchanged();
}

void protected_dacl_roundtrip(const fs::path& base, const std::wstring& name, const wchar_t* descriptor) {
    Fixture f(base, name, true);
    dacl(f.target / L"ChsWubi.lex", descriptor);
    f.primary_sd = security(f.target / L"ChsWubi.lex"); f.remember_full_security();
    std::cout << "OBSERVE: protected DACL controls before="
              << reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(f.primary_sd.data())->Control << '\n';
    auto d = f.deployer();
    try {
        const auto b = d.install(f.generated); f.installed_state(); d.restore(b); f.original_state();
    } catch (...) {
        f.original_state(); // Failure must remain safe even when a legal descriptor cannot be deployed.
        throw;
    }
}

void additional_preflight_tests(const fs::path& base) {
    Fixture f(base, L"双文件完整预检", true); auto d = f.deployer();
    const auto ads = fs::path((f.target / L"ChsWubiNew.lex").wstring() + L":unbacked");
    save(ads, Bytes{std::byte{2}});
    rejects([&] { (void)d.install(f.generated); });
    require(backups(f.backup_root).empty(), "second-file ADS failure produced an incomplete backup");
    require(load(f.target / L"ChsWubi.lex") == f.original && load(f.target / L"ChsWubiNew.lex") == f.secondary &&
            same_security(security(f.target / L"ChsWubi.lex"), f.primary_sd), "second-file preflight changed native target state");
    require(DeleteFileW(ads.c_str()), "remove own second-file ADS failed");
    f.original_state();
    const auto b = d.install(f.generated);
    const auto clean = load(b / L"manifest.lhb"), payload = load(b / L"original-1.bin");
    const auto payload_sd = security(b / L"original-1.bin");
    const auto count = backups(f.backup_root).size();
    require(DeleteFileW((b / L"original-1.bin").c_str()), "remove own payload for preflight test failed");
    rejects([&] { d.restore(b); }); f.installed_state();
    require(backups(f.backup_root).size() == count, "missing second payload created a recovery point");
    save_new_secure(b / L"original-1.bin", payload, payload_sd);
    const auto offsets = state_offsets(clean);
    const auto second = offsets[1];
    for (unsigned variant = 0; variant < 15; ++variant) {
        auto corrupt = clean;
        const auto sd = second + 88, dacl_at = sd + u32(clean, sd + 16);
        if (variant == 0) put32(corrupt, second, 2);
        if (variant == 1) put32(corrupt, second + 80, 0x31445346); // Partial/unknown security provenance.
        if (variant == 2) put32(corrupt, second + 84, 65537);
        if (variant == 3) corrupt[sd] = std::byte{2};
        if (variant == 4) put32(corrupt, sd + 4, 21); // Misaligned owner.
        if (variant == 5) put32(corrupt, sd + 8, 0xfffffff0);
        if (variant == 6) put32(corrupt, sd + 16, 0); // Null DACL unsupported.
        if (variant == 7) corrupt[dacl_at] = std::byte{255};
        if (variant == 8) corrupt[dacl_at + 8] = std::byte{ACCESS_ALLOWED_CALLBACK_ACE_TYPE};
        if (variant == 9) corrupt[dacl_at + 9] = std::byte{0xff};
        if (variant == 10) { corrupt[dacl_at + 10] = std::byte{0xfc}; corrupt[dacl_at + 11] = std::byte{0xff}; }
        if (variant == 11) corrupt[dacl_at + 16] = std::byte{2}; // ACE SID revision.
        if (variant == 12) put32(corrupt, second + 44, FILE_ATTRIBUTE_SPARSE_FILE);
        if (variant == 13) put32(corrupt, second + 4, 64 * 1024 * 1024 + 1);
        if (variant == 14) put32(corrupt, second + 76, 0xffffffff); // Negative ChangeTime.
        refresh_digest(corrupt); save(b / L"manifest.lhb", corrupt);
        rejects([&] { d.restore(b); }); f.installed_state();
        require(backups(f.backup_root).size() == count, "malformed second state created a recovery point");
    }
    save(b / L"manifest.lhb", clean);
    for (const auto* name : {L"manifest.lhb", L"original-0.bin", L"original-1.bin"}) {
        const auto sd = security(b / name);
        dacl(b / name, L"D:P(A;;FA;;;WD)");
        rejects([&] { d.restore(b); }); f.installed_state();
        apply_security(b / name, sd);
        const auto link = f.root / (std::wstring(name) + L".link");
        require(CreateHardLinkW(link.c_str(), (b / name).c_str(), nullptr), "create backup-file alias failed");
        rejects([&] { d.restore(b); }); f.installed_state();
        require(DeleteFileW(link.c_str()), "remove own backup-file alias failed");
    }
    d.restore(b); f.original_state();
    require(load(b / L"manifest.lhb") == clean && load(b / L"original-1.bin") == payload,
            "restoring modified historical backup bytes");

    Fixture absent(base, L"无New-多余备份载荷", false); auto da = absent.deployer(); const auto ba = da.install(absent.generated);
    save_new_secure(ba / L"original-1.bin", payload, security(ba / L"original-0.bin"));
    rejects([&] { da.restore(ba); }); absent.installed_state();

    Fixture paths(base, L"大小写与设备路径", true); auto dp = paths.deployer();
    for (const auto& invalid : {fs::path(L"\\\\?\\D:\\temp"), fs::path(L"\\\\.\\NUL"), fs::path(L"\\\\localhost\\share"),
                               paths.target / L"bad ", paths.target / L"bad?name"})
        rejects([&] { lexhelper::Deployer unused({invalid, paths.backup_root, false}); });
    rejects([&] { lexhelper::Deployer bad({paths.target, paths.root / L"模拟词库" / L"CaseAlias", false}); });
    auto mixed = paths.target.wstring();
    for (auto& c : mixed) if (c >= L'a' && c <= L'z') c = wchar_t(c - L'a' + L'A');
    rejects([&] { lexhelper::Deployer overlap({paths.target, fs::path(mixed) / L"backup", false}); });
    auto bd = lexhelper::Deployer({fs::path(mixed), paths.backup_root, false});
    const auto bp = bd.install(paths.generated); paths.installed_state(); dp.restore(bp); paths.original_state();
    rejects([&] { (void)dp.install(paths.root / L"NUL"); }); paths.original_state();
}

#include "deploy_backup_consistency.inc"
#include "deploy_destination_conflicts.inc"

fs::path unique_sandbox() {
    const fs::path base = L"D:\\temp\\aiRunner\\opencode";
    auto current = base.root_path();
    for (const auto& component : base.relative_path()) {
        current /= component; const DWORD a = GetFileAttributesW(current.c_str());
        require(a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT),
                "approved test root unavailable or contains reparse point; no fallback");
    }
    std::array<unsigned char, 16> random{};
    require(BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
            "sandbox random failed");
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring name = L"LexHelper-deploy-tests-";
    for (auto b : random) { name += digits[b >> 4]; name += digits[b & 15]; }
    const auto path = base / name;
    require(CreateDirectoryW(path.c_str(), nullptr) != FALSE, "unique test sandbox failed");
    return path;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring(argv[1]) == L"--hold-mutex") return hold_mutex_child(argv[2]);
    fs::path sandbox;
    try {
        sandbox = unique_sandbox();
        const auto initial_tokens = capture_tokens();
        std::cout << "Sandbox: " << sandbox.string() << '\n';
        unsigned failed_groups{}, total_groups{};
        auto group = [&](const char* name, auto&& operation) {
            ++total_groups;
            std::cout << "GROUP: " << name << '\n';
            try { operation(); std::cout << "GROUP PASS: " << name << '\n'; }
            catch (const std::exception& ex) { ++failed_groups; std::cerr << "GROUP FAIL: " << name << ": " << ex.what() << '\n'; }
            lexhelper::deploy_testing::inject_failure(lexhelper::deploy_testing::FailurePoint::none);
            lexhelper::deploy_testing::set_observer({}, nullptr, nullptr);
        };
        group("roundtrip-without-New", [&] { roundtrip(sandbox, false); });
        group("roundtrip-with-New", [&] { roundtrip(sandbox, true); });
        group("failure-paths", [&] { failure_paths(sandbox); });
        group("corrupt-backups", [&] { corrupt_backups(sandbox); });
        group("unsafe-paths", [&] { unsafe_paths(sandbox); });
        group("exclusive-and-permissions", [&] { exclusive_and_permissions(sandbox); });
        group("thread-and-process-mutex", [&] { mutex_contention(sandbox); });
        group("junction", [&] { junction_test(sandbox); });
        group("complete-security", [&] { complete_security_tests(sandbox); });
        group("hardlink-sentinels", [&] { hardlink_sentinel_tests(sandbox); });
        group("independent-hardlink-matrix", [&] { independent_hardlink_matrix(sandbox); });
        group("additional-preflight", [&] { additional_preflight_tests(sandbox); });
        group("protected-OwnerRights-DACL", [&] {
            protected_dacl_roundtrip(sandbox, L"受保护OwnerRights-DACL", L"D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"); });
        group("protected-simple-DACL", [&] {
            protected_dacl_roundtrip(sandbox, L"受保护普通-DACL", L"D:P(A;;FA;;;WD)"); });
        backup_consistency_groups(sandbox, group);
        destination_conflict_groups(sandbox, group);
        require(capture_tokens() == initial_tokens, "deployment test suite leaked a privilege or thread token");
        std::cout << "OBSERVE: sentinel metadata comparisons with changed LastAccessTime=" << observed_last_access_changes
                  << "; changed ChangeTime=" << observed_change_time_changes
                  << "; creation/write/attributes/content/SD asserted unchanged\n";
        if (failed_groups) {
            std::ofstream(sandbox / L"result.txt") << "FAIL groups=" << failed_groups << " checks=" << checks << "\n";
            std::cerr << "FAIL: " << failed_groups << " groups; " << checks << " checks reached; sandbox retained\n";
            return 1;
        }
        std::ofstream(sandbox / L"result.txt") << "PASS checks=" << checks << "\n";
        std::cout << "PASS GROUPS: " << total_groups << '/' << total_groups << '\n';
        std::cout << "PASS: " << checks << " checks; simulation only; no system installation\n";
        // Retain only this run's small evidence sandbox for the parent workflow's safe cleanup.
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "FAIL: " << ex.what() << "\nEvidence sandbox retained; no system files used.\n";
        return 1;
    }
}
