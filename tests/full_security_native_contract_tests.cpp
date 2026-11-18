// TC-007: ordinary-token, real Windows contracts. No API substitutes, no UAC.
// Build using the superproject in full_security_native_validation.ps1.
#define wmain full_security_probe_cli_entry
#include "full_security_native_probe.cpp"
#undef wmain
#include <winioctl.h>

namespace ordinary_contract {
using namespace native_probe;
unsigned checks{}, groups{}, failures{}, os_refusals{};
void require(bool ok, const char* message) { ++checks; check(ok, message); }
template<class F> void rejected(F&& f, std::string_view reason) {
    bool caught{};
    try { f(); } catch (const std::exception& e) {
        caught = true;
        std::cout << "EXPECTED_REJECTION " << e.what() << '\n';
        require(std::string_view(e.what()).find(reason) != std::string_view::npos, "unexpected rejection stage");
    }
    require(caught, "unsafe operation was accepted");
}
template<class F> void group(const char* name, F&& f) {
    ++groups;
    try { f(); std::cout << "PASS " << name << '\n'; }
    catch (const std::exception& e) { ++failures; std::cout << "FAIL " << name << ": " << e.what() << '\n'; }
}
std::wstring sid_text() {
    auto sid = lexhelper::current_user_sid(); LPWSTR text{};
    wincheck(ConvertSidToStringSidW(sid.data(), &text), "test SID conversion");
    lexhelper::LocalPtr holder(text); return text; // Never print SID / descriptor.
}
lexhelper::LocalPtr sd_from(const std::wstring& text) {
    PSECURITY_DESCRIPTOR raw{};
    wincheck(ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(), SDDL_REVISION_1, &raw, nullptr), "test SD");
    return lexhelper::LocalPtr(raw);
}
fs::path new_root(const fs::path& first = {}, PSECURITY_DESCRIPTOR sd = nullptr) {
    const auto path = first.empty() ? fs::path(std::wstring(prefix) + random_leaf().substr(8)) : first;
    require(allowed_root(path.wstring()), "runner root syntax");
    lexhelper::PinnedDirectory base(L"D:\\temp\\aiRunner\\opencode");
    lexhelper::require_ntfs(base.get(), base.path);
    lexhelper::Security security(false);
    auto h = relative(base.get(), path.filename().wstring(), directory_access | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY,
        FILE_CREATE, true, sd ? sd : security.attributes.lpSecurityDescriptor);
    auto made = object(std::move(h), path, true); verify(made);
    std::cout << "ROOT_CREATED " << lexhelper::utf8(path.wstring()) << std::endl;
    return path; // Creation SD is atomic; never repair ACL of an existing object.
}
Handle open_owned(const fs::path& path, DWORD access, bool directory = false) {
    Handle h(CreateFileW(path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
    wincheck(h.valid(), "open own fixture"); return h;
}
std::string read_handle(HANDLE h) {
    LARGE_INTEGER zero{}, size{}; wincheck(GetFileSizeEx(h, &size), "fixture length");
    check(size.QuadPart >= 0 && size.QuadPart <= 65536, "fixture too large");
    wincheck(SetFilePointerEx(h, zero, nullptr, FILE_BEGIN), "fixture seek");
    std::string text(static_cast<std::size_t>(size.QuadPart), '\0'); DWORD done{};
    wincheck(ReadFile(h, text.data(), static_cast<DWORD>(text.size()), &done, nullptr), "fixture read");
    check(done == text.size(), "short read"); return text;
}
std::string read_path(const fs::path& path) { auto h = open_owned(path, FILE_READ_DATA); return read_handle(h.get()); }
void seed(const fs::path& path, std::wstring_view leaf, bool directory = false) {
    auto parent = open_owned(path, FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | SYNCHRONIZE, true);
    lexhelper::Security security(false);
    auto h = relative(parent.get(), leaf, directory ? directory_access : FILE_READ_DATA | FILE_WRITE_DATA | low_access,
        FILE_CREATE, directory, security.attributes.lpSecurityDescriptor);
    if (!directory) write(h.get(), "DO_NOT_OVERWRITE_SENTINEL\r\n");
}
void verify_owner(HANDLE h) {
    PSECURITY_DESCRIPTOR raw{}; PSID owner{};
    require(GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &raw) == 0,
        "owner query failed");
    lexhelper::LocalPtr holder(raw); auto user = lexhelper::current_user_sid();
    require(owner && EqualSid(owner, user.data()), "created object owner mismatch");
}
void os_denied(BOOL result, const char* operation) {
    const auto code = result ? ERROR_SUCCESS : GetLastError();
    std::cout << "OS_ATTEMPT " << operation << "; success=" << !!result << "; Win32=" << code << '\n';
    require(!result && code == ERROR_SHARING_VIOLATION, "held sharing guard did not reject mutation");
    ++os_refusals; // OS prevention, NOT a mutation followed by a probe rejection.
}
void parser_contract() {
    const auto root = std::wstring(prefix) + std::wstring(32, L'0');
    require(parse({L"--diagnose", L"--root", root}) == Mode::diagnose, "valid root rejected");
    const std::vector<std::wstring> bad{L"\\\\server\\share\\x", L"\\\\.\\D:\\x", L"\\??\\" + root,
        L"\\\\?\\" + root, root + L":$DATA", root + L" ", root + L"\\..", root + L"/child",
        root + L"\\", root + L".", L"D:/temp/aiRunner/opencode/" + root.substr(prefix.size()),
        L"D:\\temp\\aiRunner\\opencode\\.\\" + root.substr(26), L"C:" + root.substr(2),
        L"d:" + root.substr(2), std::wstring(prefix) + std::wstring(32, L'F'), root + std::wstring(1, L'\0')};
    for (const auto& text : bad) require(parse({L"--diagnose", L"--root", text}) == Mode::invalid, "unsafe path accepted");
    for (std::size_t n : {0u, 1u, 31u, 33u, 64u, 4096u})
        require(!allowed_root(std::wstring(prefix) + std::wstring(n, L'a')), "root length accepted");
    for (std::size_t i = 0; i != prefix.size(); ++i) {
        auto changed = root; const auto c = changed[i];
        if (c >= L'a' && c <= L'z') { changed[i] = static_cast<wchar_t>(c - 32);
            require(!allowed_root(changed), "prefix casing normalized"); }
    }
    require(parse({L"--diagnose", L"--root", root, L"--self-test"}) == Mode::invalid, "extra option accepted");
    require(parse({L"--diagnose", L"--root", root, L"--root", root}) == Mode::invalid, "duplicate option accepted");
    require(parse({L"--self-test", L"--diagnose"}) == Mode::invalid, "mixed mode accepted");
    require(parse({L"--root=" + root}) == Mode::invalid, "unknown option accepted");
}
void token_contract() {
    const auto process = process_token(); const auto baseline = effective_token();
    for (bool existing : {false, true}) {
        // Install only a fresh ordinary impersonation token; never adjust shared baseline.
        lexhelper::Privileges outer;
        if (existing) outer.enable_names(true, {});
        const auto before = effective_token();
        for (unsigned scenario = 0; scenario != 5; ++scenario) {
            bool caught{};
            try {
                lexhelper::Privileges scope;
                if (scenario == 2) scope.enable_names(true, {SE_SECURITY_NAME}); // missing before install
                else {
                    scope.enable_names(true, {});
                    auto copy = private_token(before);
                    require(effective_token().thread && !same_id(effective_token().id, before.id), "private token identity");
                    require(process_token() == process, "process mutated inside scope");
                    if (privilege(before, SE_CHANGE_NOTIFY_NAME)) {
                        disable(copy.get(), SE_CHANGE_NOTIFY_NAME);
                        require(!(privilege(effective_token(), SE_CHANGE_NOTIFY_NAME).value() & SE_PRIVILEGE_ENABLED), "private disable failed");
                        scope.enable_names(true, {SE_CHANGE_NOTIFY_NAME});
                        require(privilege(effective_token(), SE_CHANGE_NOTIFY_NAME).value() & SE_PRIVILEGE_ENABLED, "ordinary privilege enable failed");
                    }
                    if (scenario == 1) throw std::runtime_error("intentional unwind");
                    if (scenario == 3) scope.enable_names(true, {SE_SECURITY_NAME}); // fail after private install
                    if (scenario == 4) rejected([&] { (void)private_token(effective_token()); }, "private copy token not installed");
                }
            } catch (const std::exception& e) {
                caught = true; std::cout << "TOKEN_EXPECTED_ERROR scenario=" << scenario << "; " << e.what() << '\n';
            }
            require(caught == (scenario == 1 || scenario == 2 || scenario == 3), "token scenario result");
            require(effective_token() == before, "effective token not restored exactly");
            require(process_token() == process, "process token not preserved exactly");
        }
    }
    require(effective_token() == baseline && process_token() == process, "outer existing token restoration");
}
void real_queries(HANDLE low, const Object& file, Report& report) {
    const auto& api = lexhelper::native_api(); unsigned failures_expected{};
    for (const SECURITY_INFORMATION flags : {0x7UL, 0x1fUL, 0x10000UL, 0x1001fUL}) {
        PSECURITY_DESCRIPTOR raw{};
        const auto win = GetSecurityInfo(low, SE_FILE_OBJECT, flags, nullptr, nullptr, nullptr, nullptr, &raw);
        lexhelper::LocalPtr holder(raw); Bytes bytes(65536); ULONG needed{};
        const auto nt = api.query_security(low, flags, bytes.data(), static_cast<ULONG>(bytes.size()), &needed);
        std::cout << "INDEPENDENT_RAW flags=" << lexhelper::hex32(flags) << "; GSI=" << win
            << "; NTSTATUS=" << lexhelper::hex32(static_cast<DWORD>(nt)) << "; mapped=" << (nt ? api.dos_error(nt) : 0)
            << "; needed=" << needed << '\n';
        if (flags == 7) {
            require(win == 0 && raw && nt == 0, "ordinary owner/group/DACL query failed");
            require(needed >= 20 && needed <= bytes.size(), "Native length invalid");
            bytes.resize(needed); require(describe(bytes).valid, "Native ordinary SD invalid");
            require(GetSecurityDescriptorLength(raw) == bytes.size() && !std::memcmp(raw, bytes.data(), bytes.size()), "same-flags ordinary APIs differ");
        } else {
            require(win == ERROR_ACCESS_DENIED, "low GSI full query not actual access denied");
            require(nt == static_cast<NTSTATUS>(0xc0000022UL) && api.dos_error(nt) == ERROR_ACCESS_DENIED, "low Native full query not actual access denied");
            failures_expected += 2;
        }
    }
    rejected([&] { (void)lexhelper::get_full_security(low, file.path, false, "independent_ordinary"); }, "[handle_access]");
    Matrix matrix; queries(low, file, report, matrix);
    require(matrix.query_failures == failures_expected + 1, "query failure count silently lost an API/production failure");
    require(matrix.full_native == 0 && matrix.differences == 0 && matrix.production_success == 0 && matrix.unavailable == 0,
        "ordinary query mislabelled privileged success");
}
void bound_contract(const fs::path& root) {
    Boundary boundary(root); verify_owner(boundary.get());
    auto sd = lexhelper::get_security(boundary.get(), root);
    require((reinterpret_cast<SECURITY_DESCRIPTOR_RELATIVE*>(sd.data())->Control & SE_DACL_PROTECTED) != 0, "creation DACL not protected");
    Report report(boundary); report.line("BEGIN independent_ordinary_contract; elevated=0; privileged_matrix=NOT_VERIFIED");
    const auto sentinel = read_path(root / L"diagnostic.log");
    rejected([&] { Report duplicate(boundary); }, "relative NtCreateFile");
    require(read_path(root / L"diagnostic.log") == sentinel, "duplicate report modified sentinel");
    auto directory = boundary.make(random_leaf(), true); auto file = fixture(boundary, directory);
    verify_owner(file.h.get()); const auto fixture_text = read_handle(file.h.get());
    require(GetFileType(file.h.get()) == FILE_TYPE_DISK, "fixture is not a disk file");
    rejected([&] { (void)fixture(boundary, directory); }, "relative NtCreateFile");
    require(read_handle(file.h.get()) == fixture_text && fixture_text == "LexHelper native full-security diagnostic fixture\r\n", "fixture overwritten");
    auto low = open_fixture(directory, file, low_access, false, report);
    auto backup = open_fixture(directory, file, low_access, true, report);
    require(low.valid() && backup.valid(), "ordinary file-ID open failed");
    require(lexhelper::identity(low.get(), file.path) == file.id && lexhelper::identity(backup.get(), file.path) == file.id, "file-ID open returned wrong object");
    verify_owner(low.get()); real_queries(low.get(), file, report);
    auto full = open_fixture(directory, file, full_access, false, report);
    require(!full.valid(), "unprivileged full open unexpectedly succeeded");
    require(!open_fixture(directory, file, full_access, true, report).valid(), "backup intent bypassed privileges");
    Matrix absent; row({"ordinary_missing_security", 1, false, false, full_access}, boundary, directory, file, report, absent);
    require(absent.unavailable == 1 && absent.query_failures == 0 && absent.full_native == 0, "missing privilege row counter");
    Matrix denied; row({"ordinary_full_open_denied", 0, false, false, full_access}, boundary, directory, file, report, denied);
    require(denied.unavailable == 1 && denied.query_failures == 0, "open refusal counted as completed query");
    for (DWORD access : std::array<DWORD, 2>{FILE_WRITE_DATA, DELETE}) {
        SetLastError(0); Handle attempted(CreateFileW(file.path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        const auto code = GetLastError(); require(!attempted.valid() && code == ERROR_SHARING_VIOLATION, "held fixture sharing was relaxed");
        std::cout << "OS_ATTEMPT fixture conflicting open; access=" << access << "; Win32=" << code << '\n'; ++os_refusals;
    }
    os_denied(MoveFileExW(file.path.c_str(), (directory.path / L"renamed.bin").c_str(), 0), "held fixture rename");
    os_denied(MoveFileExW(root.c_str(), (root.wstring() + L"-moved").c_str(), 0), "held root rename");
    verify(file); boundary.check_all();
    // Forged expectation tests are structure tests, not simulated Windows success.
    auto saved = file.id; file.id.file ^= 1;
    rejected([&] { (void)open_fixture(directory, file, low_access, false, report); }, "bound object identity changed"); file.id = saved;
    const auto old_path = file.path; file.path = directory.path / L"different.bin";
    rejected([&] { (void)open_fixture(directory, file, low_access, false, report); }, "bound object location changed"); file.path = old_path;
    rejected([&] { (void)inspect(file.h.get(), true, file.path); }, "unsupported attributes");
    wincheck(SetFileAttributesW(file.path.c_str(), FILE_ATTRIBUTE_TEMPORARY), "set own fixture temporary");
    rejected([&] { (void)open_fixture(directory, file, low_access, false, report); }, "unsupported attributes");
    wincheck(SetFileAttributesW(file.path.c_str(), FILE_ATTRIBUTE_NORMAL), "restore own fixture attributes");
    report.line("INTENTIONAL_NEXT_WRITE_FAILURE ordinary_contract_only=1; privileged_matrix=NOT_VERIFIED");
    const auto complete = read_path(root / L"diagnostic.log");
    require(complete.find("NTSTATUS=0xC0000022; Win32=5") != complete.npos && complete.find("sd_valid=0") != complete.npos,
        "raw API failure/validity evidence missing");
    require(complete.find("SUMMARY matrix_completed=1") == complete.npos && complete.find("field_problem_fixed=VERIFIED") == complete.npos,
        "internal contract log pretends matrix completion");
    // A real post-bind report attribute change must fail before writing another byte.
    wincheck(SetFileAttributesW((root / L"diagnostic.log").c_str(), FILE_ATTRIBUTE_TEMPORARY), "set own report temporary");
    rejected([&] { report.line("SHOULD_NOT_BE_WRITTEN"); }, "unsupported attributes");
    require(read_path(root / L"diagnostic.log") == complete, "unsafe report wrote after attribute change");
    require(complete.find("\r\nEND ") == complete.npos, "partial log incorrectly contains final END");
    std::cout << "REAL_MUTATION report TEMPORARY=1; line_rejected=1; previous_bytes_unchanged=1\n";
    // Hard links may be blocked by Windows sharing. Only call this an event if successful.
    const auto linked = CreateHardLinkW((directory.path / L"additional-link.bin").c_str(), file.path.c_str(), nullptr);
    const auto code = linked ? 0 : GetLastError();
    std::cout << "OS_ATTEMPT held hardlink; success=" << !!linked << "; Win32=" << code << '\n';
    if (linked) rejected([&] { verify(file); }, "unexpected hard links");
    else { require(code == ERROR_SHARING_VIOLATION || code == ERROR_ACCESS_DENIED, "unexpected hardlink failure"); ++os_refusals; }
}
void changed_objects(const fs::path& root) {
    auto parent = open_owned(root, FILE_ADD_FILE | SYNCHRONIZE, true); lexhelper::Security security(false);
    auto raw = lexhelper::relative_file(parent.get(), L"movable.bin", FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, false, security.attributes.lpSecurityDescriptor);
    check(raw.handle.valid() && raw.result == FILE_CREATED, "movable fixture create");
    auto obj = object(std::move(raw.handle), root / L"movable.bin", false); write(obj.h.get(), "POSITION_SENTINEL");
    const auto id = obj.id;
    wincheck(MoveFileExW(obj.path.c_str(), (root / L"moved.bin").c_str(), 0), "move own unpinned fixture");
    require(lexhelper::identity(obj.h.get(), obj.path) == id, "rename changed object identity");
    rejected([&] { verify(obj); }, "bound object location changed");
    require(read_handle(obj.h.get()) == "POSITION_SENTINEL", "held handle redirected by DOS rename");
    std::cout << "REAL_MUTATION unpinned_fixture_renamed=1; held_identity_and_data_unchanged=1; verify_rejected=1\n";
    obj.path = root / L"moved.bin";
    wincheck(CreateHardLinkW((root / L"second-link.bin").c_str(), obj.path.c_str(), nullptr), "hardlink own unpinned fixture");
    rejected([&] { verify(obj); }, "unexpected hard links");
    // Sparse bit is unsupported regardless of payload, and is real NTFS metadata.
    auto sparse = lexhelper::relative_file(parent.get(), L"sparse.bin", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, false, security.attributes.lpSecurityDescriptor);
    require(sparse.handle.valid(), "sparse fixture create"); DWORD done{};
    wincheck(DeviceIoControl(sparse.handle.get(), FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &done, nullptr), "set own sparse fixture");
    rejected([&] { (void)object(std::move(sparse.handle), root / L"sparse.bin", false); }, "unsupported attributes");
}
void compressed_root() {
    const auto root = new_root(); auto h = open_owned(root, GENERIC_READ | GENERIC_WRITE, true);
    USHORT compression = COMPRESSION_FORMAT_DEFAULT; DWORD done{};
    const BOOL changed = DeviceIoControl(h.get(), FSCTL_SET_COMPRESSION, &compression, sizeof(compression), nullptr, 0, &done, nullptr);
    const auto code = changed ? 0 : GetLastError(); h.reset();
    std::cout << "OS_ATTEMPT own root compression; success=" << !!changed << "; Win32=" << code << '\n';
    if (changed) rejected([&] { Boundary b(root); }, "unsupported attributes");
    else { ++os_refusals; std::cout << "NOT_VERIFIED compression mutation (OS refused)\n"; }
}
void reparse_root(const fs::path& own_target) {
    const auto root = new_root(); auto h = open_owned(root, GENERIC_WRITE, true);
    const auto substitute = L"\\??\\" + own_target.wstring(); const auto display = own_target.wstring();
    struct Mount { DWORD tag; WORD length, reserved, sub_offset, sub_length, print_offset, print_length; };
    static_assert(sizeof(Mount) == 16);
    const auto bytes = (substitute.size() + display.size() + 2) * sizeof(wchar_t);
    std::vector<std::byte> buffer(sizeof(Mount) + bytes); auto header = reinterpret_cast<Mount*>(buffer.data());
    header->tag = IO_REPARSE_TAG_MOUNT_POINT; header->length = static_cast<WORD>(8 + bytes);
    header->sub_length = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
    header->print_offset = static_cast<WORD>((substitute.size() + 1) * sizeof(wchar_t));
    header->print_length = static_cast<WORD>(display.size() * sizeof(wchar_t));
    std::memcpy(buffer.data() + sizeof(Mount), substitute.c_str(), (substitute.size() + 1) * sizeof(wchar_t));
    std::memcpy(buffer.data() + sizeof(Mount) + header->print_offset, display.c_str(), (display.size() + 1) * sizeof(wchar_t));
    DWORD done{}; const BOOL changed = DeviceIoControl(h.get(), FSCTL_SET_REPARSE_POINT, buffer.data(), static_cast<DWORD>(buffer.size()), nullptr, 0, &done, nullptr);
    const auto code = changed ? 0 : GetLastError(); h.reset();
    std::cout << "OS_ATTEMPT own root junction to own recorded root; success=" << !!changed << "; Win32=" << code << '\n';
    if (changed) rejected([&] { Boundary b(root); }, "unsupported attributes");
    else { ++os_refusals; std::cout << "NOT_VERIFIED reparse mutation (OS refused)\n"; }
}
} // namespace ordinary_contract

int wmain(int argc, wchar_t** argv) {
    using namespace ordinary_contract;
    try {
        std::cout.setf(std::ios::unitbuf);
        const bool prepare = argc == 3 && std::wstring_view(argv[1]) == L"--prepare-root";
        if ((!prepare && argc != 2) || !allowed_root(argv[prepare ? 2 : 1])) return 2;
        TokenInvariant invariant;
        if (elevated()) return 3;
        for (auto name : {SE_SECURITY_NAME, SE_BACKUP_NAME, SE_RESTORE_NAME})
            if (privilege(invariant.effective, name) || privilege(invariant.process, name)) return 3;
        std::cout << "ORDINARY_GUARD elevated=0; SecurityBackupRestore=absent; no_UAC=1\n";
        if (prepare) {
            // Ordinary parent support only. FILE_CREATE + creation SD, no ACL
            // repair, no Report, fixture, query matrix or automatic cleanup.
            const auto path = new_root(argv[2]); Boundary boundary(path);
            verify_owner(boundary.get()); boundary.check_all(); empty_root(boundary.get());
            const auto id = lexhelper::identity(boundary.get(), path);
            verify_restore(invariant.effective, invariant.process);
            std::cout << "PREPARED_ROOT root=" << lexhelper::utf8(path.wstring())
                << "; volume=" << id.volume << "; file_id=" << id.file
                << "; atomic_FILE_CREATE=1; creation_protected_SD=1; owner_current=1; empty=1; no_reparse=1"
                << "; elevated=0; token_restored=1; privileged_matrix=NOT_EXECUTED\n";
            return 0;
        }
        group("strict_parser", parser_contract);
        group("private_thread_token_normal_error_existing", token_contract);
        fs::path root;
        group("atomic_root_create", [&] { root = new_root(argv[1]);
            rejected([&] { (void)new_root(root); }, "relative NtCreateFile"); });
        if (!root.empty()) {
            group("real_bound_fileID_queries_report_sharing", [&] { bound_contract(root); });
            group("closed_nonempty_root", [&] { rejected([&] { Boundary b(root); }, "root is not empty"); });
            group("real_position_multilink_sparse", [&] { changed_objects(root); });
            group("real_root_reparse_rejected", [&] { reparse_root(root); });
        }
        group("unprotected_root", [&] {
            const auto user = sid_text(); auto sd = sd_from(L"O:" + user + L"G:" + user + L"D:(A;OICI;FA;;;" + user + L")");
            const auto path = new_root({}, sd.get()); auto h = open_owned(path, READ_CONTROL, true);
            auto bytes = lexhelper::get_security(h.get(), path); h.reset();
            require(!(reinterpret_cast<SECURITY_DESCRIPTOR_RELATIVE*>(bytes.data())->Control & SE_DACL_PROTECTED), "unprotected setup not real");
            rejected([&] { Boundary b(path); }, "DACL 未受继承保护");
        });
        group("unknown_mutating_writer", [&] {
            const auto user = sid_text(); auto sd = sd_from(L"O:" + user + L"G:" + user + L"D:P(A;OICI;FA;;;" + user + L")(A;;FW;;;WD)");
            const auto path = new_root({}, sd.get()); rejected([&] { Boundary b(path); }, "允许非可信身份修改");
        });
        group("wrong_owner_OS_boundary", [&] {
            const auto path = new_root(); auto h = open_owned(path, WRITE_OWNER, true);
            std::array<std::byte, SECURITY_MAX_SID_SIZE> sid{}; DWORD n = static_cast<DWORD>(sid.size());
            wincheck(CreateWellKnownSid(WinLocalSystemSid, nullptr, sid.data(), &n), "owner test SID");
            const auto code = SetSecurityInfo(h.get(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, sid.data(), nullptr, nullptr, nullptr); h.reset();
            std::cout << "OS_ATTEMPT own root owner to SY; Win32=" << code << '\n';
            if (!code) rejected([&] { Boundary b(path); }, "root owner is not current user");
            else { require(code == ERROR_INVALID_OWNER || code == ERROR_PRIVILEGE_NOT_HELD || code == ERROR_ACCESS_DENIED, "unexpected owner set refusal");
                ++os_refusals; std::cout << "NOT_VERIFIED mismatched-owner bind; OS refused creating mismatch\n"; Boundary b(path); verify_owner(b.get()); }
        });
        for (const auto leaf : {L"unknown.bin", L"diagnostic.log", L"fixture-existing"}) group("preexisting_root_entry", [&] {
            const auto path = new_root(); const bool dir = std::wstring_view(leaf) == L"fixture-existing"; seed(path, leaf, dir);
            rejected([&] { Boundary b(path); }, "root is not empty");
            if (!dir) require(read_path(path / leaf) == "DO_NOT_OVERWRITE_SENTINEL\r\n", "preexisting sentinel changed");
            require(!fs::exists(path / L"diagnostic.log") || std::wstring_view(leaf) == L"diagnostic.log", "refusal created report");
        });
        group("unsupported_root_compression", compressed_root);
        group("regular_file_is_not_root_directory", [&] {
            const fs::path path(std::wstring(prefix) + random_leaf().substr(8));
            lexhelper::PinnedDirectory base(L"D:\\temp\\aiRunner\\opencode"); lexhelper::Security security(false);
            auto h = relative(base.get(), path.filename().wstring(), FILE_READ_DATA | FILE_WRITE_DATA | low_access,
                FILE_CREATE, false, security.attributes.lpSecurityDescriptor);
            auto owned = object(std::move(h), path, false);
            std::cout << "ROOT_CREATED " << lexhelper::utf8(path.wstring()) << std::endl;
            write(owned.h.get(), "ROOT_FILE_SENTINEL"); owned.h.reset();
            rejected([&] { Boundary b(path); }, "relative NtCreateFile");
            require(read_path(path) == "ROOT_FILE_SENTINEL", "wrong-type root mutated");
        });
        verify_restore(invariant.effective, invariant.process);
        std::cout << "ORDINARY_CONTRACT groups=" << groups << "; checks=" << checks << "; failures=" << failures
            << "; OS_prevention_or_unavailable=" << os_refusals << "; privileged_matrix=NOT_VERIFIED; no_cleanup=1\n";
        return failures ? 4 : 0;
    } catch (const std::exception& e) { std::cerr << "ORDINARY_CONTRACT ERROR " << e.what() << '\n'; return 4; }
}
