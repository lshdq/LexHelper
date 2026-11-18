// TC-008 / DEPLOY-001 / DEPLOY-002. Included inside deploy_tests.cpp's unnamed
// namespace to retain the original runner, fixtures and all old assertions.
// Only ordinary objects beneath the runner's own approved D-drive sandbox are used.
using ObservationPoint = lexhelper::deploy_testing::ObservationPoint;

struct ObserverScope {
    std::function<void(ObservationPoint, const fs::path&)> action;
    ObserverScope(const fs::path& target, std::function<void(ObservationPoint, const fs::path&)> callback)
        : action(std::move(callback)) {
        lexhelper::deploy_testing::set_observer(target,
            [](ObservationPoint point, const fs::path& subject, void* context) {
                static_cast<ObserverScope*>(context)->action(point, subject);
            }, this);
    }
    ~ObserverScope() { lexhelper::deploy_testing::set_observer({}, nullptr, nullptr); }
    ObserverScope(const ObserverScope&) = delete;
    ObserverScope& operator=(const ObserverScope&) = delete;
};

struct ObjectId {
    DWORD volume{};
    std::uint64_t file{};
    bool operator==(const ObjectId&) const = default;
};
ObjectId object_id(const fs::path& path) {
    Handle h(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION i{};
    require(h.h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(h.h, &i), "independent object ID failed");
    return {i.dwVolumeSerialNumber, (std::uint64_t(i.nFileIndexHigh) << 32) | i.nFileIndexLow};
}
std::array<std::byte, 32> test_digest(const Bytes& bytes) {
    std::array<std::byte, 32> result{};
    require(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        reinterpret_cast<PUCHAR>(result.data()), static_cast<ULONG>(result.size())) >= 0, "independent digest failed");
    return result;
}
// std::ifstream's Windows sharing mode does not include FILE_SHARE_DELETE;
// metadata stage handles deliberately hold DELETE. Observe using matching sharing.
Bytes load_shared(const fs::path& path) {
    Handle h(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    LARGE_INTEGER size{};
    require(h.h != INVALID_HANDLE_VALUE && GetFileSizeEx(h.h, &size) && size.QuadPart >= 0 && size.QuadPart < 4 * 1024 * 1024,
            "open shared stage observation failed");
    Bytes bytes(static_cast<std::size_t>(size.QuadPart)); DWORD read{};
    require(ReadFile(h.h, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) && read == bytes.size(),
            "read shared stage observation failed");
    return bytes;
}
void manifest_identity(const fs::path& directory, ObjectId expected, const Bytes* primary = nullptr,
                       const Bytes* secondary = nullptr) {
    const auto manifest = load(directory / L"manifest.lhb");
    require(manifest.size() > 56 && u32(manifest, 0) == 0x4248584c && u32(manifest, 4) == 2 &&
            u32(manifest, 8) == 0, "manifest v2/mode changed");
    const auto id = std::uint64_t(u32(manifest, 16)) | (std::uint64_t(u32(manifest, 20)) << 32);
    require(u32(manifest, 12) == expected.volume && id == expected.file,
            "manifest records another directory object");
    auto digest = test_digest(Bytes(manifest.begin(), manifest.end() - 32));
    require(std::equal(digest.begin(), digest.end(), manifest.end() - 32), "manifest digest differs");
    if (primary) {
        require(load(directory / L"original-0.bin") == *primary, "manifest payload is not the actual A primary");
        require(fs::exists(directory / L"original-1.bin") == (secondary != nullptr), "actual A secondary presence mismatch");
        if (secondary) require(load(directory / L"original-1.bin") == *secondary, "manifest payload is not the actual A secondary");
    }
}

// An independent direct-directory inventory: IDs, bytes, native SD, attributes and
// supported timestamps are compared after relocation as well as at the old name.
struct DirectoryImage {
    struct File { fs::path name; ObjectId id; Bytes bytes, sd, label, full; FILE_BASIC_INFO basic; };
    ObjectId id;
    Bytes sd;
    std::vector<File> files;
    explicit DirectoryImage(const fs::path& path) : id(object_id(path)), sd(security(path)) {
        for (const auto& entry : fs::directory_iterator(path)) {
            require(entry.is_regular_file(), "image fixture unexpectedly contains a directory");
            const auto name = entry.path().filename();
            const auto full = name == L"ChsWubi.lex" || name == L"ChsWubiNew.lex" ?
                lexhelper::deploy_testing::simulated_security(entry.path()) : Bytes{};
            files.push_back({entry.path().filename(), object_id(entry.path()), load(entry.path()),
                             security(entry.path()), native_label(entry.path()), full, basic_info(entry.path())});
        }
    }
    void unchanged(const fs::path& path) const {
        require(object_id(path) == id, "directory image object replaced");
        require(same_security(security(path), sd), "unrelated B directory native security changed");
        require(static_cast<std::size_t>(std::distance(fs::directory_iterator(path), fs::directory_iterator{})) == files.size(),
                "unrelated B directory gained/lost entries");
        for (const auto& file : files) {
            const auto current = path / file.name;
            require(object_id(current) == file.id && load(current) == file.bytes, "unrelated B object/bytes changed");
            require(same_security(security(current), file.sd), "unrelated B native security changed");
            require(native_label(current) == file.label, "unrelated B native label changed");
            if (!file.full.empty())
                require(same_security(lexhelper::deploy_testing::simulated_security(current), file.full),
                        "unrelated B simulated full security changed");
            const auto basic = basic_info(current);
            require(basic.FileAttributes == file.basic.FileAttributes &&
                    basic.CreationTime.QuadPart == file.basic.CreationTime.QuadPart &&
                    basic.LastWriteTime.QuadPart == file.basic.LastWriteTime.QuadPart,
                    "unrelated B supported metadata changed");
        }
    }
};
void prepare_b(const fs::path& path, const Fixture& f, bool lex_files) {
    fs::create_directory(path);
    save(path / L"B-marker.keep", Bytes{std::byte{0x42}, std::byte{0x19}});
    if (lex_files) {
        save(path / L"ChsWubi.lex", f.secondary);
        save(path / L"ChsWubiNew.lex", f.replacement);
        lexhelper::deploy_testing::enable_security_simulation(path);
    } else save(path / L"manifest.lhb", Bytes{std::byte{0x42}});
}
void swap_directory(const fs::path& old_name, const fs::path& retired, const fs::path& b,
                    ObjectId a_id, ObjectId b_id) {
    require(MoveFileExW(old_name.c_str(), retired.c_str(), 0), "owned A directory rename was not applied");
    require(MoveFileExW(b.c_str(), old_name.c_str(), 0), "owned B directory substitution was not applied");
    require(object_id(retired) == a_id && object_id(old_name) == b_id && a_id != b_id,
            "directory substitution did not actually exchange A/B identities");
    std::cout << "EVENT APPLIED: directory A=" << a_id.volume << ':' << a_id.file
              << " B=" << b_id.volume << ':' << b_id.file << '\n';
}
void compression(const fs::path& path, bool enabled) {
    Handle h(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(h.h != INVALID_HANDLE_VALUE, "open owned compression fixture failed");
    USHORT format = enabled ? COMPRESSION_FORMAT_DEFAULT : COMPRESSION_FORMAT_NONE;
    DWORD returned{};
    require(DeviceIoControl(h.h, FSCTL_SET_COMPRESSION, &format, sizeof(format), nullptr, 0, &returned, nullptr),
            "set actual NTFS compression failed");
    USHORT actual{};
    require(DeviceIoControl(h.h, FSCTL_GET_COMPRESSION, nullptr, 0, &actual, sizeof(actual), &returned, nullptr),
            "query actual NTFS compression failed");
    require((actual != COMPRESSION_FORMAT_NONE) == enabled, "NTFS compression state not actually changed");
    require(((GetFileAttributesW(path.c_str()) & FILE_ATTRIBUTE_COMPRESSED) != 0) == enabled,
            "compression attribute did not match actual state");
    std::cout << "EVENT APPLIED: compression=" << enabled << " attrs=" << GetFileAttributesW(path.c_str()) << '\n';
}
enum class BadMaterial { directory_compressed, manifest_compressed, manifest_sparse, manifest_ads,
                         manifest_links, second_compressed, second_sparse, second_ads, second_links };
const std::array material_names{"child-compressed", "manifest-compressed", "manifest-sparse", "manifest-ADS",
    "manifest-multilink", "second-compressed", "second-sparse", "second-ADS", "second-multilink"};
void change_material(const fs::path& directory, const fs::path& alias, BadMaterial kind, bool enable) {
    if (kind == BadMaterial::directory_compressed) { compression(directory, enable); return; }
    const bool manifest = kind >= BadMaterial::manifest_compressed && kind <= BadMaterial::manifest_links;
    const auto path = directory / (manifest ? L"manifest.lhb" : L"original-1.bin");
    if (kind == BadMaterial::manifest_compressed || kind == BadMaterial::second_compressed) compression(path, enable);
    if (kind == BadMaterial::manifest_sparse || kind == BadMaterial::second_sparse) {
        Handle h(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        DWORD returned{}; FILE_SET_SPARSE_BUFFER sparse{static_cast<BOOLEAN>(enable)};
        require(h.h != INVALID_HANDLE_VALUE && DeviceIoControl(h.h, FSCTL_SET_SPARSE, &sparse, sizeof(sparse),
                    nullptr, 0, &returned, nullptr), "set/reset actual sparse file failed");
        require(((GetFileAttributesW(path.c_str()) & FILE_ATTRIBUTE_SPARSE_FILE) != 0) == enable,
                "sparse attribute event not actually applied");
        std::cout << "EVENT APPLIED: sparse=" << enable << '\n';
    }
    if (kind == BadMaterial::manifest_ads || kind == BadMaterial::second_ads) {
        const auto stream = fs::path(path.wstring() + L":owned-test-stream");
        if (enable) { save(stream, Bytes{std::byte{0x71}}); require(load(stream) == Bytes{std::byte{0x71}}, "ADS not written"); }
        else require(DeleteFileW(stream.c_str()), "remove owned fixture ADS failed");
        std::cout << "EVENT APPLIED: ADS=" << enable << '\n';
    }
    if (kind == BadMaterial::manifest_links || kind == BadMaterial::second_links) {
        if (enable) require(CreateHardLinkW(alias.c_str(), path.c_str(), nullptr), "owned material hardlink failed");
        else require(DeleteFileW(alias.c_str()), "remove owned material hardlink failed");
        Handle h(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, 0, nullptr));
        BY_HANDLE_FILE_INFORMATION info{};
        require(h.h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(h.h, &info) &&
                info.nNumberOfLinks == (enable ? 2U : 1U), "hardlink count event not actually applied");
        if (enable) require(object_id(alias) == object_id(path), "alias is not the actual material object");
        std::cout << "EVENT APPLIED: material links=" << info.nNumberOfLinks << '\n';
    }
}

void compressed_backup_root(const fs::path& base, bool installing) {
    Fixture f(base, installing ? L"一致性-压缩根-install" : L"一致性-压缩根-backup", true);
    Sentinel old(f.target / L"ChsWubi.lex", f.root / L"sentinel");
    auto d = f.deployer(); const auto valid = d.backup();
    const auto root_sd = security(f.backup_root);
    compression(f.backup_root, true);
    require(same_security(root_sd, security(f.backup_root)), "compression changed trusted root ACL");
    const auto before = backups(f.backup_root).size();
    const auto message = rejects([&] { if (installing) (void)d.install(f.generated); else (void)d.backup(); });
    require(message.find("可继承属性") != std::string::npos, "compressed root not rejected by intended preflight");
    require(backups(f.backup_root).size() == before, "compressed root created a purported backup");
    require(GetFileAttributesW(f.backup_root.c_str()) & FILE_ATTRIBUTE_COMPRESSED, "deployer silently decompressed root");
    f.original_state(); old.unchanged();
    compression(f.backup_root, false);
    d.restore(valid); f.original_state(); old.unchanged();
    std::cout << "RESULT: compressed trusted root rejected before target mutation; valid prior material restores\n";
}

void persisted_material_rejected(const fs::path& base, bool installing, BadMaterial kind, unsigned number) {
    Fixture f(base, L"一致性-写读门禁-" + std::to_wstring(number), true);
    Sentinel old(f.target / L"ChsWubi.lex", f.root / L"sentinel");
    Sentinel old_new(f.target / L"ChsWubiNew.lex", f.root / L"sentinel");
    auto d = f.deployer(); fs::path corrupted; bool applied{}; unsigned validation_events{};
    const auto alias = f.root / L"owned-material-link";
    const auto point = kind == BadMaterial::directory_compressed ? ObservationPoint::backup_directory_created :
                                                                ObservationPoint::backup_files_written;
    std::string message;
    {
        ObserverScope observer(f.target, [&](auto current, const auto& subject) {
            if (current == ObservationPoint::backup_validated) ++validation_events;
            if (current != point || applied) return;
            corrupted = subject;
            change_material(subject, alias, kind, true);
            applied = true;
        });
        message = rejects([&] { if (installing) (void)d.install(f.generated); else (void)d.backup(); });
    }
    require(applied && validation_events == 0, "did not actually inject invalid material before read-side gate");
    require(message.find("目标尚未修改") != std::string::npos, "failed backup did not state pre-mutation failure");
    if (kind != BadMaterial::directory_compressed)
        require(message.find(kind <= BadMaterial::manifest_links ? "manifest.lhb" : "original-1.bin") != std::string::npos,
                "did not reject the intended persisted manifest/second payload");
    f.original_state(); old.unchanged(); old_new.unchanged();
    require(backups(f.backup_root).size() == 1, "incomplete material was hidden/deleted or extra material created");
    const auto reader = rejects([&] { d.restore(corrupted); });
    require(!reader.empty() && backups(f.backup_root).size() == 1, "restore accepted invalid material or created recovery point");
    f.original_state(); old.unchanged(); old_new.unchanged();
    change_material(corrupted, alias, kind, false);
    if (kind != BadMaterial::directory_compressed) {
        manifest_identity(corrupted, object_id(f.target), &f.original, &f.secondary);
        d.restore(corrupted); f.original_state(); old.unchanged(); old_new.unchanged();
    }
    std::cout << "RESULT: write/read contract rejected whole backup; target and both shared sentinels unchanged\n";
}

void restore_material_rejected(const fs::path& base, BadMaterial kind, unsigned number) {
    Fixture f(base, L"一致性-恢复读侧-" + std::to_wstring(number), true);
    auto d = f.deployer(); const auto backup = d.install(f.generated);
    const auto expected_attributes = GetFileAttributesW((f.target / L"ChsWubi.lex").c_str());
    Sentinel installed(f.target / L"ChsWubi.lex", f.root / L"installed-sentinel");
    // Creating a hardlink can set ARCHIVE. This is fixture setup, not deployment:
    // restore the manifest-authorized attributes before observing the transaction.
    require(SetFileAttributesW(installed.path.c_str(), expected_attributes), "restore installed fixture attributes failed");
    installed.basic = basic_info(installed.path);
    const auto before = backups(f.backup_root).size();
    const auto alias = f.root / L"owned-material-link";
    change_material(backup, alias, kind, true);
    const auto message = rejects([&] { d.restore(backup); });
    require(message.find(kind == BadMaterial::directory_compressed ? "可继承属性" :
            kind <= BadMaterial::manifest_links ? "manifest.lhb" : "original-1.bin") != std::string::npos,
            "historical material rejected for unrelated reason instead of actual unsupported object");
    f.installed_state(); installed.unchanged();
    require(backups(f.backup_root).size() == before, "invalid historical material created restore recovery point");
    change_material(backup, alias, kind, false);
    d.restore(backup); f.original_state(); installed.unchanged();
    std::cout << "RESULT: actual unsupported backup rejected by restore before target mutation; repaired fixture restores\n";
}

void verified_material_pinned(const fs::path& base, bool installing) {
    Fixture f(base, installing ? L"一致性-验证句柄-install" : L"一致性-验证句柄-backup", true);
    auto d = f.deployer(); unsigned reached{}, refused{}; fs::path backup;
    {
        ObserverScope observer(f.target, [&](auto point, const auto& subject) {
            if (point == ObservationPoint::backup_validated) backup = subject;
            else if (!installing || (point != ObservationPoint::stages_prepared &&
                     point != ObservationPoint::primary_unlinked && point != ObservationPoint::primary_installed)) return;
            ++reached;
            for (const auto* name : {L"manifest.lhb", L"original-0.bin", L"original-1.bin"})
                for (DWORD access : {DWORD(GENERIC_WRITE), DWORD(DELETE)}) {
                    Handle attempt(CreateFileW((backup / name).c_str(), access,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
                    const auto code = GetLastError();
                    require(attempt.h == INVALID_HANDLE_VALUE && code == ERROR_SHARING_VIOLATION,
                            "validated backup files were not continuously pinned against write/delete");
                    ++refused;
                }
        });
        backup = installing ? d.install(f.generated) : d.backup();
    }
    require(reached == (installing ? 4U : 1U) && refused == (installing ? 24U : 6U),
            "validated backup lifetime checkpoints were not all reached");
    if (installing) f.installed_state(); else f.original_state();
    d.restore(backup); f.original_state();
    std::cout << "RESULT: all three validated files refused writes/deletes (Win32=32), attempts=" << refused
              << "; returned material restores\n";
}

void restore_verified_material_pinned(const fs::path& base) {
    Fixture f(base, L"一致性-验证句柄-restore", true); auto d = f.deployer();
    const auto selected = d.install(f.generated); fs::path recovery; unsigned reached{}, refused{};
    {
        ObserverScope observer(f.target, [&](auto point, const auto& subject) {
            if (point == ObservationPoint::backup_validated) recovery = subject;
            else if (point != ObservationPoint::stages_prepared && point != ObservationPoint::primary_unlinked &&
                     point != ObservationPoint::primary_installed) return;
            require(!recovery.empty(), "restore recovery material not validated before mutation"); ++reached;
            for (const auto& directory : {selected, recovery})
                for (const auto* name : {L"manifest.lhb", L"original-0.bin", L"original-1.bin"}) {
                    if (directory == recovery && std::wstring(name) == L"original-1.bin") {
                        require(!fs::exists(directory / name), "absent installed secondary has unexpected recovery payload");
                        continue;
                    }
                    for (DWORD access : {DWORD(GENERIC_WRITE), DWORD(DELETE)}) {
                        Handle attempt(CreateFileW((directory / name).c_str(), access,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
                        const auto code = GetLastError();
                        require(attempt.h == INVALID_HANDLE_VALUE && code == ERROR_SHARING_VIOLATION,
                                "selected/recovery backup lost its restore-transaction lifetime pin"); ++refused;
                    }
                }
        });
        d.restore(selected);
    }
    require(reached == 4 && refused == 40, "restore selected/recovery lifetime checkpoints incomplete");
    f.original_state();
    d.restore(recovery); f.installed_state(); // The new recovery point is itself usable.
    std::cout << "RESULT: selected and recovery material refused all 40 write/delete attempts; restore recovery point restores\n";
}

enum class Entry { backup, install, restore };
const std::array entry_names{"backup", "install", "restore"};
void target_directory_swap(const fs::path& base, Entry entry, unsigned number) {
    Fixture f(base, L"身份-目标-" + std::to_wstring(number), true);
    Sentinel old(f.target / L"ChsWubi.lex", f.root / L"sentinel");
    Sentinel old_new(f.target / L"ChsWubiNew.lex", f.root / L"sentinel");
    auto d = f.deployer(); fs::path selected;
    if (entry == Entry::restore) selected = d.install(f.generated);
    const auto before = backups(f.backup_root);
    const auto original_name = f.target, retired = f.root / L"actual-A", b = f.root / L"prepared-B";
    prepare_b(b, f, true); const DirectoryImage b_image(b);
    const auto a_id = object_id(original_name); bool applied{};
    {
        ObserverScope observer(original_name, [&](auto point, const auto&) {
            if (point != ObservationPoint::directories_bound || applied) return;
            swap_directory(original_name, retired, b, a_id, b_image.id); applied = true;
        });
        const auto message = rejects([&] {
            if (entry == Entry::backup) (void)d.backup();
            else if (entry == Entry::install) (void)d.install(f.generated);
            else d.restore(selected);
        });
        require(message.find("改名/路径已变化") != std::string::npos, "target swap rejected for unrelated reason");
    }
    require(applied, "target A/B swap was not actually applied after identity/mutex binding");
    b_image.unchanged(original_name);
    f.target = retired; lexhelper::deploy_testing::enable_security_simulation(retired);
    if (entry == Entry::restore) f.installed_state(); else f.original_state();
    old.unchanged(); old_new.unchanged();
    for (const auto& saved : backups(f.backup_root)) if (std::find(before.begin(), before.end(), saved) == before.end())
        manifest_identity(saved, a_id, entry == Entry::restore ? &f.replacement : &f.original,
                          entry == Entry::restore ? nullptr : &f.secondary);
    require(object_id(retired) == a_id, "A identity changed during rejection");
    std::cout << "RESULT: target A/B substitution rejected; B inventory unchanged; any new manifest/payload belongs to A\n";
}

void source_directory_swap(const fs::path& base) {
    Fixture f(base, L"身份-source父目录", true);
    const auto source = f.root / L"source-A", b = f.root / L"source-B", retired = f.root / L"source-retired";
    fs::create_directory(source); fs::create_directory(b);
    save(source / L"source.lex", f.replacement); save(b / L"source.lex", f.secondary);
    const DirectoryImage a_image(source), b_image(b); bool applied{};
    Sentinel old(f.target / L"ChsWubi.lex", f.root / L"sentinel");
    auto d = f.deployer();
    {
        ObserverScope observer(f.target, [&](auto point, const auto& subject) {
            if (point != ObservationPoint::source_bound || applied) return;
            require(subject == source, "source hook subject differs from bound source");
            swap_directory(source, retired, b, a_image.id, b_image.id); applied = true;
        });
        rejects([&] { (void)d.install(source / L"source.lex"); });
    }
    require(applied, "source parent swap not applied");
    a_image.unchanged(retired); b_image.unchanged(source); f.original_state(); old.unchanged();
    const auto saved = backups(f.backup_root);
    require(saved.size() == 1, "source binding case did not create its pre-mutation material");
    manifest_identity(saved.front(), object_id(f.target), &f.original, &f.secondary);
    const auto bytes = load(saved.front() / L"manifest.lhb"); const auto offsets = state_offsets(bytes);
    const auto hash = test_digest(f.replacement);
    require(std::equal(hash.begin(), hash.end(), bytes.begin() + offsets[2] + 12),
            "installation expected bytes came from substituted B source, not bound A");
    std::cout << "RESULT: source bytes/expected hash stayed bound to A; path change rejected before target mutation\n";
}

void backup_directory_swap(const fs::path& base, bool child, bool installing, unsigned number) {
    Fixture f(base, L"身份-备份-" + std::to_wstring(number), true);
    auto d = f.deployer(); Sentinel old(f.target / L"ChsWubi.lex", f.root / L"sentinel");
    const auto b = f.root / L"prepared-B", retired = f.root / L"actual-A";
    prepare_b(b, f, false); const DirectoryImage b_image(b);
    bool applied{}; fs::path old_name; ObjectId a_id{};
    {
        ObserverScope observer(f.target, [&](auto point, const auto& subject) {
            if (applied || point != (child ? ObservationPoint::backup_directory_ready : ObservationPoint::directories_bound)) return;
            old_name = child ? subject : f.backup_root; a_id = object_id(old_name);
            swap_directory(old_name, retired, b, a_id, b_image.id); applied = true;
        });
        rejects([&] { if (installing) (void)d.install(f.generated); else (void)d.backup(); });
    }
    require(applied, "backup A/B directory swap not applied");
    b_image.unchanged(old_name); require(object_id(retired) == a_id, "backup A object not preserved");
    if (child) manifest_identity(retired, object_id(f.target), &f.original, &f.secondary);
    else require(fs::is_empty(retired), "changed backup root gained unexpected material");
    f.original_state(); old.unchanged();
    std::cout << "RESULT: backup directory swap rejected; no B writes; child payload creation (when reached) stayed in A\n";
}

void selected_directory_swap(const fs::path& base) {
    Fixture f(base, L"身份-选定恢复备份", true); auto d = f.deployer(); const auto selected = d.install(f.generated);
    Sentinel installed(f.target / L"ChsWubi.lex", f.root / L"installed-sentinel");
    const auto b = f.root / L"prepared-B", retired = f.root / L"actual-A";
    prepare_b(b, f, false); const DirectoryImage a_image(selected), b_image(b); bool applied{};
    const auto before = backups(f.backup_root).size();
    {
        ObserverScope observer(f.target, [&](auto point, const auto& subject) {
            if (point != ObservationPoint::selected_backup_bound || applied) return;
            require(subject == selected, "selected backup hook differs");
            swap_directory(selected, retired, b, a_image.id, b_image.id); applied = true;
        });
        rejects([&] { d.restore(selected); });
    }
    require(applied, "selected backup substitution was not actually applied");
    a_image.unchanged(retired); b_image.unchanged(selected); f.installed_state(); installed.unchanged();
    require(backups(f.backup_root).size() == before, "changed selected backup created recovery material");
    std::cout << "RESULT: selected backup A/B substitution rejected; both directory inventories and installed target unchanged\n";
}

struct JunctionEvent {
    HANDLE handle{INVALID_HANDLE_VALUE}; bool applied{}; DWORD error{};
    void try_apply(const fs::path& path, const fs::path& destination) {
        handle = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (handle == INVALID_HANDLE_VALUE) { error = GetLastError(); return; }
        const auto substitute = L"\\??\\" + destination.wstring(), print = destination.wstring();
        struct Header { DWORD tag; WORD length, reserved, sub_offset, sub_length, print_offset, print_length; };
        Header header{}; header.tag = IO_REPARSE_TAG_MOUNT_POINT;
        header.sub_length = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
        header.print_offset = header.sub_length + sizeof(wchar_t);
        header.print_length = static_cast<WORD>(print.size() * sizeof(wchar_t));
        header.length = static_cast<WORD>(8 + header.print_offset + header.print_length + sizeof(wchar_t));
        Bytes buffer(8 + header.length);
        std::memcpy(buffer.data(), &header, sizeof(header));
        std::memcpy(buffer.data() + sizeof(header), substitute.c_str(), header.sub_length + sizeof(wchar_t));
        std::memcpy(buffer.data() + sizeof(header) + header.print_offset, print.c_str(), header.print_length + sizeof(wchar_t));
        DWORD returned{};
        applied = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, buffer.data(), static_cast<DWORD>(buffer.size()),
                                  nullptr, 0, &returned, nullptr) != FALSE;
        error = applied ? ERROR_SUCCESS : GetLastError();
        FILE_ATTRIBUTE_TAG_INFO actual{};
        require(GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &actual, sizeof(actual)), "junction event query failed");
        require(((actual.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) == applied &&
                (!applied || actual.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT), "junction state did not match actual event");
        std::cout << (applied ? "EVENT APPLIED: junction" : "EVENT OS-REFUSED (not successful interleaving): junction")
                  << " Win32=" << error << '\n';
    }
    bool clear() noexcept {
        if (!applied) return true;
        struct Header { DWORD tag; WORD length, reserved; } header{IO_REPARSE_TAG_MOUNT_POINT, 0, 0};
        DWORD returned{};
        if (!DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &header, sizeof(header), nullptr, 0, &returned, nullptr)) return false;
        applied = false; return true;
    }
    ~JunctionEvent() { clear(); if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
};
void empty_backup_junction(const fs::path& base, bool child) {
    Fixture f(base, child ? L"身份-空子目录原地junction" : L"身份-空备份根原地junction", true);
    const auto b = f.root / L"B"; prepare_b(b, f, false); const DirectoryImage b_image(b);
    Sentinel old(f.target / L"ChsWubi.lex", f.root / L"sentinel");
    auto d = f.deployer(); JunctionEvent event; bool reached{}; fs::path changed; ObjectId before{};
    {
        ObserverScope observer(f.target, [&](auto point, const auto& subject) {
            if (reached || point != (child ? ObservationPoint::backup_directory_ready : ObservationPoint::directories_bound)) return;
            changed = child ? subject : f.backup_root;
            require(fs::is_empty(changed), "junction event must start with controlled EMPTY directory");
            before = object_id(changed); event.try_apply(changed, b); reached = true;
            require(event.applied, "required successful empty-directory junction event was refused by OS");
            require(object_id(changed) == before, "junction event replaced object instead of in-place mutation");
        });
        const auto message = rejects([&] { (void)d.install(f.generated); });
        if (child) require(message.find("NTSTATUS=") != std::string::npos, "child junction did not reach relative Native create refusal");
    }
    require(reached && event.applied, "empty directory was not actually changed into junction");
    b_image.unchanged(b); f.original_state(); old.unchanged();
    require(event.clear(), "remove own junction through original handle failed");
    require(object_id(changed) == before && fs::is_empty(changed), "bound original directory gained files through junction");
    std::cout << "RESULT: successful in-place empty-directory junction rejected; B and original directory unchanged\n";
}

void late_directory_event(const fs::path& base, ObservationPoint point, bool junction, bool restoring, unsigned number) {
    Fixture f(base, L"身份-事务中事件-" + std::to_wstring(number), true); auto d = f.deployer(); fs::path backup;
    Sentinel old(f.target / L"ChsWubi.lex", f.root / L"sentinel");
    Sentinel old_new(f.target / L"ChsWubiNew.lex", f.root / L"sentinel");
    if (restoring) backup = d.install(f.generated);
    std::vector<Sentinel> installed;
    if (restoring) installed.emplace_back(f.target / L"ChsWubi.lex", f.root / L"installed-sentinel");
    const auto old_name = f.target, retired = f.root / L"actual-A", b = f.root / L"prepared-B";
    prepare_b(b, f, true); const DirectoryImage b_image(b); const auto a_id = object_id(f.target);
    bool reached{}, applied{}; DWORD code{}; JunctionEvent event;
    {
        ObserverScope observer(f.target, [&](auto current, const auto&) {
            if (current != point || reached) return;
            reached = true;
            if (junction) { event.try_apply(old_name, b); applied = event.applied; code = event.error; }
            else {
                applied = MoveFileExW(old_name.c_str(), retired.c_str(), 0) != FALSE;
                code = applied ? ERROR_SUCCESS : GetLastError();
                if (applied) {
                    require(MoveFileExW(b.c_str(), old_name.c_str(), 0), "late substitution B move failed");
                    require(object_id(retired) == a_id && object_id(old_name) == b_image.id, "late A/B IDs differ");
                }
                std::cout << (applied ? "EVENT APPLIED: late directory rename" : "EVENT OS-REFUSED (not successful interleaving): late directory rename")
                          << " Win32=" << code << '\n';
            }
            throw std::runtime_error("owned-observer-stop-after-actual-event");
        });
        const auto message = rejects([&] { if (restoring) d.restore(backup); else (void)d.install(f.generated); });
        require(message.find("owned-observer-stop-after-actual-event") != std::string::npos &&
                message.find("已校验回滚") != std::string::npos, "transaction event did not verify rollback");
    }
    require(reached, "late directory event hook not reached");
    if (!applied) require(code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION || code == ERROR_DIR_NOT_EMPTY,
                          "unclassified OS refusal of owned directory event");
    if (junction) require(event.clear(), "clear own late junction failed");
    if (applied && !junction) {
        b_image.unchanged(old_name); f.target = retired; lexhelper::deploy_testing::enable_security_simulation(retired);
    } else b_image.unchanged(b);
    if (restoring) f.installed_state(); else f.original_state();
    old.unchanged(); old_new.unchanged();
    require(object_id(f.target) == a_id, "rollback accessed another target directory object");
    for (const auto& item : installed) item.unchanged();
    std::cout << "RESULT: transaction rollback kept original A state and B/shared sentinels; event classification above is authoritative\n";
}

void stage_object_association(const fs::path& base, bool rollback) {
    Fixture f(base, rollback ? L"身份-回滚stage关联" : L"身份-正向stage关联", true); auto d = f.deployer();
    Sentinel old(f.target / L"ChsWubi.lex", f.root / L"sentinel");
    Sentinel old_new(f.target / L"ChsWubiNew.lex", f.root / L"sentinel");
    const auto b = f.root / L"prepared-B.tmp", retired = f.target / L"owned-relocated-stage.tmp";
    save(b, Bytes{std::byte{0x42}, std::byte{0x77}});
    const auto b_id = object_id(b); const auto b_bytes = load(b), b_sd = security(b); const auto b_basic = basic_info(b);
    fs::path old_name; ObjectId a_id{}; Bytes a_bytes; bool applied{}; unsigned stage_count{};
    {
        ObserverScope observer(f.target, [&](auto point, const auto&) {
            if (point != ObservationPoint::stages_prepared || applied) return;
            for (const auto& item : fs::directory_iterator(f.target))
                if (item.path().filename().wstring().starts_with(L"LexHelper-stage-")) {
                    ++stage_count;
                    const auto bytes = load_shared(item.path());
                    if (bytes == (rollback ? f.original : f.replacement)) old_name = item.path();
                }
            require(stage_count == 3 && !old_name.empty(), "did not observe both forward and two rollback stage objects");
            a_id = object_id(old_name); a_bytes = load_shared(old_name);
            require(MoveFileExW(old_name.c_str(), retired.c_str(), 0), "owned stage A relocation not applied");
            require(MoveFileExW(b.c_str(), old_name.c_str(), 0), "owned stage B substitution not applied");
            require(object_id(retired) == a_id && object_id(old_name) == b_id && a_id != b_id, "stage identities did not change");
            applied = true;
            if (rollback) lexhelper::deploy_testing::inject_failure(lexhelper::deploy_testing::FailurePoint::after_primary_write);
            std::cout << "EVENT APPLIED: " << (rollback ? "rollback" : "forward") << " stage A=" << a_id.file << " B=" << b_id.file << '\n';
        });
        const auto message = rejects([&] { (void)d.install(f.generated); });
        std::cout << "OBSERVE: stage substitution rejection=" << message << '\n';
        require(applied, "stage substitution was not actually applied");
        require(message.find("目录项身份与持有句柄不一致") != std::string::npos, "stage mismatch did not use object identity gate");
        require(message.find(rollback ? "回滚不完整" : "已校验回滚") != std::string::npos,
                "stage mismatch rollback status inaccurate");
    }
    require(applied && object_id(old_name) == b_id && load(old_name) == b_bytes && same_security(security(old_name), b_sd),
            "unknown B staging object was modified/renamed/deleted");
    const auto after = basic_info(old_name);
    require(after.FileAttributes == b_basic.FileAttributes && after.CreationTime.QuadPart == b_basic.CreationTime.QuadPart &&
            after.LastWriteTime.QuadPart == b_basic.LastWriteTime.QuadPart, "unknown stage B supported metadata changed");
    old.unchanged(); old_new.unchanged();
    const auto saved = backups(f.backup_root); require(saved.size() == 1, "stage failure lost recovery material");
    manifest_identity(saved.front(), object_id(f.target), &f.original, &f.secondary);
    if (rollback) {
        require(!fs::exists(f.target / L"ChsWubi.lex") && load(f.target / L"ChsWubiNew.lex") == f.secondary,
                "rollback-stage collision concrete incomplete state differs");
        require(object_id(retired) == a_id && load(retired) == a_bytes, "actual rollback A copy was lost or modified");
        rejects([&] { d.restore(saved.front()); }); // Do not overwrite this deliberately manufactured unknown/mixed state.
    } else {
        f.original_state();
        require(!fs::exists(retired), "uninstalled owned forward A stage leaked");
    }
    std::cout << "RESULT: stage identity mismatch never operated on B; "
              << (rollback ? "incomplete rollback accurately reported and actual A recovery copy retained" : "original target rollback verified") << '\n';
}

template<class Group> void backup_consistency_groups(const fs::path& base, Group&& group) {
    unsigned sequence{};
    for (bool installing : {false, true}) {
        auto name = std::string("backup-contract-compressed-root-") + (installing ? "install" : "backup");
        group(name.c_str(), [&] { compressed_backup_root(base, installing); });
        for (unsigned i = 0; i < material_names.size(); ++i) {
            name = std::string("backup-contract-") + (installing ? "install-" : "backup-") + material_names[i];
            ++sequence;
            group(name.c_str(), [&] { persisted_material_rejected(base, installing, static_cast<BadMaterial>(i), sequence); });
        }
        name = std::string("backup-contract-verified-lifetime-") + (installing ? "install" : "backup");
        group(name.c_str(), [&] { verified_material_pinned(base, installing); });
    }
    for (unsigned i = 0; i < material_names.size(); ++i) {
        const auto name = std::string("restore-contract-") + material_names[i];
        group(name.c_str(), [&] { restore_material_rejected(base, static_cast<BadMaterial>(i), i); });
    }
    group("restore-contract-verified-lifetime", [&] { restore_verified_material_pinned(base); });
    for (unsigned i = 0; i < entry_names.size(); ++i) {
        const auto name = std::string("object-binding-target-swap-") + entry_names[i];
        group(name.c_str(), [&] { target_directory_swap(base, static_cast<Entry>(i), i); });
    }
    group("object-binding-source-parent-swap", [&] { source_directory_swap(base); });
    for (bool child : {false, true}) for (bool installing : {false, true}) {
        const auto name = std::string("object-binding-backup-") + (child ? "child-" : "root-") + (installing ? "install" : "backup");
        ++sequence;
        group(name.c_str(), [&] { backup_directory_swap(base, child, installing, sequence); });
    }
    group("object-binding-selected-restore-swap", [&] { selected_directory_swap(base); });
    group("object-binding-empty-backup-root-junction", [&] { empty_backup_junction(base, false); });
    group("object-binding-empty-backup-child-junction", [&] { empty_backup_junction(base, true); });
    const std::array points{ObservationPoint::stages_prepared, ObservationPoint::primary_unlinked, ObservationPoint::primary_installed};
    const std::array point_names{"stages-prepared", "primary-unlinked", "primary-installed"};
    for (bool restoring : {false, true}) for (unsigned i = 0; i < points.size(); ++i) {
        const auto name = std::string("object-binding-late-rename-") + (restoring ? "restore-" : "install-") + point_names[i];
        ++sequence;
        group(name.c_str(), [&] { late_directory_event(base, points[i], false, restoring, sequence); });
    }
    for (const auto point : {ObservationPoint::stages_prepared, ObservationPoint::primary_unlinked}) {
        const auto name = std::string("object-binding-nonempty-junction-") +
            (point == ObservationPoint::stages_prepared ? "stages-prepared" : "primary-unlinked");
        ++sequence;
        group(name.c_str(), [&] { late_directory_event(base, point, true, false, sequence); });
    }
    group("object-binding-forward-stage-substitution", [&] { stage_object_association(base, false); });
    group("object-binding-rollback-stage-substitution", [&] { stage_object_association(base, true); });
}
