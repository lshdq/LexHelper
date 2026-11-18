// TC-008 / DEPLOY-003. This is a destination-name race, NOT a pre-call
// unknown-state rejection or a substitution of a held stage's source name.
// Included after deploy_backup_consistency.inc; no separate runner or CMake target.
struct DestinationFileImage {
    ObjectId id;
    Bytes bytes, sd, label, full;
    FILE_BASIC_INFO basic{};
    DestinationFileImage(const fs::path& path, bool logical = false)
        : id(object_id(path)), bytes(load_shared(path)), sd(security(path)), label(native_label(path)),
          full(logical ? lexhelper::deploy_testing::simulated_security(path) : Bytes{}), basic(basic_info(path)) {}
    void unchanged(const fs::path& path, bool trace = false) const {
        // Collect and print all independent comparisons before any semantic
        // assertion: an erroneous successful overwrite must expose its state,
        // not merely fail the first "operation must throw" assertion.
        const DestinationFileImage after(path, !full.empty());
        const bool same_id = after.id == id, same_bytes = after.bytes == bytes;
        const bool same_sd = same_security(after.sd, sd), same_label = after.label == label;
        const bool same_full = full.empty() || same_security(after.full, full);
        const bool same_attrs = after.basic.FileAttributes == basic.FileAttributes;
        const bool same_times = after.basic.CreationTime.QuadPart == basic.CreationTime.QuadPart &&
                               after.basic.LastWriteTime.QuadPart == basic.LastWriteTime.QuadPart;
        if (trace) std::cout << "DESTINATION STATE: before=" << id.volume << ':' << id.file
            << " after=" << after.id.volume << ':' << after.id.file << " id=" << same_id
            << " bytes=" << same_bytes << " nativeSD=" << same_sd << " nativeLabel=" << same_label
            << " simulatedFullSD=" << same_full << " attrs=" << same_attrs << " creation/write=" << same_times << '\n';
        require(same_id, "concurrent destination object was overwritten/removed/replaced");
        require(same_bytes, "concurrent destination bytes changed");
        require(same_sd && same_label && same_full, "concurrent destination native/simulated security changed");
        require(same_attrs && same_times, "concurrent destination attributes or supported timestamps changed");
    }
};

void destination_name_conflict(const fs::path& base, bool restoring, bool has_new, unsigned number) {
    using namespace lexhelper::deploy_testing;
    Fixture f(base, L"目的名冲突-" + std::to_wstring(number), has_new);
    set_simulated_sacl(f.target / L"ChsWubi.lex", sacl_descriptor(L"S:PAI(AU;SAFA;FR;;;WD)(ML;;NW;;;ME)"));
    if (has_new) set_simulated_sacl(f.target / L"ChsWubiNew.lex",
        sacl_descriptor(L"S:P(AU;SA;0x2;;;WD)(ML;;NW;;;LW)"));
    f.remember_full_security();
    Sentinel old(f.target / L"ChsWubi.lex", f.root / L"original-sentinel");
    std::vector<Sentinel> old_new, installed;
    if (has_new) old_new.emplace_back(f.target / L"ChsWubiNew.lex", f.root / L"original-sentinel");
    auto d = f.deployer(); fs::path selected;
    if (restoring) {
        selected = d.install(f.generated); f.installed_state(); old.unchanged();
        const auto attrs = GetFileAttributesW((f.target / L"ChsWubi.lex").c_str());
        installed.emplace_back(f.target / L"ChsWubi.lex", f.root / L"installed-sentinel");
        // Hard-link setup can set ARCHIVE; do not manufacture a pre-call unknown
        // state. Restore the manifest-authorized attrs before starting the race.
        require(SetFileAttributesW(installed.front().path.c_str(), attrs), "restore installed sentinel fixture attrs failed");
        installed.front().basic = basic_info(installed.front().path);
        f.installed_state();
    }
    const auto primary = f.target / L"ChsWubi.lex", secondary = f.target / L"ChsWubiNew.lex";
    const auto before_id = object_id(primary), target_id = object_id(f.target);
    const auto before_backups = backups(f.backup_root);
    std::vector<DirectoryImage> before_history;
    for (const auto& material : before_backups) before_history.emplace_back(material);
    const bool secondary_present = !restoring && has_new;
    std::vector<DestinationFileImage> other_slot;
    if (secondary_present) other_slot.emplace_back(secondary, true);
    const Bytes unknown = lexhelper::write_lex({{"z", u"并发维护独立未知对象", 0}});
    require(unknown != f.original && unknown != f.replacement && unknown != f.secondary,
            "unknown destination fixture must differ from all known payloads");
    struct Stage { fs::path path; DestinationFileImage image; };
    std::vector<Stage> stages;
    std::vector<DestinationFileImage> unknown_image;
    fs::path recovery, undo_primary;
    unsigned prepared{}, unlinked{}, committed{};
    bool created{}, creator_closed{}, exclusive_closed{}, returned{}, succeeded{};
    std::string message;
    {
        ObserverScope observer(f.target, [&](auto point, const auto& subject) {
            if (point == ObservationPoint::backup_validated) recovery = subject;
            if (point == ObservationPoint::stages_prepared) {
                ++prepared;
                for (const auto& entry : fs::directory_iterator(f.target))
                    if (entry.path().filename().wstring().starts_with(L"LexHelper-stage-"))
                        stages.push_back({entry.path(), DestinationFileImage(entry.path())});
                require(stages.size() == (has_new ? 3U : 2U), "missing independent forward/undo stage objects");
                unsigned forward{}, undo{}, other{};
                for (const auto& stage : stages) {
                    if (stage.image.bytes == (restoring ? f.original : f.replacement)) ++forward;
                    if (stage.image.bytes == (restoring ? f.replacement : f.original)) {
                        ++undo; undo_primary = stage.path;
                    }
                    if (stage.image.bytes == f.secondary) ++other;
                    require(stage.image.id != before_id, "stage reused original shared inode");
                }
                require(forward == 1 && undo == 1 && other == (has_new ? 1U : 0U), "stage roles/bytes not independently identified");
            }
            if (point == ObservationPoint::primary_installed) ++committed;
            if (point != ObservationPoint::primary_unlinked) return;
            ++unlinked;
            require(subject == f.target && prepared == 1 && !recovery.empty() && !created,
                    "destination race not reached after backup and all stages");
            require(!fs::exists(primary), "primary destination was not actually unlinked");
            // All stage names/IDs/bytes remain intact, so require_owned_name is
            // not the rejection under test. Nothing is renamed or substituted.
            for (const auto& stage : stages) stage.image.unchanged(stage.path);
            {
                Handle writer(CreateFileW(primary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
                require(writer.h != INVALID_HANDLE_VALUE, "create actual competing destination failed");
                DWORD count{};
                require(WriteFile(writer.h, unknown.data(), static_cast<DWORD>(unknown.size()), &count, nullptr) &&
                        count == unknown.size() && FlushFileBuffers(writer.h), "write competing destination failed");
                created = true;
            }
            creator_closed = true; // writer's owning RAII scope has ended.
            dacl(primary, L"D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)");
            set_simulated_sacl(primary, sacl_descriptor(L"S:P(AU;SAFA;0x2;;;WD)(ML;;NW;;;LW)"));
            require(SetFileAttributesW(primary.c_str(), FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
                    "set ordinary writable destination attrs failed");
            {
                // Exclusive success both demonstrates there is no leftover
                // creator/observer handle and proves data-write/DELETE access.
                // No READONLY, deny DACL or sharing lock can explain the rename.
                Handle exclusive(CreateFileW(primary.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE |
                    READ_CONTROL | WRITE_DAC, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                BY_HANDLE_FILE_INFORMATION info{};
                require(exclusive.h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(exclusive.h, &info),
                        "competing destination is not exclusively writable/deletable");
                require(info.nNumberOfLinks == 1 && !(info.dwFileAttributes & (FILE_ATTRIBUTE_READONLY |
                    FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)),
                    "competing destination is not an ordinary writable independent file");
            }
            exclusive_closed = true;
            unknown_image.emplace_back(primary, true); // Owns snapshots, NOT handles.
            require(unknown_image.front().id != before_id && unknown_image.front().bytes == unknown,
                    "destination object was not independently created with actual unknown bytes");
            for (const auto& stage : stages) require(unknown_image.front().id != stage.image.id,
                    "competing destination aliases an owned stage");
            std::cout << "EVENT APPLIED: destination CREATE_NEW after primary_unlinked; entry="
                << (restoring ? "restore" : "install") << " historicalNew=" << has_new
                << " original=" << before_id.volume << ':' << before_id.file
                << " unknown=" << unknown_image.front().id.volume << ':' << unknown_image.front().id.file
                << " attrs=" << unknown_image.front().basic.FileAttributes
                << " creatorClosed=" << creator_closed << " exclusiveWriteDeleteClosed=" << exclusive_closed << '\n';
            returned = true;
            // Deliberately return normally. No throw, fault injection, stage
            // substitution or pre-call unknown object is used to stop commit.
        });
        try { if (restoring) d.restore(selected); else (void)d.install(f.generated); succeeded = true; }
        catch (const std::exception& ex) { message = ex.what(); }
    }
    std::cout << "DESTINATION RESULT: succeeded=" << succeeded << " prepared=" << prepared
              << " primaryUnlinked=" << unlinked << " callbackReturned=" << returned
              << " primaryInstalled=" << committed << "\nNATIVE REJECTION: " << message << '\n';
    require(created && creator_closed && exclusive_closed && returned && unlinked == 1 && prepared == 1 &&
            unknown_image.size() == 1, "destination observer did not complete the real, handle-free event");
    // Assert state BEFORE the failure result. ReplaceIfExists=TRUE would remove
    // B and commit A; its changed ID/bytes/SD/attrs and successful return fail here.
    unknown_image.front().unchanged(primary, true);
    require(!succeeded && committed == 0, "destination conflict falsely reported successful commit");
    const std::string collision = "NTSTATUS=3221225525, Win32=183"; // STATUS_OBJECT_NAME_COLLISION
    const auto first = message.find(collision);
    require(message.find("目录对象相对重命名失败（不覆盖）") != std::string::npos && first != std::string::npos &&
            message.find(collision, first + collision.size()) != std::string::npos,
            "normal forward rename and undo rename did not both hit actual Native destination collisions");
    require(message.find("回滚不完整") != std::string::npos && message.find("已校验回滚") == std::string::npos &&
            message.find("受保护恢复副本=") != std::string::npos && message.find("ChsWubi.lex") != std::string::npos,
            "destination conflict rollback/recovery reporting is inaccurate");
    require(object_id(f.target) == target_id && fs::exists(secondary) == secondary_present,
            "destination conflict changed target identity or other-slot existence");
    if (secondary_present) other_slot.front().unchanged(secondary);
    require(load(f.target / L"unrelated.keep") == Bytes{std::byte{42}}, "destination race changed unrelated marker");
    auto sentinels_unchanged = [&] {
        old.unchanged(); for (const auto& s : old_new) s.unchanged(); for (const auto& s : installed) s.unchanged();
    };
    sentinels_unchanged();
    const auto saved = backups(f.backup_root);
    require(saved.size() == before_backups.size() + 1 && !recovery.empty() &&
            std::find(saved.begin(), saved.end(), recovery) != saved.end() &&
            std::find(before_backups.begin(), before_backups.end(), recovery) == before_backups.end(),
            "destination collision lost complete pre-operation backup/recovery point");
    manifest_identity(recovery, target_id, restoring ? &f.replacement : &f.original,
                      secondary_present ? &f.secondary : nullptr);
    if (restoring) manifest_identity(selected, target_id, &f.original, has_new ? &f.secondary : nullptr);
    unsigned retained{};
    for (const auto& stage : stages) {
        if (stage.path == undo_primary) {
            require(fs::exists(stage.path), "necessary primary undo copy was not actually retained");
            stage.image.unchanged(stage.path); ++retained;
            require(stage.image.bytes == (restoring ? f.replacement : f.original), "retained undo bytes not pre-operation primary");
            std::cout << "RETAINED UNDO: " << stage.path.filename().string() << " id=" << stage.image.id.volume
                      << ':' << stage.image.id.file << " bytes=" << stage.image.bytes.size() << '\n';
        } else require(!fs::exists(stage.path), "unused forward/other-slot stage was not cleaned by owned handle");
    }
    unsigned actual_retained{};
    for (const auto& entry : fs::directory_iterator(f.target))
        if (entry.path().filename().wstring().starts_with(L"LexHelper-stage-")) ++actual_retained;
    require(retained == 1 && actual_retained == 1, "collision retained the wrong set of necessary undo artifacts");
    // Every saved backup must first pass the real read-side validation, then
    // reject the unknown/mixed current state WITHOUT creating another backup
    // or changing even the retained undo sidecar. This is a second, distinct path.
    for (std::size_t i = 0; i < before_backups.size(); ++i) before_history[i].unchanged(before_backups[i]);
    auto utf8_path = [](const fs::path& path) { const auto text = path.u8string(); return std::string(text.begin(), text.end()); };
    require(message.find(utf8_path(undo_primary)) != std::string::npos && message.find(utf8_path(recovery)) != std::string::npos,
            "failure diagnostics do not name the actual retained undo and complete backup");
    const DirectoryImage mixed(f.target);
    for (const auto& material : saved) {
        const DirectoryImage history(material);
        const auto refusal = rejects([&] { d.restore(material); });
        require(refusal.find("当前内容/存在性/权限不匹配备份的原态或预期部署态") != std::string::npos,
                "follow-up restore did not validate complete backup and refuse unknown/mixed state");
        require(backups(f.backup_root).size() == saved.size(), "unknown-state restore created new recovery point");
        mixed.unchanged(f.target); history.unchanged(material); sentinels_unchanged();
    }
    std::cout << "RESULT: Native forward AND compensation collisions (0xC0000035/183); unknown ID/bytes/native SD/label/attrs"
              << " unchanged; other slot and all shared sentinels intact; complete material and one actual undo retained;"
              << " all " << saved.size() << " subsequent restores refuse unknown/mixed state\n";
}

template<class Group> void destination_conflict_groups(const fs::path& base, Group&& group) {
    unsigned number{};
    for (const bool restoring : {false, true}) for (const bool has_new : {false, true}) {
        const auto name = std::string("destination-conflict-") + (restoring ? "restore-" : "install-") +
                          (has_new ? "with-New" : "without-New");
        ++number;
        group(name.c_str(), [&] { destination_name_conflict(base, restoring, has_new, number); });
    }
}
