#pragma once

#include <filesystem>
#include <cstddef>
#include <span>
#include <vector>

namespace lexhelper {

struct DeployOptions {
    std::filesystem::path target_directory;
    std::filesystem::path backup_root;
    bool system_mode{false};
};

class Deployer {
public:
    explicit Deployer(DeployOptions options);
    [[nodiscard]] std::filesystem::path backup();
    // Full owner/group/DACL/SACL/label snapshots must succeed before mutation.
    [[nodiscard]] std::filesystem::path install(const std::filesystem::path& generated_lex);
    void restore(const std::filesystem::path& backup_directory);

private:
    DeployOptions options_;
};

[[nodiscard]] std::filesystem::path system_lex_directory();
[[nodiscard]] std::filesystem::path default_backup_root();

// Deterministic, thread-local simulation hooks; never enabled by environment or a manifest.
namespace deploy_testing {
enum class FailurePoint { none, after_backup, after_primary_write, after_new_disabled,
                          before_security_restore, full_security_read, after_sacl_restore,
                          after_primary_unlink, after_new_unlink, after_first_cleanup_mark };
void inject_failure(FailurePoint point, bool fail_rollback = false) noexcept;
// Explicit fake SACL backend for registered D-drive test sandboxes only. It never
// enables privileges or writes an OS SACL, and is ignored by system_mode=true.
void enable_security_simulation(const std::filesystem::path& target_directory);
void set_simulated_sacl(const std::filesystem::path& file,
                        std::span<const std::byte> full_self_relative_descriptor);
[[nodiscard]] std::vector<std::byte> simulated_security(const std::filesystem::path& file);
// Development interleavings: explicit callback on this thread, only for an
// already registered, current-user-owned D-drive simulation directory object.
enum class ObservationPoint { directories_bound, source_bound, backup_directory_created,
                              backup_files_written, backup_validated, stages_prepared,
                              primary_unlinked, primary_installed, selected_backup_bound, backup_directory_ready };
using Observer = void(*)(ObservationPoint point, const std::filesystem::path& subject, void* context);
void set_observer(const std::filesystem::path& registered_target, Observer observer, void* context);
}

} // namespace lexhelper
