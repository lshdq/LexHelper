#pragma once

// Internal, per-call orchestration. No global hooks, privilege changes, pathname
// reopen, or partial-descriptor fallback. Tests can supply local callables without
// introducing a simulated-success route into the deployment library.
#include <windows.h>
#include <cstddef>
#include <utility>
#include <vector>

namespace lexhelper::deploy_detail {
inline constexpr SECURITY_INFORMATION full_security_information = BACKUP_SECURITY_INFORMATION;
inline constexpr DWORD full_security_access = READ_CONTROL | ACCESS_SYSTEM_SECURITY;

struct SecurityQueryAttempt {
    DWORD code{ERROR_SUCCESS};
    LONG native_status{};
    bool has_native_status{};
    std::vector<std::byte> descriptor;
};
struct FullSecurityQuery {
    bool access_complete{};
    bool primary_attempted{};
    bool native_attempted{};
    SecurityQueryAttempt primary;
    SecurityQueryAttempt native;
    const SecurityQueryAttempt& final_attempt() const { return native_attempted ? native : primary; }
};

template<class Primary, class Native>
FullSecurityQuery query_full_security(DWORD granted, Primary&& primary, Native&& native) {
    FullSecurityQuery result;
    result.access_complete = (granted & full_security_access) == full_security_access;
    if (!result.access_complete) {
        result.primary.code = ERROR_ACCESS_DENIED;
        return result;
    }
    result.primary_attempted = true;
    result.primary = std::forward<Primary>(primary)(full_security_information);
    // A granted handle is not repaired by enabling a privilege after open. Try
    // the direct full-descriptor API once, using the SAME handle and BACKUP flag.
    // Other failures are not treated as permissions failures or retried.
    if (result.primary.code == ERROR_ACCESS_DENIED || result.primary.code == ERROR_PRIVILEGE_NOT_HELD) {
        result.native_attempted = true;
        result.native = std::forward<Native>(native)(full_security_information);
    }
    return result;
}
} // namespace lexhelper::deploy_detail
