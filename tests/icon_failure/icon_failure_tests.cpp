// R1 / TC-006: compile the real implementation, never a copy of its algorithms.
// Include SDK headers before substituting only the relevant Win32 call sites.
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <wrl/client.h>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <system_error>

namespace probe {
struct Icon { HICON handle{}; unsigned destroys{}; };
struct Event { UINT kind{}; HICON icon{}; };
struct State {
    std::array<Icon, 128> icons{};
    std::array<Event, 256> events{};
    std::size_t count{}, event_count{};
    unsigned loads{}, fail_at{}, errors{}, create_calls{}, nc_destroy{}, closes{}, destroys{};
    LRESULT create_result{}, reload_result{};
    unsigned reload_callbacks{};
    HWND window{}, failed_window{};
    HMENU menu{};
    HINSTANCE instance{};
    HICON class_large{}, class_small{};
    WNDPROC original{};
    bool registered{}, violation{}, runtime{}, runtime_done{};
} state;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void event(UINT kind, HICON icon) noexcept {
    if (state.event_count == state.events.size()) { state.violation = true; return; }
    state.events[state.event_count++] = {kind, icon};
}
HANDLE WINAPI load(HINSTANCE instance, LPCWSTR name, UINT type, int cx, int cy, UINT flags) {
    ++state.loads;
    if (state.loads == state.fail_at) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return nullptr; }
    const auto result = ::LoadImageW(instance, name, type, cx, cy, flags);
    if (result) {
        require(type == IMAGE_ICON && !(flags & LR_SHARED), "unexpected/shared image load");
        require(state.count < state.icons.size(), "icon ledger capacity");
        state.icons[state.count++] = {static_cast<HICON>(result), 0};
    }
    return result;
}
bool live(HICON icon) noexcept {
    for (std::size_t i = state.count; i > 0; --i)
        if (state.icons[i - 1].handle == icon && !state.icons[i - 1].destroys) return true;
    return false;
}
BOOL WINAPI destroy(HICON icon) noexcept {
    event(WM_DESTROY, icon);
    if ((state.registered && (icon == state.class_large || icon == state.class_small)) ||
        (IsWindow(state.window) &&
            (icon == reinterpret_cast<HICON>(::SendMessageW(state.window, WM_GETICON, ICON_BIG, 0)) ||
             icon == reinterpret_cast<HICON>(::SendMessageW(state.window, WM_GETICON, ICON_SMALL, 0)))))
        state.violation = true; // Destroying a handle still borrowed by a window/class.
    for (std::size_t i = state.count; i > 0; --i) {
        auto& item = state.icons[i - 1];
        if (item.handle == icon && !item.destroys) {
            ++item.destroys;
            const auto ok = ::DestroyIcon(icon);
            if (!ok) state.violation = true;
            return ok;
        }
    }
    state.violation = true; // Unknown ownership or duplicate release: do not destroy twice.
    return FALSE;
}
LRESULT WINAPI send(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_SETICON) {
        const auto icon = reinterpret_cast<HICON>(lparam);
        if (!live(icon)) state.violation = true;
        event(wparam == ICON_BIG ? ICON_BIG : ICON_SMALL, icon);
    }
    return ::SendMessageW(window, message, wparam, lparam);
}
int WINAPI message_box(HWND, LPCWSTR text, LPCWSTR, UINT flags) noexcept {
    // Never display modal error UI in an automated failure case. Only expected errors.
    ++state.errors;
    if (!(flags & MB_ICONERROR) || !text || !wcsstr(text, L"LoadImageW")) state.violation = true;
    return IDOK;
}
LRESULT CALLBACK monitor(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept {
    if (message == WM_NCCREATE) state.window = window;
    const auto result = state.original(window, message, wparam, lparam);
    if (message == WM_CREATE) { ++state.create_calls; state.create_result = result; }
    if (message == WM_THEMECHANGED || message == WM_SETTINGCHANGE || message == WM_DPICHANGED) {
        ++state.reload_callbacks;
        state.reload_result = result;
    }
    if (message == WM_CLOSE) ++state.closes;
    if (message == WM_DESTROY) ++state.destroys;
    if (message == WM_NCDESTROY) { ++state.nc_destroy; state.failed_window = window; }
    return result;
}
ATOM WINAPI register_class(const WNDCLASSEXW* descriptor) {
    auto copy = *descriptor;
    state.original = copy.lpfnWndProc;
    state.instance = copy.hInstance;
    state.class_large = copy.hIcon;
    state.class_small = copy.hIconSm;
    copy.lpfnWndProc = monitor;
    const auto atom = ::RegisterClassExW(&copy);
    state.registered = atom != 0;
    return atom;
}
BOOL WINAPI unregister_class(LPCWSTR name, HINSTANCE instance) noexcept {
    const auto ok = ::UnregisterClassW(name, instance);
    if (ok) state.registered = false;
    else state.violation = true;
    return ok;
}
HWND WINAPI create_window(DWORD ex, LPCWSTR name, LPCWSTR title, DWORD style,
    int x, int y, int width, int height, HWND parent, HMENU menu, HINSTANCE instance, LPVOID param) {
    if (!parent && name && !IS_INTRESOURCE(name) && wcscmp(name, L"LexHelper.MainWindow") == 0)
        state.menu = menu;
    return ::CreateWindowExW(ex, name, title, style, x, y, width, height, parent, menu, instance, param);
}
void runtime_cases();
BOOL WINAPI get_message(LPMSG message, HWND window, UINT low, UINT high) {
    if (state.runtime && !state.runtime_done) {
        state.runtime_done = true;
        runtime_cases();
        // The normal callback handles busy refresh by deferring close until its worker ends.
        ::SendMessageW(state.window, WM_CLOSE, 0, 0);
    }
    return ::GetMessageW(message, window, low, high);
}
} // namespace probe

#define LoadImageW probe::load
#define DestroyIcon probe::destroy
#define SendMessageW probe::send
#define MessageBoxW probe::message_box
#define RegisterClassExW probe::register_class
#define UnregisterClassW probe::unregister_class
#define CreateWindowExW probe::create_window
#define GetMessageW probe::get_message
#include "../../src/gui/main.cpp"
#undef LoadImageW
#undef DestroyIcon
#undef SendMessageW
#undef MessageBoxW
#undef RegisterClassExW
#undef UnregisterClassW
#undef CreateWindowExW
#undef GetMessageW

namespace probe {
void valid(HICON icon) {
    require(icon && live(icon), "icon not live/owned");
    ICONINFO info{};
    require(GetIconInfo(icon, &info) != FALSE, "old/new real HICON is invalid");
    if (info.hbmMask) DeleteObject(info.hbmMask);
    if (info.hbmColor) DeleteObject(info.hbmColor);
}
HICON window_icon(WPARAM kind) {
    return reinterpret_cast<HICON>(::SendMessageW(state.window, WM_GETICON, kind, 0));
}
void finished() {
    require(!state.violation, "borrowed/double/unknown release or callback report violation");
    require(!state.registered, "window class leaked");
    require(!IsWindow(state.window), "window leaked");
    require(!state.menu || !IsMenu(state.menu), "main menu leaked");
    for (std::size_t i = 0; i < state.count; ++i)
        require(state.icons[i].destroys == 1, "loaded icon not released exactly once");
}
void runtime_cases() {
    require(IsWindow(state.window) && state.create_result == 0, "runtime window not created");
    for (const UINT message : {WM_THEMECHANGED, WM_SETTINGCHANGE, WM_DPICHANGED}) {
        for (const unsigned position : {1U, 2U}) {
            const auto old_large = window_icon(ICON_BIG), old_small = window_icon(ICON_SMALL);
            valid(old_large); valid(old_small);
            const auto before = state.count, events = state.event_count;
            const auto loads = state.loads, errors = state.errors;
            state.fail_at = loads + position;
            RECT suggested{};
            require(GetWindowRect(state.window, &suggested) != FALSE, "GetWindowRect");
            const auto dpi = GetDpiForWindow(state.window);
            const auto wp = message == WM_DPICHANGED ? MAKEWPARAM(dpi, dpi) : 0;
            const auto lp = message == WM_DPICHANGED ? reinterpret_cast<LPARAM>(&suggested) : 0;
            auto callbacks = state.reload_callbacks;
            (void)::SendMessageW(state.window, message, wp, lp);
            require(state.reload_callbacks == callbacks + 1 && state.reload_result == 0, "callback failure result");
            require(state.errors == errors + 1 && state.loads == loads + position, "failure not caught/reported at expected load");
            require(state.count == before + position - 1, "unexpected partial load count");
            require(window_icon(ICON_BIG) == old_large && window_icon(ICON_SMALL) == old_small,
                "failed reload partially replaced old icon pair");
            valid(old_large); valid(old_small);
            require(state.event_count == events + position - 1, "failed reload sent WM_SETICON");
            if (position == 2) {
                require(state.icons[before].destroys == 1, "first new icon leaked on second load failure");
                require(state.events[events].kind == WM_DESTROY, "partial icon not destroyed");
            }
            state.fail_at = 0;
            const auto recovery_events = state.event_count;
            callbacks = state.reload_callbacks;
            // Windows theme subclassing can alter SendMessage's outer return value.
            // Assert the actual production procedure result recorded by our monitor.
            (void)::SendMessageW(state.window, message, wp, lp);
            require(state.reload_callbacks == callbacks + 1 && state.reload_result == 0, "recovery callback result");
            require(state.errors == errors + 1 && state.count == before + position + 1, "recovery did not load two icons");
            require(window_icon(ICON_BIG) == state.icons[state.count - 2].handle &&
                    window_icon(ICON_SMALL) == state.icons[state.count - 1].handle, "recovery pair not committed");
            valid(window_icon(ICON_BIG)); valid(window_icon(ICON_SMALL));
            require(!live(old_large) && !live(old_small), "old pair not released after recovery");
            require(state.event_count == recovery_events + 4 &&
                state.events[recovery_events].kind == ICON_BIG &&
                state.events[recovery_events + 1].kind == ICON_SMALL &&
                state.events[recovery_events + 2].kind == WM_DESTROY &&
                state.events[recovery_events + 3].kind == WM_DESTROY,
                "old pair released before both WM_SETICON calls");
            require(!state.violation, "runtime ownership violation");
            std::printf("PASS runtime message=%u failure_position=%u: old pair valid/unchanged, partial cleanup, catch, recovery\n", message, position);
        }
    }
}
} // namespace probe

int main() {
    using namespace probe;
    try {
        require(!elevated(), "run tests with an ordinary non-elevated token");
        ComApartment apartment(COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES};
        require(InitCommonControlsEx(&controls) != FALSE, "InitCommonControlsEx");
        const auto instance = GetModuleHandleW(nullptr);
        for (const unsigned position : {1U, 2U}) {
            state = {};
            state.fail_at = position;
            bool caught = false;
            try { auto icons = load_application_icons(instance, 96); }
            catch (const std::system_error& error) { caught = error.code().value() == ERROR_RESOURCE_DATA_NOT_FOUND; }
            require(caught && state.loads == position && state.count == position - 1, "pair load did not fail at injected call");
            finished();
            std::printf("PASS pair load failure_position=%u: deterministic error and exact partial cleanup\n", position);
        }
        for (const unsigned position : {1U, 2U}) {
            state = {};
            state.fail_at = 2 + position; // Class pair succeeds; fail the WM_CREATE pair.
            bool caught = false;
            {
                Application application(instance);
                try { (void)application.run(SW_HIDE); }
                catch (const std::system_error&) { caught = true; }
                require(caught && state.create_calls == 1 && state.create_result == -1,
                    "WM_CREATE failure did not reject creation");
                require(state.errors == 1 && state.loads == 2 + position && state.count == position + 1,
                    "WM_CREATE failure did not reach expected callback catch/load");
                require(state.nc_destroy == 1 && !IsWindow(state.failed_window), "failed HWND not destroyed");
                for (std::size_t i = 0; i < state.event_count; ++i)
                    require(state.events[i].kind == WM_DESTROY, "failed create partially set window icons");
            }
            finished();
            MSG quit{};
            while (PeekMessageW(&quit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {}
            std::printf("PASS WM_CREATE failure_position=%u: returns -1, HWND/menu/class/all icons released\n", position);
        }
        state = {};
        state.runtime = true;
        {
            Application application(instance);
            require(application.run(SW_HIDE) == 0, "normal message loop exit code");
        }
        require(state.runtime_done && state.errors == 6 && state.closes >= 1 && state.destroys == 1 && state.nc_destroy == 1,
            "runtime cases/normal WM_CLOSE lifecycle incomplete");
        finished();
        std::printf("PASS normal WM_CLOSE after six failure/recovery cases: all %zu icons released exactly once\n", state.count);
        std::puts("RESULT PASS: 10 failure cases, 6 successful recoveries, normal shutdown; no deployment");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "RESULT FAIL: %s\n", error.what());
        return 1;
    }
}
