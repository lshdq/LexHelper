#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <wrl/client.h>

#if __has_include("lexhelper/core.hpp")
#include "lexhelper/core.hpp"
#include "lexhelper/deploy.hpp"
#else
#include "core.hpp"
#include "deploy.hpp"
#endif
#include "../../resources/resource.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace {
using Microsoft::WRL::ComPtr;
namespace fs = std::filesystem;
constexpr wchar_t window_class[] = L"LexHelper.MainWindow";
constexpr UINT job_message = WM_APP + 17;
constexpr UINT_PTR completion_timer = 1;
constexpr int minimum_width = 840;
constexpr int minimum_height = 570;

std::wstring widen(std::string_view input) {
    if (input.empty()) return {};
    if (input.size() <= static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        const auto count = static_cast<int>(input.size());
        const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), count, nullptr, 0);
        if (length > 0) {
            std::wstring text(static_cast<std::size_t>(length), L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), count, text.data(), length)) return text;
        }
    }
    // Preserve non-UTF-8 exception bytes without guessing the machine's ANSI code page.
    std::wstring escaped = L"[非 UTF-8 错误字节] ";
    constexpr wchar_t hex[] = L"0123456789ABCDEF";
    for (const unsigned char ch : input) {
        if (ch >= 32 && ch < 127) escaped.push_back(ch);
        else { escaped += L"\\x"; escaped.push_back(hex[ch >> 4]); escaped.push_back(hex[ch & 15]); }
    }
    return escaped;
}

[[noreturn]] void win_error(const char* operation, DWORD error = GetLastError()) {
    throw std::system_error(static_cast<int>(error), std::system_category(), operation);
}

void check_hr(HRESULT hr, const char* operation) {
    if (FAILED(hr)) throw std::system_error(static_cast<int>(hr), std::system_category(), operation);
}

struct ComApartment {
    HRESULT status;
    explicit ComApartment(DWORD model) : status(CoInitializeEx(nullptr, model)) { check_hr(status, "CoInitializeEx"); }
    ~ComApartment() { CoUninitialize(); }
    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;
};

struct UniqueHandle {
    HANDLE value{};
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : value(handle) {}
    ~UniqueHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
            value = std::exchange(other.value, nullptr);
        }
        return *this;
    }
};

struct TaskMemory {
    PWSTR value{};
    ~TaskMemory() { CoTaskMemFree(value); }
};

struct UniqueAccelerator {
    HACCEL value{};
    ~UniqueAccelerator() { if (value) DestroyAcceleratorTable(value); }
    UniqueAccelerator() = default;
    UniqueAccelerator(const UniqueAccelerator&) = delete;
    UniqueAccelerator& operator=(const UniqueAccelerator&) = delete;
};

struct UniqueIcon {
    HICON value{};
    explicit UniqueIcon(HICON icon = nullptr) noexcept : value(icon) {}
    ~UniqueIcon() { if (value) DestroyIcon(value); }
    UniqueIcon(const UniqueIcon&) = delete;
    UniqueIcon& operator=(const UniqueIcon&) = delete;
    UniqueIcon(UniqueIcon&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    UniqueIcon& operator=(UniqueIcon&& other) noexcept {
        if (this != &other) {
            if (value) DestroyIcon(value);
            value = std::exchange(other.value, nullptr);
        }
        return *this;
    }
};

struct ApplicationIcons {
    UniqueIcon large_icon;
    UniqueIcon small_icon;
};

ApplicationIcons load_application_icons(HINSTANCE instance, UINT dpi) {
    const auto load = [instance, dpi](int width_metric, int height_metric) {
        const int width = GetSystemMetricsForDpi(width_metric, dpi);
        const int height = GetSystemMetricsForDpi(height_metric, dpi);
        if (width <= 0 || height <= 0) throw std::runtime_error("Invalid system icon dimensions");
        // No LR_SHARED: each size has a distinct owner and is released with DestroyIcon.
        HICON icon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_LEXHELPER), IMAGE_ICON, width, height, 0));
        if (!icon) win_error("LoadImageW(LexHelper icon)");
        return UniqueIcon(icon);
    };
    return {load(SM_CXICON, SM_CYICON), load(SM_CXSMICON, SM_CYSMICON)};
}

bool elevated() {
    UniqueHandle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) win_error("OpenProcessToken");
    TOKEN_ELEVATION information{};
    DWORD size{};
    if (!GetTokenInformation(token.value, TokenElevation, &information, sizeof(information), &size)) win_error("GetTokenInformation");
    return information.TokenIsElevated != 0;
}

std::wstring exception_text(std::exception_ptr error) {
    try {
        if (error) std::rethrow_exception(error);
    } catch (const std::exception& ex) { return widen(ex.what()); }
    catch (...) { return L"未知异常；操作未报告成功。请保留日志与备份。"; }
    return L"未知错误";
}

struct SystemInformation {
    fs::path directory;
    fs::path backup_root;
    std::wstring description;
};

SystemInformation query_system() {
    SystemInformation result;
    result.directory = lexhelper::system_lex_directory();
    result.backup_root = lexhelper::default_backup_root();
    for (const auto* name : {L"ChsWubi.lex", L"ChsWubiNew.lex"}) {
        const auto path = result.directory / name;
        std::error_code ec;
        const bool exists = fs::exists(path, ec);
        result.description += name;
        if (ec) result.description += L"：无法查询（" + widen(ec.message()) + L"）";
        else if (!exists) result.description += L"：不存在";
        else {
            const auto bytes = fs::file_size(path, ec);
            result.description += ec ? L"：存在，大小不可读" : L"：" + std::to_wstring(bytes) + L" 字节";
        }
        result.description += L"   ";
    }
    return result;
}

std::wstring statistics(const lexhelper::Table& table) {
    std::array<std::size_t, 5> lengths{};
    std::size_t single{};
    for (const auto& entry : table) {
        if (entry.code.size() <= 4) ++lengths[entry.code.size()];
        const auto& text = entry.text;
        if (text.size() == 1 || (text.size() == 2 && text[0] >= 0xD800 && text[0] <= 0xDBFF && text[1] >= 0xDC00 && text[1] <= 0xDFFF)) ++single;
    }
    return L"共 " + std::to_wstring(table.size()) + L" 条记录（非去重字数）；单 Unicode 字符 " + std::to_wstring(single) +
        L"；码长 1/2/3/4：" + std::to_wstring(lengths[1]) + L" / " + std::to_wstring(lengths[2]) + L" / " +
        std::to_wstring(lengths[3]) + L" / " + std::to_wstring(lengths[4]) + L"。虚拟列表按需显示。";
}

struct VerifiedArtifact {
    UniqueHandle file;
    std::vector<std::byte> bytes;
};

VerifiedArtifact load_generated(const fs::path& path) {
    VerifiedArtifact artifact;
    artifact.file.value = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (artifact.file.value == INVALID_HANDLE_VALUE) win_error("CreateFileW(generated verification)");
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(artifact.file.value, &information)) win_error("GetFileInformationByHandle(generated)");
    if (information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) throw std::runtime_error("Generated lex must be a regular non-reparse file");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(artifact.file.value, &size)) win_error("GetFileSizeEx(generated)");
    if (size.QuadPart <= 0 || size.QuadPart > 512LL * 1024 * 1024) throw std::runtime_error("Generated lex has an invalid or excessive size");
    artifact.bytes.resize(static_cast<std::size_t>(size.QuadPart));
    std::size_t offset{};
    while (offset < artifact.bytes.size()) {
        const auto count = static_cast<DWORD>((std::min)(artifact.bytes.size() - offset, std::size_t{1} << 20));
        DWORD received{};
        if (!ReadFile(artifact.file.value, artifact.bytes.data() + offset, count, &received, nullptr)) win_error("ReadFile(generated)");
        if (!received) throw std::runtime_error("Generated lex was truncated during verification");
        offset += received;
    }
    // Retain a read-only handle without write/delete sharing until deployment finishes.
    return artifact;
}

struct StagingDirectory {
    fs::path path;
    std::vector<UniqueHandle> pinned;
};

StagingDirectory create_staging_directory() {
    TaskMemory local;
    check_hr(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &local.value), "SHGetKnownFolderPath");
    const auto local_path = fs::path(local.value).lexically_normal();
    if (!local_path.is_absolute()) throw std::runtime_error("LocalAppData must be an absolute path");
    StagingDirectory staging;
    const auto pin = [&](const fs::path& path) {
        UniqueHandle handle(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (handle.value == INVALID_HANDLE_VALUE) win_error("CreateFileW(staging directory)");
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(handle.value, &info)) win_error("GetFileInformationByHandle(staging)");
        if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) throw std::runtime_error("Staging parents must be real directories, not junctions or symbolic links");
        staging.pinned.push_back(std::move(handle));
    };
    // Pin every existing ancestor before any elevated directory creation. This avoids
    // traversing a user-controlled junction in LexHelper or any LocalAppData ancestor.
    auto current = local_path.root_path();
    pin(current);
    for (const auto& component : local_path.relative_path()) { current /= component; pin(current); }
    for (const auto* component : {L"LexHelper", L"Generated"}) {
        current /= component;
        if (!CreateDirectoryW(current.c_str(), nullptr)) {
            const DWORD error = GetLastError();
            if (error != ERROR_ALREADY_EXISTS) win_error("CreateDirectoryW(staging parent)", error);
        }
        pin(current);
    }
    GUID guid{};
    check_hr(CoCreateGuid(&guid), "CoCreateGuid");
    wchar_t name[40]{};
    if (!StringFromGUID2(guid, name, static_cast<int>(std::size(name)))) throw std::runtime_error("StringFromGUID2 failed");
    current /= name;
    // A fresh directory is mandatory: never re-use a prior generated artifact.
    if (!CreateDirectoryW(current.c_str(), nullptr)) win_error("CreateDirectoryW(staging)");
    pin(current);
    staging.path = std::move(current);
    return staging;
}

enum class JobKind { refresh, import, save, backup, install, restore };
enum class Continuation { none, open, close };

struct Result {
    JobKind kind{};
    std::exception_ptr error;
    std::shared_ptr<const lexhelper::Table> table;
    fs::path file;
    fs::path backup;
    fs::path generated;
    std::wstring source;
    std::wstring stats;
    SystemInformation system;
};

class Application {
public:
    explicit Application(HINSTANCE instance) : instance_(instance), administrator_(elevated()) {}
    ~Application() {
        // Workers never outlive this object, even during exceptional message-loop exit.
        if (worker_.joinable()) worker_.join();
        if (window_ && IsWindow(window_)) DestroyWindow(window_);
        if (font_) DeleteObject(font_);
        if (registered_) UnregisterClassW(window_class, instance_);
    }
    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;

    int run(int show);

private:
    HINSTANCE instance_{};
    HWND window_{};
    HMENU menu_{}; // Borrowed; DestroyWindow destroys the assigned menu.
    HFONT font_{}; // Owned, unlike DEFAULT_GUI_FONT.
    // The class/window only borrow these; destruction follows DestroyWindow/UnregisterClass.
    ApplicationIcons class_icons_;
    ApplicationIcons window_icons_;
    UINT dpi_{96};
    bool administrator_{};
    bool registered_{};
    bool busy_{};
    bool dirty_{};
    bool close_requested_{};
    Continuation after_save_{};
    std::shared_ptr<const lexhelper::Table> table_;
    fs::path input_file_;
    std::wstring source_;
    std::wstring stats_;
    SystemInformation system_;
    std::jthread worker_;
    std::mutex completion_mutex_;
    std::unique_ptr<Result> completed_;

    static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept;
    LRESULT dispatch(UINT message, WPARAM wparam, LPARAM lparam);
    void controls();
    void layout();
    void rebuild_font();
    void rebuild_icons();
    HMENU create_menu();
    HWND control(int id) const { return GetDlgItem(window_, id); }
    int scale(int value) const { return MulDiv(value, static_cast<int>(dpi_), 96); }
    void position(int id, int x, int y, int width, int height);
    void set_status(const std::wstring& message);
    void append_log(const std::wstring& message);
    void update_commands();
    void update_document();
    void report_error(const std::wstring& message);
    bool choose_path(bool saving, bool folder, fs::path& result);
    void start(JobKind kind, std::wstring description, std::function<void(Result&)> operation);
    void finish();
    void refresh();
    void open();
    bool save(Continuation after = Continuation::none);
    bool may_replace(Continuation requested);
    void close();
    void install();
    void backup();
    void restore();
    bool require_administrator();
    void relaunch_elevated();
    void command(int id);
    void preview(NMLVDISPINFOW& information) noexcept;
};

HMENU Application::create_menu() {
    HMENU root = CreateMenu();
    if (!root) win_error("CreateMenu");
    try {
        const auto add = [](HMENU menu, UINT flags, UINT_PTR id, const wchar_t* label) {
            if (!AppendMenuW(menu, flags, id, label)) win_error("AppendMenuW");
        };
        const auto submenu = [&](const wchar_t* label) {
            HMENU child = CreatePopupMenu();
            if (!child) win_error("CreatePopupMenu");
            if (!AppendMenuW(root, MF_POPUP, reinterpret_cast<UINT_PTR>(child), label)) { const DWORD error = GetLastError(); DestroyMenu(child); win_error("AppendMenuW", error); }
            return child;
        };
        auto file = submenu(L"文件(&F)");
        add(file, MF_STRING, ID_FILE_OPEN, L"打开码表(&O)…\tCtrl+O");
        add(file, MF_STRING, ID_FILE_SAVE, L"另存为新 lex(&S)…\tCtrl+S");
        add(file, MF_SEPARATOR, 0, nullptr);
        add(file, MF_STRING, ID_FILE_EXIT, L"退出(&X)\tAlt+F4");
        auto system = submenu(L"系统(&Y)");
        add(system, MF_STRING, ID_SYSTEM_REFRESH, L"刷新词库状态(&Q)");
        add(system, MF_STRING, ID_SYSTEM_BACKUP, L"创建系统备份(&B)…");
        add(system, MF_STRING, ID_SYSTEM_INSTALL, L"备份并安装当前码表(&I)…");
        add(system, MF_STRING, ID_SYSTEM_RESTORE, L"从备份目录恢复(&R)…");
        add(system, MF_SEPARATOR, 0, nullptr);
        add(system, MF_STRING, ID_SYSTEM_ELEVATE, L"以管理员身份重新打开(&A)…");
        auto help = submenu(L"帮助(&H)");
        add(help, MF_STRING, ID_HELP_ABOUT, L"关于与安全说明(&A)…");
        return root;
    } catch (...) { DestroyMenu(root); throw; }
}

void Application::controls() {
    const auto create = [&](const wchar_t* type, const wchar_t* text, DWORD style, int id, DWORD extended = 0) {
        HWND handle = CreateWindowExW(extended, type, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, window_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
        if (!handle) win_error("CreateWindowExW(control)");
        return handle;
    };
    create(L"STATIC", L"系统词库：正在查询（仅读取路径与文件状态，不解析系统词库）…", SS_LEFT, IDC_SYSTEM_STATE);
    create(L"EDIT", L"正在查询系统路径…", WS_TABSTOP | ES_READONLY | ES_AUTOHSCROLL, IDC_SYSTEM_PATH, WS_EX_CLIENTEDGE);
    for (const auto& item : std::array<std::pair<int, const wchar_t*>, 6>{{
        {ID_FILE_OPEN, L"打开码表(&O)…"}, {ID_FILE_SAVE, L"另存新 lex(&S)…"},
        {ID_SYSTEM_BACKUP, L"系统备份(&B)…"}, {ID_SYSTEM_INSTALL, L"备份并安装(&I)…"},
        {ID_SYSTEM_RESTORE, L"恢复备份(&R)…"}, {ID_SYSTEM_REFRESH, L"刷新状态(&Q)"}}}) {
        create(L"BUTTON", item.second, WS_TABSTOP | BS_PUSHBUTTON, item.first);
    }
    create(L"BUTTON", L"管理员重新打开(&A)…", WS_TABSTOP | BS_PUSHBUTTON, ID_SYSTEM_ELEVATE);
    SendMessageW(control(ID_SYSTEM_ELEVATE), BCM_SETSHIELD, 0, TRUE);
    create(L"STATIC", administrator_ ? L"管理员实例：系统操作仍须再次确认。" : L"普通权限：可导入与保存；系统操作需重新打开管理员实例。", SS_LEFT, IDC_PERMISSION);
    create(L"STATIC", L"尚未导入码表。打开 CWB 时只读取 WBC3（新世纪）；也支持文本和 lex。", SS_LEFT, IDC_DOCUMENT_STATE);
    HWND list = create(WC_LISTVIEWW, L"当前码表预览", WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS, IDC_PREVIEW, WS_EX_CLIENTEDGE);
    ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    const wchar_t* columns[] = {L"编码", L"词条", L"权重（小值优先）"};
    for (int i = 0; i < 3; ++i) {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        column.pszText = const_cast<wchar_t*>(columns[i]);
        column.cx = scale(i == 1 ? 470 : 140);
        column.iSubItem = i;
        if (ListView_InsertColumn(list, i, &column) < 0) win_error("ListView_InsertColumn");
    }
    create(L"STATIC", L"操作日志（含错误与恢复路径）(&L)", SS_LEFT, IDC_LOG_LABEL);
    HWND log = create(L"EDIT", L"", WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_HSCROLL | ES_AUTOHSCROLL, IDC_LOG, WS_EX_CLIENTEDGE);
    SendMessageW(log, EM_SETLIMITTEXT, 160000, 0);
    create(STATUSCLASSNAMEW, L"就绪", SBARS_SIZEGRIP, IDC_STATUS);
    rebuild_font();
    update_commands();
    append_log(L"程序启动；不会自动安装、不结束输入法进程、不修改服务。系统词库仅查询。" );
}

void Application::position(int id, int x, int y, int width, int height) {
    if (!SetWindowPos(control(id), nullptr, scale(x), scale(y), scale((std::max)(0, width)), scale((std::max)(0, height)), SWP_NOZORDER | SWP_NOACTIVATE)) win_error("SetWindowPos(control)");
}

void Application::layout() {
    if (!control(IDC_PREVIEW)) return;
    RECT area{};
    if (!GetClientRect(window_, &area)) win_error("GetClientRect");
    const int width = MulDiv(area.right, 96, static_cast<int>(dpi_));
    const int height = MulDiv(area.bottom, 96, static_cast<int>(dpi_));
    position(IDC_SYSTEM_STATE, 12, 8, width - 24, 24);
    position(IDC_SYSTEM_PATH, 12, 34, width - 24, 28);
    int left = 12;
    const std::array<std::pair<int, int>, 6> buttons{{{ID_FILE_OPEN, 120}, {ID_FILE_SAVE, 140}, {ID_SYSTEM_BACKUP, 112}, {ID_SYSTEM_INSTALL, 144}, {ID_SYSTEM_RESTORE, 120}, {ID_SYSTEM_REFRESH, 104}}};
    for (const auto& [id, size] : buttons) { position(id, left, 72, size, 32); left += size + 8; }
    position(ID_SYSTEM_ELEVATE, 12, 112, 208, 32);
    position(IDC_PERMISSION, 232, 117, width - 244, 25);
    position(IDC_DOCUMENT_STATE, 12, 152, width - 24, 48);
    const int log_top = height - 143;
    position(IDC_PREVIEW, 12, 206, width - 24, log_top - 214);
    position(IDC_LOG_LABEL, 12, log_top, width - 24, 22);
    position(IDC_LOG, 12, log_top + 24, width - 24, 88);
    SendMessageW(control(IDC_STATUS), WM_SIZE, 0, 0);
    ListView_SetColumnWidth(control(IDC_PREVIEW), 0, scale(125));
    ListView_SetColumnWidth(control(IDC_PREVIEW), 1, scale((std::max)(280, width - 340)));
    ListView_SetColumnWidth(control(IDC_PREVIEW), 2, scale(160));
}

void Application::rebuild_font() {
    NONCLIENTMETRICSW metrics{};
    metrics.cbSize = sizeof(metrics);
    HFONT replacement{};
    if (SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, dpi_)) replacement = CreateFontIndirectW(&metrics.lfMessageFont);
    HFONT selected = replacement ? replacement : static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    if (!selected) win_error("GetStockObject(DEFAULT_GUI_FONT)");
    for (HWND child = GetWindow(window_, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(selected), TRUE);
    if (HWND header = ListView_GetHeader(control(IDC_PREVIEW))) SendMessageW(header, WM_SETFONT, reinterpret_cast<WPARAM>(selected), TRUE);
    const HFONT old = std::exchange(font_, replacement);
    if (old) DeleteObject(old);
}

void Application::rebuild_icons() {
    // Load both before changing either borrowed handle; failure leaves the old pair alive.
    auto replacement = load_application_icons(instance_, dpi_);
    // WM_SETICON returns a borrowed previous handle, not an error status or ownership transfer.
    SendMessageW(window_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(replacement.large_icon.value));
    SendMessageW(window_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(replacement.small_icon.value));
    window_icons_ = std::move(replacement); // Release the previous pair only after replacement.
}

void Application::set_status(const std::wstring& message) {
    SendMessageW(control(IDC_STATUS), SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(message.c_str()));
}

void Application::append_log(const std::wstring& message) {
    HWND log = control(IDC_LOG);
    if (!log) return;
    if (GetWindowTextLengthW(log) > 120000) {
        SendMessageW(log, EM_SETSEL, 0, 40000);
        SendMessageW(log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L"[较早日志已从界面移除]\r\n"));
    }
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t prefix[32]{};
    swprintf_s(prefix, L"[%02u:%02u:%02u] ", time.wHour, time.wMinute, time.wSecond);
    std::wstring text = prefix + message + L"\r\n";
    SendMessageW(log, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
    SendMessageW(log, EM_SCROLLCARET, 0, 0);
}

void Application::update_commands() {
    const bool data = table_ && !table_->empty();
    for (int id : {ID_FILE_OPEN, ID_FILE_SAVE, ID_SYSTEM_REFRESH, ID_SYSTEM_BACKUP, ID_SYSTEM_INSTALL, ID_SYSTEM_RESTORE, ID_SYSTEM_ELEVATE}) {
        bool enabled = !busy_;
        if (id == ID_FILE_SAVE || id == ID_SYSTEM_INSTALL) enabled = enabled && data;
        if (id == ID_SYSTEM_BACKUP || id == ID_SYSTEM_INSTALL || id == ID_SYSTEM_RESTORE) enabled = enabled && !system_.directory.empty() && !system_.backup_root.empty();
        if (id == ID_SYSTEM_ELEVATE) enabled = enabled && !administrator_;
        EnableWindow(control(id), enabled);
        EnableMenuItem(menu_, id, MF_BYCOMMAND | (enabled ? MF_ENABLED : MF_GRAYED));
    }
    // Exit stays available while busy, but requests a deferred close at the safe boundary.
    DrawMenuBar(window_);
    std::wstring title = L"LexHelper — 新世纪五笔码表重建";
    if (dirty_) title += L" *（未另存）";
    if (administrator_) title += L" [管理员]";
    if (busy_) title += L" [处理中]";
    if (close_requested_) title += L" [等待安全退出]";
    SetWindowTextW(window_, title.c_str());
}

void Application::update_document() {
    if (table_) {
        const auto text = (dirty_ ? L"未另存 · " : L"已另存 · ") + source_ + L"\r\n" + stats_;
        SetWindowTextW(control(IDC_DOCUMENT_STATE), text.c_str());
    }
    const auto count = table_ ? (std::min)(table_->size(), static_cast<std::size_t>((std::numeric_limits<int>::max)())) : 0;
    ListView_SetItemCountEx(control(IDC_PREVIEW), static_cast<int>(count), LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    InvalidateRect(control(IDC_PREVIEW), nullptr, TRUE);
    update_commands();
}

void Application::report_error(const std::wstring& message) {
    append_log(L"失败：" + message);
    set_status(L"操作失败；详见日志。原码表仍保留。" );
    MessageBoxW(window_, message.c_str(), L"LexHelper — 操作未成功", MB_OK | MB_ICONERROR);
}

bool Application::choose_path(bool saving, bool folder, fs::path& result) {
    ComPtr<IFileDialog> dialog;
    check_hr(CoCreateInstance(saving ? CLSID_FileSaveDialog : CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)), "CoCreateInstance(FileDialog)");
    FILEOPENDIALOGOPTIONS options{};
    check_hr(dialog->GetOptions(&options), "IFileDialog::GetOptions");
    options |= FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_DONTADDTORECENT;
    if (folder) options |= FOS_PICKFOLDERS;
    else if (!saving) options |= FOS_FILEMUSTEXIST;
    // The core never overwrites. Do not offer the system's misleading overwrite confirmation.
    if (saving) options &= ~FOS_OVERWRITEPROMPT;
    check_hr(dialog->SetOptions(options), "IFileDialog::SetOptions");
    if (folder) {
        check_hr(dialog->SetTitle(L"选择 LexHelper 备份目录（须含可验证的备份清单）"), "IFileDialog::SetTitle");
        if (!system_.backup_root.empty()) {
            ComPtr<IShellItem> initial;
            if (SUCCEEDED(SHCreateItemFromParsingName(system_.backup_root.c_str(), nullptr, IID_PPV_ARGS(&initial)))) dialog->SetDefaultFolder(initial.Get());
        }
    } else {
        const COMDLG_FILTERSPEC open_types[] = {
            {L"支持的码表（CWB / WBC3 / 文本 / lex）", L"*.cwb;*.wbc3;*.txt;*.tsv;*.lex"},
            {L"搜狗备份 CWB（仅新世纪 WBC3）", L"*.cwb"},
            {L"文本码表", L"*.txt;*.tsv"}, {L"微软五笔词库", L"*.lex"}, {L"所有文件", L"*.*"}};
        const COMDLG_FILTERSPEC save_type[] = {{L"微软五笔词库（新文件，不覆盖）", L"*.lex"}};
        check_hr(dialog->SetFileTypes(saving ? 1U : static_cast<UINT>(std::size(open_types)), saving ? save_type : open_types), "IFileDialog::SetFileTypes");
        check_hr(dialog->SetTitle(saving ? L"另存为新 lex：请选择不存在的文件名，不覆盖任何已有文件" : L"打开码表：CWB 只读取 WBC3（新世纪），不会混入 WBC1/2"), "IFileDialog::SetTitle");
        if (saving) {
            check_hr(dialog->SetDefaultExtension(L"lex"), "IFileDialog::SetDefaultExtension");
            check_hr(dialog->SetFileName(L"新世纪.lex"), "IFileDialog::SetFileName");
        }
    }
    const HRESULT shown = dialog->Show(window_);
    if (shown == HRESULT_FROM_WIN32(ERROR_CANCELLED)) return false;
    check_hr(shown, "IFileDialog::Show");
    ComPtr<IShellItem> item;
    check_hr(dialog->GetResult(&item), "IFileDialog::GetResult");
    TaskMemory path;
    check_hr(item->GetDisplayName(SIGDN_FILESYSPATH, &path.value), "IShellItem::GetDisplayName");
    result = fs::path(path.value);
    return true;
}

void Application::start(JobKind kind, std::wstring description, std::function<void(Result&)> operation) {
    if (busy_) return;
    auto result = std::make_unique<Result>();
    result->kind = kind;
    append_log(description);
    set_status(description + L"；关闭将等待当前操作安全结束。" );
    busy_ = true;
    update_commands();
    try {
        const HWND destination = window_;
        worker_ = std::jthread([this, destination, result = std::move(result), operation = std::move(operation)]() mutable noexcept {
            try {
                ComApartment apartment(COINIT_MULTITHREADED);
                operation(*result);
            } catch (...) { result->error = std::current_exception(); }
            {
                std::lock_guard lock(completion_mutex_);
                completed_ = std::move(result);
            }
            // No pointer is transferred through the message queue. The UI timer also consumes
            // completed_ if PostMessage fails, so queue failure cannot strand ownership or busy state.
            if (!PostMessageW(destination, job_message, 0, 0)) {
                // Expected recovery path: the live window's completion timer retrieves
                // the already-owned result. Never throw or surrender ownership here.
            }
        });
    } catch (...) {
        busy_ = false;
        update_commands();
        throw;
    }
}

void Application::finish() {
    std::unique_ptr<Result> result;
    {
        std::lock_guard lock(completion_mutex_);
        result = std::move(completed_);
    }
    if (!result) return;
    if (worker_.joinable()) worker_.join();
    busy_ = false;
    // Reset continuations before any modal UI or throwing allocation can re-enter the loop.
    const auto next = std::exchange(after_save_, Continuation::none);
    if (result->error) {
        if (result->kind == JobKind::refresh) {
            system_ = {};
            SetWindowTextW(control(IDC_SYSTEM_PATH), L"");
            SetWindowTextW(control(IDC_SYSTEM_STATE), L"系统状态查询失败；请刷新后重试。");
        }
        if (!result->generated.empty()) append_log(L"本次唯一生成制品（未复用旧文件）：" + result->generated.native());
        if (!result->backup.empty()) append_log(L"本次选用的恢复目录：" + result->backup.native());
        if (result->kind == JobKind::backup || result->kind == JobKind::install || result->kind == JobKind::restore) {
            append_log(L"部署未报告成功；不能据此断言回滚完成。备份根目录：" + system_.backup_root.native() + L"。具体可恢复目录与状态以以下真实错误及备份清单为准。" );
        }
        report_error(exception_text(result->error));
    } else {
        switch (result->kind) {
        case JobKind::refresh:
            system_ = std::move(result->system);
            SetWindowTextW(control(IDC_SYSTEM_PATH), system_.directory.c_str());
            SetWindowTextW(control(IDC_SYSTEM_STATE), system_.description.c_str());
            append_log(L"系统状态已查询；备份根目录：" + system_.backup_root.native());
            set_status(L"已查询系统文件状态；未读取或修改系统词库内容。" );
            break;
        case JobKind::import:
            table_ = std::move(result->table);
            input_file_ = std::move(result->file);
            source_ = std::move(result->source);
            stats_ = std::move(result->stats);
            dirty_ = true;
            update_document();
            append_log(L"导入成功：" + input_file_.native() + L"\r\n" + source_ + L"\r\n" + stats_);
            set_status(L"导入完成。请检查预览；安装前仍需明确确认。" );
            SetFocus(control(IDC_PREVIEW));
            break;
        case JobKind::save:
            dirty_ = false;
            update_document();
            append_log(L"已写入新文件：" + result->file.native());
            set_status(L"另存完成；未覆盖任何已有文件。" );
            break;
        case JobKind::backup:
            append_log(L"备份成功，恢复目录：" + result->backup.native());
            set_status(L"备份完成；恢复路径见日志。" );
            MessageBoxW(window_, (L"备份已完成。请保留以下目录：\r\n\r\n" + result->backup.native()).c_str(), L"LexHelper — 备份完成", MB_OK | MB_ICONINFORMATION);
            break;
        case JobKind::install:
            append_log(L"安装调用完成；备份/恢复目录：" + result->backup.native() + L"\r\n本次已验证生成制品：" + result->generated.native());
            set_status(L"安装已完成；请注销并重新登录以验证。" );
            MessageBoxW(window_, (L"词库替换已完成，但不等于输入法兼容性已实测。\r\n请保存其他工作后注销并重新登录，再验证新世纪编码。\r\n\r\n未结束输入法进程，也未停止服务。Windows 更新可能覆盖词库。\r\n恢复目录：\r\n" + result->backup.native()).c_str(), L"LexHelper — 请重新登录后验证", MB_OK | MB_ICONINFORMATION);
            break;
        case JobKind::restore:
            append_log(L"恢复完成，所用备份目录：" + result->backup.native());
            set_status(L"恢复完成；请注销并重新登录后验证。" );
            MessageBoxW(window_, L"已按所选备份恢复。请保存工作，注销并重新登录后验证。未结束输入法进程。", L"LexHelper — 恢复完成", MB_OK | MB_ICONINFORMATION);
            break;
        }
    }
    // Commands must reflect the committed result, not the state preceding this task.
    update_commands();
    if (std::exchange(close_requested_, false)) { update_commands(); close(); return; }
    if (!result->error && result->kind == JobKind::save) {
        if (next == Continuation::open) open();
        else if (next == Continuation::close) close();
    }
}

void Application::refresh() {
    start(JobKind::refresh, L"正在查询系统词库状态", [](Result& result) { result.system = query_system(); });
}

bool Application::may_replace(Continuation requested) {
    if (!dirty_) return true;
    const TASKDIALOG_BUTTON buttons[] = {{IDYES, L"另存为新 lex"}, {IDNO, L"放弃未保存结果"}, {IDCANCEL, L"取消"}};
    TASKDIALOGCONFIG dialog{sizeof(dialog)};
    dialog.hwndParent = window_;
    dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW | TDF_SIZE_TO_CONTENT;
    dialog.pszWindowTitle = L"LexHelper — 码表尚未另存";
    dialog.pszMainIcon = TD_WARNING_ICON;
    dialog.pszMainInstruction = L"要先保存当前导入的码表吗？";
    dialog.pszContent = L"原始输入文件不会改变。放弃仅丢弃当前内存中的重建结果；安装不会自动视为另存。";
    dialog.cButtons = static_cast<UINT>(std::size(buttons));
    dialog.pButtons = buttons;
    dialog.nDefaultButton = IDCANCEL;
    int selected{};
    check_hr(TaskDialogIndirect(&dialog, &selected, nullptr, nullptr), "TaskDialogIndirect(unsaved)");
    if (selected == IDYES) { save(requested); return false; }
    return selected == IDNO;
}

void Application::open() {
    if (!may_replace(Continuation::open)) return;
    fs::path path;
    if (!choose_path(false, false, path)) return;
    start(JobKind::import, L"正在导入码表；CWB 只选择 WBC3（新世纪）", [path](Result& result) {
        auto imported = lexhelper::import_file(path);
        if (imported.entries.empty()) throw std::runtime_error("The selected table contains no entries");
        result.stats = statistics(imported.entries);
        result.source = widen(imported.source);
        result.file = path;
        result.table = std::make_shared<lexhelper::Table>(std::move(imported.entries));
    });
}

bool Application::save(Continuation after) {
    if (!table_ || table_->empty()) return false;
    fs::path path;
    if (!choose_path(true, false, path)) return false;
    start(JobKind::save, L"正在生成并另存新 lex（不覆盖已有文件）", [path, table = table_](Result& result) {
        lexhelper::save_lex(path, *table);
        result.file = path;
    });
    after_save_ = after;
    return true;
}

void Application::close() {
    if (busy_) {
        if (!close_requested_) append_log(L"收到关闭请求：当前操作不可强制取消，将等待线程结束后执行未保存确认。安装/恢复不会被中途杀死。" );
        close_requested_ = true;
        set_status(L"等待当前操作安全结束后退出；请勿强制结束进程。窗口仍可移动和查看日志。" );
        update_commands();
        return;
    }
    if (!may_replace(Continuation::close)) return;
    if (worker_.joinable()) worker_.join();
    if (!DestroyWindow(window_)) win_error("DestroyWindow");
}

void Application::relaunch_elevated() {
    if (administrator_) return;
    if (MessageBoxW(window_, L"将通过 Windows UAC 打开一个新的管理员实例；本窗口及未保存码表保持不变。\r\n\r\n新窗口不会自动导入、安装、备份或恢复。请在新窗口重新打开所需码表，再明确点击操作并确认。是否继续？", L"LexHelper — 管理员重新打开", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;
    std::wstring executable(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (!length || length >= executable.size()) win_error("GetModuleFileNameW");
    executable.resize(length);
    SHELLEXECUTEINFOW launch{sizeof(launch)};
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    launch.hwnd = window_;
    launch.lpVerb = L"runas";
    launch.lpFile = executable.c_str();
    launch.lpParameters = nullptr; // Never encode an automatic deployment command.
    launch.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&launch)) {
        const DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) { append_log(L"用户取消 UAC；未执行系统操作。" ); return; }
        win_error("ShellExecuteExW(runas)", error);
    }
    UniqueHandle process{launch.hProcess};
    append_log(L"已请求打开管理员实例；当前实例未部署任何文件。" );
}

bool Application::require_administrator() {
    if (administrator_) return true;
    relaunch_elevated();
    return false;
}

void Application::backup() {
    if (system_.directory.empty() || system_.backup_root.empty()) return;
    if (!require_administrator()) return;
    if (MessageBoxW(window_, (L"将备份系统五笔 lex 与可验证的安全信息；不替换系统词库。\r\n每次创建独立目录，不覆盖旧备份。\r\n\r\n目标：" + system_.directory.native() + L"\r\n备份根目录：" + system_.backup_root.native() + L"\r\n\r\n继续？").c_str(), L"LexHelper — 创建系统备份", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
    start(JobKind::backup, L"正在备份系统词库与安全信息", [](Result& result) {
        lexhelper::Deployer deployer({lexhelper::system_lex_directory(), lexhelper::default_backup_root(), true});
        result.backup = deployer.backup();
    });
}

void Application::install() {
    if (!table_ || table_->empty() || system_.directory.empty() || system_.backup_root.empty() || !require_administrator()) return;
    const auto content = L"来源：" + input_file_.native() + L"\r\n类型：" + source_ + L"\r\n记录数：" + std::to_wstring(table_->size()) +
        L"\r\n\r\n系统目标：" + system_.directory.native() + L"\r\n备份根目录：" + system_.backup_root.native() +
        L"\r\n\r\n将先创建独立备份，再替换 CHS 词库目录项；不原位改写其他硬链接指向的原实体。备份恢复内容、存在性及完整安全属性，不恢复硬链接关系或文件 ID。\r\n无法安全读取或恢复安全属性时拒绝执行；失败仅尽力回滚，不保证跨文件、断电或崩溃原子性。\r\n请仅在有系统级恢复途径的可恢复环境操作。不保证所有 Windows 版本或输入法兼容；Windows 更新可能覆盖结果。\r\n完成后需注销并重新登录验证；不会强杀输入法进程或停止服务。";
    const TASKDIALOG_BUTTON buttons[] = {{IDYES, L"创建备份并安装"}, {IDCANCEL, L"取消"}};
    TASKDIALOGCONFIG dialog{sizeof(dialog)};
    dialog.hwndParent = window_;
    dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW | TDF_SIZE_TO_CONTENT;
    dialog.pszWindowTitle = L"LexHelper — 高风险系统词库替换";
    dialog.pszMainIcon = TD_WARNING_ICON;
    dialog.pszMainInstruction = L"确认把当前完整码表安装为系统五笔词库？";
    dialog.pszContent = content.c_str();
    dialog.cButtons = static_cast<UINT>(std::size(buttons));
    dialog.pButtons = buttons;
    dialog.nDefaultButton = IDCANCEL;
    int selected{};
    check_hr(TaskDialogIndirect(&dialog, &selected, nullptr, nullptr), "TaskDialogIndirect(install)");
    if (selected != IDYES) return;
    start(JobKind::install, L"正在生成独立 lex、读回校验、备份并安装", [table = table_](Result& result) {
        auto staging = create_staging_directory();
        result.generated = staging.path / L"ChsWubi.lex";
        lexhelper::save_lex(result.generated, *table);
        const auto artifact = load_generated(result.generated);
        const auto& bytes = artifact.bytes;
        const auto roundtrip = lexhelper::read_lex(bytes);
        if (roundtrip.size() != table->size() || lexhelper::write_lex(*table) != bytes || lexhelper::write_lex(roundtrip) != bytes) throw std::runtime_error("Generated lex failed source and canonical round-trip verification; no system deployment was attempted");
        lexhelper::Deployer deployer({lexhelper::system_lex_directory(), lexhelper::default_backup_root(), true});
        result.backup = deployer.install(result.generated);
        // Retain this uniquely named artifact as troubleshooting evidence. Never re-use it.
    });
}

void Application::restore() {
    if (system_.directory.empty() || system_.backup_root.empty()) return;
    if (!require_administrator()) return;
    fs::path path;
    if (!choose_path(false, true, path)) return;
    const auto content = L"备份目录：" + path.native() + L"\r\n系统目标：" + system_.directory.native() +
        L"\r\n\r\n将验证 v2 备份并先创建当前状态恢复点，再恢复内容、存在性及完整安全属性；不恢复硬链接关系或文件 ID。\r\n旧版、损坏备份或无法识别的当前状态会拒绝；本操作不是打开任意 lex 文件。无法安全读取或恢复安全属性时拒绝执行。\r\n失败仅尽力回滚，不保证跨文件、断电或崩溃原子性。请仅在有系统级恢复途径的可恢复环境操作，不保证所有 Windows 版本或输入法兼容。\r\n恢复后需注销并重新登录验证；不会强杀输入法进程或停止服务。";
    const TASKDIALOG_BUTTON buttons[] = {{IDYES, L"验证备份并恢复"}, {IDCANCEL, L"取消"}};
    TASKDIALOGCONFIG dialog{sizeof(dialog)};
    dialog.hwndParent = window_;
    dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW | TDF_SIZE_TO_CONTENT;
    dialog.pszWindowTitle = L"LexHelper — 高风险系统词库恢复";
    dialog.pszMainIcon = TD_WARNING_ICON;
    dialog.pszMainInstruction = L"确认按所选备份恢复系统五笔词库？";
    dialog.pszContent = content.c_str();
    dialog.cButtons = static_cast<UINT>(std::size(buttons));
    dialog.pButtons = buttons;
    dialog.nDefaultButton = IDCANCEL;
    int selected{};
    check_hr(TaskDialogIndirect(&dialog, &selected, nullptr, nullptr), "TaskDialogIndirect(restore)");
    if (selected != IDYES) return;
    start(JobKind::restore, L"正在验证备份并恢复系统词库与权限", [path](Result& result) {
        result.backup = path;
        lexhelper::Deployer deployer({lexhelper::system_lex_directory(), lexhelper::default_backup_root(), true});
        deployer.restore(path);
    });
}

void Application::command(int id) {
    if (id == ID_FILE_EXIT) { close(); return; }
    if (busy_) return;
    switch (id) {
    case ID_FILE_OPEN: open(); break;
    case ID_FILE_SAVE: save(); break;
    case ID_SYSTEM_REFRESH: refresh(); break;
    case ID_SYSTEM_BACKUP: backup(); break;
    case ID_SYSTEM_INSTALL: install(); break;
    case ID_SYSTEM_RESTORE: restore(); break;
    case ID_SYSTEM_ELEVATE: relaunch_elevated(); break;
    case ID_HELP_ABOUT:
        MessageBoxW(window_, L"LexHelper — 新世纪五笔码表整体重建\r\n\r\n未内置任何私人词库。普通权限打开自己的 CWB，自动选择 WBC3（新世纪），预览后另存为不存在的新 lex；不混入 WBC1/2，不覆盖已有文件。\r\n预览的“权重（小值优先）”是导入后的 lex 代价，越小越靠前，不是搜狗原始词频。文本频次与 WBC3 候选顺序会转换，不保留全部搜狗元数据。\r\n系统操作须管理员重开；安装需在新窗口重新导入、核对并明确确认。恢复内容、存在性及完整安全属性，不恢复硬链接关系或文件 ID。\r\n仅在有系统级恢复途径的可恢复环境操作，不保证所有 Windows 或输入法兼容，也不保证跨文件、断电或崩溃原子性。更新可能覆盖结果，完成后请注销并重新登录验证。\r\n程序不联网、不自动更新、不结束输入法进程、不修改服务。", L"关于 LexHelper", MB_OK | MB_ICONINFORMATION);
        break;
    }
}

void Application::preview(NMLVDISPINFOW& info) noexcept {
    auto& item = info.item;
    if (!(item.mask & LVIF_TEXT) || !item.pszText || item.cchTextMax <= 0) return;
    item.pszText[0] = L'\0';
    if (!table_ || item.iItem < 0 || static_cast<std::size_t>(item.iItem) >= table_->size()) return;
    const auto& entry = (*table_)[static_cast<std::size_t>(item.iItem)];
    std::size_t length{};
    const auto capacity = static_cast<std::size_t>(item.cchTextMax - 1);
    if (item.iSubItem == 0) {
        length = (std::min)(capacity, entry.code.size());
        for (std::size_t i = 0; i < length; ++i) item.pszText[i] = static_cast<unsigned char>(entry.code[i]);
    } else if (item.iSubItem == 1) {
        length = (std::min)(capacity, entry.text.size());
        // Avoid splitting a surrogate pair when the control requests a short text buffer.
        if (length && length < entry.text.size() && entry.text[length - 1] >= 0xD800 && entry.text[length - 1] <= 0xDBFF) --length;
        for (std::size_t i = 0; i < length; ++i) item.pszText[i] = static_cast<wchar_t>(entry.text[i]);
    } else if (item.iSubItem == 2) {
        wchar_t weight[16]{};
        swprintf_s(weight, L"%u", static_cast<unsigned>(entry.weight));
        length = (std::min)(capacity, wcslen(weight));
        std::copy_n(weight, length, item.pszText);
    }
    item.pszText[length] = L'\0';
}

LRESULT CALLBACK Application::procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept {
    Application* self = reinterpret_cast<Application*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        self = static_cast<Application*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
        self->window_ = window;
        SetLastError(ERROR_SUCCESS);
        if (!SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self)) && GetLastError() != ERROR_SUCCESS) return FALSE;
    }
    if (!self) return DefWindowProcW(window, message, wparam, lparam);
    try { return self->dispatch(message, wparam, lparam); }
    catch (...) {
        // No exception may cross a Win32 callback, including allocation failures in error UI.
        try { self->report_error(exception_text(std::current_exception())); }
        catch (...) { MessageBoxW(window, L"无法完成操作（内存或系统资源不足）。未报告成功，请保留备份。", L"LexHelper", MB_OK | MB_ICONERROR); }
        if (message == WM_CREATE) return -1;
        if (message == WM_NCCREATE) return FALSE;
        return 0;
    }
}

LRESULT Application::dispatch(UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        dpi_ = GetDpiForWindow(window_);
        if (!dpi_) dpi_ = 96;
        rebuild_icons();
        controls();
        if (!SetTimer(window_, completion_timer, 100, nullptr)) win_error("SetTimer");
        layout();
        return 0;
    case WM_SIZE: if (wparam != SIZE_MINIMIZED) layout(); return 0;
    case WM_GETMINMAXINFO: {
        RECT rectangle{0, 0, scale(minimum_width), scale(minimum_height)};
        if (!AdjustWindowRectExForDpi(&rectangle, WS_OVERLAPPEDWINDOW, TRUE, 0, dpi_)) win_error("AdjustWindowRectExForDpi");
        auto& info = *reinterpret_cast<MINMAXINFO*>(lparam);
        info.ptMinTrackSize = {rectangle.right - rectangle.left, rectangle.bottom - rectangle.top};
        return 0;
    }
    case WM_DPICHANGED: {
        dpi_ = HIWORD(wparam);
        if (!dpi_) dpi_ = 96;
        rebuild_icons();
        rebuild_font();
        const auto& suggested = *reinterpret_cast<RECT*>(lparam);
        if (!SetWindowPos(window_, nullptr, suggested.left, suggested.top, suggested.right - suggested.left, suggested.bottom - suggested.top, SWP_NOZORDER | SWP_NOACTIVATE)) win_error("SetWindowPos(DPI)");
        layout();
        return 0;
    }
    case WM_SETTINGCHANGE:
    case WM_THEMECHANGED:
        rebuild_icons();
        rebuild_font();
        InvalidateRect(window_, nullptr, TRUE);
        return 0;
    case WM_COMMAND: command(LOWORD(wparam)); return 0;
    case WM_NOTIFY: {
        const auto* header = reinterpret_cast<NMHDR*>(lparam);
        if (header->idFrom == IDC_PREVIEW && header->code == LVN_GETDISPINFOW) preview(*reinterpret_cast<NMLVDISPINFOW*>(lparam));
        return 0;
    }
    case job_message: finish(); return 0;
    case WM_TIMER: if (wparam == completion_timer) finish(); return 0;
    case WM_CLOSE: close(); return 0;
    case WM_QUERYENDSESSION:
        if (busy_ || dirty_) { set_status(L"会话退出已暂缓：请等待任务结束并保存或放弃码表，然后关闭程序。" ); return FALSE; }
        return TRUE;
    case WM_DESTROY:
        // Normal close has already joined. This also protects exceptional startup teardown.
        if (worker_.joinable()) worker_.join();
        KillTimer(window_, completion_timer);
        PostQuitMessage(0);
        return 0;
    case WM_NCDESTROY:
        SetWindowLongPtrW(window_, GWLP_USERDATA, 0);
        return DefWindowProcW(window_, message, wparam, lparam);
    default: return DefWindowProcW(window_, message, wparam, lparam);
    }
}

int Application::run(int show) {
    dpi_ = GetDpiForSystem();
    if (!dpi_) dpi_ = 96;
    class_icons_ = load_application_icons(instance_, dpi_);
    WNDCLASSEXW descriptor{sizeof(descriptor)};
    descriptor.style = CS_HREDRAW | CS_VREDRAW;
    descriptor.lpfnWndProc = procedure;
    descriptor.hInstance = instance_;
    descriptor.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    descriptor.hIcon = class_icons_.large_icon.value;
    descriptor.hIconSm = class_icons_.small_icon.value;
    descriptor.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    descriptor.lpszClassName = window_class;
    if (!descriptor.hCursor) win_error("LoadCursorW");
    if (!RegisterClassExW(&descriptor)) win_error("RegisterClassExW");
    registered_ = true;
    menu_ = create_menu();
    RECT rectangle{0, 0, scale(1080), scale(760)};
    if (!AdjustWindowRectExForDpi(&rectangle, WS_OVERLAPPEDWINDOW, TRUE, 0, dpi_)) { const DWORD error = GetLastError(); DestroyMenu(menu_); menu_ = nullptr; win_error("AdjustWindowRectExForDpi", error); }
    int width = rectangle.right - rectangle.left;
    int height = rectangle.bottom - rectangle.top;
    int x = CW_USEDEFAULT;
    int y = CW_USEDEFAULT;
    MONITORINFO monitor{sizeof(monitor)};
    if (GetMonitorInfoW(MonitorFromPoint(POINT{}, MONITOR_DEFAULTTOPRIMARY), &monitor)) {
        width = (std::min)(width, static_cast<int>(monitor.rcWork.right - monitor.rcWork.left - 24));
        height = (std::min)(height, static_cast<int>(monitor.rcWork.bottom - monitor.rcWork.top - 24));
        x = monitor.rcWork.left + (monitor.rcWork.right - monitor.rcWork.left - width) / 2;
        y = monitor.rcWork.top + (monitor.rcWork.bottom - monitor.rcWork.top - height) / 2;
    }
    HWND created = CreateWindowExW(WS_EX_CONTROLPARENT, window_class, L"LexHelper — 新世纪五笔码表重建", WS_OVERLAPPEDWINDOW,
        x, y, width, height, nullptr, menu_, instance_, this);
    if (!created) { const DWORD error = GetLastError(); if (IsMenu(menu_)) DestroyMenu(menu_); menu_ = nullptr; win_error("CreateWindowExW(main)", error); }
    ShowWindow(window_, show);
    UpdateWindow(window_);
    const ACCEL accelerators[] = {{FVIRTKEY | FCONTROL, 'O', ID_FILE_OPEN}, {FVIRTKEY | FCONTROL, 'S', ID_FILE_SAVE}};
    UniqueAccelerator shortcuts;
    shortcuts.value = CreateAcceleratorTableW(const_cast<ACCEL*>(accelerators), static_cast<int>(std::size(accelerators)));
    if (!shortcuts.value) { const DWORD error = GetLastError(); DestroyWindow(window_); win_error("CreateAcceleratorTableW", error); }
    // Query is posted into our asynchronous pipeline only after the window is fully constructed.
    try { refresh(); } catch (...) { report_error(exception_text(std::current_exception())); }
    MSG message{};
    int status{};
    while ((status = GetMessageW(&message, nullptr, 0, 0)) > 0) {
        if (!TranslateAcceleratorW(window_, shortcuts.value, &message) && !IsDialogMessageW(window_, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    const DWORD loop_error = status == -1 ? GetLastError() : ERROR_SUCCESS;
    // WM_QUIT can be received without WM_CLOSE (e.g. an exceptional loop exit).
    // Keep the HWND and App alive until no worker can publish further notifications.
    if (worker_.joinable()) worker_.join();
    if (IsWindow(window_)) DestroyWindow(window_);
    if (status == -1) win_error("GetMessageW", loop_error);
    return static_cast<int>(message.wParam);
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    try {
        ComApartment apartment(COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES};
        if (!InitCommonControlsEx(&controls)) win_error("InitCommonControlsEx");
        Application application(instance);
        return application.run(show);
    } catch (...) {
        try { const auto text = exception_text(std::current_exception()); MessageBoxW(nullptr, text.c_str(), L"LexHelper — 无法启动", MB_OK | MB_ICONERROR); }
        catch (...) { MessageBoxW(nullptr, L"无法启动：系统资源不足。", L"LexHelper", MB_OK | MB_ICONERROR); }
        return 1;
    }
}
