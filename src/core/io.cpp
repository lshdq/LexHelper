#include <windows.h>
#include <winternl.h>
#include "internal.hpp"
#include "io_test.hpp"
#include <exception>
#include <memory>

namespace lexhelper {
namespace {
struct Close {void operator()(void* h) const noexcept {if(h && h!=INVALID_HANDLE_VALUE)CloseHandle(h);}};
using Handle=std::unique_ptr<void,Close>;
[[noreturn]] void win_error(const char* operation) {const auto error=GetLastError();throw std::runtime_error(std::string(operation)+"；Win32 错误 "+std::to_string(error));}
std::vector<std::byte> read_file(const std::filesystem::path& path) {
    detail::need(!path.empty() && path.native().find(L'\0')==std::wstring::npos,"输入路径为空或含 NUL");
    Handle h(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(h.get()==INVALID_HANDLE_VALUE) win_error("打开输入失败");
    BY_HANDLE_FILE_INFORMATION info{};if(!GetFileInformationByHandle(h.get(),&info))win_error("读取输入属性失败");
    detail::need(!(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)),"输入必须为普通文件，不能为目录或重解析点");
    LARGE_INTEGER size{};if(!GetFileSizeEx(h.get(),&size))win_error("读取输入长度失败");
    detail::need(size.QuadPart>0 && size.QuadPart<=detail::max_file,"输入为空或超过 128 MiB");
    std::vector<std::byte> b(static_cast<std::size_t>(size.QuadPart));std::size_t p=0;
    while(p<b.size()) {DWORD got=0;if(!ReadFile(h.get(),b.data()+p,static_cast<DWORD>(std::min<std::size_t>(b.size()-p,1u<<20)),&got,nullptr))win_error("读取输入失败");detail::need(got!=0,"输入读取时被截断");p+=got;}
    return b;
}
struct NativeApi {
    decltype(&::NtCreateFile) create;
    decltype(&::RtlNtStatusToDosError) dos_error;
    NativeApi() {
        // ntdll 是进程已加载的系统模块；借用句柄，不搜索/加载输出目录中的 DLL。
        const auto module=GetModuleHandleW(L"ntdll.dll");
        if(!module)win_error("获取系统 ntdll 失败，拒绝不安全的路径回退");
        const auto create_proc=GetProcAddress(module,"NtCreateFile");
        if(!create_proc)win_error("系统缺少 NtCreateFile，拒绝不安全的路径回退");
        const auto error_proc=GetProcAddress(module,"RtlNtStatusToDosError");
        if(!error_proc)win_error("系统缺少 NTSTATUS 转换接口");
        create=reinterpret_cast<decltype(create)>(create_proc);
        dos_error=reinterpret_cast<decltype(dos_error)>(error_proc);
    }
    [[noreturn]] void fail(const char* operation,NTSTATUS status) const {
        // Native API 不设置 GetLastError；未知映射也保留原始 NTSTATUS。
        throw std::runtime_error(std::string(operation)+"；NTSTATUS "+
            std::to_string(static_cast<std::uint32_t>(status))+"；Win32 错误 "+std::to_string(dos_error(status)));
    }
};
struct NativeFile { Handle handle; ULONG_PTR information; };
NativeFile relative_file(const NativeApi& api,HANDLE parent,const std::wstring& name,
    ACCESS_MASK access,ULONG share,ULONG disposition,ULONG options,const char* operation) {
    // 每次只解析一个已校验组件，不允许绝对名、分隔符或 .. 逃出 RootDirectory。
    detail::need(!name.empty() && name!=L"." && name!=L".." && name.find_first_of(L"\\/:")==name.npos &&
        name.size()<=std::numeric_limits<USHORT>::max()/sizeof(wchar_t),"输出路径组件不适合相对目录对象打开");
    UNICODE_STRING object_name{};
    object_name.Length=static_cast<USHORT>(name.size()*sizeof(wchar_t));
    object_name.MaximumLength=object_name.Length;
    object_name.Buffer=const_cast<wchar_t*>(name.data());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length=sizeof(attributes);
    attributes.RootDirectory=parent;
    attributes.ObjectName=&object_name;
    attributes.Attributes=OBJ_CASE_INSENSITIVE|OBJ_DONT_REPARSE;
    IO_STATUS_BLOCK io{};HANDLE raw=nullptr;
    const auto status=api.create(&raw,access,&attributes,&io,nullptr,FILE_ATTRIBUTE_NORMAL,
        share,disposition,options|FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT,nullptr,0);
    // 使用同步句柄，不请求异步/提前完成的 oplock 选项。NT_SUCCESS 等价于 status >= 0。
    if(status<0)api.fail(operation,status);
    Handle handle(raw);
    detail::need(handle && handle.get()!=INVALID_HANDLE_VALUE,"系统未返回有效文件句柄");
    return {std::move(handle),io.Information};
}
void require_disk(HANDLE handle,const char* message) {
    SetLastError(ERROR_SUCCESS);const auto type=GetFileType(handle);
    if(type==FILE_TYPE_UNKNOWN && GetLastError()!=ERROR_SUCCESS)win_error(message);
    detail::need(type==FILE_TYPE_DISK,message);
}
void require_directory(HANDLE handle) {
    require_disk(handle,"输出父路径不是磁盘目录，或无法读取类型");
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(handle,&info))win_error("读取输出父目录失败");
    detail::need((info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) && !(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT),
        "输出父路径必须为真实目录，禁止目录联接/符号链接");
}
struct BoundOutput {std::vector<Handle> directories;std::wstring leaf;};
BoundOutput safe_output(const std::filesystem::path& raw,const NativeApi& api) {
    detail::need(!raw.empty(),"输出路径为空");
    const auto text=raw.native();
    auto namespace_text=text;std::replace(namespace_text.begin(),namespace_text.end(),L'/',L'\\');
    detail::need(text.find(L'\0')==std::wstring::npos && namespace_text.rfind(L"\\\\?\\",0)!=0 && namespace_text.rfind(L"\\\\.\\",0)!=0,"不允许设备命名空间输出路径");
    // GetFullPathName（std::filesystem::absolute）可能先规范化掉尾随空格/点，必须先检查原始路径。
    for(const auto& c:raw.relative_path()) {
        const auto s=c.native();if(s==L"." || s==L"..")continue;
        detail::need(!s.empty() && s.back()!=L'.' && s.back()!=L' ' && s.find_first_of(L"<>:\"|?*")==s.npos &&
            std::none_of(s.begin(),s.end(),[](wchar_t c){return c<32;}),"原始输出路径含非法字符、流或尾随空格/点");
    }
    const auto full=std::filesystem::absolute(raw).lexically_normal();
    std::vector<std::wstring> components;
    for(const auto& component:full.relative_path()) {
        const auto s=component.native();
        detail::need(!s.empty() && s.back()!=L'.' && s.back()!=L' ' && s.find_first_of(L"<>:\"|?*")==s.npos &&
            std::none_of(s.begin(),s.end(),[](wchar_t c){return c<32;}),"输出路径含非法字符、流或尾随空格/点");
        auto base=s.substr(0,s.find(L'.'));while(!base.empty() && base.back()==L' ')base.pop_back();
        std::transform(base.begin(),base.end(),base.begin(),[](wchar_t c)->wchar_t{return c>=L'a'&&c<=L'z'?static_cast<wchar_t>(c-32):c;});
        detail::need(base!=L"CON" && base!=L"PRN" && base!=L"AUX" && base!=L"NUL" && base!=L"CONIN$" && base!=L"CONOUT$" && !(base.size()==4 && (base.rfind(L"COM",0)==0 || base.rfind(L"LPT",0)==0) && ((base[3]>=L'1' && base[3]<=L'9') || base[3]==L'¹' || base[3]==L'²' || base[3]==L'³')),"不允许 Windows 设备文件名");
        components.push_back(s);
    }
    detail::need(full.is_absolute() && !components.empty(),"输出路径必须包含普通文件名");
    auto anchor=full.root_path();std::size_t first=0;
    // UNC 的 root_path 只有 \\server\，必须以共享根而非服务器作为目录锚点。
    const auto root_name=full.root_name().native();
    if(root_name.size()>=2 && (root_name[0]==L'\\' || root_name[0]==L'/') && root_name[0]==root_name[1]) {
        detail::need(components.size()>=2,"UNC 输出路径必须包含共享名和普通文件名");
        anchor/=components.front();anchor/=L"";first=1;
    }
    BoundOutput result;result.leaf=components.back();
    result.directories.reserve(components.size()+1);
    constexpr auto access=FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE;
    constexpr auto share=FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE;
    Handle root(CreateFileW(anchor.c_str(),access,share,nullptr,OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(root.get()==INVALID_HANDLE_VALUE)win_error("打开输出根目录失败");
    require_directory(root.get());result.directories.push_back(std::move(root));
    for(std::size_t i=first;i+1<components.size();++i) {
        auto opened=relative_file(api,result.directories.back().get(),components[i],access,share,FILE_OPEN,
            FILE_DIRECTORY_FILE,"打开输出父目录失败（禁止目录联接/符号链接）");
        require_directory(opened.handle.get());result.directories.push_back(std::move(opened.handle));
    }
    return result;
}
void save_impl(const std::filesystem::path& path,const Table& table,void(*after_parent_verified)(void*),void* context) {
    const auto bytes=write_lex(table);static const NativeApi api;
    auto bound=safe_output(path,api);
    if(after_parent_verified)after_parent_verified(context);
    // 不再从字符串全路径重新遍历祖先；父对象改名/被替换也不会改变 RootDirectory。
    auto created=relative_file(api,bound.directories.back().get(),bound.leaf,
        GENERIC_WRITE|FILE_READ_ATTRIBUTES|DELETE|SYNCHRONIZE,0,FILE_CREATE,FILE_NON_DIRECTORY_FILE,
        "创建输出失败：不能覆盖既有文件/输入，禁止重解析路径");
    const auto handle=created.handle.get();
    try {
        detail::need(created.information==FILE_CREATED,"系统未确认创建新文件，拒绝写入");
        require_disk(handle,"输出不是磁盘文件或无法读取类型，拒绝写入设备");
        BY_HANDLE_FILE_INFORMATION info{};
        if(!GetFileInformationByHandle(handle,&info))win_error("读取新建输出属性失败");
        detail::need(!(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)),"新建输出不是普通文件");
        std::size_t p=0;while(p<bytes.size()) {DWORD written=0;if(!WriteFile(handle,bytes.data()+p,static_cast<DWORD>(std::min<std::size_t>(bytes.size()-p,1u<<20)),&written,nullptr))win_error("写入 lex 失败");detail::need(written!=0,"写入 lex 未取得进展");p+=written;}
        if(!FlushFileBuffers(handle))win_error("持久化 lex 失败");
    } catch(...) {
        // 只删除已确认本次新建的对象；未知创建结果不得误删既有对象。
        if(created.information==FILE_CREATED) {
            FILE_DISPOSITION_INFO disposition{TRUE};
            if(!SetFileInformationByHandle(handle,FileDispositionInfo,&disposition,sizeof(disposition))) {
                const auto error=GetLastError();
                std::throw_with_nested(std::runtime_error("保存失败且无法清理本次半成品；Win32 错误 "+std::to_string(error)));
            }
        }
        throw;
    }
}
// 这里只判定类型，不验证或修复内容；一旦选中解析器，失败必须原样传播。
enum class InputFormat { text, cwb, lex, wbc3 };
bool tabular_text_envelope(std::span<const std::byte> b) {
    // ASCII 魔数也可以是合法词条。UTF-8 文本必须含列分隔 TAB，且不含这些
    // 二进制控制字节；Unicode、坏行、NUL 等完整校验仍只由 read_text 执行。
    bool tab=false;
    for(const auto byte:b) {
        const auto c=std::to_integer<unsigned char>(byte);
        if(c<32 && c!='\t' && c!='\r' && c!='\n')return false;
        tab=tab || c=='\t';
    }
    return tab;
}
InputFormat input_format(const std::filesystem::path& path,std::span<const std::byte> b) {
    auto extension=path.extension().native();
    std::transform(extension.begin(),extension.end(),extension.begin(),[](wchar_t c)->wchar_t {
        return c>=L'A' && c<=L'Z'?static_cast<wchar_t>(c+(L'a'-L'A')):c;
    });
    // 显式类型优先；例如 lex 改名为 .cwb 是类型冲突，不按 magic 偷换类型。
    if(extension==L".txt" || extension==L".tsv")return InputFormat::text;
    if(extension==L".cwb")return InputFormat::cwb;
    if(extension==L".lex")return InputFormat::lex;
    if(extension==L".wbc3")return InputFormat::wbc3;
    // 未知/无扩展保留文本导入；BOM 不会覆盖上面的显式二进制类型。
    if(detail::magic(b,0,"\xef\xbb\xbf") || detail::magic(b,0,"\xff\xfe") ||
        detail::magic(b,0,"\xfe\xff"))return InputFormat::text;
    if(detail::magic(b,0,"PK\x03\x04") || detail::magic(b,0,"PK\x05\x06") ||
        detail::magic(b,0,"PK\x07\x08"))return InputFormat::cwb;
    const bool lex=detail::magic(b,0,"imscwubi"), wbc3=detail::magic(b,0,"WBC3");
    const bool old_wbc=detail::magic(b,0,"WBC1") || detail::magic(b,0,"WBC2");
    if((lex || wbc3 || old_wbc) && !tabular_text_envelope(b)) {
        if(old_wbc)detail::fail("拒绝非新世纪 WBC1/2 码表");
        return lex?InputFormat::lex:InputFormat::wbc3;
    }
    return InputFormat::text;
}
}
ImportResult import_file(const std::filesystem::path& path) {
    auto b=read_file(path);
    switch(input_format(path,b)) {
    case InputFormat::lex:return {read_lex(b),"微软五笔 lex (1.1，受支持的布局)"};
    case InputFormat::wbc3:return {read_wbc3(b),"搜狗新世纪 WBC3（索引次序；未知频率字段不保留）"};
    case InputFormat::cwb:return {read_cwb(b),"搜狗 CWB / usr/wbCustom3.bin（索引次序；未知频率字段不保留）"};
    case InputFormat::text:return {read_text(b),"规范化文本（频次越大越靠前；无频次按行序）"};
    }
    detail::fail("未知输入类型");
}
void save_lex(const std::filesystem::path& path,const Table& table) {
    save_impl(path,table,nullptr,nullptr);
}
void detail::save_lex_with_parent_observer(const std::filesystem::path& path,const Table& table,
    void(*after_parent_verified)(void*),void* context) {
    save_impl(path,table,after_parent_verified,context);
}
}
