// CORE-001 / TC-007 正式回归：只使用 temp_root 内自建数据。
// 目录变更由逐调用观察点确定性排序，真实 Win32 变更失败不能算作覆盖。
// IAT 故障只限当前测试 EXE，RAII 恢复；不是磁盘满/掉电实测，也不修改被测实现。
struct IoObjectId {
    DWORD volume,high,low;
    bool operator==(const IoObjectId&) const=default;
};
IoObjectId io_object_id(HANDLE h) {
    BY_HANDLE_FILE_INFORMATION info{};CHECK(GetFileInformationByHandle(h,&info));
    return {info.dwVolumeSerialNumber,info.nFileIndexHigh,info.nFileIndexLow};
}
IoObjectId io_path_id(const std::filesystem::path& p,bool directory) {
    FixtureHandle h(CreateFileW(p.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|(directory?FILE_FLAG_BACKUP_SEMANTICS:0),nullptr));
    CHECK(h.get()!=INVALID_HANDLE_VALUE);return io_object_id(h.get());
}
void io_absent(const std::filesystem::path& p) {
    std::error_code error;const auto exists=std::filesystem::exists(p,error);CHECK(!error);CHECK(!exists);
}
void io_remove_directory(const std::filesystem::path& p) {
    CHECK(p.lexically_normal().parent_path()==temp_root);
    const auto attributes=GetFileAttributesW(p.c_str());CHECK(attributes!=INVALID_FILE_ATTRIBUTES);
    CHECK((attributes&FILE_ATTRIBUTE_DIRECTORY) && !(attributes&FILE_ATTRIBUTE_REPARSE_POINT));
    CHECK(std::filesystem::is_empty(p));CHECK(RemoveDirectoryW(p.c_str()));
}
struct IoRenameContext {
    std::filesystem::path parent,moved;IoObjectId original{};unsigned calls=0;bool changed=false;
};
void io_rename_replace(void* opaque) {
    auto& c=*static_cast<IoRenameContext*>(opaque);CHECK(++c.calls==1);
    CHECK(io_path_id(c.parent,true)==c.original);
    CHECK(MoveFileExW(c.parent.c_str(),c.moved.c_str(),0));
    CHECK(CreateDirectoryW(c.parent.c_str(),nullptr));
    CHECK(io_path_id(c.moved,true)==c.original);CHECK(!(io_path_id(c.parent,true)==c.original));
    const auto attributes=GetFileAttributesW(c.parent.c_str());
    CHECK(attributes!=INVALID_FILE_ATTRIBUTES && !(attributes&FILE_ATTRIBUTE_REPARSE_POINT));c.changed=true;
}
struct IoJunctionContext {
    std::filesystem::path parent,target;DWORD access;IoObjectId original{};
    FixtureHandle mutator;unsigned calls=0;bool changed=false,tagged=false;
    bool remove_tag() noexcept {
        if(!tagged)return true;
        struct {DWORD tag;WORD length,reserved;} header{IO_REPARSE_TAG_MOUNT_POINT,0,0};DWORD returned=0;
        if(!DeviceIoControl(mutator.get(),FSCTL_DELETE_REPARSE_POINT,&header,sizeof(header),nullptr,0,&returned,nullptr))return false;
        tagged=false;return true;
    }
    ~IoJunctionContext(){remove_tag();} // 失败也只按已拥有的联接句柄移除标签，不沿目标清理。
};
void io_make_junction(void* opaque) {
    auto& c=*static_cast<IoJunctionContext*>(opaque);CHECK(++c.calls==1);
    c.mutator.reset(CreateFileW(c.parent.c_str(),c.access,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
    CHECK(c.mutator.get()!=INVALID_HANDLE_VALUE);CHECK(io_object_id(c.mutator.get())==c.original);
    struct MountBuffer {DWORD tag;WORD length,reserved,sub_offset,sub_length,print_offset,print_length;wchar_t paths[2048];} b{};
    const auto substitute=L"\\??\\"+c.target.native(),print=c.target.native();
    CHECK(substitute.size()+print.size()+2<std::size(b.paths));
    b.tag=IO_REPARSE_TAG_MOUNT_POINT;b.sub_length=static_cast<WORD>(substitute.size()*sizeof(wchar_t));
    b.print_offset=static_cast<WORD>((substitute.size()+1)*sizeof(wchar_t));b.print_length=static_cast<WORD>(print.size()*sizeof(wchar_t));
    std::copy(substitute.begin(),substitute.end(),b.paths);std::copy(print.begin(),print.end(),b.paths+substitute.size()+1);
    b.length=static_cast<WORD>(8+(substitute.size()+print.size()+2)*sizeof(wchar_t));DWORD returned=0;
    CHECK(DeviceIoControl(c.mutator.get(),FSCTL_SET_REPARSE_POINT,&b,b.length+8,nullptr,0,&returned,nullptr));c.tagged=true;
    MountBuffer observed{};CHECK(DeviceIoControl(c.mutator.get(),FSCTL_GET_REPARSE_POINT,nullptr,0,&observed,sizeof(observed),&returned,nullptr));
    CHECK(returned>=b.length+8u && observed.tag==IO_REPARSE_TAG_MOUNT_POINT && observed.sub_offset==0 && observed.sub_length==b.sub_length);
    CHECK(std::wstring_view(observed.paths,observed.sub_length/sizeof(wchar_t))==substitute);
    BY_HANDLE_FILE_INFORMATION info{};CHECK(GetFileInformationByHandle(c.mutator.get(),&info));
    CHECK(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT);CHECK(io_object_id(c.mutator.get())==c.original);c.changed=true;
}
void io_identity_tests() {
    const auto start=checks;const Table table{{"a",u"甲",1},{"zz",u"确定性中文",2}};
    const auto parent=temp_root/L"已验证父目录",moved=temp_root/L"原对象已改名";
    CHECK(std::filesystem::create_directory(parent));IoRenameContext rename{parent,moved,io_path_id(parent,true)};
    bool saved=false;std::string error;
    try{detail::save_lex_with_parent_observer(parent/L"身份.lex",table,io_rename_replace,&rename);saved=true;}
    catch(const std::exception& e){error=e.what();}
    CHECK(rename.calls==1 && rename.changed);io_absent(parent/L"身份.lex");CHECK(std::filesystem::is_empty(parent));
    if(saved){CHECK(read_fixture(moved/L"身份.lex")==write_lex(table));CHECK(import_file(moved/L"身份.lex").entries==table);CHECK(DeleteFileW((moved/L"身份.lex").c_str()));}
    else{CHECK(!error.empty());io_absent(moved/L"身份.lex");}
    CHECK(io_path_id(moved,true)==rename.original);io_remove_directory(parent);io_remove_directory(moved);
    std::cout<<"[identity rename] mutation=actual-success; result="<<(saved?"original-object":"safe-rejection")<<"; replacement=empty\n";
    for(const auto access:{DWORD{GENERIC_WRITE},DWORD{FILE_WRITE_ATTRIBUTES}}) {
        const auto label=access==GENERIC_WRITE?L"常规写":L"仅元数据写";
        IoJunctionContext c{temp_root/(std::wstring(label)+L"父"),temp_root/(std::wstring(label)+L"重定向"),access};
        CHECK(std::filesystem::create_directory(c.parent));CHECK(std::filesystem::create_directory(c.target));c.original=io_path_id(c.parent,true);
        const auto sentinel=c.target/L"哨兵.bin";const auto unchanged=bytes("redirect-sentinel");write_bytes(sentinel,unchanged);
        saved=false;error.clear();
        try{detail::save_lex_with_parent_observer(c.parent/L"身份.lex",table,io_make_junction,&c);saved=true;}
        catch(const std::exception& e){error=e.what();}
        CHECK(c.calls==1 && c.changed && c.tagged);io_absent(c.target/L"身份.lex");CHECK(read_fixture(sentinel)==unchanged);
        CHECK(c.remove_tag());c.mutator.reset();CHECK(io_path_id(c.parent,true)==c.original);
        if(saved){CHECK(read_fixture(c.parent/L"身份.lex")==write_lex(table));CHECK(DeleteFileW((c.parent/L"身份.lex").c_str()));}
        else{CHECK(error.find("创建输出失败")!=std::string::npos);io_absent(c.parent/L"身份.lex");}
        CHECK(DeleteFileW(sentinel.c_str()));io_remove_directory(c.parent);io_remove_directory(c.target);
        std::cout<<"[identity junction] access="<<access<<"; mutation=actual-success+readback; result="<<(saved?"original-object":"safe-rejection")<<"; redirected=absent; error="<<error<<"\n";
    }
    unsigned calls=0;rejects_with([&]{detail::save_lex_with_parent_observer(temp_root/L"观察中止.lex",table,
        [](void* c){++*static_cast<unsigned*>(c);throw std::runtime_error("explicit observer abort");},&calls);},"explicit observer abort");
    CHECK(calls==1);io_absent(temp_root/L"观察中止.lex");
    const auto existing=temp_root/L"检查后既有目标.lex",source=temp_root/L"检查后硬链源.lex";save_lex(source,table);const auto before=read_fixture(source);
    struct LateLeaf {const std::filesystem::path* source;const std::filesystem::path* output;unsigned calls=0;} late{&source,&existing};
    rejects_with([&]{detail::save_lex_with_parent_observer(existing,table,[](void* opaque){auto& c=*static_cast<LateLeaf*>(opaque);CHECK(++c.calls==1);CHECK(CreateHardLinkW(c.output->c_str(),c.source->c_str(),nullptr));},&late);},"不能覆盖");
    CHECK(late.calls==1);CHECK(read_fixture(existing)==before);CHECK(read_fixture(source)==before);CHECK(io_path_id(existing,false)==io_path_id(source,false));
    std::cout<<"[identity] "<<checks-start<<" checks; deterministic mutations required, no probabilistic scheduling\n";
}

// 仅替换本测试进程 EXE 的三个导入槽，不改系统 DLL/磁盘/ACL。所有其他线程已 join。
template<class Function> class IoImportPatch {
    ULONG_PTR* slot_=nullptr;ULONG_PTR before_=0;DWORD protection_=0;
public:
    IoImportPatch(const char* name,Function replacement,Function expected) {
        auto* base=reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));CHECK(base!=nullptr);
        const auto* dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(base);CHECK(dos->e_magic==IMAGE_DOS_SIGNATURE);
        const auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS*>(base+dos->e_lfanew);CHECK(nt->Signature==IMAGE_NT_SIGNATURE);
        CHECK(nt->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        const auto directory=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];CHECK(directory.VirtualAddress!=0);
        for(auto* dll=reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base+directory.VirtualAddress);dll->Name && !slot_;++dll) {
            if(!dll->OriginalFirstThunk)continue;
            auto* names=reinterpret_cast<IMAGE_THUNK_DATA*>(base+dll->OriginalFirstThunk);
            auto* functions=reinterpret_cast<IMAGE_THUNK_DATA*>(base+dll->FirstThunk);
            for(;names->u1.AddressOfData;++names,++functions) {
                if(IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal))continue;
                const auto* entry=reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base+names->u1.AddressOfData);
                if(std::string_view(reinterpret_cast<const char*>(entry->Name))==name){slot_=&functions->u1.Function;break;}
            }
        }
        CHECK(slot_!=nullptr);before_=*slot_;CHECK(before_==reinterpret_cast<ULONG_PTR>(expected));
        CHECK(VirtualProtect(slot_,sizeof(*slot_),PAGE_READWRITE,&protection_));
        *slot_=reinterpret_cast<ULONG_PTR>(replacement);DWORD ignored=0;
        if(!VirtualProtect(slot_,sizeof(*slot_),protection_,&ignored)) {
            *slot_=before_;VirtualProtect(slot_,sizeof(*slot_),protection_,&ignored);throw std::runtime_error("无法恢复测试 IAT 页面保护");
        }
    }
    IoImportPatch(const IoImportPatch&)=delete;IoImportPatch& operator=(const IoImportPatch&)=delete;
    bool restore() noexcept {
        if(!slot_)return true;DWORD old=0,ignored=0;
        if(!VirtualProtect(slot_,sizeof(*slot_),PAGE_READWRITE,&old))return false;
        *slot_=before_;const bool ok=VirtualProtect(slot_,sizeof(*slot_),protection_,&ignored)!=FALSE;
        if(ok)slot_=nullptr;return ok;
    }
    ~IoImportPatch(){if(!restore())std::terminate();}
};
const auto io_real_write=&::WriteFile;
const auto io_real_flush=&::FlushFileBuffers;
const auto io_real_disposition=&::SetFileInformationByHandle;
enum class IoFault {partial_write,zero_progress,flush,cleanup_failure};
struct IoFaultState {
    IoFault mode;HANDLE target=nullptr;bool armed=false,created_regular=false,identity_ok=false;
    unsigned observers=0,writes=0,write_faults=0,flush_faults=0,cleanup_calls=0;
    DWORD prefix_written=0;bool prefix_ok=false,cleanup_ok=false,actual_flush_ok=false;
    std::uint64_t real_written=0;LONGLONG size_before=-1,size_at_cleanup=-1;IoObjectId identity{};
};
thread_local IoFaultState* io_active_fault=nullptr;
void io_capture_created(IoFaultState& s,HANDLE h) noexcept {
    s.target=h;BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};
    if(GetFileInformationByHandle(h,&info)) {
        s.identity={info.dwVolumeSerialNumber,info.nFileIndexHigh,info.nFileIndexLow};s.identity_ok=true;
        s.created_regular=!(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT));
    }
    if(GetFileSizeEx(h,&size))s.size_before=size.QuadPart;
}
BOOL WINAPI io_fault_write(HANDLE h,LPCVOID data,DWORD count,LPDWORD written,LPOVERLAPPED overlapped) {
    auto* s=io_active_fault;if(!s || !s->armed)return io_real_write(h,data,count,written,overlapped);
    if(!s->target)io_capture_created(*s,h);if(h!=s->target)return io_real_write(h,data,count,written,overlapped);++s->writes;
    if(s->mode==IoFault::partial_write || s->mode==IoFault::cleanup_failure) {
        s->prefix_ok=io_real_write(h,data,std::min<DWORD>(23,count),&s->prefix_written,overlapped)!=FALSE;
        s->real_written+=s->prefix_written;++s->write_faults;s->armed=false;*written=0;SetLastError(ERROR_DISK_FULL);return FALSE;
    }
    if(s->mode==IoFault::zero_progress){++s->write_faults;s->armed=false;*written=0;return TRUE;}
    const auto ok=io_real_write(h,data,count,written,overlapped);if(ok)s->real_written+=*written;return ok;
}
BOOL WINAPI io_fault_flush(HANDLE h) {
    auto* s=io_active_fault;
    if(s && s->armed && s->mode==IoFault::flush && h==s->target) {
        s->actual_flush_ok=io_real_flush(h)!=FALSE;++s->flush_faults;s->armed=false;SetLastError(ERROR_WRITE_FAULT);return FALSE;
    }
    return io_real_flush(h);
}
BOOL WINAPI io_fault_disposition(HANDLE h,FILE_INFO_BY_HANDLE_CLASS cls,LPVOID data,DWORD length) {
    auto* s=io_active_fault;
    if(s && h==s->target && cls==FileDispositionInfo) {
        ++s->cleanup_calls;LARGE_INTEGER size{};if(GetFileSizeEx(h,&size))s->size_at_cleanup=size.QuadPart;
        if(s->mode==IoFault::cleanup_failure){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
        const auto result=io_real_disposition(h,cls,data,length);s->cleanup_ok=result!=FALSE;return result;
    }
    return io_real_disposition(h,cls,data,length);
}
struct IoFaultArm {
    IoRenameContext rename;IoFaultState state;Bytes decoy;
};
void io_arm_fault(void* opaque) {
    auto& c=*static_cast<IoFaultArm*>(opaque);io_rename_replace(&c.rename);
    // 已验证对象改名后，原路径故意放入同名诱饵；按字符串清理会误删该文件。
    write_bytes(c.rename.parent/L"失败.lex",c.decoy);CHECK(io_active_fault==nullptr);
    ++c.state.observers;c.state.armed=true;io_active_fault=&c.state;
}
struct IoFaultReset {~IoFaultReset(){io_active_fault=nullptr;}};
void io_post_create_tests() {
    const auto start=checks;const Table table{{"a",u"写入故障后不能误删替换路径",1}};const auto complete=write_lex(table);
    IoImportPatch write_patch("WriteFile",&io_fault_write,io_real_write);
    IoImportPatch flush_patch("FlushFileBuffers",&io_fault_flush,io_real_flush);
    IoImportPatch disposition_patch("SetFileInformationByHandle",&io_fault_disposition,io_real_disposition);
    unsigned index=0;
    for(const auto mode:{IoFault::partial_write,IoFault::zero_progress,IoFault::flush,IoFault::cleanup_failure}) {
        const auto label=L"故障"+std::to_wstring(++index);
        IoFaultArm c{{temp_root/(label+L"原路径"),temp_root/(label+L"原对象")},{mode},bytes("replacement-must-survive")};
        CHECK(std::filesystem::create_directory(c.rename.parent));c.rename.original=io_path_id(c.rename.parent,true);
        const auto output=c.rename.moved/L"失败.lex";bool rejected=false,nested=false;std::string error;
        {IoFaultReset reset;
            try{detail::save_lex_with_parent_observer(c.rename.parent/L"失败.lex",table,io_arm_fault,&c);}
            catch(const std::exception& e){rejected=true;error=e.what();try{std::rethrow_if_nested(e);}catch(const std::exception& inner){nested=std::string_view(inner.what()).find("写入 lex 失败")!=std::string_view::npos && std::string_view(inner.what()).find("112")!=std::string_view::npos;}}
        }
        CHECK(rejected);CHECK(io_active_fault==nullptr);CHECK(c.rename.changed && c.rename.calls==1 && c.state.observers==1);
        CHECK(c.state.created_regular && c.state.identity_ok && c.state.size_before==0);CHECK(c.state.writes==1);
        CHECK(c.state.cleanup_calls==1 && !c.state.armed);CHECK(c.state.size_at_cleanup==static_cast<LONGLONG>(c.state.real_written));
        CHECK(read_fixture(c.rename.parent/L"失败.lex")==c.decoy);
        if(mode==IoFault::flush) {
            CHECK(c.state.flush_faults==1 && c.state.write_faults==0 && c.state.actual_flush_ok);
            CHECK(c.state.real_written==complete.size());CHECK(error.find("持久化 lex 失败")!=std::string::npos && error.find("Win32 错误 29")!=std::string::npos);
        } else if(mode==IoFault::zero_progress) {
            CHECK(c.state.write_faults==1 && c.state.flush_faults==0);CHECK(c.state.real_written==0);
            CHECK(error.find("未取得进展")!=std::string::npos);
        } else {
            CHECK(c.state.write_faults==1 && c.state.flush_faults==0);CHECK(c.state.prefix_ok && c.state.prefix_written==23 && c.state.real_written==23);
        }
        if(mode==IoFault::cleanup_failure) {
            CHECK(!c.state.cleanup_ok);CHECK(error.find("无法清理本次半成品")!=std::string::npos && error.find("Win32 错误 5")!=std::string::npos && nested);
            CHECK(io_path_id(output,false)==c.state.identity);CHECK(read_fixture(output)==Bytes(complete.begin(),complete.begin()+23));
            rejects_with([&]{save_lex(output,table);},"不能覆盖");CHECK(DeleteFileW(output.c_str()));
        } else {
            CHECK(c.state.cleanup_ok);CHECK(!nested);io_absent(output);
            if(mode==IoFault::partial_write)CHECK(error.find("写入 lex 失败")!=std::string::npos && error.find("Win32 错误 112")!=std::string::npos);
        }
        // 重新 CREATE_NEW 验证失败句柄已关闭、删除确实完成、注入不会污染下一次公共调用。
        save_lex(output,table);CHECK(read_fixture(output)==complete);CHECK(import_file(output).entries==table);
        CHECK(DeleteFileW(output.c_str()));CHECK(DeleteFileW((c.rename.parent/L"失败.lex").c_str()));
        io_remove_directory(c.rename.parent);io_remove_directory(c.rename.moved);
        std::cout<<"[post-create "<<index<<"] actual-bytes="<<c.state.real_written<<"; cleanup="<<(c.state.cleanup_ok?"owned-object-deleted":"reported-failure+exact-partial-retained")<<"; replacement-decoy=unchanged; error="<<error<<"; nested="<<nested<<"\n";
    }
    CHECK(disposition_patch.restore());CHECK(flush_patch.restore());CHECK(write_patch.restore());
    std::cout<<"[post-create] "<<checks-start<<" checks; scoped EXE-only injected API failures, real output/error/cleanup assertions\n";
}
void io_raw_path_tests() {
    const auto start=checks;const Table table{{"a",u"甲",1}};const auto output=temp_root/L"原始校验.lex";
    for(const auto& raw:{temp_root/L"坏. "/L".."/L"原始校验.lex",temp_root/L"坏."/L".."/L"原始校验.lex",
        temp_root/L"流:stream"/L".."/L"原始校验.lex",temp_root/L"坏?名"/L".."/L"原始校验.lex"}) {
        rejects_with([&]{save_lex(raw,table);},"原始输出路径");io_absent(output);
    }
    for(const auto control:{wchar_t{1},wchar_t{31}}) {
        rejects_with([&]{save_lex(temp_root/(std::wstring(L"控制")+control+L".lex"),table);},"原始输出路径");
    }
    for(const auto& name:{L"CONOUT$.lex",L"COM².foo",L"PRN",L"尾点.",L"尾空格 "}){rejects([&]{save_lex(temp_root/name,table);});}
    rejects_with([&]{save_lex(std::filesystem::path(L"//?/"+output.generic_wstring()),table);},"设备命名空间");
    rejects_with([&]{save_lex(std::filesystem::path(L"\\\\./"+output.generic_wstring()),table);},"设备命名空间");
    unsigned calls=0;rejects([&]{detail::save_lex_with_parent_observer(output,{},[](void* p){++*static_cast<unsigned*>(p);},&calls);});
    CHECK(calls==0);io_absent(output);
    struct CurrentPath {std::filesystem::path original=std::filesystem::current_path();~CurrentPath(){std::error_code e;std::filesystem::current_path(original,e);}} restore;
    std::filesystem::current_path(temp_root);save_lex(std::filesystem::path(L"unused")/L".."/L"规范化相对中文.lex",table);
    CHECK(import_file(temp_root/L"规范化相对中文.lex").entries==table);
    std::cout<<"[raw paths] "<<checks-start<<" checks; raw invalid components cannot disappear through normalization\n";
}
