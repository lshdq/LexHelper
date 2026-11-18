// 独立测试阶段的确定性语义/拒绝断言；由 core_tests.cpp 的既有轻量运行器接入。
// 不读取系统词库、不改 ACL、不复制私人 CWB；本文件中的所有文件均为 temp_root 内合成数据。
template<class F> void rejects_with(F&& f,std::string_view expected,const std::source_location caller=std::source_location::current()) {
    bool thrown=false;
    try{f();}catch(const std::exception& e){thrown=true;check(std::string_view(e.what()).find(expected)!=std::string_view::npos,"exception must identify expected rejection",static_cast<int>(caller.line()));}
    check(thrown,"expected std::exception",static_cast<int>(caller.line()));
}
Bytes read_fixture(const std::filesystem::path& p){
    std::ifstream in(p,std::ios::binary|std::ios::ate);CHECK(in.good());const auto n=in.tellg();CHECK(n>=0);
    Bytes b(static_cast<std::size_t>(n));in.seekg(0);in.read(reinterpret_cast<char*>(b.data()),static_cast<std::streamsize>(b.size()));CHECK(in.good());return b;
}

void lex_boundary_tests(){ // TC-002 / TC-003
    Table all;
    for(char c='z';c>='a';--c)all.push_back({std::string(1,c),std::u16string(1,static_cast<char16_t>(u'甲'+c-'a')),static_cast<std::uint16_t>(c-'a')});
    const auto encoded=write_lex(all);CHECK(encoded.size()==0xa8+26*18);CHECK(get32(encoded,20)==encoded.size());
    const auto decoded=read_lex(encoded);std::reverse(all.begin(),all.end());CHECK(decoded==all);
    for(unsigned i=0;i<26;++i){CHECK(get32(encoded,0x40+4*i)==18*i);CHECK(get16(encoded,0xa8+18*i+6)=='a'+i);auto bad=encoded;set32(bad,0x40+4*i,18*i+1);rejects_with([&]{read_lex(bad);},"索引");}
    const Table expected{{"a",u"甲",0},{"a",u"乙",65535},{"a",u"丙",65535},{"aa",u"甲",9},{"z",u"\U00010000\U0010ffff",1}};
    CHECK(read_lex(write_lex({expected[4],expected[1],expected[0],expected[3],expected[2]}))==expected);
    const auto single=write_lex({{"a",u"甲",1}});
    for(auto [offset,value]:std::vector<std::pair<std::size_t,unsigned>>{{8,0},{8,2},{10,2},{0xa8,0},{0xa8,16},{0xa8,17},{0xa8,65535},{0xac,0},{0xac,5},{0xae,'A'},{0xae,0xff61},{0xb0,1},{0xb6,0},{0xb6,0x7f},{0xb6,0xdc00},{0xb6,0xd800},{0xb8,1}}){auto bad=single;set16(bad,offset,static_cast<std::uint16_t>(value));rejects([&]{read_lex(bad);});}
    for(auto offset:{12u,16u,20u}){auto bad=single;set32(bad,offset,0xffffffff);rejects([&]{read_lex(bad);});}
    {auto bad=write_lex({{"a",u"\U00020000",1}});set16(bad,0xa8+16,u'甲');rejects_with([&]{read_lex(bad);},"代理");}
    {auto bad=write_lex({{"a",u"甲",1},{"b",u"乙",1}});set16(bad,0xa8+18+6,'a');rejects_with([&]{read_lex(bad);},"索引");}
    {auto bad=write_lex({{"a",u"甲",1},{"a",u"乙",2}});set16(bad,0xa8+18+14,u'甲');rejects_with([&]{read_lex(bad);},"重复");}
    for(char16_t control:{char16_t{0},char16_t{9},char16_t{31},char16_t{127}})rejects([&]{write_lex({{"a",std::u16string(1,control),1}});});
    CHECK(read_lex(write_lex({{"zzzz",u"中文 空格",65535}}))==Table({{"zzzz",u"中文 空格",65535}}));
}

void text_boundary_tests(){ // TC-004：独立写出预期候选，不能仅自往返。
    const Table expected{{"a",u"高",1},{"a",u"同频先",2},{"a",u"同频后",3},{"a",u"零",4},{"b",u"另码",1}};
    CHECK(read_text(bytes("# 注释\r\nb\t另码\t5\na\t零\t0\na\t高\t18446744073709551615\na\t同频先\t7\na\t同频后\t7\n"))==expected);
    CHECK(read_text(utf16bom(u"另码\tb\t5\n零\ta\t0\n高\ta\t18446744073709551615\n同频先\ta\t7\n同频后\ta\t7"))==expected);
    CHECK(read_lex(write_lex(expected))==expected);
    CHECK(read_text(bytes("a\t甲\t0000000000000000000000000000000000001"))==Table({{"a",u"甲",1}}));
    CHECK(read_text(bytes("a\t\xf4\x8f\xbf\xbf"))==Table({{"a",u"\U0010ffff",1}}));
    CHECK(read_text(utf16bom(u"a\t\U00010000"))==Table({{"a",u"\U00010000",1}}));
    for(const auto& bad:{"# only comment\n", "\xef\xbb\xbf", "a\t甲\t", "a\t甲\t+1", "a\t甲\t1.0", "a\t甲\t 1", "a\t甲\t１", "a\t甲\t1\t", "a\t", "\t甲", "a\tabcd", "甲\t乙", "A\t甲", "a\t甲\r乙", "a\t甲\x7f", "a\t\xe0\x80\xaf", "a\t\xf0\x80\x80\xaf", "a\t\xe4x\x80", "a\t\xf5\x80\x80\x80"})rejects([&]{read_text(bytes(bad));});
    {auto bad=bytes("a\t甲");bad.push_back(std::byte{0});rejects_with([&]{read_text(bad);},"NUL");}
    rejects([&]{read_text(utf16bom(std::u16string{u'a',u'\t',char16_t{0xdc00}}));});
    rejects([&]{read_text(utf16bom(std::u16string{u'a',u'\t',char16_t{0xd800},u'甲'}));});
    rejects_with([&]{read_text(bytes("#1\n\na\t甲\na\t乙\t2"));},"第 4 行");
    rejects_with([&]{read_text(bytes("a\t甲\t1\n乙\ta\t2"));},"第 2 行");
    rejects_with([&]{read_text(bytes("a\t甲\t1\na\t甲\t99"));},"重复");
    // 坏行在尾部仍整体失败，不返回前面已解析的词条。
    rejects_with([&]{read_text(bytes("a\t甲\na\t乙\nbad"));},"第 3 行");
}

void wbc_boundary_tests(){ // TC-005：物理次序和索引次序必须相互独立。
    const auto raw=wbc({{"b",u"乙",0},{"a",u"先",0},{"a",u"后",0}},{1,2,0});
    const Table expected{{"a",u"先",1},{"a",u"后",2},{"b",u"乙",1}};CHECK(read_wbc3(raw)==expected);
    auto meta=raw;const auto data=get32(raw,0x44);set16(meta,data,65535);set32(meta,data+2,0xffffffff);CHECK(read_wbc3(meta)==expected);
    for(std::size_t n=0;n<raw.size();++n){auto bad=raw;bad.resize(n);rejects([&]{read_wbc3(bad);});}
    for(auto [offset,value]:std::vector<std::pair<std::size_t,std::uint32_t>>{{0x40,0},{0x40,1000001},{0x40,0xffffffff},{0x38,0xffffffff},{0x3c,0xffffffff},{0x44,0xffffffff},{0x48,0xffffffff},{0x8c,1},{0x8c,static_cast<std::uint32_t>(raw.size()-data)}}){auto bad=raw;set32(bad,offset,value);rejects([&]{read_wbc3(bad);});}
    {auto bad=raw;set32(bad,0x8c+4,get32(bad,0x8c));rejects_with([&]{read_wbc3(bad);},"索引");}
    {auto bad=raw;std::swap_ranges(bad.begin()+0x8c,bad.begin()+0x90,bad.begin()+0x94);rejects_with([&]{read_wbc3(bad);},"非升序");}
    const auto one=wbc({{"a",u"甲",0}});const auto start=get32(one,0x44);
    for(auto n:{0u,1u,65535u}){auto bad=one;set16(bad,start+9,static_cast<std::uint16_t>(n));rejects([&]{read_wbc3(bad);});}
    for(auto packed:{26u,31u,1025u}){auto bad=one;bad[start+6]=std::byte(packed&255);bad[start+7]=std::byte((packed>>8)&255);bad[start+8]=std::byte{0};rejects_with([&]{read_wbc3(bad);},"编码");}
    for(auto c:{0u,31u,127u,0xd800u,0xdc00u}){auto bad=one;set16(bad,start+11,static_cast<std::uint16_t>(c));rejects([&]{read_wbc3(bad);});}
    rejects_with([&]{read_wbc3(wbc({{"a",u"甲",0},{"a",u"乙",0},{"a",u"甲",0}}));},"重复");
    for(char version:{'1','2','4'}){auto bad=one;bad[3]=std::byte(version);rejects_with([&]{read_wbc3(bad);},"WBC3");}
}

void candidate_limit_tests(){ // TC-005：65535 的边界必须以候选值断言，而非仅“不崩溃”。
    Table t;t.reserve(65536);
    for(unsigned i=0;i<65536;++i)t.push_back({"a",std::u16string{static_cast<char16_t>(0x4e00+i/256),static_cast<char16_t>(0x4e00+i%256)},0});
    const auto last=t.back();t.pop_back();const auto valid=read_wbc3(wbc(t));CHECK(valid.size()==65535);CHECK(valid.front().weight==1);CHECK(valid.back().weight==65535);
    bool matches=true;for(std::size_t i=0;i<t.size();++i)matches=matches && valid[i].code==t[i].code && valid[i].text==t[i].text && valid[i].weight==i+1;CHECK(matches);
    CHECK(read_lex(write_lex(valid))==valid);t.push_back(last);rejects_with([&]{read_wbc3(wbc(t));},"65535");
}

void zip_boundary_tests(){ // TC-005：每项变异均有具体拒绝断言，压缩炸弹不实际分配巨量内存。
    const auto raw=wbc({{"a",u"甲",0}});const Table expected{{"a",u"甲",1}};const auto source=zip({{"usr/wbCustom3.bin",raw,8}});
    const auto end=source.size()-22;const auto cd=get32(source,end+16);
    for(auto [off,value]:std::vector<std::pair<std::size_t,unsigned>>{{end+4,1},{end+6,1},{end+8,0},{end+8,4097},{cd+28,65535},{cd+30,65535},{cd+32,65535},{cd+34,1},{26,1},{28,65535}}){auto bad=source;set16(bad,off,static_cast<std::uint16_t>(value));rejects([&]{read_cwb(bad);});}
    for(auto [off,value]:std::vector<std::pair<std::size_t,std::uint32_t>>{{end+12,0xffffffff},{end+16,0xffffffff},{cd,0},{cd+20,0xffffffff},{cd+24,0xffffffff},{cd+42,cd},{cd+42,cd-1},{18,0xffffffff},{14,0}}){auto bad=source;set32(bad,off,value);rejects([&]{read_cwb(bad);});}
    for(auto flags:{1u,16u,64u}){auto bad=source;set16(bad,6,static_cast<std::uint16_t>(flags));set16(bad,cd+8,static_cast<std::uint16_t>(flags));rejects_with([&]{read_cwb(bad);},"标志");}
    {auto good=source;set16(good,6,0x800);set16(good,cd+8,0x800);CHECK(read_cwb(good)==expected);}
    {auto bad=source;set16(bad,8,99);set16(bad,cd+10,99);rejects_with([&]{read_cwb(bad);},"store / deflate");}
    {auto bad=source;bad[30]=std::byte{'x'};rejects_with([&]{read_cwb(bad);},"本地名");}
    {auto bad=source;bad[30]=std::byte{0};bad[cd+46]=std::byte{0};rejects_with([&]{read_cwb(bad);},"NUL");}
    for(auto mode:{0120000u,0040000u,0010000u}){auto bad=source;set32(bad,cd+38,mode<<16);rejects_with([&]{read_cwb(bad);},"普通");}
    for(auto name:{"usr/WBCustom3.bin","USR/wbCustom3.bin","usr\\wbCustom3.bin","usr/./wbCustom3.bin","../usr/wbCustom3.bin"})rejects([&]{read_cwb(zip({{name,raw,0}}));});
    // 两份同名无关条目可使本地头/CRC全部自洽，却重复引用同一物理区间。
    {auto bad=zip({{"f",bytes("same"),0},{"f",bytes("same"),0},{"usr/wbCustom3.bin",raw,8}});const auto dir=get32(bad,bad.size()-6);set32(bad,dir+47+42,0);rejects_with([&]{read_cwb(bad);},"重叠");}
    // 无关载荷不解压：故意损坏的 deflate 仍只导入规范 WBC3，不打印/落盘无关内容。
    CHECK(read_cwb(zip({{"private-unrelated",bytes("ignored"),8,Bytes{std::byte{7}}},{"usr/wbCustom3.bin",raw,0}}))==expected);
    {auto bad=source;set32(bad,cd+16,crc32(raw)^1);set32(bad,14,crc32(raw)^1);rejects_with([&]{read_cwb(bad);},"CRC 校验");}
    {auto extra=deflate_fixed(raw);extra.push_back(std::byte{0});rejects_with([&]{read_cwb(zip({{"usr/wbCustom3.bin",raw,8,extra}}));},"deflate");}
    for(auto size:{static_cast<std::uint32_t>(raw.size()-1),static_cast<std::uint32_t>(raw.size()+1)}){auto bad=source;set32(bad,cd+24,size);set32(bad,22,size);rejects_with([&]{read_cwb(bad);},"deflate");}
    for(auto size:{65u*1024*1024,get32(source,cd+20)*1000+1}){auto bad=source;set32(bad,cd+24,size);set32(bad,22,size);rejects_with([&]{read_cwb(bad);},"膨胀");}
    {auto bad=zip({{"ignored",bytes("x"),0},{"usr/wbCustom3.bin",raw,8}});const auto dir=get32(bad,bad.size()-6);set32(bad,dir+24,512u*1024*1024+1);set32(bad,22,512u*1024*1024+1);rejects_with([&]{read_cwb(bad);},"512 MiB");}
    {auto bad=source;set32(bad,cd+20,cd-47+1);set32(bad,18,cd-47+1);rejects_with([&]{read_cwb(bad);},"覆盖中央目录");}
    const auto descriptor=zip({{"usr/wbCustom3.bin",raw,8}},true);const auto dcd=get32(descriptor,descriptor.size()-6);
    for(auto off:{dcd-12,dcd-8,dcd-4}){auto bad=descriptor;set32(bad,off,get32(bad,off)^1);rejects_with([&]{read_cwb(bad);},"描述符");}
    {auto bad=descriptor;set32(bad,14,crc32(raw)^1);rejects_with([&]{read_cwb(bad);},"延迟");}
    {auto good=descriptor;good.erase(good.begin()+dcd-16,good.begin()+dcd-12);set32(good,good.size()-6,dcd-4);CHECK(read_cwb(good)==expected);}
    {auto good=source;set16(good,end+20,5);ascii(good,"hello");CHECK(read_cwb(good)==expected);}
    {auto bad=source;bad.push_back(std::byte{0});rejects_with([&]{read_cwb(bad);},"结尾");}
}

void input_size_limit_tests(){ // TC-003/004/005：分配单个有界内存缓冲区，不制造磁盘耗尽。
    Bytes oversized(128u*1024*1024+1);
    rejects_with([&]{read_lex(oversized);},"长度");rejects_with([&]{read_wbc3(oversized);},"长度");
    rejects_with([&]{read_cwb(oversized);},"长度");rejects_with([&]{read_text(oversized);},"128 MiB");
    oversized.resize(64u*1024*1024+1);rejects_with([&]{read_wbc3(oversized);},"长度");
}

struct FixtureHandleClose{void operator()(void* h)const noexcept{if(h && h!=INVALID_HANDLE_VALUE)CloseHandle(h);}};
using FixtureHandle=std::unique_ptr<void,FixtureHandleClose>;
void io_boundary_tests(){ // TC-007：只在合成临时路径测试 alias、CREATE_NEW、联接与竞争。
    const Table original{{"a",u"甲",1}},other{{"b",u"乙",1}};const auto p=temp_root/L"AliasSource.lex";save_lex(p,original);const auto before=read_fixture(p);
    for(const auto& alias:{temp_root/L"aliassource.LEX",temp_root/L"."/L"AliasSource.lex",temp_root/L"unused"/L".."/L"AliasSource.lex"}){rejects([&]{save_lex(alias,other);});CHECK(read_fixture(p)==before);}
    const auto hard=temp_root/L"自有文件硬链接.lex";CHECK(CreateHardLinkW(hard.c_str(),p.c_str(),nullptr));rejects([&]{save_lex(hard,other);});CHECK(read_fixture(hard)==before);CHECK(read_fixture(p)==before);
    for(const auto& name:{L"AUX.txt",L"LPT³.lex",L"CONIN$.lex",L"尾随点.lex.",L"a?b.lex",L"a|b.lex",L"a<b.lex"})rejects([&]{save_lex(temp_root/name,original);});
    rejects([&]{save_lex(std::filesystem::path{},original);});rejects([&]{save_lex(std::filesystem::path(L"\\\\?\\"+p.native()),original);});
    rejects([&]{save_lex(std::filesystem::path(p.native()+std::wstring(1,L'\0')+L"tail"),original);});
    {FixtureHandle locked(CreateFileW(p.c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));CHECK(locked.get()!=INVALID_HANDLE_VALUE);rejects([&]{import_file(p);});rejects([&]{save_lex(p,other);});}CHECK(read_fixture(p)==before);
    // 多种候选争抢同一新路径：只能一个完整文件获胜，不能拼接、覆盖或留下零长成功文件。
    for(unsigned iteration=0;iteration<8;++iteration){const auto race=temp_root/(L"争抢-"+std::to_wstring(iteration)+L".lex");std::barrier start(8);std::atomic<int> success=0;std::vector<std::thread> threads;std::array<Table,8> alternatives;
        for(unsigned i=0;i<8;++i)alternatives[i]={{std::string(1,static_cast<char>('a'+i)),std::u16string(100+i,static_cast<char16_t>(u'甲'+i)),static_cast<std::uint16_t>(i)}};
        for(unsigned i=0;i<8;++i)threads.emplace_back([&,i]{start.arrive_and_wait();try{save_lex(race,alternatives[i]);++success;}catch(const std::exception&) {}});
        for(auto& thread:threads)thread.join();CHECK(success==1);const auto winner=import_file(race).entries;CHECK(std::count(alternatives.begin(),alternatives.end(),winner)==1);CHECK(read_fixture(race)==write_lex(winner));
    }
    for(const auto& version:{"WBC1","WBC2"}){auto bad=bytes(version);const auto file=temp_root/(std::wstring(version,version+4)+L".bin");write_bytes(file,bad);rejects_with([&]{import_file(file);},"非新世纪");CHECK(read_fixture(file)==bad);}
    const auto direct=temp_root/L"直接码表.bin";write_bytes(direct,wbc(original));CHECK(import_file(direct).entries==original);
    // 目录 junction 不需要符号链接特权；使用本任务普通目录作为目标，从不指向系统路径。
    const auto link=temp_root/L"自有目录联接";CHECK(std::filesystem::create_directory(link));
    struct MountPointBuffer{DWORD tag;WORD length,reserved,sub_offset,sub_length,print_offset,print_length;wchar_t paths[2048];} buffer{};
    const auto substitute=L"\\??\\"+temp_root.native();const auto print=temp_root.native();CHECK(substitute.size()+print.size()+2<std::size(buffer.paths));
    buffer.tag=IO_REPARSE_TAG_MOUNT_POINT;buffer.sub_length=static_cast<WORD>(substitute.size()*2);buffer.print_offset=static_cast<WORD>((substitute.size()+1)*2);buffer.print_length=static_cast<WORD>(print.size()*2);
    std::copy(substitute.begin(),substitute.end(),buffer.paths);std::copy(print.begin(),print.end(),buffer.paths+substitute.size()+1);buffer.length=static_cast<WORD>(8+(substitute.size()+print.size()+2)*2);
    DWORD error=0;bool linked=false;
    {FixtureHandle h(CreateFileW(link.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
        if(h.get()!=INVALID_HANDLE_VALUE){DWORD returned=0;linked=DeviceIoControl(h.get(),FSCTL_SET_REPARSE_POINT,&buffer,buffer.length+8,nullptr,0,&returned,nullptr)!=FALSE;if(!linked)error=GetLastError();}else error=GetLastError();}
    if(linked){CHECK(GetFileAttributesW(link.c_str())&FILE_ATTRIBUTE_REPARSE_POINT);rejects_with([&]{save_lex(link/L"junction-forbidden.lex",original);},"禁止目录联接");CHECK(!std::filesystem::exists(temp_root/L"junction-forbidden.lex"));}
    else{skip("当前文件系统/令牌不允许创建测试目录联接");std::cout<<"[junction] Win32="<<error<<"\n";}
    CHECK(link.lexically_normal().parent_path()==temp_root);CHECK(RemoveDirectoryW(link.c_str()));CHECK(read_fixture(p)==before);
    // 后创建故障由 core_io_identity_tests.inc 定向注入；不耗尽磁盘或修改 ACL。
}
