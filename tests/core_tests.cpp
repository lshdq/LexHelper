#include <windows.h>
#include <winioctl.h>
#include "lexhelper/core.hpp"
#include "../src/core/io_test.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <numeric>
#include <random>
#include <source_location>
#include <stdexcept>
#include <thread>

// 自有轻量测试运行器：无外部框架，不跳过失败；完整保留测试源码。
namespace {
using namespace lexhelper;
using Bytes=std::vector<std::byte>;
int checks=0;
int skipped=0;
void skip(const char* reason){++skipped;std::cout<<"[skip] "<<reason<<"\n";}
void check(bool b,const char* expression,int line) {++checks;if(!b)throw std::runtime_error(std::string("断言失败 @")+std::to_string(line)+": "+expression);}
#define CHECK(...) check((__VA_ARGS__),#__VA_ARGS__,__LINE__)
template<class F> void rejects(F&& f,const std::source_location caller=std::source_location::current()) {bool thrown=false;try{f();}catch(const std::exception&){thrown=true;}check(thrown,"expected std::exception",static_cast<int>(caller.line()));}
void set16(Bytes& b,std::size_t p,std::uint16_t v){b.at(p)=std::byte(v&255);b.at(p+1)=std::byte(v>>8);}
void set32(Bytes& b,std::size_t p,std::uint32_t v){set16(b,p,static_cast<std::uint16_t>(v));set16(b,p+2,static_cast<std::uint16_t>(v>>16));}
std::uint16_t get16(const Bytes& b,std::size_t p){return static_cast<std::uint16_t>(std::to_integer<unsigned>(b.at(p))|(std::to_integer<unsigned>(b.at(p+1))<<8));}
std::uint32_t get32(const Bytes& b,std::size_t p){return get16(b,p)|(static_cast<std::uint32_t>(get16(b,p+2))<<16);}
void add16(Bytes& b,std::uint16_t v){auto p=b.size();b.resize(p+2);set16(b,p,v);}
void add32(Bytes& b,std::uint32_t v){auto p=b.size();b.resize(p+4);set32(b,p,v);}
void ascii(Bytes& b,std::string_view s){for(auto c:s)b.push_back(std::byte(c));}
Bytes bytes(std::string_view s){Bytes b;ascii(b,s);return b;}
Bytes utf16bom(std::u16string_view s){Bytes b;add16(b,0xfeff);for(auto c:s)add16(b,c);return b;}
std::uint32_t crc32(const Bytes& b){std::uint32_t c=0xffffffff;for(auto v:b){c^=std::to_integer<unsigned char>(v);for(int i=0;i<8;++i)c=(c>>1)^(0xedb88320u&(0u-(c&1)));}return ~c;}

Bytes wbc(const Table& physical,const std::vector<unsigned>& indices={}) {
    Bytes b(0x8c+4*physical.size());
    b[0]=std::byte('W');b[1]=std::byte('B');b[2]=std::byte('C');b[3]=std::byte('3');
    std::vector<std::uint32_t> offsets;const auto start=static_cast<std::uint32_t>(b.size());
    for(const auto& e:physical){offsets.push_back(static_cast<std::uint32_t>(b.size()-start));add16(b,7);add32(b,123456);std::uint32_t c=0x400000,v=0;for(auto a:e.code)v=(v<<5)|static_cast<unsigned>(a-'a'+1);c|=v;b.push_back(std::byte(c&255));b.push_back(std::byte((c>>8)&255));b.push_back(std::byte(c>>16));add16(b,static_cast<std::uint16_t>(2*e.text.size()));for(auto t:e.text)add16(b,t);}
    set32(b,0x10,static_cast<std::uint32_t>(b.size()));set32(b,0x38,0x8c);set32(b,0x3c,static_cast<std::uint32_t>(4*physical.size()));set32(b,0x40,static_cast<std::uint32_t>(physical.size()));set32(b,0x44,start);set32(b,0x48,static_cast<std::uint32_t>(b.size()-start));set32(b,0x4c,static_cast<std::uint32_t>(b.size()-start));
    for(std::size_t i=0;i<physical.size();++i)set32(b,0x8c+4*i,offsets.at(indices.empty()?i:indices.at(i)));
    return b;
}
struct BitWriter {
    Bytes b;unsigned bit=0;
    void put(unsigned value,unsigned n){for(unsigned i=0;i<n;++i){if(!bit)b.push_back(std::byte{0});if(value&(1u<<i))b.back()|=std::byte(1u<<bit);bit=(bit+1)%8;}}
    void huffman(unsigned value,unsigned n){unsigned reversed=0;for(unsigned i=0;i<n;++i)reversed=(reversed<<1)|((value>>i)&1);put(reversed,n);}
};
Bytes deflate_fixed(const Bytes& raw) {
    BitWriter w;w.put(1,1);w.put(1,2); // BFINAL=1, BTYPE=fixed
    for(auto v:raw){const unsigned c=std::to_integer<unsigned>(v);if(c<=143)w.huffman(0x30+c,8);else w.huffman(0x190+c-144,9);}
    w.huffman(0,7);return w.b; // end-of-block symbol 256
}
Bytes deflate_stored(const Bytes& raw){CHECK(raw.size()<65536);Bytes b{std::byte{1}};add16(b,static_cast<std::uint16_t>(raw.size()));add16(b,static_cast<std::uint16_t>(~raw.size()));b.insert(b.end(),raw.begin(),raw.end());return b;}
struct ZipEntry {std::string name;Bytes raw;int compression=0;Bytes compressed_override;};
Bytes zip(const std::vector<ZipEntry>& entries,bool descriptor=false) {
    Bytes b;struct Meta{const ZipEntry* e;Bytes compressed;std::uint32_t offset,crc;};std::vector<Meta> ms;
    for(const auto& e:entries){Meta m{&e,!e.compressed_override.empty()?e.compressed_override:(e.compression==0?e.raw:(e.compression==8?deflate_fixed(e.raw):deflate_stored(e.raw))),static_cast<std::uint32_t>(b.size()),crc32(e.raw)};const auto flags=descriptor?8:0;
        add32(b,0x04034b50);add16(b,20);add16(b,static_cast<std::uint16_t>(flags));add16(b,e.compression==0?0:8);add32(b,0);add32(b,descriptor?0:m.crc);add32(b,descriptor?0:static_cast<std::uint32_t>(m.compressed.size()));add32(b,descriptor?0:static_cast<std::uint32_t>(e.raw.size()));add16(b,static_cast<std::uint16_t>(e.name.size()));add16(b,0);ascii(b,e.name);b.insert(b.end(),m.compressed.begin(),m.compressed.end());
        if(descriptor){add32(b,0x08074b50);add32(b,m.crc);add32(b,static_cast<std::uint32_t>(m.compressed.size()));add32(b,static_cast<std::uint32_t>(e.raw.size()));}ms.push_back(std::move(m));}
    const auto cd=static_cast<std::uint32_t>(b.size());
    for(const auto& m:ms){const auto& e=*m.e;add32(b,0x02014b50);add16(b,20);add16(b,20);add16(b,descriptor?8:0);add16(b,e.compression==0?0:8);add32(b,0);add32(b,m.crc);add32(b,static_cast<std::uint32_t>(m.compressed.size()));add32(b,static_cast<std::uint32_t>(e.raw.size()));add16(b,static_cast<std::uint16_t>(e.name.size()));add16(b,0);add16(b,0);add16(b,0);add16(b,0);add32(b,0);add32(b,m.offset);ascii(b,e.name);}
    const auto cdsize=static_cast<std::uint32_t>(b.size()-cd);add32(b,0x06054b50);add16(b,0);add16(b,0);add16(b,static_cast<std::uint16_t>(ms.size()));add16(b,static_cast<std::uint16_t>(ms.size()));add32(b,cdsize);add32(b,cd);add16(b,0);return b;
}

std::filesystem::path temp_root;
void write_bytes(const std::filesystem::path& p,const Bytes& b){std::ofstream f(p,std::ios::binary);CHECK(f.good());f.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(b.size()));CHECK(f.good());}
void lex_tests(){
    Table t{{"trxy",u"我",10},{"a",u"工",2},{"a",u"一",1},{"z",u"\U00020000词",0},{"aa",u"恭敬",1}};
    const auto out=write_lex(t);const auto result=read_lex(out);CHECK(result.size()==5);CHECK(result[0].text==u"一");CHECK(result[1].text==u"工");CHECK(write_lex(result)==out);CHECK(write_lex(t)==out);CHECK(get16(out,8)==1);CHECK(get16(out,10)==1);
    CHECK(write_lex({{"a",u"甲",1},{"a",u"乙",1}})!=write_lex({{"a",u"乙",1},{"a",u"甲",1}}));
    rejects([]{write_lex({});});rejects([]{write_lex({{"",u"甲",0}});});rejects([]{write_lex({{"abcde",u"甲",0}});});rejects([]{write_lex({{"A",u"甲",0}});});rejects([]{write_lex({{"a",u"",0}});});rejects([]{write_lex({{"a",std::u16string(1,0xd800),0}});});rejects([]{write_lex({{"a",std::u16string(1,0xdc00),0}});});rejects([]{write_lex({{"a",std::u16string(1,0),0}});});rejects([]{write_lex({{"a",std::u16string(32760,u'甲'),0}});});rejects([]{write_lex({{"a",u"甲",0},{"a",u"甲",1}});});
    const auto long_lex=write_lex({{"a",std::u16string(32759,u'甲'),65535}});CHECK(read_lex(long_lex)[0].text.size()==32759);
    for(std::size_t n=0;n<out.size();++n){auto bad=out;bad.resize(n);rejects([&]{read_lex(bad);});}
    for(auto offset:{0u,8u,10u,12u,16u,20u,24u,64u,164u,168u,172u,176u}){auto bad=out;bad[offset]^=std::byte{0x80};rejects([&]{read_lex(bad);});}
    {auto bad=out;bad.push_back(std::byte{0});rejects([&]{read_lex(bad);});}
    {auto bad=write_lex({{"a",u"甲",1},{"a",u"乙",2}});set16(bad,0xa8+18+2,0);rejects([&]{read_lex(bad);});}
    {auto bad=out;set16(bad,0xa8+14,0xd800);rejects([&]{read_lex(bad);});}
}
void text_tests(){
    auto t=read_text(bytes("\xef\xbb\xbf# 注释\r\na\t甲\t1\r\na\t乙\t99\r\ntrxy\t我\t18446744073709551615\n"));CHECK(t.size()==3);CHECK(t[0].text==u"乙" && t[0].weight==1);CHECK(t[1].text==u"甲" && t[1].weight==2);
    auto reversed=read_text(utf16bom(u"甲\ta\t1\n乙\ta\t99\n我\ttrxy\t18446744073709551615"));CHECK(t==reversed);
    CHECK(read_text(bytes("a\t甲\na\t乙"))[0].text==u"甲");CHECK(read_text(bytes("甲\ta\n乙\ta"))[1].text==u"乙");CHECK(read_text(bytes("a\t\xf0\xa0\x80\x80"))[0].text==u"\U00020000");
    for(const auto& s:{"", "a 甲", "a\tab", "a\t甲\t-1", "a\t甲\t18446744073709551616", "a\t甲\t1\textra", "a\t甲\na\t乙\t1", "a\t甲\n乙\ta", "a\t甲\na\t甲", "abcdx\t甲", "a\t\xc0\xaf", "a\t\xed\xa0\x80", "a\t\xf4\x90\x80\x80", "a\t\xe4\xb8", "a\t\x80"})rejects([&]{read_text(bytes(s));});
    {auto b=utf16bom(u"a\t甲");b.pop_back();rejects([&]{read_text(b);});}
    {auto b=utf16bom(u"a\t甲");b[0]=std::byte{0xfe};b[1]=std::byte{0xff};rejects([&]{read_text(b);});}
    {auto b=utf16bom(u"a\t甲");set16(b,b.size()-2,0xd800);rejects([&]{read_text(b);});}
    try{read_text(bytes("#x\na\t甲\nbad"));CHECK(false);}catch(const std::exception& e){CHECK(std::string(e.what()).find("3")!=std::string::npos);}
}
void wbc_zip_tests(){
    const auto raw=wbc({{"aaaa",u"工",0},{"a",u"工",0},{"aaaa",u"劳斯莱斯",0}},{1,2,0});
    const auto t=read_wbc3(raw);CHECK(t.size()==3);CHECK(t[1].text==u"劳斯莱斯");CHECK(t[2].text==u"工");CHECK(t[1].weight==1 && t[2].weight==2);CHECK(read_lex(write_lex(t))==t);
    for(int method:{0,8,9})for(bool descriptor:{false,true})CHECK(read_cwb(zip({{"usr/wbCustom1.bin",bytes("WBC1"),0},{"usr/wbCustom3.bin",raw,method}},descriptor))==t);
    {
        // 构造动态 Huffman fixture：开发时 .NET DeflateStream 生成压缩字节，测试运行不依赖 .NET。
        std::u16string text;for(unsigned i=0;i<900;++i)text.push_back(static_cast<char16_t>(0x4e00+(i*17)%71));
        auto fixture=wbc({{"a",text,0}});std::fill(fixture.begin()+144,fixture.begin()+150,std::byte{0});fixture[152]=std::byte{0};
        constexpr std::string_view hex="EDD5395242611045E17E883C9C075404549C6770409C4710C32F655306EEC18D1A98181A5846FFA9EABCEBD6EDD3C35EBF133FF8CCE357BC47443122B288F888884AFE3D7F431651CEC39C4D1DAFA6359D7A316145CBA3B29A4377462DD973ADA0625BD79B591BCEF54D5973E2D9B886630F72CB0EDC2A5AB4EB4A66DE960B0333D69DE999B4AAEDC998BA23F74AAAF6DD18B160C7A5B44DCA26F526DD54F24D7271F55F3FC317";
        Bytes compressed;for(std::size_t i=0;i<hex.size();i+=2){auto nibble=[](char c){return c<='9'?c-'0':c-'A'+10;};compressed.push_back(std::byte((nibble(hex[i])<<4)|nibble(hex[i+1])));}
        const auto dynamic_zip=zip({{"usr/wbCustom3.bin",fixture,8,compressed}});CHECK(read_cwb(dynamic_zip)==Table({{"a",text,1}}));
    }
    for(auto offset:{0u,16u,56u,60u,64u,68u,72u,76u}){auto bad=raw;bad[offset]^=std::byte{0x80};rejects([&]{read_wbc3(bad);});}
    {auto bad=raw;set32(bad,0x8c,0xffffffff);rejects([&]{read_wbc3(bad);});}
    {auto bad=raw;set32(bad,0x8c+4,0);set32(bad,0x8c+8,0);rejects([&]{read_wbc3(bad);});}
    rejects([&]{read_wbc3(wbc({{"b",u"甲",0},{"a",u"乙",0}}));});
    rejects([&]{read_wbc3(wbc({{"a",u"甲",0},{"a",u"甲",0}}));});
    {auto bad=wbc({{"a",u"甲",0}});bad[0x90+6]=std::byte{0};bad[0x90+7]=std::byte{0};bad[0x90+8]=std::byte{0};rejects([&]{read_wbc3(bad);});}
    {auto bad=raw;bad.pop_back();rejects([&]{read_wbc3(bad);});}
    const auto archive=zip({{"usr/wbCustom3.bin",raw,8}});
    for(std::size_t n=0;n<archive.size();++n){auto bad=archive;bad.resize(n);rejects([&]{read_cwb(bad);});}
    rejects([&]{read_cwb(zip({{"usr/wbCustom1.bin",raw,0}}));});
    rejects([&]{read_cwb(zip({{"usr/wbCustom3.bin",raw,0},{"usr/wbCustom3.bin",raw,0}}));});
    rejects([&]{read_cwb(zip({{"usr\\wbCustom3.bin",raw,0}}));});
    rejects([&]{read_cwb(zip({{"usr/wbcustom3.bin",raw,0}}));});
    {auto bad=zip({{"usr/wbCustom3.bin",raw,0}});bad[30+17+4]^=std::byte{1};rejects([&]{read_cwb(bad);});}
    {auto bad=archive;set16(bad,6,1);rejects([&]{read_cwb(bad);});}
    {auto bad=archive;set32(bad,bad.size()-6,0xffffffff);rejects([&]{read_cwb(bad);});}
    {auto bad=archive;const auto cd=bad.size()-22-46-17;set32(bad,cd+24,65u*1024*1024);rejects([&]{read_cwb(bad);});}
    {auto bad=archive;const auto cd=bad.size()-22-46-17;set32(bad,cd+38,0x10);rejects([&]{read_cwb(bad);});}
    {auto bad=archive;const auto cd=bad.size()-22-46-17;set32(bad,cd+16,0);set32(bad,14,0);rejects([&]{read_cwb(bad);});}
    {auto bad=zip({{"usr/wbCustom3.bin",raw,8}},true);const auto cd=bad.size()-22-46-17;set32(bad,cd-8,0);rejects([&]{read_cwb(bad);});}
    {auto bad=archive;bad[30+17]=std::byte{7};rejects([&]{read_cwb(bad);});}
    {auto bad=zip({{"unrelated.bin",bytes("not imported"),0},{"usr/wbCustom3.bin",raw,8}});bad[0]=std::byte{0};rejects([&]{read_cwb(bad);});}
    std::vector<std::thread> threads;std::atomic<int> successes=0;
    for(int i=0;i<8;++i)threads.emplace_back([&]{try{for(int n=0;n<20;++n)if(read_cwb(archive)==t)++successes;}catch(const std::exception&) {}});
    for(auto& thread:threads)thread.join();CHECK(successes==160);
    // 有界确定性变异健壮性检查：结果可以拒绝或成功，但成功必须可往返。
    std::mt19937 rng(20261117);
    for(int i=0;i<400;++i){auto bad=(i%2)?archive:raw;const auto p=rng()%bad.size();bad[p]^=std::byte(1u<<(rng()%8));Table parsed;try{parsed=(i%2)?read_cwb(bad):read_wbc3(bad);}catch(const std::exception&) {continue;}CHECK(read_lex(write_lex(parsed))==parsed);}
}
void io_tests(){
    const Table t{{"a",u"甲",1}};auto p=temp_root/L"核心输出-中文.lex";save_lex(p,t);CHECK(import_file(p).entries==t);const auto size=std::filesystem::file_size(p);rejects([&]{save_lex(p,{{"b",u"乙",1}});});CHECK(std::filesystem::file_size(p)==size);CHECK(import_file(p).entries==t);
    rejects([&]{import_file(std::filesystem::path(p.native()+std::wstring(1,L'\0')+L"ignored"));});
    rejects([&]{save_lex(temp_root,t);});
    rejects([&]{save_lex(temp_root/L"不存在"/L"输出.lex",t);});
    rejects([&]{save_lex(temp_root/L"NUL.lex",t);});
    rejects([&]{save_lex(temp_root/L"NUL .lex",t);});
    rejects([&]{save_lex(temp_root/L"COM¹.lex",t);});
    rejects([&]{save_lex(temp_root/L"输出.lex:stream",t);});
    rejects([&]{save_lex(temp_root/L"尾随.lex ",t);});
    rejects([&]{save_lex(temp_root/L"坏表.lex",{});});CHECK(!std::filesystem::exists(temp_root/L"坏表.lex"));
    auto text=temp_root/L"源表-中文.txt";write_bytes(text,bytes("a\t甲"));CHECK(import_file(text).entries==t);rejects([&]{save_lex(text,t);});CHECK(import_file(text).entries==t);
    auto cwb=temp_root/L"合成.CWB";write_bytes(cwb,zip({{"usr/wbCustom3.bin",wbc(t),8}}));CHECK(import_file(cwb).entries==t);
    const auto truncated=temp_root/L"损坏.CWB";write_bytes(truncated,bytes("PKbroken"));rejects([&]{import_file(truncated);});
    CHECK(SetFileAttributesW(p.c_str(),FILE_ATTRIBUTE_READONLY));rejects([&]{save_lex(p,t);});CHECK(SetFileAttributesW(p.c_str(),FILE_ATTRIBUTE_NORMAL));
    const auto race=temp_root/L"并发创建.lex";std::atomic<int> created=0;
    std::thread one([&]{try{save_lex(race,t);++created;}catch(const std::exception&) {}});
    std::thread two([&]{try{save_lex(race,t);++created;}catch(const std::exception&) {}});
    one.join();two.join();CHECK(created==1);CHECK(import_file(race).entries==t);
    auto link=temp_root/L"链接目录";
    if(CreateSymbolicLinkW(link.c_str(),temp_root.c_str(),SYMBOLIC_LINK_FLAG_DIRECTORY|SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        rejects([&]{save_lex(link/L"禁止写入.lex",t);});CHECK(!std::filesystem::exists(temp_root/L"禁止写入.lex"));CHECK(RemoveDirectoryW(link.c_str()));
    } else skip("当前令牌未允许创建目录符号链接；另有目录联接补测");
    link=temp_root/L"链接输入.lex";
    if(CreateSymbolicLinkW(link.c_str(),p.c_str(),SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        rejects([&]{import_file(link);});rejects([&]{save_lex(link,t);});CHECK(DeleteFileW(link.c_str()));
    } else skip("当前令牌未允许创建文件符号链接；未更改权限");
}
#include "core_boundary_tests.inc"
#include "core_io_identity_tests.inc"
#include "core_import_detection_tests.inc"
#include "core_multitext_tests.inc"
#include "core_multitext_independent_tests.inc"
#include "core_gb2312_priority_tests.inc"
#include "core_gb2312_independent_tests.inc"
void sample_test(){
    wchar_t* env=nullptr;std::size_t length=0;CHECK(_wdupenv_s(&env,&length,L"LEXHELPER_CWB_SAMPLE")==0);
    std::unique_ptr<wchar_t,decltype(&std::free)> owner(env,&std::free);
    if(!env || !*env){skip("LEXHELPER_CWB_SAMPLE 未设置，未读取私人样本");return;}
    const auto input=import_file(env);CHECK(input.entries.size()==70870);std::array<std::size_t,5> counts{};bool me=false;
    for(const auto& e:input.entries){++counts.at(e.code.size());if(e.code=="trxy" && e.text==u"我")me=true;}
    CHECK((counts==std::array<std::size_t,5>{0,49,608,3408,66805}));CHECK(me);
    const auto compiled=write_lex(input.entries);CHECK(read_lex(compiled)==input.entries);auto output=temp_root/L"私人样本往返.lex";save_lex(output,input.entries);CHECK(import_file(output).entries==input.entries);std::cout<<"[sample] 70870 entries; 49/608/3408/66805; full semantic roundtrip OK\n";
}
}
int main(){
    SetConsoleOutputCP(CP_UTF8);
    try {
        const auto approved=std::filesystem::path(L"D:\\temp\\aiRunner\\opencode");
        // 独立测试可通过本进程 TEMP/TMP 隔离产物；不接受 C 盘或批准根外的临时位置。
        auto base=approved;std::array<wchar_t,32768> temporary{};const auto n=GetTempPathW(static_cast<DWORD>(temporary.size()),temporary.data());
        if(n && n<temporary.size()) {
            auto candidate=std::filesystem::path(temporary.data()).lexically_normal();if(candidate.filename().empty())candidate=candidate.parent_path();
            const auto prefix=approved.native()+L"\\";const auto value=candidate.native();
            if(value.size()>prefix.size() && CompareStringOrdinal(value.c_str(),static_cast<int>(prefix.size()),prefix.c_str(),static_cast<int>(prefix.size()),TRUE)==CSTR_EQUAL)base=candidate;
        }
        CHECK(std::filesystem::is_directory(base));const auto base_attributes=GetFileAttributesW(base.c_str());CHECK(base_attributes!=INVALID_FILE_ATTRIBUTES && !(base_attributes&FILE_ATTRIBUTE_REPARSE_POINT));
        temp_root=base/(L"lexhelper-core-tests-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64()));CHECK(std::filesystem::create_directory(temp_root));
        int failed=0;
        for(const auto& [name,test]:std::vector<std::pair<const char*,std::function<void()>>>{
            {"lex",lex_tests},{"text",text_tests},{"wbc/zip",wbc_zip_tests},{"io",io_tests},
            {"lex-boundaries TC002/003",lex_boundary_tests},{"text-boundaries TC004",text_boundary_tests},
            {"wbc-boundaries TC005",wbc_boundary_tests},{"candidate-limit TC005",candidate_limit_tests},
            {"zip-boundaries TC005",zip_boundary_tests},{"input-limits TC003/004/005",input_size_limit_tests},
            {"io-boundaries TC007",io_boundary_tests},{"io-identity CORE-001/TC007",io_identity_tests},
            {"io-post-create TC007",io_post_create_tests},{"io-raw-paths TC007",io_raw_path_tests},
            {"import-marker-text CORE-002/TC004",import_marker_text_tests},{"import-binary TC002/003/005",import_binary_detection_tests},
            {"import-type-conflicts TC003/004/005",import_type_conflict_tests},{"import-strict-rejections TC003/004/005",import_invalid_text_tests},
            {"multicandidate text TC001/003/004",multicandidate_text_tests},{"multicandidate rejections TC004",multicandidate_rejection_tests},
            {"all-format character priority TC002/003/005",import_character_priority_tests},{"priority boundaries TC005",import_priority_boundary_tests},
            {"independent literal scalars TC001/003/004",independent_literal_scalar_tests},{"independent structure dynamics TC001/004/005",independent_structure_dynamic_tests},
            {"independent cross-format oracle TC001/002/003/005",independent_cross_format_oracle_tests},
            {"independent separated weight boundary TC002/005",independent_separated_weight_boundary_tests},
            {"independent multitext entry limits TC005",independent_multitext_entry_limit_tests},
            {"GB2312 full BMP membership TC001/004",gb2312_membership_tests},
            {"GB2312 class combinations TC002/003/004",gb2312_class_combination_tests},
            {"GB2312 three-class boundary TC005",gb2312_three_class_boundary_tests},
            {"independent GB2312 missing phrase boundary TC001/002/003/004/005",independent_gb2312_missing_phrase_boundary_tests},
            {"sample TC006",sample_test},{"text sample TC006",text_sample_test}}){
            try{test();std::cout<<"[pass] "<<name<<"\n";}catch(const std::exception& e){++failed;std::cerr<<"[FAIL] "<<name<<": "<<e.what()<<"\n";}
        }
        if(failed){std::cerr<<failed<<" groups failed; "<<checks<<" checks executed; "<<skipped<<" skipped scenarios; evidence: "<<temp_root<<"\n";return 1;}
        // 只清理本次唯一目录，拒绝跟随任何重解析点；只删除本测试明确生成的普通文件。
        const auto normalized=temp_root.lexically_normal();CHECK(normalized.parent_path()==base && normalized.filename().native().rfind(L"lexhelper-core-tests-",0)==0);
        const auto root_attributes=GetFileAttributesW(temp_root.c_str());CHECK(root_attributes!=INVALID_FILE_ATTRIBUTES && !(root_attributes&FILE_ATTRIBUTE_REPARSE_POINT));
        for(const auto& e:std::filesystem::directory_iterator(temp_root)){const auto attrs=GetFileAttributesW(e.path().c_str());CHECK(attrs!=INVALID_FILE_ATTRIBUTES && !(attrs&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)));CHECK(std::filesystem::remove(e.path()));}
        CHECK(std::filesystem::remove(temp_root));std::cout<<checks<<" checks passed; "<<skipped<<" skipped scenarios\n";return 0;
    } catch(const std::exception& e){std::cerr<<"[FAIL] "<<e.what()<<"\n";std::cerr<<"失败临时证据保留于本任务 D 盘目录，最多保留7天；不自动删除。\n";return 1;}
}
