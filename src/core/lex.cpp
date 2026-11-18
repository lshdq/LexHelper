#include "internal.hpp"
#include <set>

namespace lexhelper {
namespace detail {
Table canonical(const Table& input) {
    need(!input.empty() && input.size()<=max_entries,"码表为空或词条数超过上限");
    Table t=input;
    for (const auto& e:t) { need(code_ok(e.code),"编码必须为 1 至 4 个 a-z 小写字母"); valid_text(e.text); }
    std::stable_sort(t.begin(),t.end(),[](const Entry& a,const Entry& b) {
        return a.code < b.code || (a.code==b.code && a.weight < b.weight);
    });
    // 不静默删除重复项，否则索引中的候选数与输入含义不一致。
    std::set<std::u16string_view> seen;
    std::string_view previous;
    for (const auto& e:t) {
        if (e.code!=previous) { seen.clear(); previous=e.code; }
        need(seen.insert(e.text).second,"同码同词重复项；请修正源码表");
    }
    return t;
}
void rank_in_order(Table& t) {
    std::stable_sort(t.begin(),t.end(),[](const Entry& a,const Entry& b){return a.code<b.code;});
    std::string_view prev; std::uint32_t rank=0;
    for (auto& e:t) {
        if (prev!=e.code) {prev=e.code; rank=0;}
        need(++rank<=65535,"同码候选超过 65535，不能无损表示次序");
        e.weight=static_cast<std::uint16_t>(rank);
    }
    t=canonical(t);
}
}

std::vector<std::byte> write_lex(const Table& input) {
    const auto t=detail::canonical(input);
    std::size_t size=0xa8;
    for (const auto& e:t) { const auto n=16+e.text.size()*2; detail::need(size<=detail::max_file-n,"生成 lex 超过 128 MiB 上限"); size+=n; }
    std::vector<std::byte> out(size);
    constexpr std::string_view signature="imscwubi";
    for (std::size_t i=0;i<signature.size();++i) out[i]=std::byte(signature[i]);
    detail::put16(out,8,1); detail::put16(out,10,1);
    detail::put32(out,12,0x40); detail::put32(out,16,0xa8);
    detail::put32(out,20,static_cast<std::uint32_t>(size)); detail::put32(out,24,0x78563412);
    std::size_t p=0xa8, letter=0;
    for (const auto& e:t) {
        while (letter<=static_cast<std::size_t>(e.code[0]-'a')) detail::put32(out,0x40+4*letter++,static_cast<std::uint32_t>(p-0xa8));
        const auto n=static_cast<std::uint16_t>(16+2*e.text.size());
        detail::put16(out,p,n); detail::put16(out,p+2,e.weight); detail::put16(out,p+4,static_cast<std::uint16_t>(e.code.size()));
        for (std::size_t i=0;i<e.code.size();++i) detail::put16(out,p+6+2*i,static_cast<unsigned char>(e.code[i]));
        for (std::size_t i=0;i<e.text.size();++i) detail::put16(out,p+14+2*i,e.text[i]);
        p+=n;
    }
    while (letter<26) detail::put32(out,0x40+4*letter++,static_cast<std::uint32_t>(p-0xa8));
    return out;
}

Table read_lex(std::span<const std::byte> b) {
    using namespace detail;
    need(b.size()>=0xa8 && b.size()<=max_file,"lex 长度不受支持");
    need(magic(b,0,"imscwubi"),"不是 imscwubi lex 码表（不支持用户短语 dat）");
    need(u16(b,8)==1 && u16(b,10)==1,"不支持的 lex 版本");
    need(u32(b,12)==0x40 && u32(b,16)==0xa8 && u32(b,20)==b.size(),"lex 头偏移或文件长度错误");
    need(u32(b,24)==0x78563412,"不支持的 lex 格式标记");
    Table t; std::size_t p=0xa8, letter=0;
    while (p<b.size()) {
        range(b,p,16); const auto n=u16(b,p); const auto nc=u16(b,p+4);
        need(n>=18 && n%2==0 && nc>=1 && nc<=4,"lex 记录长度或编码长度错误"); range(b,p,n);
        Entry e; e.weight=u16(b,p+2);
        for (std::size_t i=0;i<4;++i) {
            const auto c=u16(b,p+6+2*i);
            if(i<nc) { need(c>='a' && c<='z',"lex 含非法编码"); e.code.push_back(static_cast<char>(c)); }
            else need(c==0,"lex 编码填充非零");
        }
        need(u16(b,p+n-2)==0,"lex 词条终止符错误");
        e.text=utf16(b,p+14,n-16); valid_text(e.text);
        if (!t.empty()) need(t.back().code<e.code || (t.back().code==e.code && t.back().weight<=e.weight),"lex 编码或候选权重未按序排列");
        while (letter<=static_cast<std::size_t>(e.code[0]-'a')) need(u32(b,0x40+4*letter++)==p-0xa8,"lex 字母索引与记录不一致");
        need(t.size()<max_entries,"lex 词条数超过上限"); t.push_back(std::move(e)); p+=n;
    }
    while (letter<26) need(u32(b,0x40+4*letter++)==p-0xa8,"lex 尾部字母索引错误");
    return canonical(t);
}
}
