#include "internal.hpp"
#include <numeric>

namespace lexhelper {
namespace {
std::u16string decode(std::span<const std::byte> b) {
    using namespace detail;
    if (b.size()>=2 && u16(b,0)==0xfeff) return utf16(b,2,b.size()-2);
    need(!(b.size()>=2 && u16(b,0)==0xfffe),"不支持 UTF-16BE；请保存为 UTF-8 或带 BOM 的 UTF-16LE");
    std::size_t p=magic(b,0,"\xef\xbb\xbf")?3:0; std::u16string out;
    while(p<b.size()) {
        auto c=std::to_integer<std::uint32_t>(b[p++]); unsigned follow=0; std::uint32_t min=0;
        if(c<0x80) {}
        else if(c>=0xc2 && c<=0xdf) { c&=31; follow=1; min=0x80; }
        else if(c>=0xe0 && c<=0xef) { c&=15; follow=2; min=0x800; }
        else if(c>=0xf0 && c<=0xf4) { c&=7; follow=3; min=0x10000; }
        else fail("非法 UTF-8 起始字节；不支持系统 ANSI 编码");
        range(b,p,follow);
        for(unsigned i=0;i<follow;++i) { const auto v=std::to_integer<unsigned char>(b[p++]); need((v&0xc0)==0x80,"非法 UTF-8 延续字节"); c=(c<<6)|(v&63); }
        need(c>=min && c<=0x10ffff && !(c>=0xd800 && c<=0xdfff),"UTF-8 过长编码或非法码点");
        if(c<=65535) out.push_back(static_cast<char16_t>(c));
        else {c-=0x10000;out.push_back(static_cast<char16_t>(0xd800+(c>>10)));out.push_back(static_cast<char16_t>(0xdc00+(c&1023)));}
    }
    return out;
}
bool is_code(std::u16string_view s) {
    return !s.empty() && s.size()<=4 && std::all_of(s.begin(),s.end(),[](char16_t c){return c>=u'a' && c<=u'z';});
}
}
Table read_text(std::span<const std::byte> b) {
    using namespace detail;
    need(!b.empty() && b.size()<=max_file,"文本为空或超过 128 MiB");
    const auto text=decode(b); Table t; std::vector<std::uint64_t> frequencies;
    for(std::size_t i=0;i<text.size();++i) {
        const auto c=text[i];need(c>=32 || c==u'\t' || c==u'\n' || c==u'\r',"文本含 NUL 或非法控制字符");
        if(c>=0xd800 && c<=0xdbff){need(i+1<text.size() && text[i+1]>=0xdc00 && text[i+1]<=0xdfff,"文本含非法 UTF-16 代理对");++i;}
        else need(c<0xdc00 || c>0xdfff,"文本含孤立 UTF-16 代理项");
    }
    std::size_t start=0,line_no=0; int orientation=-1,field_count=0;
    while(start<text.size()) {
        ++line_no; auto end=text.find(u'\n',start); if(end==text.npos) end=text.size();
        std::u16string_view line(text.data()+start,end-start); start=end+1;
        if(!line.empty() && line.back()==u'\r') line.remove_suffix(1);
        if(line.empty() || line[0]==u'#') continue;
        try {
            std::vector<std::u16string_view> fields; std::size_t s=0;
            for(;;) {const auto p=line.find(u'\t',s); fields.push_back(line.substr(s,p==line.npos?p:p-s));if(p==line.npos)break;s=p+1;need(fields.size()<3,"字段过多");}
            need(fields.size()==2 || fields.size()==3,"每行必须是两个或三个制表符分隔字段");
            const bool a=is_code(fields[0]), z=is_code(fields[1]);
            need(a!=z,"无法唯一判断编码列；编码必须为 1-4 个 a-z，另一列不能也像编码");
            const int current=a?0:1;
            if(orientation==-1) {orientation=current;field_count=static_cast<int>(fields.size());}
            need(orientation==current && field_count==static_cast<int>(fields.size()),"同一文本必须保持列方向及频次列一致");
            Entry e; for(const auto c:fields[current]) e.code.push_back(static_cast<char>(c));
            e.text=fields[1-current]; valid_text(e.text);
            std::uint64_t f=0;
            if(fields.size()==3) {
                need(!fields[2].empty(),"频次为空");
                for(const auto c:fields[2]) {need(c>=u'0' && c<=u'9',"频次必须是非负十进制整数");const auto v=static_cast<unsigned>(c-u'0');need(f<=(std::numeric_limits<std::uint64_t>::max()-v)/10,"频次溢出"); f=f*10+v;}
            }
            need(t.size()<max_entries,"词条数超过上限");t.push_back(std::move(e));frequencies.push_back(f);
        } catch(const std::exception& e) {throw std::runtime_error("文本第 "+std::to_string(line_no)+" 行："+e.what());}
    }
    need(!t.empty(),"文本没有词条");
    std::vector<std::size_t> order(t.size());std::iota(order.begin(),order.end(),0);
    std::stable_sort(order.begin(),order.end(),[&](auto a,auto z){return t[a].code<t[z].code || (t[a].code==t[z].code && frequencies[a]>frequencies[z]);});
    Table result;result.reserve(t.size());for(auto i:order)result.push_back(std::move(t[i]));
    rank_in_order(result);return result;
}
}
