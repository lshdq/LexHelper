#include "internal.hpp"
#include <unordered_map>

namespace lexhelper {
Table read_wbc3(std::span<const std::byte> b) {
    using namespace detail;
    need(b.size()>=0x8c && b.size()<=max_wbc,"WBC3 长度不受支持");
    need(magic(b,0,"WBC3"),"仅支持新世纪 WBC3；不混入 WBC1/2");
    const auto index=u32(b,0x38), index_size=u32(b,0x3c), count=u32(b,0x40), data=u32(b,0x44), data_size=u32(b,0x48);
    need(count>0 && count<=max_entries && index==0x8c && index_size==static_cast<std::uint64_t>(count)*4,"WBC3 索引头错误或版本不支持");
    range(b,index,index_size); range(b,data,data_size);
    need(static_cast<std::uint64_t>(index)+index_size==data && static_cast<std::uint64_t>(data)+data_size==b.size() && u32(b,0x10)==b.size() && u32(b,0x4c)==data_size,"WBC3 长度字段不一致");
    Table physical; physical.reserve(count);
    std::unordered_map<std::uint32_t,std::size_t> starts; starts.reserve(count);
    std::size_t p=data;
    for (std::uint32_t i=0;i<count;++i) {
        range(b,p,11); starts.emplace(static_cast<std::uint32_t>(p-data),physical.size());
        const auto packed=static_cast<std::uint32_t>(std::to_integer<unsigned char>(b[p+6])) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(b[p+7]))<<8) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(b[p+8]))<<16);
        Entry e; bool begun=false;
        for(int j=3;j>=0;--j) {
            const auto c=(packed>>(5*j))&31;
            if (!c && !begun) continue;
            need(c>=1 && c<=25,"WBC3 压缩编码非法或有空洞"); begun=true; e.code.push_back(static_cast<char>('a'+c-1));
        }
        need(code_ok(e.code,'y'),"WBC3 编码为空");
        const auto bytes=u16(b,p+9); e.text=utf16(b,p+11,bytes); valid_text(e.text);
        physical.push_back(std::move(e)); p+=11+bytes;
    }
    need(p==b.size(),"WBC3 记录数或数据尾错误");
    Table ordered; ordered.reserve(count);
    for(std::uint32_t i=0;i<count;++i) {
        const auto it=starts.find(u32(b,index+4ull*i)); need(it!=starts.end(),"WBC3 索引非记录起点或重复引用");
        auto& e=physical[it->second];
        need(ordered.empty() || ordered.back().code<=e.code,"WBC3 索引编码非升序，拒绝猜测顺序");
        ordered.push_back(std::move(e)); starts.erase(it);
    }
    // 原 2+4 字节及 packed 高 4 位未定义，绝不称为频率。索引次序映射为 lex 代价。
    rank_in_order(ordered); return ordered;
}
}
