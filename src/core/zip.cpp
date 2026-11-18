#include "internal.hpp"
extern "C" {
#include "puff.h"
}
#include <cctype>
#include <mutex>

namespace lexhelper {
namespace {
std::uint32_t crc32(std::span<const std::byte> b) {
    std::uint32_t crc=0xffffffff;
    for(const auto x:b) {crc^=std::to_integer<unsigned char>(x);for(int i=0;i<8;++i)crc=(crc>>1)^(0xedb88320u & (0u-(crc&1)));}
    return ~crc;
}
std::string name_at(std::span<const std::byte> b,std::size_t p,std::size_t n) {
    detail::range(b,p,n);std::string s; s.reserve(n);
    for(std::size_t i=0;i<n;++i) {const auto c=std::to_integer<unsigned char>(b[p+i]);detail::need(c!=0,"ZIP 文件名含 NUL");s.push_back(static_cast<char>(c));}return s;
}
}
Table read_cwb(std::span<const std::byte> b) {
    using namespace detail;
    need(b.size()>=22 && b.size()<=max_file,"CWB ZIP 长度不受支持");
    std::size_t eocd=b.size()-22;bool found=false;
    const auto first=b.size()>65557?b.size()-65557:0;
    for(;;) {if(u32(b,eocd)==0x06054b50 && eocd+22ull+u16(b,eocd+20)==b.size()){found=true;break;}if(eocd==first)break;--eocd;}
    need(found,"ZIP 中央目录结尾缺失或截断");
    need(u16(b,eocd+4)==0 && u16(b,eocd+6)==0 && u16(b,eocd+8)==u16(b,eocd+10),"不支持分卷 ZIP");
    const auto count=u16(b,eocd+10);const auto cdsize=u32(b,eocd+12), cd=u32(b,eocd+16);
    need(count>0 && count<=4096 && cd!=0xffffffff && cdsize!=0xffffffff,"ZIP 条目过多或不支持 ZIP64");
    range(b,cd,cdsize);need(static_cast<std::uint64_t>(cd)+cdsize==eocd,"ZIP 中央目录偏移或长度不一致");
    struct Target {std::uint16_t flags{}, method{};std::uint32_t crc{},compressed{},size{},local{};std::string name;};
    Target target;bool selected=false;std::size_t p=cd;std::uint64_t total=0;
    std::vector<std::pair<std::size_t,std::size_t>> regions;
    for(unsigned i=0;i<count;++i) {
        range(b,p,46);need(u32(b,p)==0x02014b50,"ZIP 中央目录条目损坏");
        const auto n=u16(b,p+28),extra=u16(b,p+30),comment=u16(b,p+32);
        range(b,p,46ull+n+extra+comment);need(p+46ull+n+extra+comment<=eocd,"ZIP 中央目录条目越界");
        need(u16(b,p+34)==0 && u32(b,p+20)!=0xffffffff && u32(b,p+24)!=0xffffffff && u32(b,p+42)<cd,"ZIP64/分卷/本地头偏移不受支持");
        total+=u32(b,p+24);need(total<=512ull*1024*1024,"ZIP 声明总膨胀大小超过 512 MiB");
        const auto name=name_at(b,p+46,n);auto alias=name;
        // 不解压无关载荷，但所有目录指向的本地头/区间都要自洽，不能重叠或指入中央目录。
        const std::size_t local=u32(b,p+42);range(b,local,30);
        need(u32(b,local)==0x04034b50 && u16(b,local+6)==u16(b,p+8) && u16(b,local+8)==u16(b,p+10),"ZIP 条目的本地头与中央目录不一致");
        need(name_at(b,local+30,u16(b,local+26))==name,"ZIP 条目的本地名与中央名不一致");
        const std::size_t begin=local+30+u16(b,local+26)+u16(b,local+28);
        range(b,begin,u32(b,p+20));std::size_t finish=begin+u32(b,p+20);
        need(finish<=cd,"ZIP 条目数据覆盖中央目录");
        if(!(u16(b,p+8)&8)) need(u32(b,local+14)==u32(b,p+16) && u32(b,local+18)==u32(b,p+20) && u32(b,local+22)==u32(b,p+24),"ZIP 条目的本地 CRC/长度不一致");
        else {
            need((u32(b,local+14)==0 || u32(b,local+14)==u32(b,p+16)) && (u32(b,local+18)==0 || u32(b,local+18)==u32(b,p+20)) && (u32(b,local+22)==0 || u32(b,local+22)==u32(b,p+24)),"ZIP 条目的延迟长度字段错误");
            range(b,finish,12);if(u32(b,finish)==0x08074b50)finish+=4;range(b,finish,12);
            need(finish+12<=cd && u32(b,finish)==u32(b,p+16) && u32(b,finish+4)==u32(b,p+20) && u32(b,finish+8)==u32(b,p+24),"ZIP 条目的数据描述符不一致");finish+=12;
        }
        regions.emplace_back(local,finish);
        for(auto& c:alias) {if(c=='\\')c='/';else if(c>='A' && c<='Z')c=static_cast<char>(c-'A'+'a');}
        if(alias=="usr/wbcustom3.bin") {
            need(name=="usr/wbCustom3.bin" && !selected,"新世纪表路径非规范或出现重复条目");selected=true;
            need(!(u32(b,p+38)&0x10),"新世纪表不能是 ZIP 目录");
            // Unix symlink 条目不是文件；只接受普通文件或无 Unix 类型信息。
            const auto mode=u32(b,p+38)>>16;need((mode&0170000)==0 || (mode&0170000)==0100000,"新世纪表不是普通 ZIP 文件");
            target={u16(b,p+8),u16(b,p+10),u32(b,p+16),u32(b,p+20),u32(b,p+24),u32(b,p+42),name};
        }
        p+=46ull+n+extra+comment;
    }
    need(p==eocd && selected,"ZIP 中央目录长度错误或缺少 usr/wbCustom3.bin");
    std::sort(regions.begin(),regions.end());
    for(std::size_t i=1;i<regions.size();++i)need(regions[i-1].second<=regions[i].first,"ZIP 本地条目区间重叠或重复引用");
    need((target.flags & ~std::uint16_t(0x080e))==0 && !(target.flags&1),"不支持加密或特殊 ZIP 标志");
    need(target.method==0 || target.method==8,"仅支持 ZIP store / deflate");
    need(target.size>=0x8c && target.size<=max_wbc && target.compressed>0 && target.size<=static_cast<std::uint64_t>(target.compressed)*1000,"新世纪表大小或压缩膨胀比超过上限");
    const auto q=target.local;range(b,q,30);need(u32(b,q)==0x04034b50,"ZIP 本地头损坏");
    need(u16(b,q+6)==target.flags && u16(b,q+8)==target.method,"ZIP 本地头与中央目录不一致");
    const auto namelen=u16(b,q+26),extra=u16(b,q+28);
    need(name_at(b,q+30,namelen)==target.name,"ZIP 本地文件名不一致");
    const std::size_t data=static_cast<std::size_t>(q)+30+namelen+extra;range(b,data,target.compressed);
    need(data+target.compressed<=cd,"ZIP 压缩数据覆盖中央目录");
    if(!(target.flags&8)) need(u32(b,q+14)==target.crc && u32(b,q+18)==target.compressed && u32(b,q+22)==target.size,"ZIP 本地长度或 CRC 与目录不一致");
    else {
        need((u32(b,q+14)==0 || u32(b,q+14)==target.crc) && (u32(b,q+18)==0 || u32(b,q+18)==target.compressed) && (u32(b,q+22)==0 || u32(b,q+22)==target.size),"ZIP 本地延迟长度错误");
        auto d=data+target.compressed;range(b,d,12);if(u32(b,d)==0x08074b50)d+=4;range(b,d,12);
        need(d+12<=cd && u32(b,d)==target.crc && u32(b,d+4)==target.compressed && u32(b,d+8)==target.size,"ZIP 数据描述符不一致");
    }
    std::vector<std::byte> out(target.size);
    const auto compressed=b.subspan(data,target.compressed);
    if(target.method==0) {need(target.size==target.compressed,"ZIP store 长度不一致");std::copy(compressed.begin(),compressed.end(),out.begin());}
    else {
        // 上游 puff 的 fixed Huffman 表采用延迟静态初始化；串行调用避免数据竞争。
        static std::mutex puff_mutex;const std::lock_guard lock(puff_mutex);
        unsigned long output=target.size,input=target.compressed;
        const auto status=puff(reinterpret_cast<unsigned char*>(out.data()),&output,reinterpret_cast<const unsigned char*>(compressed.data()),&input);
        need(status==0 && output==target.size && input==target.compressed,"ZIP deflate 损坏、截断或膨胀长度不一致");
    }
    need(crc32(out)==target.crc,"ZIP 新世纪表 CRC 校验失败");return read_wbc3(out);
}
}
