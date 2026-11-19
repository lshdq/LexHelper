// 多候选文本与全格式三段优先：合成样本，不读取或安装系统词库。
constexpr std::string_view multi_source_zero="孤狐多候选文本（同行从左到右，跨行从上到下；已排除动态时间项 0 行）；全表 GB2312 常用单字→词组→其他单字（同类保持原顺序）";
constexpr std::string_view multi_source_three="孤狐多候选文本（同行从左到右，跨行从上到下；已排除动态时间项 3 行）；全表 GB2312 常用单字→词组→其他单字（同类保持原顺序）";

const std::array<bool,65536>& oracle_gb2312_members() {
    // 独立区位映射 oracle；不读取生产位图，不以 CP936 可编码性判断成员。
    static const auto members=[] {
        std::array<bool,65536> flags{};unsigned first_level=0,second_level=0;
        for(unsigned zone=16;zone<=87;++zone)for(unsigned position=1;position<=(zone==55?89u:94u);++position) {
            const char pair[]{static_cast<char>(zone+0xa0),static_cast<char>(position+0xa0)};
            wchar_t scalar{};
            CHECK(MultiByteToWideChar(936,MB_ERR_INVALID_CHARS,pair,2,&scalar,1)==1);
            CHECK(scalar>=0x4e00 && scalar<=0x9fff && !flags[scalar]);flags[scalar]=true;
            if(zone<=55)++first_level;else ++second_level;
        }
        CHECK(first_level==3755 && second_level==3008);
        CHECK(flags[u'啊'] && flags[u'座'] && flags[u'亍'] && flags[u'齄']);
        CHECK(!flags[u'丂'] && !flags[u'Ａ'] && !flags[u'。']);return flags;
    }();
    return members;
}

void check_global_priority(const Table& t) {
    const auto& common=oracle_gb2312_members();
    std::array<unsigned,3> maximum{},minimum{65536,65536,65536};
    for(const auto& e:t) {
        std::size_t scalars=0;
        for(auto c:e.text)if(c<0xdc00 || c>0xdfff)++scalars;
        const auto category=scalars!=1?1u:(e.text.size()==1 && common[e.text[0]]?0u:2u);
        maximum[category]=std::max(maximum[category],static_cast<unsigned>(e.weight));
        minimum[category]=std::min(minimum[category],static_cast<unsigned>(e.weight));
    }
    for(unsigned a=0;a<3;++a)for(unsigned b=a+1;b<3;++b)CHECK(maximum[a]<minimum[b]);
}

void multicandidate_text_tests() {
    const std::string text="# synthetic\r\nname=合成表\r\n# header\r\n[data]\r\nca 词先 戏\nca\t词后  \xf0\xa0\x80\x80\t\n# data\nca 弁 e\xcc\x81\ncad 颈\ncae 劲\ncaf 另组";
    const std::u16string wide=u"# synthetic\r\nname=合成表\r\n# header\r\n[data]\r\nca 词先 戏\nca\t词后  \U00020000\t\n# data\nca 弁 e\u0301\ncad 颈\ncae 劲\ncaf 另组";
    const Table low_level{{"ca",u"词先",1},{"ca",u"戏",2},{"ca",u"词后",3},{"ca",u"\U00020000",4},{"ca",u"弁",5},{"ca",u"e\u0301",6},{"cad",u"颈",1},{"cae",u"劲",1},{"caf",u"另组",1}};
    const Table expected{{"ca",u"戏",1},{"ca",u"弁",2},{"ca",u"词先",3},{"ca",u"词后",4},{"ca",u"e\u0301",5},{"ca",u"\U00020000",6},{"cad",u"颈",1},{"cae",u"劲",1},{"caf",u"另组",3}};
    ImportDetectionCases cases{L"多候选-编码"};
    for(const auto& encoded:import_text_encodings(text,wide)) {
        CHECK(read_text(encoded)==low_level); // 公开底层接口仍忠实保持原次序。
        for(const auto ext:{L".txt",L".TSV",L".bin",L""})
            cases.trial("structured multi-candidate",ext,encoded,&expected,multi_source_zero);
        for(const auto ext:{L".cwb",L".wbc3",L".lex"})
            cases.trial("explicit binary must not accept multi-candidate",ext,encoded);
    }
    const auto dynamic="name=synthetic\n[data]\nminute ^$mi分 ^$MI分\nca 词先 戏\nmonth\t^$m月\t^$M月\nsecond ^$s秒 ^$S秒\n";
    const Table dynamic_expected{{"ca",u"戏",1},{"ca",u"词先",2}};
    const std::u16string dynamic_wide=u"name=synthetic\n[data]\nminute ^$mi分 ^$MI分\nca 词先 戏\nmonth\t^$m月\t^$M月\nsecond ^$s秒 ^$S秒\n";
    for(const auto& encoded:import_text_encodings(dynamic,dynamic_wide))
        cases.trial("exact approved dynamic rows",L".txt",encoded,&dynamic_expected,multi_source_three);
    // name= 和 [data] 作为原 TAB 的普通词条不被方言选择抢占。
    const Table literals{{"a",u"name=literal",1},{"b",u"[data]",1}};
    cases.trial("literal metadata in legacy TAB",L".txt",bytes("name=literal\ta\n[data]\tb"),&literals,import_text_source);
    const Table literal_macro{{"a",u"^$synthetic",1}};
    cases.trial("ordinary candidate text is never evaluated or excluded",L".txt",bytes("name=synthetic\n[data]\na ^$synthetic"),&literal_macro,multi_source_zero);
    cases.finish("multicandidate TC001/003/004");
    check_global_priority(expected);
}

void multicandidate_rejection_tests() {
    ImportDetectionCases cases{L"多候选-拒绝"};
    for(const std::string& malformed:std::vector<std::string>{
        "ca 甲 乙", "[data]\nca 甲", "name=\n[data]\na 甲", "name=   \n[data]\na 甲",
        "name=synthetic", "name=synthetic\na 甲", "name=synthetic\n[other]\na 甲",
        "name=one\nname=two\n[data]\na 甲", "a\t甲\nname=synthetic\n[data]\na 乙",
        "name=synthetic\n[data]\nminute ^$mi分 ^$MI分\nmonth ^$m月 ^$M月\nsecond ^$s秒 ^$S秒",
        "name=synthetic\n[data]\n"})
        cases.trial("malformed structure or no normal entries",L".txt",bytes(malformed));
    for(const std::string& bad_line:std::vector<std::string>{
        "minute ^$mi分 ^$MI秒", "minute ^$mi分", "minute ^$mi分 ^$MI分 extra",
        "month ^$M月 ^$m月", "second ^$s秒 ^$S秒x", "otherlong 甲", "abcde 甲",
        "unknown ^$unknown", "minute ^$mi分 ^$bad", "a", " a 甲", "\ta 甲", "甲\ta",
        "[data]", "[other]", "name=again", "a 甲\r乙", "a 甲\x7f", "a 甲 甲",
        "a 乙\na 甲", "a \xc0\xaf", "a \xed\xa0\x80"}) {
        const auto encoded=bytes("name=synthetic\n[data]\na 甲\n"+bad_line);
        cases.trial("unknown structure, macro, duplicate, Unicode",L".txt",encoded);
        cases.trial("same rejection for unknown extension",L".bin",encoded);
    }
    cases.trial("bad row identifies line",L".txt",bytes("name=synthetic\n[data]\na 甲\nminute ^$bad ^$MI分"),nullptr,{},"第 4 行");
    auto bad16=utf16bom(u"name=synthetic\n[data]\na 甲");bad16.push_back(std::byte{0});
    cases.trial("odd UTF16LE",L".txt",bad16);
    cases.trial("unpaired surrogate",L".txt",utf16bom(std::u16string(u"name=synthetic\n[data]\na ")+char16_t{0xd800}));
    auto nul=bytes("name=synthetic\n[data]\na 甲");nul.push_back(std::byte{0});
    cases.trial("NUL",L".txt",nul);
    cases.finish("multicandidate-rejections TC004");
}

void import_character_priority_tests() {
    ImportDetectionCases cases{L"单字优先-格式"};
    const Table expected{{"ca",u"戏",1},{"ca",u"弁",2},{"ca",u"词先",3},{"ca",u"词后",4},{"ca",u"e\u0301",5},{"ca",u"\U00020000",6},{"cad",u"颈",1},{"cae",u"劲",1},{"caf",u"另组",3}};
    const Table prior{{"ca",u"词先",7},{"ca",u"戏",12},{"ca",u"词后",12},{"ca",u"\U00020000",19},{"ca",u"弁",88},{"ca",u"e\u0301",99},{"cad",u"颈",65535},{"cae",u"劲",0},{"caf",u"另组",0}};
    const auto lex=write_lex(prior);CHECK(read_lex(lex)==prior);CHECK(write_lex(read_lex(lex))==lex);
    cases.trial("lex original weight order and ties",L".lex",lex,&expected,import_lex_source);
    Table physical(prior.rbegin(),prior.rend());std::vector<unsigned> indices;
    for(unsigned i=0;i<prior.size();++i)indices.push_back(static_cast<unsigned>(prior.size()-1-i));
    const auto raw=wbc(physical,indices);const auto low=read_wbc3(raw);
    CHECK(low[0].text==u"词先" && low[1].text==u"戏" && low[2].text==u"词后");
    cases.trial("WBC3 index not physical order",L".wbc3",raw,&expected,import_wbc_source);
    for(int method:{0,8})cases.trial("CWB store/deflate",L".cwb",zip({{"usr/wbCustom3.bin",raw,method}}),&expected,import_cwb_source);
    for(bool word_first:{false,true}) {
        // 反转同频以外的文件顺序，明确验证频次和等频稳定先验。
        const auto text=word_first?
            "另组\tcaf\t0\n弁\tca\t2\n词先\tca\t10\n戏\tca\t9\n词后\tca\t9\ne\xcc\x81\tca\t0\n\xf0\xa0\x80\x80\tca\t7\n颈\tcad\t1\n劲\tcae\t1":
            "caf\t另组\t0\nca\t弁\t2\nca\t词先\t10\nca\t戏\t9\nca\t词后\t9\nca\te\xcc\x81\t0\nca\t\xf0\xa0\x80\x80\t7\ncad\t颈\t1\ncae\t劲\t1";
        cases.trial("TAB direction frequency and equal-frequency",L".tsv",bytes(text),&expected,import_text_source);
    }
    cases.finish("all-format-priority TC002/003/005");check_global_priority(expected);
    // ca 前缀下每个原编码仍存在；较长编码单字的 weight 也小于 ca 词组。
    CHECK(expected[6].code=="cad" && expected[6].weight<expected[2].weight);
    CHECK(expected[7].code=="cae" && expected[7].weight<expected[2].weight);
}

std::u16string scalar_text(unsigned scalar) {
    if(scalar<=0xffff)return std::u16string(1,static_cast<char16_t>(scalar));
    scalar-=0x10000;return {static_cast<char16_t>(0xd800+(scalar>>10)),static_cast<char16_t>(0xdc00+(scalar&1023))};
}
void import_priority_boundary_tests() {
    Table input;input.reserve(65536);
    // 补充平面提供足够多互异其他单字。1 词组 + 65534 其他单字精确占满 uint16。
    for(unsigned i=0;i<65534;++i)input.push_back({"a",scalar_text(0x10000+i),0});
    input.push_back({"a",u"词组",0});
    const auto valid=temp_root/L"权重分段-有效.lex";write_bytes(valid,write_lex(input));
    const auto result=import_file(valid).entries;CHECK(result.size()==65535);
    bool all=result[0].text==u"词组" && result[0].weight==1;
    for(std::size_t i=1;i<result.size();++i)all=all && result[i].text==input[i-1].text && result[i].code==input[i-1].code && result[i].weight==i+1;
    CHECK(all);CHECK(read_lex(write_lex(result))==result);check_global_priority(result);
    const auto roundtrip=temp_root/L"权重分段-幂等.lex";save_lex(roundtrip,result);CHECK(import_file(roundtrip).entries==result);
    input.push_back({"b",u"第二组",0}); // 同码均未超限，但全局分段 65534+1 仍然可表示。
    const auto other=temp_root/L"权重分段-异码.lex";write_bytes(other,write_lex(input));CHECK(import_file(other).entries.back().weight==1);
    input.push_back({"b",u"第三组",0});
    const auto overflow=temp_root/L"权重分段-溢出.lex";write_bytes(overflow,write_lex(input));
    rejects_with([&]{import_file(overflow);},"全表常用单字/词组/其他单字权重分段");
    input.pop_back();input.pop_back();input.back()={"a",scalar_text(0x10000+65534),0};
    const auto singles=temp_root/L"单字-65535.lex";write_bytes(singles,write_lex(input));CHECK(import_file(singles).entries.back().weight==65535);
    input.push_back({"a",scalar_text(0x10000+65535),0});
    const auto too_many=temp_root/L"同码-65536.lex";write_bytes(too_many,write_lex(input));
    // 低层 lex 允许等权原值忠实往返，但文件导入的无损次序必须拒绝超限。
    CHECK(read_lex(read_fixture(too_many))==input);rejects_with([&]{import_file(too_many);},"同码候选超过 65535");
    std::string phrases="name=synthetic\n[data]\na";
    for(unsigned i=0;i<65536;++i)phrases+=" Word"+std::to_string(i);
    rejects_with([&]{read_text(bytes(phrases));},"65535");
}

void text_sample_test() {
    wchar_t* env=nullptr;std::size_t length=0;CHECK(_wdupenv_s(&env,&length,L"LEXHELPER_TEXT_SAMPLE")==0);
    std::unique_ptr<wchar_t,decltype(&std::free)> owner(env,&std::free);
    if(!env || !*env){skip("LEXHELPER_TEXT_SAMPLE 未设置，未读取私人文本样本");return;}
    // 显式 opt-in，既有私人 CWB 入口及默认行为不变；不打印名称或词库内容。
    const auto before=read_fixture(env);const auto low=read_text(before);const auto input=import_file(env);
    CHECK(input.entries.size()==94942);CHECK(input.source==multi_source_three);check_global_priority(input.entries);
    auto normal=low,prior=input.entries;
    const auto less=[](const Entry& a,const Entry& b){return a.code<b.code || (a.code==b.code && a.text<b.text);};
    std::sort(normal.begin(),normal.end(),less);std::sort(prior.begin(),prior.end(),less);
    CHECK(normal.size()==prior.size());bool unchanged=true;
    for(std::size_t i=0;i<normal.size();++i)unchanged=unchanged && normal[i].code==prior[i].code && normal[i].text==prior[i].text;
    CHECK(unchanged);CHECK(read_lex(write_lex(input.entries))==input.entries);
    const auto output=temp_root/L"授权文本样本往返.lex";save_lex(output,input.entries);CHECK(import_file(output).entries==input.entries);
    CHECK(read_fixture(env)==before);
    std::cout<<"[text sample] 94942 entries; 3 excluded dynamic rows; priority, candidate set, input bytes and full roundtrip OK\n";
}
