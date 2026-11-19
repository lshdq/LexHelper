// 阶段 6 独立补测：只使用合成输入及已有公共 API；不复用生产排序实现作预期。
// 对应 TC-001..005 / DEC-002..005；真实文本另由既有 opt-in 入口验证。
std::string independent_utf8(std::u16string_view text) {
    const std::wstring wide(text.begin(),text.end());
    const auto n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide.data(),static_cast<int>(wide.size()),nullptr,0,nullptr,nullptr);
    CHECK(n>0);std::string out(static_cast<std::size_t>(n),'\0');
    CHECK(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide.data(),static_cast<int>(wide.size()),out.data(),n,nullptr,nullptr)==n);
    return out;
}

void independent_literal_scalar_tests() {
    // 空格只有 ASCII 空格/TAB；NBSP、全角空格仍是候选。一个组合标记也是单标量，
    // e+重音、变体选择符序列、两个补充字符都不是单字；禁止隐式正规化。
    const auto wide=u"# synthetic\n\nname=synthetic\n\n# header\n[data]\n"
        u"b 同词\na 词先 42 z ^$mi分 ^$MI分 #tail \u00a0 \u3000 \u00e9 e\u0301\n"
        u"caa 词先 颈\na\t\U00010000\t\U0010ffff\t\u0301\t1\t\n"
        u"b 甲\na \ud7ff \ue000 \u2764\ufe0f \U00010000\U00010001";
    const Table expected{{"a",u"词先",2},{"a",u"42",3},{"a",u"^$mi分",4},{"a",u"^$MI分",5},
        {"a",u"#tail",6},{"a",u"e\u0301",7},{"a",u"\u2764\ufe0f",8},{"a",u"\U00010000\U00010001",9},
        {"a",u"z",10},{"a",u"\u00a0",11},{"a",u"\u3000",12},{"a",u"\u00e9",13},
        {"a",u"\U00010000",14},{"a",u"\U0010ffff",15},{"a",u"\u0301",16},{"a",u"1",17},
        {"a",u"\ud7ff",18},{"a",u"\ue000",19},
        {"b",u"甲",1},{"b",u"同词",2},{"caa",u"颈",1},{"caa",u"词先",2}};
    ImportDetectionCases cases{L"独立-字面标量"};
    for(const auto& content:import_text_encodings(independent_utf8(wide),wide))
        for(const auto ext:{L".txt",L".TSV",L".bin",L""})
            cases.trial("literal numbers/macros/code-shaped words and exact scalar classification",ext,content,&expected,multi_source_zero);
    // 同一数据行的第三列仅在原 TAB 方言解释为频次，新方言中必须成为字面候选。
    const Table legacy{{"a",u"甲",1}},multi{{"a",u"甲",1},{"a",u"42",2}};
    cases.trial("legacy third column remains frequency",L".txt",bytes("a\t甲\t42"),&legacy,import_text_source);
    cases.trial("multi third field remains candidate",L".txt",bytes("name=synthetic\n[data]\na\t甲\t42"),&multi,multi_source_zero);
    cases.finish("independent-literals TC001/003/004");
}

void independent_structure_dynamic_tests() {
    ImportDetectionCases cases{L"独立-状态动态"};
    const std::array<std::u16string,3> rows{u"minute ^$mi分 ^$MI分",u"month ^$m月 ^$M月",u"second ^$s秒 ^$S秒"};
    const Table one{{"a",u"甲",1}};
    for(const auto& row:rows) {
        // 每种获批行各自计数；额外/缺失/顺序/大小写/前后缀均不能被宽松排除。
        const auto good=std::u16string(u"name=synthetic\n[data]\na 甲\n")+row+u" \t\n";
        for(const auto& content:import_text_encodings(independent_utf8(good),good))
            cases.trial("one exact dynamic row",L".txt",content,&one,
                "孤狐多候选文本（同行从左到右，跨行从上到下；已排除动态时间项 1 行）；全表 GB2312 常用单字→词组→其他单字（同类保持原顺序）");
        const auto p=row.find(u' '),q=row.find(u' ',p+1);
        auto upper=row;upper[0]=static_cast<char16_t>(upper[0]-u'a'+u'A');
        const std::vector<std::u16string> bad{row+u" extra",row.substr(0,q),row+u"x",u"x"+row,
            upper,row.substr(0,p)+u" "+row.substr(q+1)+u" "+row.substr(p+1,q-p-1),
            row.substr(0,q+1)+row.substr(p+1,q-p-1),row+u"\u200b"};
        for(const auto& line:bad) {
            const auto input=std::u16string(u"name=synthetic\n[data]\na 甲\n")+line;
            for(const auto& content:import_text_encodings(independent_utf8(input),input))
                cases.trial("near match must fail whole import",L".bin",content,nullptr,{},"第 4 行");
        }
        const auto premature=std::u16string(u"name=synthetic\n")+row+u"\n[data]\na 甲";
        cases.trial("dynamic line is not accepted in header state",L".txt",utf16bom(premature),nullptr,{},"第 2 行");
    }
    for(const auto& tail:std::vector<std::u16string>{u"name=again",u"[DATA]",u"[data] extra",u"[data]\n",u" \t",u"b 乙\na 甲"})
        cases.trial("late structural error or nonadjacent duplicate",L".txt",utf16bom(std::u16string(u"name=synthetic\n[data]\na 甲\n")+tail));
    // 重复的精确排除行仍按实际行数报告，不能误报为三种类型数或排除候选数。
    std::u16string repeated=u"name=synthetic\n[data]\na 甲\n";
    for(int n=0;n<2;++n)for(const auto& row:rows)repeated+=row+u"\n";
    const std::string six="孤狐多候选文本（同行从左到右，跨行从上到下；已排除动态时间项 6 行）；全表 GB2312 常用单字→词组→其他单字（同类保持原顺序）";
    for(const auto& content:import_text_encodings(independent_utf8(repeated),repeated))
        cases.trial("count actual excluded rows including repeated exact rows",L".txt",content,&one,six);
    cases.trial("invalid UTF8 in comment cannot be skipped",L".txt",bytes("#\x80\nname=synthetic\n[data]\na 甲"));
    cases.trial("control in comment cannot be skipped",L".txt",bytes("name=synthetic\n[data]\na 甲\n#\x01"));
    auto surrogate=std::u16string(u"name=synthetic\n[data]\na 甲\n#");surrogate.push_back(char16_t{0xdc00});
    cases.trial("invalid UTF16 in comment cannot be skipped",L".txt",utf16bom(surrogate));
    // R-001：注释也须接受全文件控制字符校验；只插入 DEL 的正反样本配对，
    // 覆盖新旧方言的首行、头部和数据尾部，以及三种受支持的文本编码。
    for(bool multi:{false,true}) {
        const std::u16string prefix=multi?u"name=synthetic\r\n[data]\n":u"";
        const auto source=multi?multi_source_zero:import_text_source;
        const std::array<std::pair<const char*,std::u16string>,3> comments{{
            {"first-line comment",std::u16string(u"# ordinary\tcomment\r\n")+prefix+u"a\t甲\n"},
            {"header comment",multi?u"name=synthetic\r\n# ordinary\tcomment\n[data]\r\na\t甲\n":u"\r\n# ordinary\tcomment\n\na\t甲\r\n"},
            {"trailing comment",prefix+u"a\t甲\r\n# ordinary\tcomment"}
        }};
        for(const auto& [label,good]:comments) {
            // 普通注释及合法 TAB/CR/LF 不应随 DEL 修复被拒绝；精确核对词条及来源。
            for(const auto& content:import_text_encodings(independent_utf8(good),good)) {
                CHECK(read_text(content)==one);
                cases.trial(label,L".txt",content,&one,source);
            }
            auto bad=good;bad.insert(bad.find(u'#')+1,1,char16_t{0x7f});
            for(const auto& content:import_text_encodings(independent_utf8(bad),bad)) {
                rejects_with([&]{read_text(content);},"控制字符");
                cases.trial(label,L".txt",content,nullptr,{},"控制字符");
            }
        }
    }
    const auto long_word=std::u16string(32757,u'甲')+u"\U00010000";
    const auto long_input=std::u16string(u"name=synthetic\n[data]\na ")+long_word;
    const Table long_expected{{"a",long_word,1}};
    cases.trial("maximum 32759 UTF16 units including surrogate pair",L".txt",utf16bom(long_input),&long_expected,multi_source_zero);
    cases.trial("one extra UTF16 unit rejects without truncation",L".txt",utf16bom(long_input+u"乙"),nullptr,{},"长度上限");
    cases.finish("independent-structure TC001/004/005");
}

void independent_cross_format_oracle_tests() {
    // 预期来自带显式三类标志的生成模型，不调用生产分类器/排序生成预期。
    struct Item {std::u16string text;unsigned category;};
    constexpr std::u16string_view common_words=u"甲乙丙丁戊己庚辛壬癸亍弁";
    const std::array<std::string,6> codes{"a","ca","cad","cae","d","yyyy"};
    ImportDetectionCases cases{L"独立-跨格式模型"};std::mt19937 rng(0x18c0ffee);
    for(unsigned round=0;round<18;++round) {
        std::array<std::vector<Item>,6> groups;std::array<unsigned,3> maxima{};
        const auto mask=1+round%7; // 覆盖全部七种非空类别组合。
        for(unsigned c=0;c<groups.size();++c) {
            const unsigned count=1+rng()%12;
            std::array<unsigned,3> counts{};
            for(unsigned i=0;i<count;++i) {
                unsigned category=rng()%3;while(!(mask&(1u<<category)))category=(category+1)%3;
                auto word=scalar_text(0x20000+round*128+c*16+i);
                if(category==0)word=common_words.substr(i,1);
                if(category==1)word+=u"词";
                groups[c].push_back({std::move(word),category});++counts[category];
            }
            std::shuffle(groups[c].begin(),groups[c].end(),rng);
            for(unsigned category=0;category<3;++category)maxima[category]=std::max(maxima[category],counts[category]);
        }
        Table prior,expected;std::u16string tab,reverse_tab,multi=u"name=synthetic\n[data]\n";
        for(unsigned c=0;c<groups.size();++c) {
            const std::u16string code(codes[c].begin(),codes[c].end());
            for(std::size_t i=0;i<groups[c].size();++i) {
                const auto& word=groups[c][i].text;
                prior.push_back({codes[c],word,static_cast<std::uint16_t>(i/2)}); // 含原权重并列。
                const auto frequency=std::to_wstring(100-i/2);
                const std::u16string f(frequency.begin(),frequency.end());
                tab+=code+u"\t"+word+u"\t"+f+u"\n";
                reverse_tab+=word+u"\t"+code+u"\t"+f+u"\n";
            }
            unsigned offset=0;
            for(unsigned category=0;category<3;++category) {
                unsigned rank=offset;
                for(const auto& item:groups[c])if(item.category==category)expected.push_back({codes[c],item.text,static_cast<std::uint16_t>(++rank)});
                offset+=maxima[category];
            }
        }
        // 新方言跨编码交错，同码仍按上下/左右顺序；刻意与按编码物理分组不同。
        for(std::size_t i=0;i<12;i+=2)for(std::size_t c=groups.size();c-->0;)if(i<groups[c].size()) {
            multi+=std::u16string(codes[c].begin(),codes[c].end())+u" "+groups[c][i].text;
            if(i+1<groups[c].size())multi+=u"\t"+groups[c][i+1].text;
            multi+=u"\n";
        }
        std::vector<unsigned> physical_order(prior.size());std::iota(physical_order.begin(),physical_order.end(),0);
        std::shuffle(physical_order.begin(),physical_order.end(),rng);Table physical;std::vector<unsigned> indices(prior.size());
        for(unsigned i=0;i<physical_order.size();++i){physical.push_back(prior[physical_order[i]]);indices[physical_order[i]]=i;}
        const auto raw=wbc(physical,indices),lex=write_lex(prior);CHECK(read_lex(lex)==prior);
        cases.trial("lex weight ties versus known model",L".lex",lex,&expected,import_lex_source);
        cases.trial("WBC3 shuffled physical records versus known index model",L".wbc3",raw,&expected,import_wbc_source);
        cases.trial("CWB store with descriptor versus known model",L".cwb",zip({{"usr/wbCustom3.bin",raw,0}},true),&expected,import_cwb_source);
        cases.trial("CWB deflate with descriptor versus known model",L".cwb",zip({{"usr/wbCustom3.bin",raw,8}},true),&expected,import_cwb_source);
        cases.trial("TAB frequency ties code-first",L".tsv",utf16bom(tab),&expected,import_text_source);
        cases.trial("TAB frequency ties word-first",L".txt",bytes(independent_utf8(reverse_tab)),&expected,import_text_source);
        cases.trial("multi cross-line and left-right stable model",L".bin",bytes(independent_utf8(multi)),&expected,multi_source_zero);
    }
    cases.finish("independent-cross-format-model TC001/002/003/005");
}

void independent_separated_weight_boundary_tests() {
    // 三类极值分别出现在 a/b/c，三组各自合法，C+P+R 仍要全局相加。
    Table prior,expected;prior.reserve(65536);expected.reserve(65535);
    for(unsigned i=0;i<32768;++i){auto word=scalar_text(0x10000+i);prior.push_back({"a",word,0});expected.push_back({"a",word,static_cast<std::uint16_t>(32768+i)});}
    CHECK(expected.back().weight==65535);
    for(unsigned i=0;i<32766;++i){auto word=std::u16string(u"词")+scalar_text(0x20000+i);prior.push_back({"b",word,0});expected.push_back({"b",word,static_cast<std::uint16_t>(2+i)});}
    prior.push_back({"c",u"亍",0});expected.push_back({"c",u"亍",1});
    ImportDetectionCases cases{L"独立-分离分段"};
    cases.trial("global C+P+R exact 65535 with three separate maxima",L".lex",write_lex(prior),&expected,import_lex_source);
    cases.trial("WBC3 global C+P+R exact boundary",L".wbc3",wbc(prior),&expected,import_wbc_source);
    prior.insert(prior.end()-1,{"b",std::u16string(u"词")+scalar_text(0x20000+32766),0});
    const auto raw=wbc(prior);
    CHECK(read_lex(write_lex(prior))==prior); // 合法底层文件不得被低层策略重写或错误拒绝。
    cases.trial("lex valid codec but import C+P+R 65536 must reject",L".lex",write_lex(prior),nullptr,{},"全表常用单字/词组/其他单字权重分段");
    cases.trial("WBC3 cross-group overflow must reject",L".wbc3",raw,nullptr,{},"全表常用单字/词组/其他单字权重分段");
    cases.trial("CWB cross-group overflow must reject",L".cwb",zip({{"usr/wbCustom3.bin",raw,8}}),nullptr,{},"全表常用单字/词组/其他单字权重分段");
    std::u16string text=u"name=synthetic\n[data]\n";
    for(const auto& e:prior)text+=std::u16string(e.code.begin(),e.code.end())+u" "+e.text+u"\n";
    cases.trial("multi individually legal groups but global overflow",L".txt",utf16bom(text),nullptr,{},"全表常用单字/词组/其他单字权重分段");
    cases.finish("independent-separated-weight-boundary TC002/005");
}

void independent_multitext_entry_limit_tests() {
    // 两个不同的限额检查：单行字段数，以及跨行累计条数。任何重复/同码限额检查之前
    // 就须在 100 万输入条目边界拒绝，不能靠后续排序才发现超量。
    std::string single_line="name=synthetic\n[data]\na";
    single_line.reserve(2'000'025);
    for(unsigned i=0;i<1'000'001;++i)single_line+=" x";
    rejects_with([&]{read_text(bytes(single_line));},"词条数超过上限");
    single_line.clear();single_line.shrink_to_fit();
    std::string many_lines="name=synthetic\n[data]\n";many_lines.reserve(4'000'025);
    for(unsigned i=0;i<1'000'001;++i)many_lines+="a x\n";
    rejects_with([&]{read_text(bytes(many_lines));},"词条数超过上限");
}
