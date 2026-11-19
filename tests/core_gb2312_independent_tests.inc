// 本轮阶段 6 独立补测 TC-001/002/003/004/005：缺失中间类别的满容量与首次出现。
// 数据来自测试的 Win32 明确区位 oracle；不读取生产位图或调用生产分类/排序函数。
void independent_gb2312_missing_phrase_boundary_tests() {
    const auto& members=oracle_gb2312_members();
    constexpr unsigned common_count=6763,other_count=65535-common_count;
    Table prior,expected;prior.reserve(65536);expected.reserve(65535);
    // 倒序放入全部常用汉字，避免将 Unicode 正序误当作同类先验顺序。
    for(unsigned scalar=0xffff;scalar>0;--scalar)if(members[scalar]) {
        prior.push_back({"a",scalar_text(scalar),0});
        expected.push_back({"a",scalar_text(scalar),static_cast<std::uint16_t>(expected.size()+1)});
    }
    CHECK(prior.size()==common_count);
    for(unsigned i=0;i<other_count;++i) {
        auto word=scalar_text(0x10000+i);prior.push_back({"yyyy",word,0});
        expected.push_back({"yyyy",std::move(word),static_cast<std::uint16_t>(common_count+i+1)});
    }
    CHECK(expected.size()==65535 && expected[common_count].weight==6764 && expected.back().weight==65535);
    ImportDetectionCases cases{L"独立-GB2312-中间空类边界"};
    const auto run_formats=[&](const Table& table,const Table* wanted) {
        const std::string_view error=wanted?std::string_view{}:
            "全表常用单字/词组/其他单字权重分段超过 65535";
        auto low=table;unsigned rank=0;std::string previous;
        std::u16string tab,reverse_tab,multi=u"name=synthetic\n[data]\n";
        for(auto& e:low) {
            if(e.code!=previous){rank=0;previous=e.code;}
            e.weight=static_cast<std::uint16_t>(++rank);
            const std::u16string code(e.code.begin(),e.code.end());
            tab+=code+u"\t"+e.text+u"\t0\n";
            reverse_tab+=e.text+u"\t"+code+u"\t0\n";
            multi+=code+u" "+e.text+u"\n";
        }
        const auto lex=write_lex(table),raw=wbc(table);
        CHECK(read_lex(lex)==table);CHECK(read_wbc3(raw)==low);
        cases.trial("all common members, missing phrase class, lex",L".lex",lex,wanted,import_lex_source,error);
        cases.trial("all common members, missing phrase class, WBC3",L".wbc3",raw,wanted,import_wbc_source,error);
        for(int method:{0,8}) {
            const auto archive=zip({{"usr/wbCustom3.bin",raw,method}},true);
            CHECK(read_cwb(archive)==low);
            cases.trial("missing/first phrase CWB store/deflate",L".cwb",archive,wanted,import_cwb_source,error);
        }
        const auto tab_bytes=utf16bom(tab),reverse_bytes=bytes(independent_utf8(reverse_tab));
        const auto multi_bytes=bytes(std::string("\xef\xbb\xbf")+independent_utf8(multi));
        CHECK(read_text(tab_bytes)==low);CHECK(read_text(reverse_bytes)==low);CHECK(read_text(multi_bytes)==low);
        cases.trial("boundary TAB code-first UTF16LE",L".tsv",tab_bytes,wanted,import_text_source,error);
        cases.trial("boundary TAB word-first UTF8",L".txt",reverse_bytes,wanted,import_text_source,error);
        cases.trial("boundary multi UTF8 BOM unknown extension",L".bin",multi_bytes,wanted,multi_source_zero,error);
    };
    run_formats(prior,&expected); // C=6763、P=0、R=58772；每码上限远未耗尽。
    prior.insert(prior.begin()+common_count,{"m",u"词组",0});
    run_formats(prior,nullptr); // 独立码首次出现一个词组，三段之和变为 65536，整体拒绝。
    const Table only_phrases{{"a",u"词组",0},{"a",u"另一词",65535}};
    const Table phrases_expected{{"a",u"词组",1},{"a",u"另一词",2}};
    cases.trial("fresh import after rejected maxima has no retained offsets",L".lex",
        write_lex(only_phrases),&phrases_expected,import_lex_source);
    cases.finish("independent GB2312 missing phrase 65535/65536 TC001/002/003/004/005");
}
