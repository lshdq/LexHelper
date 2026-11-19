// GB2312 三段策略开发回归；只走公共 API，不引用生产位图/分类器。
void gb2312_membership_tests() {
    const auto& common=oracle_gb2312_members();
    Table prior,expected;prior.reserve(64000);expected.reserve(64000);
    // 穷举底层 codec 接受的全部 BMP 单标量，既验证全部成员，也验证区间外不误收。
    for(unsigned scalar=32;scalar<=0xffff;++scalar) {
        if(scalar==127 || (scalar>=0xd800 && scalar<=0xdfff))continue;
        prior.push_back({"a",scalar_text(scalar),0});
        if(common[scalar])expected.push_back({"a",scalar_text(scalar),static_cast<std::uint16_t>(expected.size()+1)});
    }
    CHECK(expected.size()==6763);
    const std::array<std::u16string,3> phrases{u"e\u0301",u"甲\ufe0f",u"\U00010000\U00010001"};
    for(const auto& phrase:phrases) {
        prior.push_back({"a",phrase,0});
        expected.push_back({"a",phrase,static_cast<std::uint16_t>(expected.size()+1)});
    }
    for(const auto& e:prior)if(e.text.size()==1 && !common[e.text[0]])
        expected.push_back({"a",e.text,static_cast<std::uint16_t>(expected.size()+1)});
    for(const auto scalar:{0x10000u,0x20000u,0x10ffffu}) {
        prior.push_back({"a",scalar_text(scalar),0});
        expected.push_back({"a",scalar_text(scalar),static_cast<std::uint16_t>(expected.size()+1)});
    }
    const auto encoded=write_lex(prior);CHECK(read_lex(encoded)==prior);
    ImportDetectionCases cases{L"GB2312-全部BMP"};
    cases.trial("6763 members and every permitted BMP nonmember; unchanged bytes and idempotence",L".lex",encoded,&expected,import_lex_source);
    check_global_priority(expected);cases.finish("GB2312 full membership TC001/004");
}

void gb2312_class_combination_tests() {
    struct Item {std::u16string text;unsigned category;};
    // 二级汉字、GBK-only、GB2312 标点、ASCII、补充平面和多标量序列的显式分类。
    const std::array<Item,8> items{{{u"丂",2},{u"丂词",1},{u"亍",0},{u"。",2},
        {u"甲\ufe0f",1},{u"甲",0},{u"A",2},{u"\U00020000",2}}};
    ImportDetectionCases cases{L"GB2312-七种组合"};
    for(unsigned mask=1;mask<8;++mask) {
        Table prior,expected;std::u16string multi=u"name=synthetic\n[data]\nca";
        for(const auto& item:items)if(mask&(1u<<item.category)) {
            prior.push_back({"ca",item.text,0});multi+=u" "+item.text;
        }
        unsigned rank=0;
        for(unsigned category=0;category<3;++category)for(const auto& item:items)
            if((mask&(1u<<category)) && item.category==category)
                expected.push_back({"ca",item.text,static_cast<std::uint16_t>(++rank)});
        const auto lex=write_lex(prior),raw=wbc(prior);
        CHECK(read_lex(lex)==prior);CHECK(read_wbc3(raw).size()==prior.size());
        cases.trial("lex seven exact class combinations",L".lex",lex,&expected,import_lex_source);
        cases.trial("WBC3 seven exact class combinations",L".wbc3",raw,&expected,import_wbc_source);
        for(int method:{0,8})cases.trial("CWB seven exact class combinations",L".cwb",zip({{"usr/wbCustom3.bin",raw,method}}),&expected,import_cwb_source);
        for(const auto& encoded:import_text_encodings(independent_utf8(multi),multi))
            cases.trial("multi seven exact class combinations",L".bin",encoded,&expected,multi_source_zero);
        check_global_priority(expected);
    }
    // C=3/P=4/R=5 在不同编码达到极值；保留原编码，前缀、不同码长均受同一分段约束。
    const Table prior{{"ca",u"丂",0},{"ca",u"先词",0},{"ca",u"亍",0},{"ca",u"甲",0},{"ca",u"乙",0},
        {"cad",u"A",0},{"cad",u"词一",0},{"cad",u"丙",0},{"cad",u"词二",0},{"cad",u"词三",0},{"cad",u"词四",0},
        {"cae",u"B",0},{"cae",u"另词",0},{"cae",u"丁",0},{"cae",u"。",0},{"cae",u"丂",0},{"cae",u"\U00020000",0},{"cae",u"Ａ",0}};
    const Table expected{{"ca",u"亍",1},{"ca",u"甲",2},{"ca",u"乙",3},{"ca",u"先词",4},{"ca",u"丂",8},
        {"cad",u"丙",1},{"cad",u"词一",4},{"cad",u"词二",5},{"cad",u"词三",6},{"cad",u"词四",7},{"cad",u"A",8},
        {"cae",u"丁",1},{"cae",u"另词",4},{"cae",u"B",8},{"cae",u"。",9},{"cae",u"丂",10},{"cae",u"\U00020000",11},{"cae",u"Ａ",12}};
    cases.trial("three separate maxima, prefix codes and stable class ranks",L".lex",write_lex(prior),&expected,import_lex_source);
    cases.trial("same maxima across index-driven WBC3",L".wbc3",wbc(prior),&expected,import_wbc_source);
    check_global_priority(expected);cases.finish("GB2312 class combinations TC002/003/004");
}

void gb2312_three_class_boundary_tests() {
    Table prior,expected;prior.reserve(65536);expected.reserve(65535);
    expected.push_back({"a",u"亍",1});expected.push_back({"a",u"词组",2});
    for(unsigned i=0;i<65533;++i) {
        auto text=scalar_text(0x10000+i);prior.push_back({"a",text,0});
        expected.push_back({"a",std::move(text),static_cast<std::uint16_t>(i+3)});
    }
    prior.push_back({"a",u"亍",0});prior.push_back({"a",u"词组",0});
    CHECK(expected.back().weight==65535);ImportDetectionCases cases{L"GB2312-三类同码边界"};
    cases.trial("C=1 P=1 R=65533 same code exact 65535",L".lex",write_lex(prior),&expected,import_lex_source);
    cases.trial("three nonzero classes WBC3 exact 65535",L".wbc3",wbc(prior),&expected,import_wbc_source);
    prior.push_back({"a",scalar_text(0x10000+65533),0});
    const auto lex=write_lex(prior);CHECK(read_lex(lex)==prior);
    cases.trial("same code 65536 rejects entire import, codec remains faithful",L".lex",lex,nullptr,{},"同码候选超过 65535");
    cases.finish("GB2312 three-class boundary TC005");
}
