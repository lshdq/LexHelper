// CORE-002 / TC-002..006：只经公共 import_file 导入磁盘合成文件。
// 与开发探针独立的正式矩阵；沿用轻量 runner、ZIP/WBC 合成夹具和安全临时根。
// 每个 trial 即使导入结果不符合预期，也先检查原输入的全部字节，再报告失败。
constexpr std::string_view import_text_source="规范化文本（频次越大越靠前；无频次按行序）";
constexpr std::string_view import_lex_source="微软五笔 lex (1.1，受支持的布局)";
constexpr std::string_view import_wbc_source="搜狗新世纪 WBC3（索引次序；未知频率字段不保留）";
constexpr std::string_view import_cwb_source="搜狗 CWB / usr/wbCustom3.bin（索引次序；未知频率字段不保留）";

struct ImportDetectionCases {
    std::wstring prefix;
    unsigned files=0,accepted=0,rejected=0,failed=0;
    int initial_checks=checks;

    void trial(std::string_view label,std::wstring_view extension,const Bytes& content,
               const Table* expected=nullptr,std::string_view source={},std::string_view error_contains={}) {
        const auto stem=prefix+L"-"+std::to_wstring(++files);
        const auto input=temp_root/(stem+std::wstring(extension));
        try {
            write_bytes(input,content);
            ImportResult result;bool threw=false;std::string error;
            try{result=import_file(input);}catch(const std::exception& e){threw=true;error=e.what();}
            CHECK(read_fixture(input)==content);
            if(expected) {
                if(threw)throw std::runtime_error("unexpected import rejection: "+error);
                CHECK(result.entries==*expected); // 精确词条、编码、位置和 weight，不仅比较条数。
                CHECK(result.source==source);
                const auto compiled=write_lex(result.entries);
                CHECK(read_lex(compiled)==*expected);
                const auto output=temp_root/(stem+L"-roundtrip.lex");
                save_lex(output,result.entries);
                const auto reread=import_file(output);
                CHECK(reread.entries==*expected);
                CHECK(reread.source==import_lex_source);
                CHECK(read_fixture(output)==compiled);
                CHECK(read_fixture(input)==content); // 完整文件往返后仍不得改输入。
                ++accepted;
            } else {
                CHECK(threw);
                CHECK(!error.empty());
                if(!error_contains.empty())check(error.find(error_contains)!=std::string::npos,
                    ("expected rejection detail: "+std::string(error_contains)+"; actual: "+error).c_str(),__LINE__);
                ++rejected;
            }
        } catch(const std::exception& e) {
            ++failed;
            std::cerr<<"[FAIL import case "<<files<<"] "<<label<<": "<<e.what()<<"\n";
        }
    }
    void finish(std::string_view group)const {
        std::cout<<"[import "<<group<<"] files="<<files<<"; accepted="<<accepted
                 <<"; rejected="<<rejected<<"; failed="<<failed<<"; checks="<<checks-initial_checks<<"\n";
        CHECK(failed==0);
    }
};

std::array<Bytes,3> import_text_encodings(std::string_view utf8,std::u16string_view utf16) {
    return {bytes(utf8),bytes(std::string("\xef\xbb\xbf")+std::string(utf8)),utf16bom(utf16)};
}

void import_marker_text_tests(){
    ImportDetectionCases cases{L"分流-魔数文本"};
    const std::array<std::wstring_view,11> extensions{L".txt",L".TXT",L".TxT",L".tsv",L".TSV",L".TsV",L".bin",L".BiN",L".unknown",L".wbc",L""};
    for(const std::string& marker:std::vector<std::string>{"PK","PK"+std::string(510,'Q'),"WBC1","WBC2","WBC3","imscwubi"}) {
        // 首词确实以魔数起始，没有 BOM/注释为无 BOM 矩阵规避判定；混合频次与等频稳定。
        const auto text=marker+"\taaaa\t7\r\nHigherWord\taaaa\t99\r\nTieWord\taaaa\t7\r\nZeroWord\taaaa\t0\r\n";
        const std::u16string wide(text.begin(),text.end()),word(marker.begin(),marker.end());
        const Table expected{{"aaaa",u"HigherWord",1},{"aaaa",word,2},{"aaaa",u"TieWord",3},{"aaaa",u"ZeroWord",4}};
        for(const auto ext:extensions)for(const auto& encoded:import_text_encodings(text,wide))
            cases.trial(marker,ext,encoded,&expected,import_text_source);
        // 两列无频次的文本同样不能被 marker 占用，按行序权重 1/2。
        const auto plain=marker+"\taaaa\nSecondWord\taaaa";
        const std::u16string plain_wide(plain.begin(),plain.end());
        const Table plain_expected{{"aaaa",word,1},{"aaaa",u"SecondWord",2}};
        for(const auto ext:{L".txt",L".tsv",L".bin",L".unknown",L""})
            for(const auto& encoded:import_text_encodings(plain,plain_wide))
                cases.trial("marker without frequency",ext,encoded,&plain_expected,import_text_source);
    }
    // 非 marker 的未知/无扩展规范文本仍保留，两种列方向、中文和补充平面字符。
    const Table unicode_expected{{"a",u"扩展\U00020000",1},{"a",u"普通词",2}};
    for(bool word_first:{false,true}) {
        const auto utf8=word_first?"普通词\ta\t1\n扩展\xf0\xa0\x80\x80\ta\t2\n":"a\t普通词\t1\na\t扩展\xf0\xa0\x80\x80\t2\n";
        const auto wide=word_first?u"普通词\ta\t1\n扩展\U00020000\ta\t2\n":u"a\t普通词\t1\na\t扩展\U00020000\t2\n";
        for(const auto ext:{L".txt",L".tsv",L".bin",L".unknown",L""})
            for(const auto& encoded:import_text_encodings(utf8,wide))
                cases.trial("ordinary Unicode text",ext,encoded,&unicode_expected,import_text_source);
    }
    cases.finish("marker-text CORE-002/TC004");
}

void import_binary_detection_tests(){
    ImportDetectionCases cases{L"分流-二进制"};
    // WBC 的物理次序特意不同于索引次序；不能只往返同一个错误的候选顺序。
    const Table expected{{"a",u"先\U00020000",1},{"a",u"后",2},{"trxy",u"我",1}};
    const auto raw=wbc({{"trxy",u"我",0},{"a",u"后",0},{"a",u"先\U00020000",0}},{2,1,0});
    const auto lex=write_lex(expected);
    for(const auto ext:{L".lex",L".LEX",L".LeX",L".bin",L".unknown",L""}) {
        cases.trial("valid lex",ext,lex,&expected,import_lex_source);
        // 格式专属错误也必须保留，防止 catch 后用文本错误掩盖真正损坏。
        auto bad=lex;bad[24]^=std::byte{1};cases.trial("lex damaged header",ext,bad,nullptr,{},"lex 格式标记");
        bad=lex;bad.resize(12);cases.trial("lex truncated header",ext,bad,nullptr,{},"lex 长度");
        bad=lex;bad.pop_back();cases.trial("lex truncated record",ext,bad,nullptr,{},"lex 头偏移或文件长度");
    }
    for(const auto ext:{L".wbc3",L".WBC3",L".WbC3",L".wbc",L".bin",L".unknown",L""}) {
        cases.trial("valid WBC3",ext,raw,&expected,import_wbc_source);
        auto bad=raw;bad[0x10]^=std::byte{1};cases.trial("WBC3 damaged length",ext,bad,nullptr,{},"WBC3 长度字段");
        bad=raw;bad.resize(4);cases.trial("WBC3 truncated header",ext,bad,nullptr,{},"WBC3 长度");
        bad=raw;bad.pop_back();cases.trial("WBC3 truncated record",ext,bad);
        // 构造含 NUL、长度/记录完整的二进制旧版本头，不把合法 WBC1/2 文本当旧表。
        for(char v:{'1','2'}){bad=raw;bad[3]=std::byte(v);cases.trial("WBC1/2 binary rejected",ext,bad,nullptr,{},"WBC1/2");}
    }
    for(int method:{0,8})for(bool descriptor:{false,true}) {
        const auto archive=zip({{"usr/wbCustom1.bin",bytes("WBC1"),0},{"usr/wbCustom3.bin",raw,method}},descriptor);
        for(const auto ext:{L".cwb",L".CWB",L".CwB",L".bin",L".unknown",L""}) {
            cases.trial("CWB store/deflate descriptor matrix",ext,archive,&expected,import_cwb_source);
            auto bad=archive;bad.pop_back();cases.trial("CWB truncated EOCD",ext,bad,nullptr,{},"ZIP 中央目录结尾");
        }
    }
    // 同时改本地/中央 CRC 使二者一致但不等于载荷 CRC，必须实际执行 CRC 校验而非仅比头。
    for(int method:{0,8}) {
        auto bad=zip({{"usr/wbCustom3.bin",raw,method}});
        const auto cd=get32(bad,bad.size()-6);set32(bad,14,crc32(raw)^1);set32(bad,cd+16,crc32(raw)^1);
        for(const auto ext:{L".cwb",L".CwB",L".bin",L".unknown",L""})
            cases.trial("CWB payload CRC mismatch",ext,bad,nullptr,{},"CRC 校验");
    }
    for(const auto ext:{L".cwb",L".bin",L".unknown",L""}) {
        cases.trial("CWB missing new-century table",ext,zip({{"usr/wbCustom1.bin",raw,0}}));
        cases.trial("CWB duplicate new-century table",ext,zip({{"usr/wbCustom3.bin",raw,0},{"usr/wbCustom3.bin",raw,8}}));
        auto bad=zip({{"usr/wbCustom3.bin",raw,8}});set32(bad,bad.size()-6,0xffffffff);
        cases.trial("CWB corrupt directory offset",ext,bad);
    }
    cases.finish("binary TC002/003/005");
}

void import_type_conflict_tests(){
    ImportDetectionCases cases{L"分流-类型冲突"};
    const Table one{{"a",u"甲",1}};const auto lex=write_lex(one),raw=wbc(one);
    const auto archive=zip({{"usr/wbCustom3.bin",raw,8}});
    for(const auto ext:{L".txt",L".TxT",L".tsv",L".TsV"})
        for(const auto& binary:{lex,raw,archive})cases.trial("binary renamed as explicit text",ext,binary);
    // 所有二进制类型两两冲突；不能因文件头有效而覆盖用户声明的扩展名。
    for(const auto ext:{L".cwb",L".CwB"})for(const auto& wrong:{lex,raw})cases.trial("not CWB",ext,wrong);
    for(const auto ext:{L".lex",L".LeX"})for(const auto& wrong:{raw,archive})cases.trial("not lex",ext,wrong);
    for(const auto ext:{L".wbc3",L".WbC3"})for(const auto& wrong:{lex,archive})cases.trial("not WBC3",ext,wrong);
    for(const auto ext:{L".cwb",L".CwB",L".lex",L".LeX",L".wbc3",L".WbC3"}) {
        for(const auto& text:import_text_encodings("WBC3\taaaa\nOtherWord\taaaa\n",u"WBC3\taaaa\nOtherWord\taaaa\n"))
            cases.trial("text BOM must not override binary extension",ext,text);
        for(const auto& binary:{lex,raw,archive}) {
            auto prefixed=bytes("\xef\xbb\xbf");prefixed.insert(prefixed.end(),binary.begin(),binary.end());
            cases.trial("BOM before binary cannot repair header",ext,prefixed);
        }
    }
    cases.finish("explicit-type-conflicts TC003/004/005");
}

void import_invalid_text_tests(){
    ImportDetectionCases cases{L"分流-非法输入"};
    for(const std::string& marker:std::vector<std::string>{"PK","PKLongWord","WBC1","WBC2","WBC3","imscwubi"}) {
        const auto valid=marker+"\taaaa\t1\nOtherWord\taaaa\t2\n";
        const std::u16string wide(valid.begin(),valid.end());
        for(const auto ext:{L".txt",L".TSV",L".bin",L".unknown",L""}) {
            // marker 包络只负责分流，坏行不可当作可跳过的元数据或部分成功。
            cases.trial("marker envelope with bad final line",ext,bytes(valid+"BADLINE\n"),nullptr,{},"第 3 行");
            cases.trial("marker envelope with bad first line",ext,bytes(marker+"\nOtherWord\taaaa\n"),nullptr,{},"第 1 行");
            cases.trial("marker envelope duplicate entry",ext,bytes(valid+marker+"\taaaa\t9\n"),nullptr,{},"重复");
            cases.trial("marker envelope invalid UTF8",ext,bytes(valid+"\xc0\xaf\taaaa\t3\n"),nullptr,{},"UTF-8");
            auto nul=bytes(valid);nul.push_back(std::byte{0});cases.trial("NUL disqualifies marker text envelope",ext,nul);
            auto control=bytes(valid);control.push_back(std::byte{1});cases.trial("binary control disqualifies envelope",ext,control);
            auto surrogate=wide;surrogate.push_back(char16_t{0xd800});
            cases.trial("UTF16 BOM unpaired surrogate",ext,utf16bom(surrogate));
            auto short16=utf16bom(wide);short16.pop_back();cases.trial("UTF16 BOM odd length",ext,short16);
            auto bomnul=wide;bomnul.push_back(char16_t{0});cases.trial("UTF16 BOM NUL",ext,utf16bom(bomnul),nullptr,{},"NUL");
        }
    }
    for(const auto ext:{L".txt",L".tsv",L".bin",L".unknown",L""}) {
        auto be=bytes("\xfe\xff");for(char16_t c:std::u16string_view(u"PK\taaaa\nOtherWord\taaaa\n")){
            be.push_back(std::byte(c>>8));be.push_back(std::byte(c&255));
        }
        cases.trial("UTF16BE remains unsupported",ext,be,nullptr,{},"UTF-16BE");
        // 三种完整 ZIP magic 用于分流，但并未新增空 CWB 或分卷支持。
        for(const auto signature:{0x04034b50u,0x06054b50u,0x08074b50u}) {
            Bytes short_zip;add32(short_zip,signature);
            const bool explicit_text=std::wstring_view(ext)==L".txt" || std::wstring_view(ext)==L".tsv";
            cases.trial("complete ZIP signature without body",ext,short_zip,nullptr,{},explicit_text?"控制字符":"CWB ZIP 长度");
        }
        cases.trial("empty ZIP is not CWB",ext,zip({}));
        auto spanned=zip({{"usr/wbCustom3.bin",wbc({{"a",u"甲",1}}),0}});set16(spanned,spanned.size()-18,1);
        // 显式文本中的 ZIP 可先被 UTF-8 校验拒绝，不约束文本内部的校验先后。
        cases.trial("spanned ZIP remains unsupported",ext,spanned,nullptr,{},
                    std::wstring_view(ext)==L".txt" || std::wstring_view(ext)==L".tsv"?"":"分卷 ZIP");
        cases.trial("bare legacy magic is not text",ext,bytes("WBC1"));
        cases.trial("bare legacy magic is not text",ext,bytes("WBC2"));
        // 不完整的 PK 前缀不是 ZIP magic，也不能使坏行悄悄成功。
        cases.trial("PK prefix plus invalid table",ext,bytes("PKbroken\n"));
    }
    cases.finish("strict-rejections TC003/004/005");
}
