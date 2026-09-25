// The control protocol is only as reliable as its parser. These tests exist
// because a hand-written parser that "works on the happy path" is a liability.

#include <gtest/gtest.h>

#include "airframe/json.hpp"

using namespace airframe::json;

TEST(JsonWriter, BuildsAFlatObject) {
    Writer w;
    w.str("cmd", "connect").integer("seed", 42).boolean("ok", true).num("p", 0.5);
    EXPECT_EQ(w.build(), R"({"cmd":"connect","seed":42,"ok":true,"p":0.5})");
}

TEST(JsonWriter, EscapesQuotesBackslashesAndControlCharacters) {
    Writer w;
    w.str("msg", "he said \"hi\"\n\tpath C:\\tmp");
    const std::string out = w.build();
    EXPECT_NE(out.find(R"(\")"), std::string::npos);
    EXPECT_NE(out.find(R"(\n)"), std::string::npos);
    EXPECT_NE(out.find(R"(\t)"), std::string::npos);
    EXPECT_NE(out.find(R"(\\)"), std::string::npos);

    // And it must survive a round trip -- escaping that does not reparse is
    // just corruption with extra steps.
    Value v;
    std::string err;
    ASSERT_TRUE(parse(out, v, err)) << err;
    EXPECT_EQ(v.get_str("msg"), "he said \"hi\"\n\tpath C:\\tmp");
}

TEST(JsonWriter, NonFiniteNumbersBecomeNull) {
    // JSON has no Inf or NaN. Emitting them produces a document no parser
    // accepts, so degrading to null is the only correct option.
    Writer w;
    w.num("inf", std::numeric_limits<double>::infinity());
    w.num("nan", std::numeric_limits<double>::quiet_NaN());
    const std::string out = w.build();
    EXPECT_EQ(out, R"({"inf":null,"nan":null})");

    Value v;
    std::string err;
    EXPECT_TRUE(parse(out, v, err)) << err;
}

TEST(JsonParser, ParsesEveryScalarType) {
    Value v;
    std::string err;
    ASSERT_TRUE(parse(R"({"s":"x","n":-12.5,"b":false,"z":null,"i":7})", v, err)) << err;
    EXPECT_EQ(v.get_str("s"), "x");
    EXPECT_DOUBLE_EQ(v.get_num("n"), -12.5);
    EXPECT_FALSE(v.get_bool("b", true));
    EXPECT_TRUE(v.has("z"));
    EXPECT_EQ(v.get_int("i"), 7);
}

TEST(JsonParser, HandlesNestedObjectsAndArrays) {
    Value v;
    std::string err;
    ASSERT_TRUE(parse(R"({"a":{"b":{"c":1}},"list":[1,"two",true,null]})", v, err)) << err;
    EXPECT_TRUE(v.obj.at("a").is_object());
    EXPECT_EQ(v.obj.at("a").obj.at("b").get_int("c"), 1);
    ASSERT_EQ(v.obj.at("list").arr.size(), 4u);
    EXPECT_EQ(v.obj.at("list").arr[1].s, "two");
}

TEST(JsonParser, IgnoresInsignificantWhitespace) {
    Value v;
    std::string err;
    EXPECT_TRUE(parse("  {\n \"a\" : 1 ,\t\"b\":[ 2 , 3 ]\r\n}  ", v, err)) << err;
    EXPECT_EQ(v.get_int("a"), 1);
}

TEST(JsonParser, DecodesUnicodeEscapes) {
    Value v;
    std::string err;
    ASSERT_TRUE(parse(R"({"s":"A\u00e9\u0041"})", v, err)) << err;
    EXPECT_EQ(v.get_str("s"), "A\xc3\xa9" "A") << "e-acute must encode as 2-byte UTF-8";
}

TEST(JsonParser, RejectsMalformedInputWithAnOffset) {
    // An error message without a position is nearly useless on a 2KB message.
    for (const char* bad : {"{", "{\"a\"}", "{\"a\":}", "{,}", "[1,", "{\"a\":1}}",
                            "{\"a\":1,}", "tru", "{'a':1}"}) {
        Value v;
        std::string err;
        EXPECT_FALSE(parse(bad, v, err)) << "should have rejected: " << bad;
        EXPECT_FALSE(err.empty()) << "no error message for: " << bad;
        EXPECT_NE(err.find("offset"), std::string::npos)
            << "error for " << bad << " lacks a position: " << err;
    }
}

TEST(JsonParser, RejectsTrailingData) {
    Value v;
    std::string err;
    EXPECT_FALSE(parse(R"({"a":1} {"b":2})", v, err));
    EXPECT_NE(err.find("trailing"), std::string::npos);
}

TEST(JsonParser, RejectsExcessiveNesting) {
    // A depth guard, so a malicious or buggy client cannot exhaust the stack.
    std::string deep;
    for (int i = 0; i < 100; ++i) deep += "{\"a\":";
    deep += "1";
    for (int i = 0; i < 100; ++i) deep += "}";

    Value v;
    std::string err;
    EXPECT_FALSE(parse(deep, v, err));
    EXPECT_NE(err.find("deep"), std::string::npos);
}

TEST(JsonParser, AccessorsFallBackWhenTypesMismatch) {
    Value v;
    std::string err;
    ASSERT_TRUE(parse(R"({"s":"text","n":5})", v, err));
    EXPECT_EQ(v.get_num("s", -1.0), -1.0)      << "a string is not a number";
    EXPECT_EQ(v.get_bool("n", true), true)     << "a number is not a bool";
    EXPECT_EQ(v.get_str("missing", "dflt"), "dflt");
    EXPECT_FALSE(v.has("missing"));
}

TEST(JsonParser, NumbersKeepTheirOriginalTextForIntegerFidelity) {
    Value v;
    std::string err;
    ASSERT_TRUE(parse(R"({"big":1234567890123})", v, err));
    EXPECT_EQ(v.get_int("big"), 1234567890123LL);
    EXPECT_EQ(v.obj.at("big").s, "1234567890123") << "raw text is retained";
}

TEST(JsonParser, ParsesScientificNotation) {
    Value v;
    std::string err;
    ASSERT_TRUE(parse(R"({"a":1.5e3,"b":-2E-2})", v, err)) << err;
    EXPECT_DOUBLE_EQ(v.get_num("a"), 1500.0);
    EXPECT_DOUBLE_EQ(v.get_num("b"), -0.02);
}
