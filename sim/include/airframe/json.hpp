// A deliberately small JSON encoder/decoder.
//
// Scope: flat objects whose values are string | number | bool | null, plus arrays
// of those, plus one level of nested object. That is exactly what the control
// protocol and the session summary need, and no more.
//
// Why not a real library (nlohmann/json, RapidJSON)? Two reasons, and the second
// is the honest one:
//   1. Zero third-party dependencies keeps `cmake --build` working offline.
//   2. This is a teaching codebase. A 200-line parser you can read start to finish
//      teaches tokenising, escaping and error handling; a header-only library
//      teaches nothing.
//
// In production code the answer flips — you would take the library. Knowing which
// way that trade-off points, and why, is the actual skill.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace airframe::json {

// ---------------------------------------------------------------- encoding

// Escapes per RFC 8259: quote, backslash, and the C0 control range.
std::string escape(const std::string& s);

class Writer {
public:
    Writer& key(const std::string& k);
    Writer& str(const std::string& k, const std::string& v);
    Writer& num(const std::string& k, double v);
    Writer& integer(const std::string& k, std::int64_t v);
    Writer& boolean(const std::string& k, bool v);
    Writer& null(const std::string& k);
    Writer& raw(const std::string& k, const std::string& already_json);
    Writer& str_array(const std::string& k, const std::vector<std::string>& vals);

    std::string build() const;          // wraps accumulated fields in { }
    bool empty() const { return parts_.empty(); }

private:
    std::vector<std::string> parts_;
};

// ---------------------------------------------------------------- decoding

// A parsed value. Numbers are kept as both text and double so an integer field
// round-trips without picking up a spurious ".0".
struct Value {
    enum class Type { Null, Bool, Number, String, Array, Object } type = Type::Null;

    bool                             b = false;
    double                           n = 0.0;
    std::string                      s;
    std::vector<Value>               arr;
    std::map<std::string, Value>     obj;

    bool is_null()   const { return type == Type::Null; }
    bool is_string() const { return type == Type::String; }
    bool is_number() const { return type == Type::Number; }
    bool is_object() const { return type == Type::Object; }

    // Convenience accessors with defaults — the control protocol is full of
    // optional fields and this keeps the dispatch code free of boilerplate.
    std::string get_str(const std::string& key, const std::string& fallback = "") const;
    double      get_num(const std::string& key, double fallback = 0.0) const;
    std::int64_t get_int(const std::string& key, std::int64_t fallback = 0) const;
    bool        get_bool(const std::string& key, bool fallback = false) const;
    bool        has(const std::string& key) const;
};

// Parses `text`. On failure returns false and fills `error` with a message that
// includes the byte offset — a parser that only says "invalid JSON" is useless
// when you are staring at a 2KB control message.
bool parse(const std::string& text, Value& out, std::string& error);

}  // namespace airframe::json
