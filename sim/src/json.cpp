#include "airframe/json.hpp"

#include <cctype>
#include <cmath>
#include <cstdio>

namespace airframe::json {

// ---------------------------------------------------------------- encoding

std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char raw : s) {
        const unsigned char c = static_cast<unsigned char>(raw);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

Writer& Writer::key(const std::string& k) { parts_.push_back("\"" + escape(k) + "\":"); return *this; }

Writer& Writer::str(const std::string& k, const std::string& v) {
    parts_.push_back("\"" + escape(k) + "\":\"" + escape(v) + "\"");
    return *this;
}

Writer& Writer::num(const std::string& k, double v) {
    char buf[64];
    if (std::isfinite(v)) {
        // %.6g keeps output compact and stable; JSON has no Inf/NaN so those
        // degrade to null rather than emitting something no parser accepts.
        std::snprintf(buf, sizeof(buf), "%.6g", v);
        parts_.push_back("\"" + escape(k) + "\":" + buf);
    } else {
        parts_.push_back("\"" + escape(k) + "\":null");
    }
    return *this;
}

Writer& Writer::integer(const std::string& k, std::int64_t v) {
    parts_.push_back("\"" + escape(k) + "\":" + std::to_string(v));
    return *this;
}

Writer& Writer::boolean(const std::string& k, bool v) {
    parts_.push_back("\"" + escape(k) + "\":" + (v ? "true" : "false"));
    return *this;
}

Writer& Writer::null(const std::string& k) {
    parts_.push_back("\"" + escape(k) + "\":null");
    return *this;
}

Writer& Writer::raw(const std::string& k, const std::string& already_json) {
    parts_.push_back("\"" + escape(k) + "\":" + already_json);
    return *this;
}

Writer& Writer::str_array(const std::string& k, const std::vector<std::string>& vals) {
    std::string a = "[";
    for (std::size_t i = 0; i < vals.size(); ++i) {
        if (i) a += ",";
        a += "\"" + escape(vals[i]) + "\"";
    }
    a += "]";
    return raw(k, a);
}

std::string Writer::build() const {
    std::string out = "{";
    for (std::size_t i = 0; i < parts_.size(); ++i) {
        if (i) out += ",";
        out += parts_[i];
    }
    out += "}";
    return out;
}

// ---------------------------------------------------------------- decoding

namespace {

struct Parser {
    const std::string& src;
    std::size_t        pos = 0;
    std::string        err;

    explicit Parser(const std::string& s) : src(s) {}

    void skip_ws() {
        while (pos < src.size() &&
               (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\n' || src[pos] == '\r'))
            ++pos;
    }

    bool fail(const std::string& msg) {
        if (err.empty()) err = msg + " at offset " + std::to_string(pos);
        return false;
    }

    bool parse_value(Value& out, int depth);

    bool parse_string(std::string& out) {
        if (pos >= src.size() || src[pos] != '"') return fail("expected '\"'");
        ++pos;
        out.clear();
        while (pos < src.size()) {
            char c = src[pos];
            if (c == '"') { ++pos; return true; }
            if (c == '\\') {
                if (++pos >= src.size()) return fail("truncated escape");
                char e = src[pos++];
                switch (e) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'u': {
                        if (pos + 4 > src.size()) return fail("truncated \\u escape");
                        unsigned code = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = src[pos + static_cast<std::size_t>(i)];
                            code <<= 4;
                            if (h >= '0' && h <= '9')      code |= static_cast<unsigned>(h - '0');
                            else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
                            else return fail("bad hex in \\u escape");
                        }
                        pos += 4;
                        // Minimal UTF-8 encode. Surrogate pairs are out of scope:
                        // the control protocol is ASCII, and pretending otherwise
                        // would be a silent correctness claim we do not test.
                        if (code < 0x80) {
                            out += static_cast<char>(code);
                        } else if (code < 0x800) {
                            out += static_cast<char>(0xC0 | (code >> 6));
                            out += static_cast<char>(0x80 | (code & 0x3F));
                        } else {
                            out += static_cast<char>(0xE0 | (code >> 12));
                            out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                            out += static_cast<char>(0x80 | (code & 0x3F));
                        }
                        break;
                    }
                    default: return fail("unknown escape");
                }
            } else {
                out += c;
                ++pos;
            }
        }
        return fail("unterminated string");
    }
};

bool Parser::parse_value(Value& out, int depth) {
    if (depth > 32) return fail("nesting too deep");
    skip_ws();
    if (pos >= src.size()) return fail("unexpected end of input");

    char c = src[pos];
    if (c == '{') {
        ++pos;
        out.type = Value::Type::Object;
        skip_ws();
        if (pos < src.size() && src[pos] == '}') { ++pos; return true; }
        while (true) {
            skip_ws();
            std::string k;
            if (!parse_string(k)) return false;
            skip_ws();
            if (pos >= src.size() || src[pos] != ':') return fail("expected ':'");
            ++pos;
            Value v;
            if (!parse_value(v, depth + 1)) return false;
            out.obj[k] = std::move(v);
            skip_ws();
            if (pos < src.size() && src[pos] == ',') { ++pos; continue; }
            if (pos < src.size() && src[pos] == '}') { ++pos; return true; }
            return fail("expected ',' or '}'");
        }
    }
    if (c == '[') {
        ++pos;
        out.type = Value::Type::Array;
        skip_ws();
        if (pos < src.size() && src[pos] == ']') { ++pos; return true; }
        while (true) {
            Value v;
            if (!parse_value(v, depth + 1)) return false;
            out.arr.push_back(std::move(v));
            skip_ws();
            if (pos < src.size() && src[pos] == ',') { ++pos; continue; }
            if (pos < src.size() && src[pos] == ']') { ++pos; return true; }
            return fail("expected ',' or ']'");
        }
    }
    if (c == '"') {
        out.type = Value::Type::String;
        return parse_string(out.s);
    }
    if (src.compare(pos, 4, "true") == 0)  { pos += 4; out.type = Value::Type::Bool; out.b = true;  return true; }
    if (src.compare(pos, 5, "false") == 0) { pos += 5; out.type = Value::Type::Bool; out.b = false; return true; }
    if (src.compare(pos, 4, "null") == 0)  { pos += 4; out.type = Value::Type::Null; return true; }

    if (c == '-' || (c >= '0' && c <= '9')) {
        std::size_t start = pos;
        if (src[pos] == '-') ++pos;
        while (pos < src.size() && std::isdigit(static_cast<unsigned char>(src[pos]))) ++pos;
        if (pos < src.size() && src[pos] == '.') {
            ++pos;
            while (pos < src.size() && std::isdigit(static_cast<unsigned char>(src[pos]))) ++pos;
        }
        if (pos < src.size() && (src[pos] == 'e' || src[pos] == 'E')) {
            ++pos;
            if (pos < src.size() && (src[pos] == '+' || src[pos] == '-')) ++pos;
            while (pos < src.size() && std::isdigit(static_cast<unsigned char>(src[pos]))) ++pos;
        }
        out.type = Value::Type::Number;
        out.s    = src.substr(start, pos - start);
        out.n    = std::strtod(out.s.c_str(), nullptr);
        return true;
    }
    return fail("unexpected character");
}

}  // namespace

bool parse(const std::string& text, Value& out, std::string& error) {
    Parser p(text);
    if (!p.parse_value(out, 0)) { error = p.err; return false; }
    p.skip_ws();
    if (p.pos != text.size()) { error = "trailing data at offset " + std::to_string(p.pos); return false; }
    return true;
}

bool Value::has(const std::string& key) const {
    return type == Type::Object && obj.find(key) != obj.end();
}

std::string Value::get_str(const std::string& key, const std::string& fallback) const {
    auto it = obj.find(key);
    if (it == obj.end()) return fallback;
    if (it->second.type == Type::String) return it->second.s;
    if (it->second.type == Type::Number) return it->second.s;
    return fallback;
}

double Value::get_num(const std::string& key, double fallback) const {
    auto it = obj.find(key);
    if (it == obj.end() || it->second.type != Type::Number) return fallback;
    return it->second.n;
}

std::int64_t Value::get_int(const std::string& key, std::int64_t fallback) const {
    auto it = obj.find(key);
    if (it == obj.end() || it->second.type != Type::Number) return fallback;
    return static_cast<std::int64_t>(it->second.n);
}

bool Value::get_bool(const std::string& key, bool fallback) const {
    auto it = obj.find(key);
    if (it == obj.end() || it->second.type != Type::Bool) return fallback;
    return it->second.b;
}

}  // namespace airframe::json
