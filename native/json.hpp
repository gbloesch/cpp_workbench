#pragma once
// Small dependency-free JSON protocol implementation. UTF-8 strings; bounded input/depth.
#include <cctype>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

struct Json {
    using Array = std::vector<Json>;
    using Object = std::map<std::string, Json>;
    std::variant<std::nullptr_t, bool, double, std::string, Array, Object> value;
    Json() : value(nullptr) {}
    Json(bool x) : value(x) {}
    Json(int x) : value(double(x)) {}
    Json(size_t x) : value(double(x)) {}
    Json(double x) : value(x) {}
    Json(const char* x) : value(std::string(x)) {}
    Json(std::string x) : value(std::move(x)) {}
    Json(Array x) : value(std::move(x)) {}
    Json(Object x) : value(std::move(x)) {}
    static Json object() { return Object{}; }
    static Json array() { return Array{}; }
    bool isArray() const { return std::holds_alternative<Array>(value); }
    bool isObject() const { return std::holds_alternative<Object>(value); }
    bool isString() const { return std::holds_alternative<std::string>(value); }
    bool has(const std::string& k) const { return isObject() && std::get<Object>(value).count(k); }
    Json& operator[](const std::string& k) { return std::get<Object>(value)[k]; }
    const Json& operator[](const std::string& k) const {
        static const Json empty;
        if (!has(k)) return empty;
        return std::get<Object>(value).at(k);
    }
    const Array& items() const { return std::get<Array>(value); }
    Array& items() { return std::get<Array>(value); }
    void push(Json j) { items().push_back(std::move(j)); }
    std::string str(std::string fallback = "") const {
        return isString() ? std::get<std::string>(value) : fallback;
    }
    double number(double fallback = 0) const {
        return std::holds_alternative<double>(value) ? std::get<double>(value) : fallback;
    }
    bool boolean(bool fallback = false) const {
        return std::holds_alternative<bool>(value) ? std::get<bool>(value) : fallback;
    }
    static void utf8(std::string& out, unsigned cp) {
        if (cp < 128) out += char(cp);
        else if (cp < 2048) { out += char(192 | (cp >> 6)); out += char(128 | (cp & 63)); }
        else if (cp < 65536) { out += char(224 | (cp >> 12)); out += char(128 | ((cp >> 6) & 63)); out += char(128 | (cp & 63)); }
        else { out += char(240 | (cp >> 18)); out += char(128 | ((cp >> 12) & 63)); out += char(128 | ((cp >> 6) & 63)); out += char(128 | (cp & 63)); }
    }
    struct Reader;
    static Json parse(const std::string& s);
    static std::string quote(const std::string& s) {
        std::ostringstream out; out << '"';
        for (unsigned char c : s) {
            if (c == '"' || c == '\\') out << '\\' << char(c);
            else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << int(c) << std::dec;
            else out << char(c);
        }
        out << '"'; return out.str();
    }
    std::string dump() const {
        if (std::holds_alternative<std::nullptr_t>(value)) return "null";
        if (std::holds_alternative<bool>(value)) return boolean() ? "true" : "false";
        if (std::holds_alternative<double>(value)) { std::ostringstream o; o << std::setprecision(15) << number(); return o.str(); }
        if (isString()) return quote(str());
        std::string out = isArray() ? "[" : "{"; bool first = true;
        if (isArray()) for (const auto& x : items()) { if (!first) out += ','; first = false; out += x.dump(); }
        else for (const auto& p : std::get<Object>(value)) { if (!first) out += ','; first = false; out += quote(p.first) + ":" + p.second.dump(); }
        return out + (isArray() ? "]" : "}");
    }
};
struct Json::Reader {
    const std::string& s; size_t p = 0;
    void ws() { while (p < s.size() && std::isspace((unsigned char)s[p])) ++p; }
    char take() { if (p >= s.size()) throw std::runtime_error("Truncated JSON"); return s[p++]; }
    void expect(char c) { if (take() != c) throw std::runtime_error("Invalid JSON delimiter"); }
    unsigned hex() {
        unsigned n = 0;
        for (int i=0;i<4;++i) { char c=take(); n*=16; if(c>='0'&&c<='9') n+=c-'0'; else if(c>='a'&&c<='f') n+=c-'a'+10; else if(c>='A'&&c<='F') n+=c-'A'+10; else throw std::runtime_error("Invalid JSON Unicode"); }
        return n;
    }
    std::string string() {
        expect('"'); std::string out;
        while (true) {
            char c = take(); if (c == '"') return out;
            if ((unsigned char)c < 32) throw std::runtime_error("Unescaped JSON control character");
            if (c != '\\') { out += c; continue; }
            c = take();
            switch(c) {
                case '"': case '\\': case '/': out += c; break;
                case 'b': out += '\b'; break; case 'f': out += '\f'; break;
                case 'n': out += '\n'; break; case 'r': out += '\r'; break; case 't': out += '\t'; break;
                case 'u': { unsigned cp=hex(); if(cp>=0xd800 && cp<=0xdbff) { expect('\\'); expect('u'); unsigned low=hex(); if(low<0xdc00||low>0xdfff) throw std::runtime_error("Invalid surrogate"); cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00); } else if(cp>=0xdc00 && cp<=0xdfff) throw std::runtime_error("Invalid surrogate"); Json::utf8(out,cp); break; }
                default: throw std::runtime_error("Invalid JSON escape");
            }
        }
    }
    Json read(int depth=0) {
        if(depth>64) throw std::runtime_error("JSON nesting limit");
        ws();
        if(p>=s.size()) throw std::runtime_error("Missing JSON value");
        char c=s[p]; if(c=='"') return string();
        if(c=='{' || c=='[') {
            ++p; bool obj=c=='{'; Json out=obj?Json::object():Json::array(); ws();
            if(p<s.size()&&s[p]==(obj?'}':']')) { ++p; return out; }
            while(true) {
                ws(); if(obj) { auto k=string(); ws(); expect(':'); out[k]=read(depth+1); } else out.push(read(depth+1));
                ws(); c=take(); if(c==(obj?'}':']')) break; if(c!=',') throw std::runtime_error("Invalid JSON separator");
            } return out;
        }
        for(auto literal: {std::string("true"),std::string("false"),std::string("null")}) if(s.compare(p,literal.size(),literal)==0) { p+=literal.size(); if(literal=="null") return Json(); return literal=="true"; }
        size_t begin=p; if(s[p]=='-') ++p;
        if(p>=s.size()||!std::isdigit((unsigned char)s[p])) throw std::runtime_error("Invalid JSON number");
        if(s[p]=='0') ++p; else while(p<s.size()&&std::isdigit((unsigned char)s[p])) ++p;
        if(p<s.size()&&s[p]=='.') { ++p; size_t q=p; while(p<s.size()&&std::isdigit((unsigned char)s[p])) ++p; if(p==q) throw std::runtime_error("Invalid fraction"); }
        if(p<s.size()&&(s[p]=='e'||s[p]=='E')) { ++p; if(p<s.size()&&(s[p]=='+'||s[p]=='-')) ++p; size_t q=p; while(p<s.size()&&std::isdigit((unsigned char)s[p])) ++p; if(p==q) throw std::runtime_error("Invalid exponent"); }
        double n=std::stod(s.substr(begin,p-begin)); if(!std::isfinite(n)) throw std::runtime_error("JSON number out of range"); return n;
    }
};
inline Json Json::parse(const std::string& s) { Reader r{s}; Json j=r.read(); r.ws(); if(r.p!=s.size()) throw std::runtime_error("Trailing JSON content"); return j; }
inline Json readRequest() {
    std::string s; char buf[4096];
    while(std::cin.read(buf,sizeof(buf)) || std::cin.gcount()) { s.append(buf,size_t(std::cin.gcount())); if(s.size()>8*1024*1024) throw std::runtime_error("Request exceeds 8 MiB"); }
    return Json::parse(s);
}
