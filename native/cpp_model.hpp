#pragma once
#include "json.hpp"
#include <algorithm>
#include <set>
#include <memory>

struct Token { std::string text; size_t start, end; bool identifier=false, literal=false; };
struct Node { std::string kind; int begin=0,end=0,headBegin=0,headEnd=0; std::vector<Node> children; };
struct Function { std::string name; int paramsBegin,paramsEnd; Node body; };
struct Region { std::string kind; size_t start,end; };

// This is a bounded lexical/statement model, not a complete C++ compiler.
struct CppModel {
    const std::string& source;
    std::vector<Token> tokens;
    std::vector<int> mate;
    std::vector<Function> functions;
    std::vector<Region> regions;
    std::vector<std::string> notes;
    explicit CppModel(const std::string& s) : source(s) { lex(); pair(); findFunctions(); }
    std::string at(int i) const { return i>=0 && i<(int)tokens.size()?tokens[i].text:""; }
    size_t start(int i) const { return i>=0 && i<(int)tokens.size()?tokens[i].start:source.size(); }
    size_t end(int i) const { return i>=0 && i<(int)tokens.size()?tokens[i].end:source.size(); }
    void lex() {
        size_t p=0; bool directive=false;
        while(p<source.size()) {
            unsigned char c=source[p];
            if(std::isspace(c)) { ++p; continue; }
            if(source.compare(p,2,"//")==0) { auto e=source.find('\n',p); p=e==std::string::npos?source.size():e; continue; }
            if(source.compare(p,2,"/*")==0) { auto e=source.find("*/",p+2); if(e==std::string::npos) notes.push_back("Unclosed block comment."); p=e==std::string::npos?source.size():e+2; continue; }
            if(c=='#') {
                directive=true;
                while(p<source.size()) { if(source[p]=='\n' && (p==0||source[p-1]!='\\')) { ++p; break; } ++p; }
                continue;
            }
            size_t b=p; size_t quote=std::string::npos; bool raw=false;
            for(const auto& prefix: {"u8R\"","LR\"","uR\"","UR\"","R\"","u8\"","L\"","u\"","U\"","\"","L'","u'","U'","'"}) {
                std::string pre=prefix;
                if(source.compare(p,pre.size(),pre)==0) { quote=p+pre.size()-1; raw=pre.find('R')!=std::string::npos; break; }
            }
            if(quote!=std::string::npos) {
                if(raw) {
                    auto open=source.find('(',quote+1);
                    if(open==std::string::npos||open-quote>17) { p=source.size(); notes.push_back("Unclosed raw string."); }
                    else { auto close=")"+source.substr(quote+1,open-quote-1)+"\""; auto e=source.find(close,open+1); p=e==std::string::npos?source.size():e+close.size(); if(e==std::string::npos) notes.push_back("Unclosed raw string."); }
                } else {
                    char delimiter=source[quote]; p=quote+1; bool closed=false;
                    while(p<source.size()) { char d=source[p++]; if(d=='\\'&&p<source.size()) ++p; else if(d==delimiter) { closed=true; break; } }
                    if(!closed) notes.push_back("Unclosed string or character literal.");
                }
                tokens.push_back({source.substr(b,p-b),b,p,false,true}); continue;
            }
            bool id=std::isalpha(c)||c=='_'||c>=128;
            if(id || std::isdigit(c)) {
                ++p; while(p<source.size() && (std::isalnum((unsigned char)source[p])||source[p]=='_'||(unsigned char)source[p]>=128)) ++p;
            } else {
                ++p;
                if(p<source.size()) { std::string two=source.substr(b,2); if(std::set<std::string>{"::","->","++","--","+=","-=","==","!=","<=",">=","&&","||","<<",">>","*=","/=","&="}.count(two)) ++p; }
            }
            tokens.push_back({source.substr(b,p-b),b,p,id,false});
            if(tokens.size()>100000) throw std::runtime_error("Token limit exceeded");
        }
        if(directive) notes.push_back("Preprocessor directives are skipped; macros and conditional compilation are not evaluated.");
    }
    void pair() {
        mate.assign(tokens.size(),-1); std::vector<int> stack;
        for(int i=0;i<(int)tokens.size();++i) {
            auto t=at(i); if(t=="("||t=="["||t=="{") stack.push_back(i);
            else if(t==")"||t=="]"||t=="}") {
                if(stack.empty()) { notes.push_back("Unmatched closing delimiter; results may be incomplete."); continue; }
                int b=stack.back(); if((at(b)=="("&&t!=")")||(at(b)=="["&&t!="]")||(at(b)=="{"&&t!="}")) { notes.push_back("Mismatched delimiter; results may be incomplete."); continue; }
                stack.pop_back(); mate[b]=i; mate[i]=b;
            }
        }
        if(!stack.empty()) notes.push_back("Unclosed delimiter; results may be incomplete while typing.");
    }
    Node statement(int& p,int limit,int depth=0) {
        if(depth>128) throw std::runtime_error("Statement nesting limit exceeded");
        Node n; n.begin=p; n.kind="statement";
        if(p>=limit) { n.end=p; return n; }
        std::string k=at(p);
        if(k=="{") {
            n.kind="block"; int stop=mate[p]>=0?std::min(mate[p],limit):limit; ++p;
            while(p<stop) { int old=p; n.children.push_back(statement(p,stop,depth+1)); if(p<=old) ++p; }
            if(at(p)=="}") ++p;
        } else if(k=="if"||k=="for"||k=="while"||k=="switch"||k=="catch") {
            n.kind=k; ++p; if(at(p)=="constexpr") ++p;
            n.headBegin=p;
            if(at(p)=="("&&mate[p]>=0) { n.headBegin=p+1; n.headEnd=mate[p]; p=mate[p]+1; }
            else n.headEnd=p;
            n.children.push_back(statement(p,limit,depth+1));
            if(k=="if"&&at(p)=="else") { Node e; e.kind="else"; e.begin=p++; e.children.push_back(statement(p,limit,depth+1)); e.end=p; n.children.push_back(e); }
        } else if(k=="do"||k=="try"||k=="else") {
            n.kind=k=="do"?"do-while":k; ++p; n.children.push_back(statement(p,limit,depth+1));
            if(k=="do"&&at(p)=="while") { ++p; if(at(p)=="("&&mate[p]>=0) { n.headBegin=p+1; n.headEnd=mate[p]; p=mate[p]+1; } if(at(p)==";") ++p; }
            if(k=="try") while(at(p)=="catch") n.children.push_back(statement(p,limit,depth+1));
        } else if(k=="case"||k=="default") {
            n.kind=k; ++p; while(p<limit&&at(p)!=":") { if(at(p)=="("&&mate[p]>p) p=mate[p]+1; else ++p; } if(at(p)==":") ++p;
            while(p<limit&&at(p)!="case"&&at(p)!="default"&&at(p)!="}") { int old=p; n.children.push_back(statement(p,limit,depth+1)); if(p<=old) ++p; }
        } else {
            if(k=="return"||k=="throw"||k=="break"||k=="continue") n.kind=k;
            while(p<limit) { auto t=at(p); if(t==";") { ++p; break; } if(t=="}") break; if((t=="("||t=="["||t=="{")&&mate[p]>p) p=mate[p]+1; else ++p; }
            if(p==n.begin) ++p;
        }
        n.end=p; return n;
    }
    void addRegions(const Node& n) {
        static const std::set<std::string> kinds={"if","else","for","while","do-while","switch","case","default","try","catch"};
        if(kinds.count(n.kind)) regions.push_back({n.kind,start(n.begin),n.end>n.begin?end(n.end-1):start(n.begin)});
        for(const auto& c:n.children) addRegions(c);
    }
    void findFunctions() {
        for(int i=0;i<(int)tokens.size();++i) {
            if(at(i)!="{"||mate[i]<0) continue;
            int close=i-1;
            while(close>=0 && (at(close)=="const"||at(close)=="noexcept"||at(close)=="override"||at(close)=="final")) --close;
            if(at(close)!=")"||mate[close]<1) continue;
            int open=mate[close],name=open-1;
            if(!tokens[name].identifier||std::set<std::string>{"if","for","while","switch","catch"}.count(at(name))) continue;
            int p=i; Node body=statement(p,(int)tokens.size());
            functions.push_back({at(name),open+1,close,body});
            regions.push_back({"function",start(name),end(body.end-1)}); addRegions(body); i=p-1;
        }
        if(functions.empty()&&!tokens.empty()) notes.push_back("No supported function definitions found; this snapshot may be a header, incomplete, or use unsupported syntax.");
    }
    std::vector<std::pair<int,int>> args(int open) const {
        std::vector<std::pair<int,int>> out;
        if(open<0||open>=(int)mate.size()||mate[open]<0) return out;
        int b=open+1,e=mate[open];
        for(int i=b;i<e;++i) { if((at(i)=="("||at(i)=="["||at(i)=="{")&&mate[i]>i) i=mate[i]; else if(at(i)==",") { out.push_back({b,i}); b=i+1; } }
        if(b<e) out.push_back({b,e});
        return out;
    }
    int line(size_t byte) const { return 1+(int)std::count(source.begin(),source.begin()+std::min(byte,source.size()),'\n'); }
};
