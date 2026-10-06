#include "cpp_model.hpp"
#include <optional>

struct Allocation { int token; std::string variable, family; };
struct SavedBinding { std::optional<int> alias; std::optional<std::string> taint; };
struct Scope { std::map<std::string,SavedBinding> saved; std::set<int> owned; };
struct State {
    std::map<int,Allocation> live;
    std::map<std::string,int> aliases;
    std::map<std::string,std::string> taint;
    std::vector<Scope> scopes;
    std::string flow="normal";
    int exitToken=-1;
};

class SecurityAnalyzer {
    CppModel model;
    const Json& rules;
    Json findings=Json::array();
    std::set<std::string> emitted;
    size_t steps=0;
    bool truncated=false;
    static constexpr size_t MaxPaths=64,MaxSteps=80000;
    bool sqlEnabled=true,memoryEnabled=true;
    std::map<std::string,int> sinks;
    std::set<std::string> sources;
    std::set<std::string> allocators={"malloc","calloc","realloc"};
    std::set<std::string> ignoredCalls={"sizeof","alignof","decltype","printf","fprintf","puts","assert","strlen","memset","memcpy","free","malloc","calloc","realloc","unique_ptr","shared_ptr","make_unique","make_shared","move","c_str","data","size","length","empty"};
    std::string word(int i) const { return model.at(i); }
    void emit(const std::string& type,const std::string& rule,int token,const std::string& message,const std::string& evidence,int related=-1) {
        if(token<0||token>=(int)model.tokens.size()) return;
        if((type=="memory-leak"&&!memoryEnabled)||(type=="sql-injection"&&!sqlEnabled)) return;
        std::string key=rule+":"+std::to_string(model.start(token));
        if(!emitted.insert(key).second) return;
        Json f=Json::object(); f["id"]=key; f["type"]=type; f["ruleId"]=rule;
        f["severity"]="warning"; f["confidence"]="heuristic";
        f["cwe"]=type=="memory-leak"?"CWE-401":"CWE-89";
        f["startByte"]=model.start(token); f["endByte"]=model.end(token);
        f["line"]=model.line(model.start(token)); f["message"]=message; f["evidence"]=evidence;
        if(related>=0) { Json r=Json::object(); r["startByte"]=model.start(related); r["endByte"]=model.end(related); r["line"]=model.line(model.start(related)); r["message"]="Possible path exits or loses ownership here."; f["relatedLocation"]=r; }
        findings.push(f);
    }
    void leak(const Allocation& a,const std::string& why,int related) {
        emit("memory-leak","memory.unreleased",a.token,"Possible memory leak: '"+a.variable+"' may remain allocated. "+why,"Allocation uses "+a.family+". Review ownership and all cleanup paths.",related);
    }
    void declare(State& s,const std::string& name) {
        if(s.scopes.empty()||s.scopes.back().saved.count(name)) return;
        SavedBinding saved;
        if(s.aliases.count(name)) saved.alias=s.aliases[name];
        if(s.taint.count(name)) saved.taint=s.taint[name];
        s.scopes.back().saved[name]=saved; s.aliases.erase(name); s.taint.erase(name);
    }
    void leaveScope(State& s) {
        auto scope=s.scopes.back(); s.scopes.pop_back();
        for(int id:scope.owned) s.live.erase(id);
        for(const auto& kv:scope.saved) {
            if(kv.second.alias) s.aliases[kv.first]=*kv.second.alias; else s.aliases.erase(kv.first);
            if(kv.second.taint) s.taint[kv.first]=*kv.second.taint; else s.taint.erase(kv.first);
        }
    }
    std::string taint(const State& s,int b,int e) const {
        for(int i=b;i<e;++i) {
            if(model.tokens[i].literal) continue;
            if(s.taint.count(word(i))) return s.taint.at(word(i));
            if(sources.count(word(i))&&word(i+1)=="(") return "input from "+word(i);
            if(word(i)=="argv") return "command-line input";
        } return "";
    }
    bool has(int b,int e,const std::string& w) const { for(int i=b;i<e;++i) if(word(i)==w) return true; return false; }
    std::string lastId(int b,int e) const { for(int i=e-1;i>=b;--i) if(model.tokens[i].identifier) return word(i); return ""; }
    void release(State& s,int b,int e) {
        for(int i=b;i<e;++i) if(s.aliases.count(word(i))) { s.live.erase(s.aliases[word(i)]); return; }
    }
    void process(int b,int e,State& s) {
        if(b>=e) return;
        // Detect a simple declaration or assignment. Declarations with templates and
        // pointers are supported; complex declarators remain outside this model.
        int eq=-1;
        for(int i=b;i<e;++i) {
            if(word(i)=="="||word(i)=="+=") { eq=i; break; }
            if((word(i)=="("||word(i)=="[")&&model.mate[i]>i) i=model.mate[i];
        }
        std::string target=eq>b?lastId(b,eq):"";
        int targetToken=eq-1; while(targetToken>=b&&!model.tokens[targetToken].identifier) --targetToken;
        bool declaration=eq>b&&targetToken>b&&word(b)!="return"&&word(b)!="throw" && !has(b,eq,".")&&!has(b,eq,"->")&&!has(b,eq,"[");
        if(declaration) declare(s,target);
        std::string rhsTaint=eq>=0?taint(s,eq+1,e):"";
        if(!target.empty()) {
            if(word(eq)=="+="&&!rhsTaint.empty()) s.taint[target]=rhsTaint;
            else if(word(eq)=="=") { if(rhsTaint.empty()) s.taint.erase(target); else s.taint[target]=rhsTaint; }
        }
        if(has(b,e,"cin")) for(int i=b;i+1<e;++i) if(word(i)==">>"&&model.tokens[i+1].identifier) s.taint[word(i+1)]="standard input";
        for(int i=b;i<e;++i) {
            std::string w=word(i);
            if(w=="getline"&&word(i+1)=="(") { auto args=model.args(i+1); if(args.size()>1) { auto name=lastId(args[1].first,args[1].second); if(!name.empty()) s.taint[name]="line input"; } }
            if((w=="fgets"||w=="gets"||w=="scanf"||w=="recv"||w=="read")&&word(i+1)=="(") {
                auto args=model.args(i+1); size_t pos=(w=="recv"||w=="read"||w=="scanf")?1:0;
                for(size_t a=pos;a<args.size()&&(w=="scanf"||a==pos);++a) { auto name=lastId(args[a].first,args[a].second); if(!name.empty()) s.taint[name]="input from "+w; }
            }
            if((w=="sprintf"||w=="snprintf"||w=="strcpy"||w=="strcat")&&word(i+1)=="(") {
                auto args=model.args(i+1); if(args.size()>1) { auto name=lastId(args[0].first,args[0].second); std::string reason=taint(s,args[1].first,model.mate[i+1]); if(!reason.empty()) s.taint[name]=reason; else if(w!="strcat") s.taint.erase(name); }
            }
            if((w=="append"||w=="assign")&&word(i-1)=="."&&word(i+1)=="(") {
                std::string reason=taint(s,i+2,model.mate[i+1]); if(!reason.empty()) s.taint[word(i-2)]=reason; else if(w=="assign") s.taint.erase(word(i-2));
            }
            if(sinks.count(w)&&word(i+1)=="(") {
                auto args=model.args(i+1); int index=sinks[w];
                if(index>=0&&index<(int)args.size()) {
                    auto q=args[index]; std::string reason=taint(s,q.first,q.second);
                    if(!reason.empty()) emit("sql-injection","sql.tainted-query",i,"Possible SQL injection: input-derived data reaches the SQL text passed to "+w+". Use a fixed query with bound parameters.",reason);
                }
            }
            if(w=="delete") release(s,i+1,e);
            if(w=="free"&&word(i+1)=="(") release(s,i+2,model.mate[i+1]);
        }
        // Model aliases and manual allocations. Smart-pointer construction takes
        // ownership; managed allocations are released when their scope exits.
        int allocation=-1;
        for(int i=b;i<e;++i) if(word(i)=="new"||(allocators.count(word(i))&&word(i+1)=="(")) { allocation=i; break; }
        bool smart=has(b,e,"unique_ptr")||has(b,e,"shared_ptr");
        if(allocation>=0) {
            // Placement new initializes existing storage; it does not allocate here.
            if(word(allocation)=="new"&&word(allocation+1)=="("&&!has(allocation+1,e,"nothrow")) return;
            if(word(b)=="return") return; // Explicit ownership transfer to caller.
            bool stored=!target.empty();
            if(word(allocation)=="realloc") {
                auto args=model.args(allocation+1);
                if(!args.empty()) {
                    auto old=lastId(args[0].first,args[0].second);
                    if(old==target&&s.aliases.count(old)&&s.live.count(s.aliases[old])) {
                        emit("memory-leak","memory.realloc-overwrite",allocation,"Possible memory leak: assigning realloc directly to its original pointer loses that pointer if realloc fails. Use a temporary pointer.","Original pointer: "+old);
                        s.live.erase(s.aliases[old]);
                    } else {
                        // Success/failure of indirect realloc requires a richer model.
                        if(s.aliases.count(old)) s.live.erase(s.aliases[old]);
                        return;
                    }
                }
            }
            if(stored&&s.aliases.count(target)&&s.live.count(s.aliases[target])) {
                int old=s.aliases[target]; bool other=false;
                for(const auto& a:s.aliases) if(a.first!=target&&a.second==old) other=true;
                if(!other) { leak(s.live[old],"The pointer is overwritten before cleanup.",targetToken); s.live.erase(old); }
            }
            if(smart) { if(!s.scopes.empty()) s.scopes.back().owned.insert(allocation); }
            else if(!stored) {
                // A new-expression passed to a call may transfer ownership.
                if(word(b)!="new") return;
            }
            s.live[allocation]={allocation,stored?target:"unnamed allocation",word(allocation)};
            if(stored) s.aliases[target]=allocation;
        } else if(!target.empty()&&word(eq)=="=") {
            int alias=-1;
            for(int i=eq+1;i<e;++i) if(s.aliases.count(word(i))) { alias=s.aliases[word(i)]; break; }
            if(s.aliases.count(target)&&s.live.count(s.aliases[target])&&s.aliases[target]!=alias) {
                int old=s.aliases[target]; bool other=false; for(const auto& a:s.aliases) if(a.first!=target&&a.second==old) other=true;
                if(!other) { leak(s.live[old],"The pointer is overwritten before cleanup.",targetToken); s.live.erase(old); }
            }
            if(alias>=0) s.aliases[target]=alias; else s.aliases.erase(target);
        }
        if(smart) for(int i=b;i<e;++i) if(s.aliases.count(word(i))&&!s.scopes.empty()) s.scopes.back().owned.insert(s.aliases[word(i)]);
        if(word(b)=="return") for(int i=b+1;i<e;++i) if(s.aliases.count(word(i))) s.live.erase(s.aliases[word(i)]);
        // Unknown callees may retain/free pointer arguments. Suppress those
        // allocations to avoid claiming a leak when ownership is unknown.
        for(int i=b;i+1<e;++i) if(model.tokens[i].identifier&&word(i+1)=="("&&!ignoredCalls.count(word(i))&&!sinks.count(word(i))&&!sources.count(word(i))&&word(i)!="getline") {
            int close=model.mate[i+1]; if(close<0) continue;
            for(int j=i+2;j<close;++j) if(s.aliases.count(word(j))) s.live.erase(s.aliases[word(j)]);
        }
    }
    std::vector<State> limit(std::vector<State> v) { if(v.size()>MaxPaths) { truncated=true; v.resize(MaxPaths); } return v; }
    std::vector<State> sequence(const std::vector<Node>& nodes,std::vector<State> states) {
        for(const auto& n:nodes) states=run(n,std::move(states));
        return states;
    }
    void refine(const Node& n,State& s,bool truth) {
        // On !p, p == nullptr/NULL/0, or p != nullptr branches, avoid treating a
        // failed malloc as an allocation. This is deliberately a small model.
        int b=n.headBegin,e=n.headEnd; std::string name; bool nullBranch=false;
        if(e-b==2&&word(b)=="!") { name=word(b+1); nullBranch=truth; }
        else if(e-b==1) { name=word(b); nullBranch=!truth; }
        else if(e-b==3&&(word(b+1)=="=="||word(b+1)=="!=")&&(word(b+2)=="nullptr"||word(b+2)=="NULL"||word(b+2)=="0")) { name=word(b); nullBranch=(word(b+1)=="==")==truth; }
        if(nullBranch&&s.aliases.count(name)) s.live.erase(s.aliases[name]);
    }
    std::vector<State> run(const Node& n,std::vector<State> input) {
        if((steps+=input.size())>MaxSteps) { truncated=true; return input; }
        std::vector<State> output;
        for(auto s:input) {
            if(s.flow!="normal") { output.push_back(std::move(s)); continue; }
            if(n.kind=="block") {
                s.scopes.push_back({}); auto states=sequence(n.children,{s});
                for(auto& x:states) { leaveScope(x); output.push_back(std::move(x)); }
            } else if(n.kind=="if") {
                process(n.headBegin,n.headEnd,s);
                bool canTrue=!(n.headEnd-n.headBegin==1&&(word(n.headBegin)=="false"||word(n.headBegin)=="0"));
                bool canFalse=!(n.headEnd-n.headBegin==1&&(word(n.headBegin)=="true"||word(n.headBegin)=="1"));
                if(canTrue) { State yes=s; refine(n,yes,true); auto ys=run(n.children[0],{yes}); output.insert(output.end(),ys.begin(),ys.end()); }
                if(canFalse) { refine(n,s,false); auto ns=n.children.size()>1?run(n.children[1],{s}):std::vector<State>{s}; output.insert(output.end(),ns.begin(),ns.end()); }
            } else if(n.kind=="for"||n.kind=="while"||n.kind=="do-while") {
                // Zero/one iteration approximation; never claim full loop reasoning.
                process(n.headBegin,n.headEnd,s);
                if(n.kind!="do-while") output.push_back(s);
                auto body=run(n.children[0],{s});
                for(auto& x:body) { if(x.flow=="break"||x.flow=="continue") { x.flow="normal"; x.exitToken=-1; } output.push_back(std::move(x)); }
            } else if(n.kind=="switch") {
                process(n.headBegin,n.headEnd,s); const auto& branches=n.children[0].children; bool hasDefault=false;
                for(size_t i=0;i<branches.size();++i) if(branches[i].kind=="case"||branches[i].kind=="default") {
                    hasDefault|=branches[i].kind=="default";
                    std::vector<State> branch{s};
                    for(size_t j=i;j<branches.size();++j) branch=run(branches[j],std::move(branch));
                    for(auto& x:branch) { if(x.flow=="break") { x.flow="normal"; x.exitToken=-1; } output.push_back(std::move(x)); }
                }
                if(!hasDefault) output.push_back(s);
            } else if(n.kind=="try") {
                // Each try/catch is a possible path; exception matching is not modeled.
                for(const auto& child:n.children) { auto xs=run(child,{s}); output.insert(output.end(),xs.begin(),xs.end()); }
            } else if(n.kind=="case"||n.kind=="default"||n.kind=="else"||n.kind=="catch") {
                auto xs=sequence(n.children,{s}); output.insert(output.end(),xs.begin(),xs.end());
            } else {
                process(n.begin,n.end,s);
                if(n.kind=="return"||n.kind=="throw"||n.kind=="break"||n.kind=="continue") { s.flow=n.kind; s.exitToken=n.begin; }
                output.push_back(std::move(s));
            }
            if(output.size()>MaxPaths) { truncated=true; output.resize(MaxPaths); break; }
        } return limit(std::move(output));
    }
public:
    SecurityAnalyzer(const std::string& source,const Json& r):model(source),rules(r) {
        sqlEnabled=rules["sqlEnabled"].boolean(true); memoryEnabled=rules["memoryEnabled"].boolean(true);
        if(rules["sqlSinks"].isArray()) for(const auto& x:rules["sqlSinks"].items()) sinks[x["name"].str()]=(int)x["queryArgument"].number();
        if(rules["inputFunctions"].isArray()) for(const auto& x:rules["inputFunctions"].items()) sources.insert(x.str());
    }
    Json analyze() {
        for(const auto& f:model.functions) {
            State s;
            // A configurable assumption, recorded in every parameter-derived finding.
            if(rules["treatParametersAsInput"].boolean(true)) {
                int b=f.paramsBegin;
                for(int i=b;i<=f.paramsEnd;++i) if(i==f.paramsEnd||word(i)==",") {
                    if(has(b,i,"string")||has(b,i,"string_view")||has(b,i,"char")||has(b,i,"wchar_t")) { auto name=lastId(b,i); if(!name.empty()) s.taint[name]="potentially untrusted function parameter '"+name+"' (configured assumption)"; }
                    b=i+1;
                }
            }
            auto paths=run(f.body,{s});
            for(const auto& path:paths) for(const auto& a:path.live) leak(a.second,path.flow=="return"||path.flow=="throw"?"An exit can skip cleanup.":"No modeled release or ownership transfer was found on an explored path.",path.exitToken>=0?path.exitToken:f.body.end-1);
        }
        Json result=Json::object(); result["schemaVersion"]=1; result["engine"]="cpp-security-workbench/0.1"; result["analysisKind"]="heuristic-static-analysis"; result["findings"]=findings;
        result["functionsAnalyzed"]=model.functions.size(); result["truncated"]=truncated;
        Json notes=Json::array(); for(const auto& n:model.notes) notes.push(n);
        if(truncated) notes.push("Path or step limit reached; results are incomplete.");
        result["notes"]=notes; return result;
    }
};
int main() {
    try { auto req=readRequest(); if(!req["source"].isString()||!req["rules"].isObject()) throw std::runtime_error("Expected source string and rules object"); auto source=req["source"].str(); SecurityAnalyzer analyzer(source,req["rules"]); std::cout<<analyzer.analyze().dump()<<'\n'; return 0; }
    catch(const std::exception& e) { std::cerr<<"Security analyzer: "<<e.what()<<'\n'; return 1; }
}
