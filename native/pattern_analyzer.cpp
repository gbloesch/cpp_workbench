#include "cpp_model.hpp"

static const std::vector<std::string> Locations={"for","while","do-while","if","else","case","default","switch","try","catch","function","global-or-unknown"};
Json contextAt(const CppModel& model,size_t byte) {
    std::vector<Region> regions;
    for(const auto& r:model.regions) if(byte>=r.start&&byte<r.end) regions.push_back(r);
    std::sort(regions.begin(),regions.end(),[](const Region& a,const Region& b) { return (a.end-a.start)>(b.end-b.start); });
    Json path=Json::array(); for(const auto& r:regions) path.push(r.kind);
    if(path.items().empty()) path.push("global-or-unknown");
    return path;
}
int main() {
    try {
        auto req=readRequest();
        if(!req["source"].isString()||!req["analysis"]["findings"].isArray()) throw std::runtime_error("Expected source and analysis.findings");
        auto source=req["source"].str(); CppModel model(source);
        auto findings=req["analysis"]["findings"];
        std::map<std::string,int> counts; std::map<std::string,int> byType;
        for(auto& f:findings.items()) {
            size_t byte=(size_t)f["startByte"].number(); auto contexts=contextAt(model,byte);
            std::string primary=contexts.items().back().str();
            f["contexts"]=contexts; f["primaryContext"]=primary;
            if(f.has("relatedLocation")) f["relatedLocation"]["contexts"]=contextAt(model,(size_t)f["relatedLocation"]["startByte"].number());
            ++counts[f["type"].str()+":"+primary]; ++byType[f["type"].str()];
        }
        size_t total=findings.items().size(); Json rows=Json::array();
        for(const auto& type:{"memory-leak","sql-injection"}) for(const auto& location:Locations) {
            int count=counts[std::string(type)+":"+location],denom=byType[type];
            Json row=Json::object(); row["type"]=type; row["location"]=location; row["count"]=count;
            row["percentOfType"]=denom?std::round(10000.0*count/denom)/100.0:0.0;
            row["percentOfAll"]=total?std::round(10000.0*count/total)/100.0:0.0;
            rows.push(row);
        }
        Json result=Json::object(); result["schemaVersion"]=1; result["totalFindings"]=total;
        result["memoryLeakCount"]=byType["memory-leak"]; result["sqlInjectionCount"]=byType["sql-injection"];
        result["locationBasis"]="innermost recognized construct at the finding's primary source location; memory leaks use the allocation site";
        result["rows"]=rows; result["findings"]=findings; result["analysis"]=req["analysis"];
        // Avoid duplicating findings in the report metadata.
        std::get<Json::Object>(result["analysis"].value).erase("findings");
        std::cout<<result.dump()<<'\n'; return 0;
    } catch(const std::exception& e) { std::cerr<<"Pattern analyzer: "<<e.what()<<'\n'; return 1; }
}
