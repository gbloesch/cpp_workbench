#pragma once
#include "cpp_model.hpp"
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string>

// Conservative heuristic: report signed-int overflow only when both values
// are established (literal values or simple straight-line constant assignments).
// Unknown operands are deliberately silent. This is not full C++ range analysis.
template <typename Emit>
void scanIntegerOverflow(const CppModel& model, Emit emit) {
    auto at = [&](int i) -> std::string { return model.at(i); };
    constexpr int64_t minimum = std::numeric_limits<int32_t>::min();
    constexpr int64_t maximum = std::numeric_limits<int32_t>::max();
    auto literal = [&](int i, int64_t& value) -> bool {
        const std::string s = at(i);
        if (s.empty()) return false;
        for (char c : s) if (c < '0' || c > '9') return false;
        try { value = std::stoll(s); return true; }
        catch (...) { return false; }
    };
    for (const auto& f : model.functions) {
        std::set<std::string> signedInts;
        std::map<std::string, int64_t> known;
        for (int i = f.paramsBegin; i + 1 < f.paramsEnd; ++i)
            if (at(i) == "int" && model.tokens[i + 1].identifier &&
                at(i - 1) != "unsigned") signedInts.insert(at(i + 1));

        // The simple constant tracker is valid only before control flow.
        // Literal-vs-literal checks still run after branches or loops.
        bool straightLine = true;
        auto operand = [&](int i, int64_t& value) -> bool {
            if (literal(i, value)) return true;
            auto k = known.find(at(i));
            if (straightLine && k != known.end()) { value = k->second; return true; }
            return false;
        };
        auto report = [&](int token) {
            emit(token, "integer.overflow-proven",
                 "Integer overflow: arithmetic exceeds the signed 32-bit int range.",
                 "Operands have known values; signed 32-bit range is -2147483648 to 2147483647. Validate operands or use checked/wider arithmetic.");
        };
        for (int i = f.body.begin + 1; i + 1 < f.body.end; ++i) {
            const auto op = at(i);
            if (op == "if" || op == "for" || op == "while" || op == "do" ||
                op == "switch" || op == "try" || op == "catch" || op == "goto") {
                known.clear();
                straightLine = false;
            }
            if (op == "int" && model.tokens[i + 1].identifier &&
                at(i - 1) != "unsigned" && at(i - 1) != "::")
                signedInts.insert(at(i + 1));

            if (op == "=" && i > f.body.begin && signedInts.count(at(i - 1))) {
                int64_t v = 0;
                if (straightLine && operand(i + 1, v) && at(i + 2) == ";" &&
                    v >= minimum && v <= maximum)
                    known[at(i - 1)] = v;
                else known.erase(at(i - 1));
            }
            if (op == "++" || op == "--") {
                // Prefix ++x or postfix x++.
                const std::string name = model.tokens[i + 1].identifier ? at(i + 1) : at(i - 1);
                if (!signedInts.count(name)) continue;
                auto k = known.find(name);
                if (straightLine && k != known.end()) {
                    int64_t value = k->second + (op == "++" ? 1 : -1);
                    if (value < minimum || value > maximum) { report(i); known.erase(name); }
                    else k->second = value;
                } else known.erase(name);
                continue;
            }
            if (op != "+" && op != "-" && op != "*" &&
                op != "+=" && op != "-=" && op != "*=") continue;
            if (i <= f.body.begin || at(i - 1) == "=" || at(i - 1) == "(" ||
                at(i - 1) == "," || at(i - 1) == "return") continue;
            if (at(i + 1) == "+" || at(i + 1) == "-") continue;

            const bool compound = op == "+=" || op == "-=" || op == "*=";
            bool signedContext = signedInts.count(at(i - 1)) || signedInts.count(at(i + 1));
            // int result = <arithmetic>
            if (!signedContext && i >= f.body.begin + 3 &&
                at(i - 2) == "=" && signedInts.count(at(i - 3))) signedContext = true;
            if (!signedContext) continue;
            int64_t lhs = 0, rhs = 0;
            bool leftKnown = operand(i - 1, lhs), rightKnown = operand(i + 1, rhs);
            if (!leftKnown || !rightKnown) {
                if (compound) known.erase(at(i - 1));
                continue;
            }
            int64_t result = 0;
            if (op == "+" || op == "+=") result = lhs + rhs;
            else if (op == "-" || op == "-=") result = lhs - rhs;
            else result = lhs * rhs; // int32 operands: product fits in int64
            if (result < minimum || result > maximum) {
                report(i);
                if (compound) known.erase(at(i - 1));
            } else if (compound && straightLine) known[at(i - 1)] = result;
        }
    }
}
