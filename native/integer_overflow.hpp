#pragma once
#include "cpp_model.hpp"
#include <cstdint>
#include <limits>
#include <map>
#include <string>

// Lightweight, heuristic check for 32-bit signed-int arithmetic.
// This is not a full type-checker or a path-sensitive range analysis.
template <typename Emit>
void scanIntegerOverflow(const CppModel& model, Emit emit) {
    const auto& t = model.tokens;
    auto at = [&](int i) { return model.at(i); };
    auto number = [](const std::string& s, int64_t& result) -> bool {
        if (s.empty()) return false;
        for (char c : s) if (c < '0' || c > '9') return false;
        try { result = std::stoll(s); return true; }
        catch (...) { return false; }
    };
    const int64_t low = std::numeric_limits<int32_t>::min();
    const int64_t high = std::numeric_limits<int32_t>::max();
    for (const auto& f : model.functions) {
        std::map<std::string, bool> signedInts;
        // Simple signed-int local declarations.
        for (int i = f.body.begin; i + 1 < f.body.end; ++i) {
            if (at(i) == "int" && t[i + 1].identifier &&
                at(i - 1) != "unsigned" && at(i - 1) != "::")
                signedInts[at(i + 1)] = true;
        }
        // Simple signed-int function parameters.
        for (int i = f.paramsBegin; i + 1 < f.paramsEnd; ++i) {
            if (at(i) == "int" && t[i + 1].identifier && at(i - 1) != "unsigned")
                signedInts[at(i + 1)] = true;
        }
        for (int i = f.body.begin + 1; i + 1 < f.body.end; ++i) {
            const auto op = at(i);
            if (op != "+" && op != "-" && op != "*" &&
                op != "+=" && op != "-=" && op != "*=" &&
                op != "++" && op != "--") continue;

            std::string lhs = at(i - 1), rhs = at(i + 1);
            bool increment = op == "++" || op == "--";
            if (increment && t[i + 1].identifier) lhs = rhs; // prefix
            bool lhsInt = signedInts.count(lhs) != 0;
            bool rhsInt = signedInts.count(rhs) != 0;
            bool targetInt = false;
            // Recognize "int result = a + b" or "result = a + b".
            if (!increment && op != "+=" && op != "-=" && op != "*=") {
                for (int j = i - 2; j >= f.body.begin && j >= i - 8; --j) {
                    if (at(j) == ";" || at(j) == "{" || at(j) == "}") break;
                    if (at(j) == "=" && j > f.body.begin &&
                        signedInts.count(at(j - 1))) { targetInt = true; break; }
                }
            }
            if (!lhsInt && !rhsInt && !targetInt) continue;
            if (increment && !lhsInt) continue;

            int64_t a = 0, b = 0;
            bool knownA = number(at(i - 1), a), knownB = number(at(i + 1), b);
            bool definite = false;
            if (!increment && op != "+=" && op != "-=" && op != "*=" && knownA && knownB) {
                long double result = op == "+" ? (long double)a + b :
                                     op == "-" ? (long double)a - b :
                                                 (long double)a * b;
                definite = result < low || result > high;
                if (!definite) continue;
            }
            // Avoid flagging unary minus as a binary operation.
            if (op == "-" && (at(i - 1) == "=" || at(i - 1) == "(" ||
                              at(i - 1) == "," || at(i - 1) == "return")) continue;

            emit(i,
                 definite ? "integer.overflow-constant" : "integer.possible-overflow",
                 definite
                     ? "Integer overflow: this constant arithmetic exceeds the signed 32-bit int range."
                     : "Possible integer overflow: signed int arithmetic may exceed its valid range.",
                 "Signed 32-bit int range: -2147483648 to 2147483647. Check operands before computing or use safe, wider arithmetic.");
        }
    }
}
