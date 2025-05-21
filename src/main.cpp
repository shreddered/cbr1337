#include "dex/disasm.h"
#include "graph/dalvik.h"
#include "obfus.h"

#include <LIEF/LIEF.hpp>

#include <boost/functional/hash.hpp>

#include <boost/graph/graphviz.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace aid::graph;

void addRelation(const LIEF::DEX::Class* from, const LIEF::DEX::Class* to,
    aid::graph::DexGraph& g)
{
    auto src = boost::add_vertex(ClassVertex{from->index(), from->fullname()}, g);
    auto dst = boost::add_vertex(ClassVertex{to->index(), to->fullname()}, g);
    boost::add_edge(src, dst, g);
}

void processMethod(std::unique_ptr<LIEF::DEX::File> const &dex, const std::unordered_set<size_t> imp,
    const LIEF::DEX::Method& mtd, aid::graph::DexGraph& g)
{
    const auto& code = mtd.bytecode();
    if (code.empty())
        return;

    auto bc = aid::dalvik::Bytecode(code);
    const auto methods = dex->methods();
    const auto fields = dex->fields();
    const auto classes = dex->classes();

    for (auto insn : bc) {
        const auto op = insn.opcode();
        uint32_t id = 0;
        switch (op) {
            case aid::dalvik::Opcode::INVOKE_VIRTUAL:
            case aid::dalvik::Opcode::INVOKE_STATIC:
            case aid::dalvik::Opcode::INVOKE_DIRECT:
                id = insn.arg();
                if (id < methods.size()) {
                    const auto& callee = methods[id];
                    const auto clz = callee.cls();
                    if (clz->index() != mtd.cls()->index() && !imp.contains(clz->index()))
                        addRelation(mtd.cls(), clz, g);
                }
                break;
            case aid::dalvik::Opcode::IGET:
            case aid::dalvik::Opcode::IGET_WIDE:
            case aid::dalvik::Opcode::IGET_OBJECT:
            case aid::dalvik::Opcode::IGET_BOOLEAN:
            case aid::dalvik::Opcode::IGET_BYTE:
            case aid::dalvik::Opcode::IGET_CHAR:
            case aid::dalvik::Opcode::IGET_SHORT:
            case aid::dalvik::Opcode::IPUT:
            case aid::dalvik::Opcode::IPUT_WIDE:
            case aid::dalvik::Opcode::IPUT_OBJECT:
            case aid::dalvik::Opcode::IPUT_BOOLEAN:
            case aid::dalvik::Opcode::IPUT_BYTE:
            case aid::dalvik::Opcode::IPUT_CHAR:
            case aid::dalvik::Opcode::IPUT_SHORT:

            case aid::dalvik::Opcode::SGET:
            case aid::dalvik::Opcode::SGET_WIDE:
            case aid::dalvik::Opcode::SGET_OBJECT:
            case aid::dalvik::Opcode::SGET_BOOLEAN:
            case aid::dalvik::Opcode::SGET_BYTE:
            case aid::dalvik::Opcode::SGET_CHAR:
            case aid::dalvik::Opcode::SGET_SHORT:
            case aid::dalvik::Opcode::SPUT:
            case aid::dalvik::Opcode::SPUT_WIDE:
            case aid::dalvik::Opcode::SPUT_OBJECT:
            case aid::dalvik::Opcode::SPUT_BOOLEAN:
            case aid::dalvik::Opcode::SPUT_BYTE:
            case aid::dalvik::Opcode::SPUT_CHAR:
            case aid::dalvik::Opcode::SPUT_SHORT:
               id = insn.arg();
               if (id < fields.size()) {
                    const auto& field = fields[id];
                    const auto clz = field.cls();
                    if (clz->index() != mtd.cls()->index() && !imp.contains(clz->index()))
                        addRelation(mtd.cls(), clz, g);
               }
               break;
            case aid::dalvik::Opcode::CONST_CLASS:
                id = insn.arg();
                if (id < classes.size()) {
                    const auto& clz = classes[id];
                    if (clz.index() != mtd.cls()->index() && !imp.contains(clz.index()))
                        addRelation(mtd.cls(), &clz, g);
                }
                break;
            default:
                break;
        }
    }
}

std::unordered_set<size_t> importedClasses(const std::unique_ptr<LIEF::DEX::File>& dex) {
    std::unordered_set<size_t> res;
    auto classes = dex->classes();
    for (const auto& cls : classes) {
        auto methods = cls.methods();
        bool imported = true;
        for (const auto& m : methods) {
            if (!m.bytecode().empty()) {
                imported = false;
                break;
            }
        }
        if (imported)
            res.insert(cls.index());
    }
    return res;
}

aid::graph::DexGraph createCallGraph(std::unique_ptr<LIEF::DEX::File> const &dex) {
    // first simple try
    auto imported = importedClasses(dex);
    aid::graph::DexGraph g;
    std::cout << "num of v: " << boost::num_vertices(g) << std::endl;

    auto classes = dex->classes();
    for (const auto& cls : classes) {
        auto methods = cls.methods();
        for (const auto& m : methods)
            processMethod(dex, imported, m, g);
    }
    return g;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <path/to/classes.dex> <path/to/output>" << std::endl;
        return -1;
    }
    const auto dexPath = argv[1];
    const auto outPath = argv[2];
    auto dex = LIEF::DEX::Parser::parse(dexPath);
    if (dex == nullptr) {
        std::cout << "Invalid DEX file: '" << dexPath << '\'' << std::endl;
        return -1;
    }
    auto g = createCallGraph(dex);
    auto map = boost::get(&ClassVertex::classId, g);
    {
        const auto kek = boost::vertices(g);
        for (auto it = kek.first; it != kek.second; ++it) {
            std::cout << map[*it] << std::endl;
        }
    }
    {
        const auto kek = boost::edges(g);
        for (auto it = kek.first; it != kek.second; ++it) {
            const auto v1 = boost::source(*it, g);
            const auto v2 = boost::target(*it, g);
            std::cout << map[v1] << " <=> " << map[v2] << std::endl;
        }
    }
    std::ofstream out{outPath, std::ofstream::out | std::ofstream::trunc};
    if (!out) {
        std::cout << "Failed to open file '" << outPath << "' for output" << std::endl;
        return -1;
    }
    boost::write_graphviz(out, g);

    std::vector<std::unique_ptr<aid::IAnomalyDetector>> detectors;
    detectors.emplace_back(new aid::XorDetector());
    auto classes = dex->classes();
    for (const auto& c : classes) {
        for (const auto& m : c.methods()) {
            if (aid::isAbnormal(m, detectors))
                std::cout << m << std::endl;
        }
    }
    return 0;
}

