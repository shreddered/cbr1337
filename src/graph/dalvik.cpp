#include "dex/disasm.h"
#include "graph/dalvik.h"

#include <unordered_set>

namespace aid::graph {

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

DexGraph createCallGraph(const std::unique_ptr<LIEF::DEX::File>& dex) {
    auto imported = importedClasses(dex);
    aid::graph::DexGraph g;

    auto classes = dex->classes();
    for (const auto& cls : classes) {
        auto methods = cls.methods();
        for (const auto& m : methods)
            processMethod(dex, imported, m, g);
    }
    return g;
}

} // namespace aid::graph
