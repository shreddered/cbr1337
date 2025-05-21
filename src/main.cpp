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

