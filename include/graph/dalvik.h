#ifndef INCLUDE_GRAPH_DALVIK_H_
#define INCLUDE_GRAPH_DALVIK_H_

#include <memory>
#include <string>

#include <boost/graph/named_graph.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>

#include <LIEF/LIEF.hpp>

#include "graph/defs.h"

namespace aid::graph {

struct ClassVertex {
    size_t classId;
    std::string name = "";
    inline bool operator==(const ClassVertex& other) const {
        return other.classId == classId;
    }
};

using DexGraph = Graph<ClassVertex>;
using DexVertex = Vertex<ClassVertex>;
using DexEdge = DexGraph::edge_descriptor;

DexGraph createCallGraph(const std::unique_ptr<LIEF::DEX::File>& dex);

} // namespace aid


#endif // INCLUDE_GRAPH_DALVIK_H_

