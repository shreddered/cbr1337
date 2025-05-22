#ifndef INCLUDE_GRAPH_CONN_H_
#define INCLUDE_GRAPH_CONN_H_

#include <unordered_set>
#include <vector>

#include "graph/dalvik.h"

namespace aid::graph {

std::vector<DexGraph> twoConnectedSubgraphs(DexGraph g);

} // namespace aid::graph

#endif // INCLUDE_GRAPH_CONN_H_
