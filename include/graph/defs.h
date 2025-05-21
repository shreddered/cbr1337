#ifndef INCLUDE_GRAPH_DEFS_H_
#define INCLUDE_GRAPH_DEFS_H_

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/copy.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/graph_traits.hpp>

#include <functional>

namespace aid {

namespace graph {

// template typedef for vertex descriptor T
template<class T>
using Graph = boost::adjacency_list<boost::hash_setS, boost::vecS, boost::bidirectionalS, T>;

template<class T>
using Vertex = boost::graph_traits<Graph<T>>::vertex_descriptor;

template<typename G, typename N, typename V = G::vertex_descriptor>
auto inducedSubgraph(G& g, N&& nodes) {
    std::function pred{[nodes](V v) { return nodes.contains(v); }};
    G res;
    auto tmp = boost::filtered_graph(g, boost::keep_all{}, pred);
    boost::copy_graph(tmp, res);
    return res;
}

}

}

#endif // INCLUDE_GRAPH_DEFS_H_

