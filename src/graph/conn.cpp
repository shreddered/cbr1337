#include "graph/conn.h"
#include "graph/dalvik.h"

#include <iostream>

#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/strong_components.hpp>
#include <boost/functional.hpp>

#include <cmath>

namespace std {

template<>
struct hash<aid::graph::ClassVertex> {
    std::uint64_t operator()(const ::aid::graph::ClassVertex& v) const {
        return std::hash<size_t>()(v.classId);
    }
};

} // namespace std


namespace aid::graph {

struct State {
    DexGraph dfsTree;
    size_t count;
};

struct DfsStop {};

// build limited dfs tree
struct AuxVisitor : public boost::default_dfs_visitor {
    State& state_;
    const int delta_;
    AuxVisitor(State& state, int delta) : state_(state), delta_(delta) {}

    void tree_edge(DexEdge e, const DexGraph& g) {
        if (state_.count >= delta_)
            throw DfsStop{};
        ++state_.count;
        const auto src = boost::source(e, g);
        const auto dst = boost::target(e, g);
        boost::add_edge(src, dst, state_.dfsTree);
    }
};

struct WeightVisitor : public boost::default_dfs_visitor {
    std::unordered_map<DexVertex, int>& weights;
    WeightVisitor(std::unordered_map<DexVertex, int>& w) : weights(w) {}

    void finish_vertex(DexVertex v, const DexGraph& g) {
        weights[v] = 1;
        typename boost::graph_traits<DexGraph>::out_edge_iterator ei, ei_end;
        for (boost::tie(ei, ei_end) = boost::out_edges(v, g); ei != ei_end; ++ei) {
            auto dst = boost::target(*ei, g);
            weights[v] += weights[dst];
        }
    }
};

std::vector<DexEdge> heavyPath(DexGraph& dfs, const ClassVertex& start, int delta) {
    std::vector<DexEdge> res{};

    std::unordered_map<DexVertex, int> weights{};
    WeightVisitor vis{weights};
    auto v = *dfs.vertex_by_property(start);
    boost::depth_first_search(dfs, boost::visitor(vis)
        .root_vertex(v)
        .vertex_index_map(boost::get(&ClassVertex::classId, dfs))
    );

    typename boost::graph_traits<DexGraph>::edge_iterator ei, ei_end;
    for (boost::tie(ei, ei_end) = boost::edges(dfs); ei != ei_end; ++ei) {
        const auto dst = boost::target(*ei, dfs);
        if (weights[dst] >= delta)
            res.push_back(*ei);
    }
    return res;
}

std::unordered_set<ClassVertex> verticesToClasses(DexGraph::vertex_iterator start,
    DexGraph::vertex_iterator end, const DexGraph& g)
{
    std::unordered_set<ClassVertex> res{};
    std::transform(start, end, std::inserter(res, res.end()), [&](auto x) { return g[x]; });
    return res;
}

std::unordered_set<ClassVertex> oneEdgeOut(DexGraph g, const ClassVertex& start, int delta) {
    State state{{}, 0};
    const int threshold = 2 * delta + 1;
    try {
        AuxVisitor vis{state, threshold};

        auto v = *g.vertex_by_property(start);
        boost::depth_first_search(g, boost::visitor(vis)
            .root_vertex(v)
            .vertex_index_map(boost::get(&ClassVertex::classId, g))
        );
    } catch (const DfsStop&) {}
    if (state.count < threshold) {
        const auto vertices = boost::vertices(state.dfsTree);
        return verticesToClasses(vertices.first, vertices.second, state.dfsTree);
    }

    auto p = heavyPath(state.dfsTree, start, delta);
    for (const auto& e : p)
        boost::remove_edge(e, g);

    state = State{{}, 0};
    const int threshold2 = delta + 1;
    try {
        AuxVisitor vis{state, threshold2};
        auto v = *g.vertex_by_property(start);
        boost::depth_first_search(g, boost::visitor(vis)
            .root_vertex(v)
            .vertex_index_map(boost::get(&ClassVertex::classId, g))
        );
    } catch (const DfsStop&) {}
    if (state.count < threshold2) {
        const auto vertices = boost::vertices(state.dfsTree);
        return verticesToClasses(vertices.first, vertices.second, state.dfsTree);
    }
    return std::unordered_set<ClassVertex>{};
}

size_t sccCount(DexGraph& g) {
    std::vector<int> component(boost::num_vertices(g));
    return boost::strong_components(g, make_iterator_property_map(component.begin(),
        boost::get(&ClassVertex::classId, g)));
}

std::vector<DexEdge> strongBridges(DexGraph& g) {
    std::vector<DexEdge> res{};
    DexGraph::edge_iterator ei, ei_end;

    for (boost::tie(ei, ei_end) = boost::edges(g); ei != ei_end; ++ei) {
        DexGraph tmp = g;
        const auto src = boost::source(*ei, g);
        const auto dst = boost::target(*ei, g);
        boost::remove_edge(src, dst, tmp);
        if (sccCount(g) < sccCount(tmp))
            res.push_back(*ei);
    }
    return res;
}

std::vector<DexGraph> twoConnectedSubgraphs(DexGraph& g, size_t m0) {
    std::vector<DexGraph> res;
    if (strongBridges(g).empty()) {
        res = { g };
        return res;
    }

    const auto threshold = std::round(2 * std::sqrt(m0));
    auto [vi, vi_end] = boost::vertices(g);
    auto [ei, ei_end] = boost::edges(g);
    std::vector<DexGraph::vertex_descriptor> vertices(vi, vi_end);
    while (!vertices.empty() && std::distance(ei, ei_end) > threshold) {

    }
    return res;
}

} // namespace aid::graph

