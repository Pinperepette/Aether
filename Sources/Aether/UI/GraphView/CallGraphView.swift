import SwiftUI
import AppKit

// MARK: - Call Graph View

/// Interactive view for visualizing function call relationships
struct CallGraphView: View {
    @EnvironmentObject var appState: AppState
    @StateObject private var viewModel = CallGraphViewModel()
    @State private var scale: CGFloat = 1.0
    @State private var offset: CGSize = .zero
    @State private var selectedNode: CallGraphNode?
    @State private var searchText: String = ""
    @State private var showSettings: Bool = false
    @State private var maxDepth: Int = 3
    @State private var showExternalCalls: Bool = true
    @State private var layoutStyle: LayoutStyle = .hierarchical

    enum LayoutStyle: String, CaseIterable {
        case hierarchical = "Hierarchical"
        case radial = "Radial"
        case forceDirected = "Force-Directed"
    }

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            callGraphToolbar

            Divider()

            // Main content
            HSplitView {
                // Graph view
                graphContent
                    .frame(minWidth: 400)

                // Details panel
                if let node = selectedNode {
                    nodeDetailsPanel(node: node)
                        .frame(width: 280)
                }
            }
        }
        .background(Color.background)
        .onAppear {
            if let binary = appState.currentFile {
                viewModel.buildGraph(from: appState.functions, binary: binary)
            }
        }
        .onChange(of: appState.functions) { _, newFunctions in
            if let binary = appState.currentFile {
                viewModel.buildGraph(from: newFunctions, binary: binary)
            }
        }
    }

    // MARK: - Toolbar

    private var callGraphToolbar: some View {
        HStack {
            Image(systemName: "arrow.triangle.branch")
                .foregroundColor(.accent)
            Text("Call Graph")
                .font(.headline)

            Spacer()

            // Search
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Search functions...", text: $searchText)
                    .textFieldStyle(.plain)
                    .frame(width: 150)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Color.sidebar)
            .cornerRadius(6)

            Divider()
                .frame(height: 20)

            // Layout picker
            Picker("Layout", selection: $layoutStyle) {
                ForEach(LayoutStyle.allCases, id: \.self) { style in
                    Text(style.rawValue).tag(style)
                }
            }
            .pickerStyle(.segmented)
            .frame(width: 200)

            Divider()
                .frame(height: 20)

            // Depth control
            HStack {
                Text("Depth:")
                    .foregroundColor(.secondary)
                Stepper("\(maxDepth)", value: $maxDepth, in: 1...10)
                    .frame(width: 80)
            }

            Toggle("External", isOn: $showExternalCalls)
                .toggleStyle(.checkbox)

            Divider()
                .frame(height: 20)

            // Zoom controls
            HStack(spacing: 8) {
                Button {
                    withAnimation { scale = max(0.25, scale - 0.25) }
                } label: {
                    Image(systemName: "minus.magnifyingglass")
                }
                .buttonStyle(.plain)

                Text("\(Int(scale * 100))%")
                    .font(.caption)
                    .frame(width: 40)

                Button {
                    withAnimation { scale = min(3.0, scale + 0.25) }
                } label: {
                    Image(systemName: "plus.magnifyingglass")
                }
                .buttonStyle(.plain)

                Button {
                    withAnimation {
                        scale = 1.0
                        offset = .zero
                    }
                } label: {
                    Image(systemName: "arrow.counterclockwise")
                }
                .buttonStyle(.plain)
                .help("Reset view")
            }

            Button {
                openInWindow()
            } label: {
                Image(systemName: "arrow.up.left.and.arrow.down.right")
            }
            .buttonStyle(.plain)
            .help("Open in separate window")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color.sidebar)
    }

    // MARK: - Graph Content

    private var graphContent: some View {
        GeometryReader { geometry in
            ZStack {
                // Background
                Color.background

                // Edges
                ForEach(viewModel.edges, id: \.id) { edge in
                    CallGraphEdgeView(edge: edge, nodePositions: viewModel.nodePositions)
                        .opacity(shouldShowEdge(edge) ? 1.0 : 0.1)
                }

                // Nodes
                ForEach(filteredNodes, id: \.id) { node in
                    if let position = viewModel.nodePositions[node.address] {
                        CallGraphNodeView(
                            node: node,
                            isSelected: selectedNode?.address == node.address,
                            isHighlighted: isNodeHighlighted(node)
                        )
                        .position(position)
                        .onTapGesture {
                            selectedNode = node
                            appState.goToAddress(node.address)
                        }
                        .contextMenu {
                            nodeContextMenu(node: node)
                        }
                    }
                }
            }
            .scaleEffect(scale)
            .offset(offset)
            .gesture(dragGesture)
            .gesture(magnificationGesture)
            .onAppear {
                viewModel.layout(style: layoutStyle, in: geometry.size)
            }
            .onChange(of: layoutStyle) { _, _ in
                viewModel.layout(style: layoutStyle, in: geometry.size)
            }
        }
        .clipped()
    }

    // MARK: - Details Panel

    private func nodeDetailsPanel(node: CallGraphNode) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header
            HStack {
                Image(systemName: "function")
                    .foregroundColor(.accent)
                Text("Function Details")
                    .font(.headline)
                Spacer()
                Button {
                    selectedNode = nil
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
            }

            Divider()

            // Function info
            VStack(alignment: .leading, spacing: 8) {
                DetailRow(label: "Name", value: node.name)
                DetailRow(label: "Address", value: String(format: "0x%llX", node.address))
                DetailRow(label: "Size", value: "\(node.size) bytes")
                DetailRow(label: "Type", value: node.isExternal ? "External" : "Internal")
            }

            Divider()

            // Callers
            VStack(alignment: .leading, spacing: 4) {
                Text("Callers (\(node.callers.count))")
                    .font(.subheadline)
                    .fontWeight(.medium)

                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(node.callers), id: \.self) { callerAddr in
                            if let callerNode = viewModel.nodes.first(where: { $0.address == callerAddr }) {
                                Button {
                                    selectedNode = callerNode
                                    appState.goToAddress(callerAddr)
                                } label: {
                                    HStack {
                                        Image(systemName: "arrow.right")
                                            .font(.caption)
                                        Text(callerNode.name)
                                            .lineLimit(1)
                                        Spacer()
                                    }
                                    .padding(.vertical, 2)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
                .frame(maxHeight: 100)
            }

            Divider()

            // Callees
            VStack(alignment: .leading, spacing: 4) {
                Text("Calls (\(node.callees.count))")
                    .font(.subheadline)
                    .fontWeight(.medium)

                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(node.callees), id: \.self) { calleeAddr in
                            if let calleeNode = viewModel.nodes.first(where: { $0.address == calleeAddr }) {
                                Button {
                                    selectedNode = calleeNode
                                    appState.goToAddress(calleeAddr)
                                } label: {
                                    HStack {
                                        Image(systemName: "arrow.left")
                                            .font(.caption)
                                        Text(calleeNode.name)
                                            .lineLimit(1)
                                        Spacer()
                                    }
                                    .padding(.vertical, 2)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
                .frame(maxHeight: 100)
            }

            Spacer()

            // Actions
            VStack(spacing: 8) {
                Button("Show Only This Subgraph") {
                    viewModel.filterToSubgraph(root: node.address, depth: maxDepth)
                }
                .buttonStyle(.borderedProminent)

                Button("Reset Filter") {
                    viewModel.resetFilter()
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .background(Color.sidebar)
    }

    // MARK: - Helpers

    private var filteredNodes: [CallGraphNode] {
        var nodes = viewModel.visibleNodes

        if !searchText.isEmpty {
            nodes = nodes.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
        }

        if !showExternalCalls {
            nodes = nodes.filter { !$0.isExternal }
        }

        return nodes
    }

    private func shouldShowEdge(_ edge: CallGraphEdge) -> Bool {
        let sourceVisible = filteredNodes.contains { $0.address == edge.source }
        let targetVisible = filteredNodes.contains { $0.address == edge.target }
        return sourceVisible && targetVisible
    }

    private func isNodeHighlighted(_ node: CallGraphNode) -> Bool {
        guard let selected = selectedNode else { return false }
        return selected.callers.contains(node.address) || selected.callees.contains(node.address)
    }

    private var dragGesture: some Gesture {
        DragGesture()
            .onChanged { value in
                offset = CGSize(
                    width: offset.width + value.translation.width / scale,
                    height: offset.height + value.translation.height / scale
                )
            }
    }

    private var magnificationGesture: some Gesture {
        MagnificationGesture()
            .onChanged { value in
                scale = min(max(0.25, scale * value), 3.0)
            }
    }

    @ViewBuilder
    private func nodeContextMenu(node: CallGraphNode) -> some View {
        Button("Go to Function") {
            appState.goToAddress(node.address)
        }

        Divider()

        Button("Show Callers Only") {
            viewModel.filterToCallers(of: node.address, depth: maxDepth)
        }

        Button("Show Callees Only") {
            viewModel.filterToCallees(of: node.address, depth: maxDepth)
        }

        Button("Show Subgraph") {
            viewModel.filterToSubgraph(root: node.address, depth: maxDepth)
        }

        Divider()

        Button("Copy Name") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(node.name, forType: .string)
        }

        Button("Copy Address") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(String(format: "0x%llX", node.address), forType: .string)
        }
    }

    private func openInWindow() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1200, height: 800),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )

        window.title = "Call Graph"
        window.center()
        window.contentView = NSHostingView(rootView: CallGraphView().environmentObject(appState))
        window.makeKeyAndOrderFront(nil)
    }
}

// MARK: - Detail Row

private struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundColor(.secondary)
                .frame(width: 60, alignment: .leading)
            Text(value)
                .fontWeight(.medium)
                .lineLimit(1)
            Spacer()
        }
        .font(.caption)
    }
}

// MARK: - Call Graph Node View

struct CallGraphNodeView: View {
    let node: CallGraphNode
    let isSelected: Bool
    let isHighlighted: Bool

    var body: some View {
        VStack(spacing: 4) {
            Text(node.name)
                .font(.system(.caption, design: .monospaced))
                .lineLimit(1)
                .frame(maxWidth: 120)

            Text(String(format: "0x%llX", node.address))
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(backgroundColor)
        .cornerRadius(6)
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(borderColor, lineWidth: isSelected ? 2 : 1)
        )
        .shadow(color: .black.opacity(0.1), radius: 2, x: 0, y: 1)
    }

    private var backgroundColor: Color {
        if isSelected {
            return Color.accent.opacity(0.3)
        }
        if isHighlighted {
            return Color.orange.opacity(0.2)
        }
        if node.isExternal {
            return Color.purple.opacity(0.2)
        }
        return Color.sidebar
    }

    private var borderColor: Color {
        if isSelected {
            return Color.accent
        }
        if isHighlighted {
            return Color.orange
        }
        if node.isExternal {
            return Color.purple
        }
        return Color.secondary.opacity(0.5)
    }
}

// MARK: - Call Graph Edge View

struct CallGraphEdgeView: View {
    let edge: CallGraphEdge
    let nodePositions: [UInt64: CGPoint]

    var body: some View {
        if let from = nodePositions[edge.source],
           let to = nodePositions[edge.target] {
            Path { path in
                path.move(to: from)

                // Bezier curve
                let midX = (from.x + to.x) / 2
                let midY = (from.y + to.y) / 2
                let controlOffset: CGFloat = 30

                path.addQuadCurve(
                    to: to,
                    control: CGPoint(x: midX, y: midY - controlOffset)
                )
            }
            .stroke(
                edge.isRecursive ? Color.red : Color.secondary.opacity(0.5),
                style: StrokeStyle(
                    lineWidth: edge.isRecursive ? 2 : 1,
                    lineCap: .round,
                    dash: edge.isIndirect ? [5, 3] : []
                )
            )

            // Arrow head
            arrowHead(from: from, to: to)
        }
    }

    private func arrowHead(from: CGPoint, to: CGPoint) -> some View {
        let angle = atan2(to.y - from.y, to.x - from.x)
        let arrowLength: CGFloat = 8

        return Path { path in
            let tip = to
            let left = CGPoint(
                x: tip.x - arrowLength * cos(angle - .pi / 6),
                y: tip.y - arrowLength * sin(angle - .pi / 6)
            )
            let right = CGPoint(
                x: tip.x - arrowLength * cos(angle + .pi / 6),
                y: tip.y - arrowLength * sin(angle + .pi / 6)
            )

            path.move(to: tip)
            path.addLine(to: left)
            path.move(to: tip)
            path.addLine(to: right)
        }
        .stroke(Color.secondary.opacity(0.5), lineWidth: 1)
    }
}

// MARK: - View Model

class CallGraphViewModel: ObservableObject {
    @Published var nodes: [CallGraphNode] = []
    @Published var edges: [CallGraphEdge] = []
    @Published var nodePositions: [UInt64: CGPoint] = [:]
    @Published var visibleNodes: [CallGraphNode] = []

    private var allNodes: [CallGraphNode] = []
    private var allEdges: [CallGraphEdge] = []

    func buildGraph(from functions: [Function], binary: BinaryFile) {
        var nodesDict: [UInt64: CallGraphNode] = [:]

        // Create nodes for all functions
        for function in functions {
            let node = CallGraphNode(
                address: function.startAddress,
                name: function.displayName,
                size: Int(function.size),
                isExternal: function.name.hasPrefix("_") && function.size < 16,
                callers: function.callers,
                callees: function.callees
            )
            nodesDict[function.startAddress] = node
        }

        // Add external symbols as nodes
        for symbol in binary.symbols where symbol.type == .function {
            if nodesDict[symbol.address] == nil {
                let node = CallGraphNode(
                    address: symbol.address,
                    name: symbol.displayName,
                    size: Int(symbol.size),
                    isExternal: true,
                    callers: [],
                    callees: []
                )
                nodesDict[symbol.address] = node
            }
        }

        allNodes = Array(nodesDict.values)
        nodes = allNodes

        // Create edges
        var edgesSet: Set<CallGraphEdge> = []
        for function in functions {
            for calleeAddr in function.callees {
                let edge = CallGraphEdge(
                    source: function.startAddress,
                    target: calleeAddr,
                    isRecursive: calleeAddr == function.startAddress,
                    isIndirect: false
                )
                edgesSet.insert(edge)
            }
        }

        allEdges = Array(edgesSet)
        edges = allEdges
        visibleNodes = nodes
    }

    func layout(style: CallGraphView.LayoutStyle, in size: CGSize) {
        switch style {
        case .hierarchical:
            layoutHierarchical(in: size)
        case .radial:
            layoutRadial(in: size)
        case .forceDirected:
            layoutForceDirected(in: size)
        }
    }

    private func layoutHierarchical(in size: CGSize) {
        // Find roots (nodes with no callers)
        let roots = visibleNodes.filter { node in
            !edges.contains { $0.target == node.address && visibleNodes.contains { $0.address == $0.address } }
        }

        var levels: [[CallGraphNode]] = []
        var assigned = Set<UInt64>()

        // Assign nodes to levels using BFS
        var currentLevel = roots.isEmpty ? [visibleNodes.first].compactMap { $0 } : roots
        while !currentLevel.isEmpty {
            levels.append(currentLevel)
            for node in currentLevel {
                assigned.insert(node.address)
            }

            var nextLevel: [CallGraphNode] = []
            for node in currentLevel {
                for edge in edges where edge.source == node.address {
                    if let targetNode = visibleNodes.first(where: { $0.address == edge.target }),
                       !assigned.contains(edge.target) {
                        nextLevel.append(targetNode)
                    }
                }
            }
            currentLevel = nextLevel
        }

        // Add remaining unassigned nodes
        let unassigned = visibleNodes.filter { !assigned.contains($0.address) }
        if !unassigned.isEmpty {
            levels.append(unassigned)
        }

        // Calculate positions
        let verticalSpacing: CGFloat = 100
        let horizontalSpacing: CGFloat = 150

        var positions: [UInt64: CGPoint] = [:]

        for (levelIdx, level) in levels.enumerated() {
            let levelWidth = CGFloat(level.count) * horizontalSpacing
            let startX = (size.width - levelWidth) / 2 + horizontalSpacing / 2

            for (nodeIdx, node) in level.enumerated() {
                let x = startX + CGFloat(nodeIdx) * horizontalSpacing
                let y = 50 + CGFloat(levelIdx) * verticalSpacing
                positions[node.address] = CGPoint(x: x, y: y)
            }
        }

        withAnimation {
            nodePositions = positions
        }
    }

    private func layoutRadial(in size: CGSize) {
        let center = CGPoint(x: size.width / 2, y: size.height / 2)
        let radius: CGFloat = min(size.width, size.height) / 3

        var positions: [UInt64: CGPoint] = [:]
        let count = visibleNodes.count

        for (i, node) in visibleNodes.enumerated() {
            let angle = (2 * .pi * Double(i)) / Double(count) - .pi / 2
            let x = center.x + radius * CGFloat(cos(angle))
            let y = center.y + radius * CGFloat(sin(angle))
            positions[node.address] = CGPoint(x: x, y: y)
        }

        withAnimation {
            nodePositions = positions
        }
    }

    private func layoutForceDirected(in size: CGSize) {
        // Simple force-directed layout
        var positions: [UInt64: CGPoint] = [:]

        // Initialize random positions
        for node in visibleNodes {
            positions[node.address] = CGPoint(
                x: CGFloat.random(in: 50...(size.width - 50)),
                y: CGFloat.random(in: 50...(size.height - 50))
            )
        }

        // Iterate
        let iterations = 50
        let repulsion: CGFloat = 5000
        let attraction: CGFloat = 0.01

        for _ in 0..<iterations {
            var forces: [UInt64: CGVector] = [:]
            for node in visibleNodes {
                forces[node.address] = .zero
            }

            // Repulsion between all nodes
            for i in 0..<visibleNodes.count {
                for j in (i + 1)..<visibleNodes.count {
                    let nodeA = visibleNodes[i]
                    let nodeB = visibleNodes[j]

                    guard let posA = positions[nodeA.address],
                          let posB = positions[nodeB.address] else { continue }

                    let dx = posB.x - posA.x
                    let dy = posB.y - posA.y
                    let dist = max(sqrt(dx * dx + dy * dy), 1)

                    let force = repulsion / (dist * dist)
                    let fx = (dx / dist) * force
                    let fy = (dy / dist) * force

                    forces[nodeA.address]?.dx -= fx
                    forces[nodeA.address]?.dy -= fy
                    forces[nodeB.address]?.dx += fx
                    forces[nodeB.address]?.dy += fy
                }
            }

            // Attraction along edges
            for edge in edges {
                guard let posA = positions[edge.source],
                      let posB = positions[edge.target] else { continue }

                let dx = posB.x - posA.x
                let dy = posB.y - posA.y

                forces[edge.source]?.dx += dx * attraction
                forces[edge.source]?.dy += dy * attraction
                forces[edge.target]?.dx -= dx * attraction
                forces[edge.target]?.dy -= dy * attraction
            }

            // Apply forces
            for node in visibleNodes {
                guard var pos = positions[node.address],
                      let force = forces[node.address] else { continue }

                pos.x += force.dx
                pos.y += force.dy

                // Keep in bounds
                pos.x = max(50, min(size.width - 50, pos.x))
                pos.y = max(50, min(size.height - 50, pos.y))

                positions[node.address] = pos
            }
        }

        withAnimation {
            nodePositions = positions
        }
    }

    func filterToSubgraph(root: UInt64, depth: Int) {
        var included = Set<UInt64>()
        collectNodes(from: root, depth: depth, included: &included)

        visibleNodes = allNodes.filter { included.contains($0.address) }
        edges = allEdges.filter { included.contains($0.source) && included.contains($0.target) }
    }

    func filterToCallers(of address: UInt64, depth: Int) {
        var included = Set<UInt64>([address])
        collectCallers(of: address, depth: depth, included: &included)

        visibleNodes = allNodes.filter { included.contains($0.address) }
        edges = allEdges.filter { included.contains($0.source) && included.contains($0.target) }
    }

    func filterToCallees(of address: UInt64, depth: Int) {
        var included = Set<UInt64>([address])
        collectCallees(of: address, depth: depth, included: &included)

        visibleNodes = allNodes.filter { included.contains($0.address) }
        edges = allEdges.filter { included.contains($0.source) && included.contains($0.target) }
    }

    func resetFilter() {
        visibleNodes = allNodes
        edges = allEdges
    }

    private func collectNodes(from address: UInt64, depth: Int, included: inout Set<UInt64>) {
        guard depth > 0, !included.contains(address) else { return }
        included.insert(address)

        // Collect callees
        for edge in allEdges where edge.source == address {
            collectNodes(from: edge.target, depth: depth - 1, included: &included)
        }

        // Collect callers
        for edge in allEdges where edge.target == address {
            collectNodes(from: edge.source, depth: depth - 1, included: &included)
        }
    }

    private func collectCallers(of address: UInt64, depth: Int, included: inout Set<UInt64>) {
        guard depth > 0 else { return }

        for edge in allEdges where edge.target == address && !included.contains(edge.source) {
            included.insert(edge.source)
            collectCallers(of: edge.source, depth: depth - 1, included: &included)
        }
    }

    private func collectCallees(of address: UInt64, depth: Int, included: inout Set<UInt64>) {
        guard depth > 0 else { return }

        for edge in allEdges where edge.source == address && !included.contains(edge.target) {
            included.insert(edge.target)
            collectCallees(of: edge.target, depth: depth - 1, included: &included)
        }
    }
}

// MARK: - Data Models

struct CallGraphNode: Identifiable, Hashable {
    let id = UUID()
    let address: UInt64
    let name: String
    let size: Int
    let isExternal: Bool
    var callers: Set<UInt64>
    var callees: Set<UInt64>

    func hash(into hasher: inout Hasher) {
        hasher.combine(address)
    }

    static func == (lhs: CallGraphNode, rhs: CallGraphNode) -> Bool {
        lhs.address == rhs.address
    }
}

struct CallGraphEdge: Identifiable, Hashable {
    let id = UUID()
    let source: UInt64
    let target: UInt64
    let isRecursive: Bool
    let isIndirect: Bool

    func hash(into hasher: inout Hasher) {
        hasher.combine(source)
        hasher.combine(target)
    }

    static func == (lhs: CallGraphEdge, rhs: CallGraphEdge) -> Bool {
        lhs.source == rhs.source && lhs.target == rhs.target
    }
}
