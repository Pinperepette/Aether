import SwiftUI
import AppKit

struct CFGView: View {
    @EnvironmentObject var appState: AppState
    @State private var scale: CGFloat = 1.0
    @State private var offset: CGSize = .zero
    @State private var nodePositions: [UInt64: CGPoint] = [:]
    var showOpenInWindowButton: Bool = true

    // MARK: - Open in Window

    private func openCFGWindow() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1000, height: 700),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )

        let functionName = appState.selectedFunction?.name ?? "CFG"
        window.title = "Control Flow Graph - \(functionName)"
        window.center()
        window.setFrameAutosaveName("CFGWindow")
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 600, height: 400)

        // Create CFG view without the "open in window" button
        let cfgView = CFGView(showOpenInWindowButton: false)
            .environmentObject(appState)

        window.contentView = NSHostingView(rootView: cfgView)
        window.makeKeyAndOrderFront(nil)

        // Store reference to prevent deallocation
        CFGWindowManager.shared.addWindow(window)
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .foregroundColor(.accent)
                Text("Control Flow Graph")
                    .font(.headline)

                if let function = appState.selectedFunction {
                    Text("- \(function.name)")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }

                Spacer()

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
                        withAnimation { scale = min(2.0, scale + 0.25) }
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

                    if showOpenInWindowButton {
                        Divider()
                            .frame(height: 16)

                        Button {
                            openCFGWindow()
                        } label: {
                            Image(systemName: "arrow.up.left.and.arrow.down.right")
                        }
                        .buttonStyle(.plain)
                        .help("Open in separate window")
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color.sidebar)

            Divider()

            // Graph content
            if let function = appState.selectedFunction, !function.basicBlocks.isEmpty {
                GeometryReader { geometry in
                    ZStack {
                        // Edges
                        ForEach(function.basicBlocks) { block in
                            ForEach(block.successors, id: \.self) { successor in
                                if let startPos = nodePositions[block.startAddress],
                                   let endPos = nodePositions[successor] {
                                    EdgeView(
                                        from: startPos,
                                        to: endPos,
                                        isConditional: block.type == .conditional
                                    )
                                }
                            }
                        }

                        // Nodes
                        ForEach(function.basicBlocks) { block in
                            if let position = nodePositions[block.startAddress] {
                                CFGNodeView(block: block, isSelected: appState.selectedAddress >= block.startAddress && appState.selectedAddress < block.endAddress)
                                    .position(position)
                                    .onTapGesture {
                                        appState.goToAddress(block.startAddress)
                                    }
                            }
                        }
                    }
                    .scaleEffect(scale)
                    .offset(offset)
                    .gesture(
                        DragGesture()
                            .onChanged { value in
                                offset = CGSize(
                                    width: offset.width + value.translation.width / scale,
                                    height: offset.height + value.translation.height / scale
                                )
                            }
                    )
                    .gesture(
                        MagnificationGesture()
                            .onChanged { value in
                                scale = min(max(0.25, scale * value), 2.0)
                            }
                    )
                    .onAppear {
                        layoutGraph(in: geometry.size, blocks: function.basicBlocks)
                    }
                    .onChange(of: function.basicBlocks) { _, newBlocks in
                        layoutGraph(in: geometry.size, blocks: newBlocks)
                    }
                }
                .clipped()
            } else {
                EmptyStateView(
                    icon: "point.3.connected.trianglepath.dotted",
                    title: "No CFG Available",
                    message: "Select a function to view its control flow graph"
                )
            }
        }
        .background(Color.background)
    }

    // MARK: - Graph Layout

    private func layoutGraph(in size: CGSize, blocks: [BasicBlock]) {
        guard !blocks.isEmpty else { return }

        // Simple layered layout algorithm
        var layers: [[BasicBlock]] = []
        var assigned = Set<UInt64>()

        // Find entry block
        if let entry = blocks.first(where: { $0.type == .entry }) ?? blocks.first {
            layers.append([entry])
            assigned.insert(entry.startAddress)
        }

        // Assign remaining blocks to layers
        while assigned.count < blocks.count {
            var nextLayer: [BasicBlock] = []

            for block in blocks where !assigned.contains(block.startAddress) {
                // Check if all predecessors are assigned
                let allPredsAssigned = block.predecessors.allSatisfy { assigned.contains($0) }
                if allPredsAssigned || block.predecessors.isEmpty {
                    nextLayer.append(block)
                }
            }

            if nextLayer.isEmpty {
                // Handle cycles - add remaining blocks
                for block in blocks where !assigned.contains(block.startAddress) {
                    nextLayer.append(block)
                    break
                }
            }

            for block in nextLayer {
                assigned.insert(block.startAddress)
            }

            if !nextLayer.isEmpty {
                layers.append(nextLayer)
            }
        }

        // Calculate positions
        let nodeWidth: CGFloat = 200
        let nodeHeight: CGFloat = 100
        let horizontalSpacing: CGFloat = 50
        let verticalSpacing: CGFloat = 80

        var positions: [UInt64: CGPoint] = [:]

        for (layerIndex, layer) in layers.enumerated() {
            let layerWidth = CGFloat(layer.count) * nodeWidth + CGFloat(layer.count - 1) * horizontalSpacing
            let startX = (size.width - layerWidth) / 2 + nodeWidth / 2

            for (nodeIndex, block) in layer.enumerated() {
                let x = startX + CGFloat(nodeIndex) * (nodeWidth + horizontalSpacing)
                let y = 50 + CGFloat(layerIndex) * (nodeHeight + verticalSpacing) + nodeHeight / 2

                positions[block.startAddress] = CGPoint(x: x, y: y)
            }
        }

        withAnimation {
            nodePositions = positions
        }
    }
}

// MARK: - CFG Node View

struct CFGNodeView: View {
    let block: BasicBlock
    let isSelected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // Header
            HStack {
                Text(String(format: "0x%llX", block.startAddress))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.addressColor)

                Spacer()

                // Block type badge
                Text(block.type.rawValue)
                    .font(.caption2)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(blockTypeColor.opacity(0.3))
                    .cornerRadius(4)
            }

            Divider()

            // Instructions preview
            ScrollView {
                VStack(alignment: .leading, spacing: 1) {
                    ForEach(block.instructions.prefix(5)) { insn in
                        HStack(spacing: 4) {
                            Text(insn.mnemonic)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.accent)

                            Text(insn.operands)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                        }
                    }

                    if block.instructions.count > 5 {
                        Text("... +\(block.instructions.count - 5) more")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding(8)
        .frame(width: 180, height: 90)
        .background(isSelected ? Color.accent.opacity(0.2) : Color.sidebar)
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isSelected ? Color.accent : blockTypeColor, lineWidth: 2)
        )
        .shadow(color: .black.opacity(0.2), radius: 4, x: 0, y: 2)
    }

    private var blockTypeColor: Color {
        switch block.type {
        case .entry:
            return .green
        case .exit:
            return .red
        case .conditional:
            return .orange
        case .loop:
            return .purple
        case .normal:
            return .secondary
        }
    }
}

// MARK: - Edge View

struct EdgeView: View {
    let from: CGPoint
    let to: CGPoint
    let isConditional: Bool

    var body: some View {
        Path { path in
            path.move(to: CGPoint(x: from.x, y: from.y + 45))

            // Bezier curve for smooth edges
            let midY = (from.y + to.y) / 2 + 45
            path.addCurve(
                to: CGPoint(x: to.x, y: to.y - 45),
                control1: CGPoint(x: from.x, y: midY),
                control2: CGPoint(x: to.x, y: midY)
            )
        }
        .stroke(
            isConditional ? Color.orange : Color.accent,
            style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round)
        )

        // Arrow head
        Path { path in
            let angle = atan2(to.y - 45 - from.y - 45, to.x - from.x)
            let arrowLength: CGFloat = 10
            let arrowAngle: CGFloat = .pi / 6

            let tip = CGPoint(x: to.x, y: to.y - 45)
            let left = CGPoint(
                x: tip.x - arrowLength * cos(angle - arrowAngle),
                y: tip.y - arrowLength * sin(angle - arrowAngle)
            )
            let right = CGPoint(
                x: tip.x - arrowLength * cos(angle + arrowAngle),
                y: tip.y - arrowLength * sin(angle + arrowAngle)
            )

            path.move(to: tip)
            path.addLine(to: left)
            path.move(to: tip)
            path.addLine(to: right)
        }
        .stroke(
            isConditional ? Color.orange : Color.accent,
            style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round)
        )
    }
}

// MARK: - CFG Window Manager

class CFGWindowManager: NSObject, NSWindowDelegate {
    static let shared = CFGWindowManager()

    private var windows: [NSWindow] = []

    private override init() {
        super.init()
    }

    func addWindow(_ window: NSWindow) {
        window.delegate = self
        windows.append(window)
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow else { return }
        windows.removeAll { $0 === window }
    }
}
