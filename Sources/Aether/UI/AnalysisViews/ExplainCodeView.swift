import SwiftUI

struct ExplainCodeView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "text.bubble")
                    .font(.title2)
                    .foregroundColor(.blue)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Code Explanation")
                        .font(.headline)

                    if let function = appState.selectedFunction {
                        Text(function.shortDisplayName)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Spacer()

                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            // Content
            if appState.isExplainingCode {
                loadingView
            } else if let error = appState.explainError {
                errorView(error)
            } else if let explanation = appState.codeExplanation {
                explanationView(explanation)
            } else {
                emptyView
            }
        }
        .frame(minWidth: 500, minHeight: 400)
        .frame(idealWidth: 600, idealHeight: 500)
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)

            Text("Analyzing code...")
                .font(.headline)
                .foregroundColor(.secondary)

            Text("This may take a few seconds")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorView(_ error: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundColor(.orange)

            Text("Analysis Failed")
                .font(.headline)

            Text(error)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button("Try Again") {
                appState.explainCurrentFunction()
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "questionmark.circle")
                .font(.system(size: 48))
                .foregroundColor(.secondary)

            Text("No explanation available")
                .font(.headline)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func explanationView(_ explanation: CodeExplanation) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Summary
                VStack(alignment: .leading, spacing: 8) {
                    Label("Summary", systemImage: "text.alignleft")
                        .font(.headline)
                        .foregroundColor(.blue)

                    Text(explanation.summary)
                        .font(.body)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.blue.opacity(0.1))
                        .cornerRadius(8)
                }

                // Complexity
                HStack {
                    Label("Complexity", systemImage: "gauge.medium")
                        .font(.subheadline)
                        .foregroundColor(.secondary)

                    ComplexityBadge(complexity: explanation.complexity)
                }

                // Patterns
                if !explanation.patterns.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Recognized Patterns", systemImage: "sparkles")
                            .font(.headline)
                            .foregroundColor(.purple)

                        FlowLayout(spacing: 8) {
                            ForEach(explanation.patterns, id: \.self) { pattern in
                                PatternTag(pattern: pattern)
                            }
                        }
                    }
                }

                // Detailed Explanation
                VStack(alignment: .leading, spacing: 8) {
                    Label("Detailed Explanation", systemImage: "doc.text")
                        .font(.headline)
                        .foregroundColor(.green)

                    Text(explanation.detailed)
                        .font(.body)
                        .textSelection(.enabled)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.green.opacity(0.05))
                        .cornerRadius(8)
                }

                // Raw Response (collapsible)
                DisclosureGroup {
                    ScrollView(.horizontal, showsIndicators: true) {
                        Text(explanation.rawResponse)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .padding()
                    }
                    .frame(maxHeight: 200)
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(8)
                } label: {
                    Label("Raw Response", systemImage: "doc.plaintext")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }
            .padding()
        }
    }
}

// MARK: - Supporting Views

struct ComplexityBadge: View {
    let complexity: String

    var color: Color {
        switch complexity.lowercased() {
        case "simple": return .green
        case "medium": return .orange
        case "high": return .red
        default: return .secondary
        }
    }

    var icon: String {
        switch complexity.lowercased() {
        case "simple": return "1.circle.fill"
        case "medium": return "2.circle.fill"
        case "high": return "3.circle.fill"
        default: return "questionmark.circle.fill"
        }
    }

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
            Text(complexity.capitalized)
        }
        .font(.caption)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(color.opacity(0.2))
        .foregroundColor(color)
        .cornerRadius(12)
    }
}

struct PatternTag: View {
    let pattern: String

    var icon: String {
        let p = pattern.lowercased()
        if p.contains("crypto") || p.contains("encrypt") { return "lock.fill" }
        if p.contains("network") || p.contains("http") { return "network" }
        if p.contains("file") { return "doc.fill" }
        if p.contains("string") { return "text.quote" }
        if p.contains("memory") { return "memorychip" }
        if p.contains("license") || p.contains("check") { return "key.fill" }
        if p.contains("debug") { return "ladybug.fill" }
        return "tag.fill"
    }

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
            Text(pattern)
        }
        .font(.caption)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(Color.purple.opacity(0.1))
        .foregroundColor(.purple)
        .cornerRadius(16)
    }
}

// MARK: - Flow Layout

struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let result = layout(proposal: proposal, subviews: subviews)
        return result.size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = layout(proposal: proposal, subviews: subviews)
        for (index, subview) in subviews.enumerated() {
            subview.place(at: CGPoint(x: bounds.minX + result.positions[index].x,
                                      y: bounds.minY + result.positions[index].y),
                         proposal: .unspecified)
        }
    }

    private func layout(proposal: ProposedViewSize, subviews: Subviews) -> (size: CGSize, positions: [CGPoint]) {
        let maxWidth = proposal.width ?? .infinity
        var positions: [CGPoint] = []
        var currentX: CGFloat = 0
        var currentY: CGFloat = 0
        var lineHeight: CGFloat = 0
        var maxX: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)

            if currentX + size.width > maxWidth && currentX > 0 {
                currentX = 0
                currentY += lineHeight + spacing
                lineHeight = 0
            }

            positions.append(CGPoint(x: currentX, y: currentY))
            lineHeight = max(lineHeight, size.height)
            currentX += size.width + spacing
            maxX = max(maxX, currentX)
        }

        return (CGSize(width: maxX, height: currentY + lineHeight), positions)
    }
}
