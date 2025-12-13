import SwiftUI

struct XRefsView: View {
    @EnvironmentObject var appState: AppState
    let address: UInt64

    var xrefsTo: [CrossReference] {
        appState.getXRefsTo(address: address)
    }

    var xrefsFrom: [CrossReference] {
        appState.getXRefsFrom(address: address)
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Cross References")
                    .font(.headline)

                Spacer()

                Text(String(format: "0x%llX", address))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            if xrefsTo.isEmpty && xrefsFrom.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "arrow.triangle.branch")
                        .font(.system(size: 40))
                        .foregroundColor(.secondary)

                    Text("No cross-references found")
                        .foregroundColor(.secondary)

                    Text("Run 'Analyze All' to build cross-references")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    // References TO this address (who calls/references this?)
                    if !xrefsTo.isEmpty {
                        SwiftUI.Section("Referenced by (\(xrefsTo.count))") {
                            ForEach(xrefsTo) { xref in
                                XRefRow(xref: xref, direction: .to) {
                                    appState.goToAddress(xref.fromAddress)
                                }
                            }
                        }
                    }

                    // References FROM this address (what does this call/reference?)
                    if !xrefsFrom.isEmpty {
                        SwiftUI.Section("References (\(xrefsFrom.count))") {
                            ForEach(xrefsFrom) { xref in
                                XRefRow(xref: xref, direction: .from) {
                                    appState.goToAddress(xref.toAddress)
                                }
                            }
                        }
                    }
                }
                .listStyle(.sidebar)
            }
        }
        .frame(width: 350, height: 300)
    }
}

struct XRefRow: View {
    let xref: CrossReference
    let direction: XRefDirection
    let action: () -> Void

    enum XRefDirection {
        case to, from
    }

    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: iconForType(xref.type))
                    .foregroundColor(colorForType(xref.type))
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 2) {
                    Text(direction == .to ?
                         String(format: "0x%llX", xref.fromAddress) :
                         String(format: "0x%llX", xref.toAddress))
                        .font(.system(.caption, design: .monospaced))

                    Text(xref.type.rawValue)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Image(systemName: direction == .to ? "arrow.right" : "arrow.left")
                    .foregroundColor(.secondary)
                    .font(.caption)
            }
        }
        .buttonStyle(.plain)
    }

    private func iconForType(_ type: XRefType) -> String {
        switch type {
        case .call: return "phone.arrow.right"
        case .jump: return "arrow.uturn.right"
        case .data: return "doc"
        case .string: return "text.quote"
        }
    }

    private func colorForType(_ type: XRefType) -> Color {
        switch type {
        case .call: return .accent
        case .jump: return .orange
        case .data: return .green
        case .string: return .purple
        }
    }
}

// MARK: - XRefs Popover Button

struct XRefsButton: View {
    @EnvironmentObject var appState: AppState
    let address: UInt64
    @State private var showPopover = false

    var hasXRefs: Bool {
        !appState.getXRefsTo(address: address).isEmpty ||
        !appState.getXRefsFrom(address: address).isEmpty
    }

    var body: some View {
        Button {
            showPopover.toggle()
        } label: {
            HStack(spacing: 2) {
                Image(systemName: "arrow.triangle.branch")
                    .font(.caption2)

                if hasXRefs {
                    Text("\(appState.getXRefsTo(address: address).count)")
                        .font(.caption2)
                }
            }
            .foregroundColor(hasXRefs ? .accent : .secondary)
        }
        .buttonStyle(.plain)
        .popover(isPresented: $showPopover) {
            XRefsView(address: address)
                .environmentObject(appState)
        }
    }
}
