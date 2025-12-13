import SwiftUI

struct StatusBarView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        HStack(spacing: 16) {
            // Status indicator
            HStack(spacing: 6) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 8, height: 8)

                Text(statusText)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Divider()
                .frame(height: 12)

            // File info
            if let file = appState.currentFile {
                HStack(spacing: 16) {
                    // Filename
                    Label(file.name, systemImage: "doc")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Divider()
                        .frame(height: 12)

                    // Format
                    Label(file.format.rawValue, systemImage: "square.stack.3d.up")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Divider()
                        .frame(height: 12)

                    // Architecture
                    Label(file.architecture.rawValue, systemImage: "cpu")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Divider()
                        .frame(height: 12)

                    // Size
                    Label(formatSize(file.fileSize), systemImage: "doc.text")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            // Analysis stats
            if appState.currentFile != nil {
                HStack(spacing: 16) {
                    StatBadge(
                        icon: "function",
                        value: appState.functions.count,
                        label: "functions"
                    )

                    StatBadge(
                        icon: "text.quote",
                        value: appState.strings.count,
                        label: "strings"
                    )

                    StatBadge(
                        icon: "tag",
                        value: appState.symbols.count,
                        label: "symbols"
                    )
                }
            }

            Divider()
                .frame(height: 12)

            // Current address
            if appState.selectedAddress != 0 {
                Text(String(format: "0x%llX", appState.selectedAddress))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.accent)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 6)
        .background(Color.sidebar)
    }

    private var statusColor: Color {
        if appState.isLoading {
            return .yellow
        } else if appState.currentFile != nil {
            return .green
        } else {
            return .gray
        }
    }

    private var statusText: String {
        if appState.isLoading {
            return appState.loadingMessage
        } else if appState.currentFile != nil {
            return "Ready"
        } else {
            return "No file loaded"
        }
    }

    private func formatSize(_ bytes: Int) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(bytes))
    }
}

// MARK: - Stat Badge

struct StatBadge: View {
    let icon: String
    let value: Int
    let label: String

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.caption2)
            Text("\(value)")
                .font(.system(.caption, design: .monospaced))
        }
        .foregroundColor(.secondary)
        .help("\(value) \(label)")
    }
}
