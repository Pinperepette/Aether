import SwiftUI

struct AIRenameView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    @State private var showPreview = false

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "textformat.abc")
                    .font(.title2)
                    .foregroundColor(.orange)

                VStack(alignment: .leading, spacing: 2) {
                    Text("AI Variable Renaming")
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
            if appState.isGeneratingRenames {
                loadingView
            } else if let error = appState.renameError {
                errorView(error)
            } else if appState.suggestedRenames.isEmpty {
                emptyView
            } else {
                renameListView
            }

            // Footer with actions
            if !appState.suggestedRenames.isEmpty && !appState.isGeneratingRenames {
                Divider()
                footerView
            }
        }
        .frame(minWidth: 500, minHeight: 400)
        .frame(idealWidth: 600, idealHeight: 500)
        .sheet(isPresented: $showPreview) {
            previewSheet
        }
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)

            Text("Analyzing variables...")
                .font(.headline)
                .foregroundColor(.secondary)

            Text("AI is examining your code for generic variable names")
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
                appState.suggestVariableNames()
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 48))
                .foregroundColor(.green)

            Text("No suggestions")
                .font(.headline)

            Text("The code doesn't have any generic variable names that need renaming")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var renameListView: some View {
        VStack(spacing: 0) {
            // Stats bar
            HStack {
                Text("\(appState.suggestedRenames.count) suggestions")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                let selected = appState.suggestedRenames.filter { $0.isAccepted }.count
                Text("\(selected) selected")
                    .font(.caption)
                    .foregroundColor(selected > 0 ? .orange : .secondary)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(Color.background.opacity(0.5))

            Divider()

            // List
            List {
                ForEach(appState.suggestedRenames) { rename in
                    RenameRow(rename: rename) {
                        appState.toggleRenameSelection(rename)
                    }
                }
            }
            .listStyle(.plain)
        }
    }

    private var footerView: some View {
        HStack {
            Button("Select All") {
                appState.selectAllRenames()
            }
            .buttonStyle(.plain)
            .foregroundColor(.accent)

            Button("Deselect All") {
                appState.deselectAllRenames()
            }
            .buttonStyle(.plain)
            .foregroundColor(.secondary)

            Spacer()

            Button("Preview") {
                showPreview = true
            }
            .disabled(appState.suggestedRenames.filter { $0.isAccepted }.isEmpty)

            Button("Apply Selected") {
                appState.applySelectedRenames()
                dismiss()
            }
            .buttonStyle(.borderedProminent)
            .tint(.orange)
            .disabled(appState.suggestedRenames.filter { $0.isAccepted }.isEmpty)
        }
        .padding()
        .background(Color.sidebar)
    }

    private var previewSheet: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Preview Changes")
                    .font(.headline)

                Spacer()

                Button("Close") {
                    showPreview = false
                }
                .buttonStyle(.plain)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            // Preview content
            ScrollView {
                Text(previewCode)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(minWidth: 500, minHeight: 400)
    }

    private var previewCode: String {
        let acceptedRenames = appState.suggestedRenames.filter { $0.isAccepted }
        var code = appState.decompilerOutput

        for rename in acceptedRenames {
            let pattern = "\\b\(NSRegularExpression.escapedPattern(for: rename.originalName))\\b"
            if let regex = try? NSRegularExpression(pattern: pattern, options: []) {
                let range = NSRange(code.startIndex..<code.endIndex, in: code)
                code = regex.stringByReplacingMatches(in: code, options: [], range: range, withTemplate: rename.suggestedName)
            }
        }

        return code
    }
}

// MARK: - Rename Row

struct RenameRow: View {
    let rename: VariableRename
    let onToggle: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            // Checkbox
            Button {
                onToggle()
            } label: {
                Image(systemName: rename.isAccepted ? "checkmark.square.fill" : "square")
                    .foregroundColor(rename.isAccepted ? .orange : .secondary)
                    .font(.title3)
            }
            .buttonStyle(.plain)

            // Names
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(rename.originalName)
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.red.opacity(0.8))
                        .strikethrough(rename.isAccepted)

                    Image(systemName: "arrow.right")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Text(rename.suggestedName)
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.green)
                        .fontWeight(rename.isAccepted ? .semibold : .regular)
                }

                Text(rename.reason)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }

            Spacer()
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .onTapGesture {
            onToggle()
        }
    }
}
