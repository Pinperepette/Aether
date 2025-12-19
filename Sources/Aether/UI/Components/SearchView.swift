import SwiftUI

struct SearchView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var searchQuery = ""
    @State private var searchType: SearchType = .all

    var body: some View {
        VStack(spacing: 0) {
            // Search header
            VStack(spacing: 12) {
                HStack {
                    Text("Search")
                        .font(.headline)

                    Spacer()

                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }

                // Search input
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.secondary)

                    TextField("Search...", text: $searchQuery)
                        .textFieldStyle(.plain)
                        .onSubmit {
                            performSearch()
                        }

                    if appState.isSearching {
                        ProgressView()
                            .scaleEffect(0.7)
                    }

                    if !searchQuery.isEmpty {
                        Button {
                            searchQuery = ""
                            appState.searchResults = []
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(10)
                .background(Color.background)
                .cornerRadius(8)

                // Search type picker
                Picker("Type", selection: $searchType) {
                    ForEach(SearchType.allCases, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .pickerStyle(.segmented)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            // Results
            if appState.searchResults.isEmpty {
                if searchQuery.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 40))
                            .foregroundColor(.secondary)

                        Text("Enter a search query")
                            .foregroundColor(.secondary)

                        Text("Search for functions, strings, symbols, bytes, or addresses")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if !appState.isSearching {
                    VStack(spacing: 8) {
                        Image(systemName: "questionmark.circle")
                            .font(.system(size: 40))
                            .foregroundColor(.secondary)

                        Text("No results found")
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                List(appState.searchResults) { result in
                    SearchResultRow(result: result) {
                        appState.goToAddress(result.address)
                        dismiss()
                    }
                }
                .listStyle(.plain)
            }
        }
        .frame(width: 500, height: 400)
    }

    private func performSearch() {
        guard !searchQuery.isEmpty else { return }
        Task {
            await appState.search(query: searchQuery, type: searchType)
        }
    }
}

struct SearchResultRow: View {
    let result: SearchResult
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: iconForType(result.type))
                    .foregroundColor(colorForType(result.type))
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 2) {
                    Text(result.name)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)

                    Text(String(format: "0x%llX", result.address))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.secondary)
                }

                Spacer()

                Text(result.type.displayName)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.2))
                    .cornerRadius(4)
            }
        }
        .buttonStyle(.plain)
    }

    private func iconForType(_ type: SearchResultType) -> String {
        switch type {
        case .function: return "function"
        case .string: return "text.quote"
        case .symbol: return "tag"
        case .bytes: return "number"
        case .address: return "location"
        }
    }

    private func colorForType(_ type: SearchResultType) -> Color {
        switch type {
        case .function: return .accent
        case .string: return .green
        case .symbol: return .orange
        case .bytes: return .purple
        case .address: return .blue
        }
    }
}

extension SearchResultType {
    var displayName: String {
        switch self {
        case .function: return "Function"
        case .string: return "String"
        case .symbol: return "Symbol"
        case .bytes: return "Bytes"
        case .address: return "Address"
        }
    }
}
