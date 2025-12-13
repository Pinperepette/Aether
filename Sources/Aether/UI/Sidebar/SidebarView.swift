import SwiftUI

struct SidebarView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(spacing: 0) {
            // Sidebar tabs
            HStack(spacing: 0) {
                ForEach(SidebarItem.allCases) { item in
                    SidebarTab(item: item, isSelected: appState.sidebarSelection == item) {
                        appState.sidebarSelection = item
                    }
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)

            Divider()

            // Content
            Group {
                switch appState.sidebarSelection {
                case .functions:
                    FunctionsListView()
                case .strings:
                    StringsListView()
                case .imports:
                    ImportsListView()
                case .exports:
                    ExportsListView()
                case .symbols:
                    SymbolsListView()
                case .sections:
                    SectionsListView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Color.sidebar)
    }
}

// MARK: - Sidebar Tab

struct SidebarTab: View {
    let item: SidebarItem
    let isSelected: Bool
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 2) {
                Image(systemName: item.icon)
                    .font(.system(size: 12))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
            .background(isSelected ? Color.accent.opacity(0.2) : (isHovered ? Color.white.opacity(0.05) : Color.clear))
            .cornerRadius(4)
        }
        .buttonStyle(.plain)
        .foregroundColor(isSelected ? .accent : .secondary)
        .onHover { hovering in
            isHovered = hovering
        }
        .help(item.rawValue)
    }
}

// MARK: - Functions List

struct FunctionsListView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""

    var filteredFunctions: [Function] {
        if searchText.isEmpty {
            return appState.functions
        }
        return appState.functions.filter {
            $0.displayName.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Search
            SearchField(text: $searchText, placeholder: "Filter functions...")

            // List
            ScrollViewReader { proxy in
                List(filteredFunctions, selection: Binding(
                    get: { appState.selectedFunction },
                    set: { newValue in
                        if let func_ = newValue {
                            appState.selectFunction(func_)
                        }
                    }
                )) { func_ in
                    FunctionRow(function: func_, isSelected: appState.selectedFunction == func_)
                        .tag(func_)
                        .id(func_.startAddress)
                }
                .listStyle(.plain)
                .onChange(of: appState.selectedFunction) { _, newValue in
                    if let func_ = newValue {
                        withAnimation {
                            proxy.scrollTo(func_.startAddress, anchor: .center)
                        }
                    }
                }
            }
        }
    }
}

struct FunctionRow: View {
    let function: Function
    let isSelected: Bool
    @EnvironmentObject var appState: AppState
    @State private var showRenameSheet = false
    @State private var newName = ""

    var displayName: String {
        appState.renamedFunctions[function.startAddress] ?? function.displayName
    }

    var body: some View {
        HStack {
            Image(systemName: function.isLeaf ? "leaf" : "function")
                .foregroundColor(function.isLeaf ? .green : .accent)
                .font(.caption)

            VStack(alignment: .leading, spacing: 2) {
                Text(displayName)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1)

                Text(String(format: "0x%llX", function.startAddress))
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(.secondary)
            }

            Spacer()

            Text(formatSize(Int(function.size)))
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 2)
        .contextMenu {
            Button("Rename...") {
                newName = displayName
                showRenameSheet = true
            }

            Button("Go to address") {
                appState.goToAddress(function.startAddress)
            }

            Divider()

            Button("Copy name") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(displayName, forType: .string)
            }

            Button("Copy address") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(String(format: "0x%llX", function.startAddress), forType: .string)
            }
        }
        .sheet(isPresented: $showRenameSheet) {
            RenameSheet(
                title: "Rename Function",
                currentName: displayName,
                newName: $newName,
                onSave: { name in
                    appState.renameFunction(at: function.startAddress, to: name)
                }
            )
        }
    }

    private func formatSize(_ bytes: Int) -> String {
        if bytes < 1024 {
            return "\(bytes)B"
        }
        return String(format: "%.1fKB", Double(bytes) / 1024.0)
    }
}

// MARK: - Strings List

struct StringsListView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""

    var filteredStrings: [StringReference] {
        if searchText.isEmpty {
            return appState.strings
        }
        return appState.strings.filter {
            $0.value.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            SearchField(text: $searchText, placeholder: "Filter strings...")

            List(filteredStrings) { str in
                Button {
                    appState.goToAddress(str.address)
                } label: {
                    HStack {
                        Text(str.value)
                            .font(.system(.caption, design: .monospaced))
                            .lineLimit(1)

                        Spacer()

                        Text(String(format: "0x%llX", str.address))
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                }
                .buttonStyle(.plain)
            }
            .listStyle(.plain)
        }
    }
}

// MARK: - Imports List

struct ImportsListView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""

    var filteredImports: [Symbol] {
        let imports = appState.imports
        if searchText.isEmpty {
            return imports
        }
        return imports.filter {
            $0.displayName.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            SearchField(text: $searchText, placeholder: "Filter imports...")

            List(filteredImports) { symbol in
                SymbolRow(symbol: symbol) {
                    appState.goToAddress(symbol.address)
                }
            }
            .listStyle(.plain)
        }
    }
}

// MARK: - Exports List

struct ExportsListView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""

    var filteredExports: [Symbol] {
        let exports = appState.exports
        if searchText.isEmpty {
            return exports
        }
        return exports.filter {
            $0.displayName.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            SearchField(text: $searchText, placeholder: "Filter exports...")

            List(filteredExports) { symbol in
                SymbolRow(symbol: symbol) {
                    appState.goToAddress(symbol.address)
                }
            }
            .listStyle(.plain)
        }
    }
}

// MARK: - Symbols List

struct SymbolsListView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""

    var filteredSymbols: [Symbol] {
        if searchText.isEmpty {
            return appState.symbols
        }
        return appState.symbols.filter {
            $0.displayName.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            SearchField(text: $searchText, placeholder: "Filter symbols...")

            List(filteredSymbols) { symbol in
                SymbolRow(symbol: symbol) {
                    appState.goToAddress(symbol.address)
                }
            }
            .listStyle(.plain)
        }
    }
}

// MARK: - Sections List

struct SectionsListView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        List(appState.currentFile?.sections ?? [], selection: Binding(
            get: { appState.selectedSection },
            set: { newValue in
                appState.selectedSection = newValue
                if let section = newValue {
                    appState.goToAddress(section.address)
                }
            }
        )) { section in
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(section.fullName)
                        .font(.system(.caption, design: .monospaced))

                    HStack(spacing: 8) {
                        Text(String(format: "0x%llX", section.address))
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.secondary)

                        if section.isExecutable {
                            Text("X")
                                .font(.caption2)
                                .padding(.horizontal, 4)
                                .background(Color.red.opacity(0.3))
                                .cornerRadius(2)
                        }
                    }
                }

                Spacer()

                Text(formatSize(Int(section.size)))
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .tag(section)
        }
        .listStyle(.plain)
    }

    private func formatSize(_ bytes: Int) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(bytes))
    }
}

// MARK: - Symbol Row

struct SymbolRow: View {
    let symbol: Symbol
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: symbol.type.icon)
                    .foregroundColor(symbolColor)
                    .font(.caption)

                VStack(alignment: .leading, spacing: 2) {
                    Text(symbol.displayName)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)

                    if symbol.address != 0 {
                        Text(String(format: "0x%llX", symbol.address))
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                }

                Spacer()
            }
        }
        .buttonStyle(.plain)
    }

    private var symbolColor: Color {
        switch symbol.type {
        case .function:
            return .accent
        case .data, .object:
            return .green
        default:
            return .secondary
        }
    }
}

// MARK: - Search Field

struct SearchField: View {
    @Binding var text: String
    let placeholder: String

    var body: some View {
        HStack {
            Image(systemName: "magnifyingglass")
                .foregroundColor(.secondary)
                .font(.caption)

            TextField(placeholder, text: $text)
                .textFieldStyle(.plain)
                .font(.caption)

            if !text.isEmpty {
                Button {
                    text = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                        .font(.caption)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(8)
        .background(Color.background)
    }
}

// MARK: - Rename Sheet

struct RenameSheet: View {
    let title: String
    let currentName: String
    @Binding var newName: String
    let onSave: (String) -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 16) {
            Text(title)
                .font(.headline)

            VStack(alignment: .leading, spacing: 4) {
                Text("Current name:")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Text(currentName)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(.secondary)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("New name:")
                    .font(.caption)
                    .foregroundColor(.secondary)

                TextField("Enter new name...", text: $newName)
                    .font(.system(.body, design: .monospaced))
                    .textFieldStyle(.roundedBorder)
            }

            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.escape)

                Spacer()

                Button("Reset") {
                    newName = ""
                    onSave("")
                    dismiss()
                }

                Button("Rename") {
                    onSave(newName)
                    dismiss()
                }
                .keyboardShortcut(.return)
                .buttonStyle(.borderedProminent)
                .disabled(newName.isEmpty || newName == currentName)
            }
        }
        .padding(20)
        .frame(width: 400)
    }
}
