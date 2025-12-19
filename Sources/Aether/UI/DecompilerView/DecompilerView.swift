import SwiftUI

struct DecompilerView: View {
    @EnvironmentObject var appState: AppState
    @AppStorage("fontSize") private var fontSize = 13.0
    @AppStorage("fontName") private var fontName = "SF Mono"

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "doc.plaintext")
                    .foregroundColor(.accent)
                Text("Decompiler")
                    .font(.headline)
                Spacer()

                if let func_ = appState.selectedFunction {
                    Button {
                        copyToClipboard()
                    } label: {
                        Image(systemName: "doc.on.clipboard")
                    }
                    .buttonStyle(.plain)
                    .help("Copy to clipboard")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color.sidebar)

            Divider()

            // Content
            if appState.selectedFunction == nil {
                EmptyStateView(
                    icon: "doc.plaintext",
                    title: "No Function Selected",
                    message: "Select a function to see pseudo-code"
                )
            } else if appState.decompilerOutput.isEmpty {
                VStack {
                    ProgressView()
                    Text("Decompiling...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    SyntaxHighlightedCode(
                        code: appState.decompilerOutput,
                        fontSize: fontSize,
                        fontName: fontName
                    )
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .background(Color.background)
    }

    private func copyToClipboard() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(appState.decompilerOutput, forType: .string)
    }
}

// MARK: - Syntax Highlighted Code

struct SyntaxHighlightedCode: View {
    let code: String
    let fontSize: Double
    let fontName: String

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(code.split(separator: "\n", omittingEmptySubsequences: false).enumerated()), id: \.offset) { index, line in
                HStack(alignment: .top, spacing: 0) {
                    // Line number
                    Text("\(index + 1)")
                        .font(.system(size: fontSize - 2, design: .monospaced))
                        .foregroundColor(.secondary)
                        .frame(width: 40, alignment: .trailing)
                        .padding(.trailing, 12)

                    // Code line
                    highlightedLine(String(line))
                }
            }
        }
    }

    private func highlightedLine(_ line: String) -> some View {
        var attributedParts: [(String, Color)] = []
        var currentIndex = line.startIndex

        // Simple tokenizer for C-like syntax
        let keywords = Set(["if", "else", "while", "for", "return", "void", "int", "char",
                           "long", "short", "unsigned", "signed", "const", "static",
                           "struct", "enum", "typedef", "goto", "break", "continue"])
        let types = Set(["int", "void", "char", "long", "short", "unsigned", "signed",
                        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                        "int8_t", "int16_t", "int32_t", "int64_t"])

        var remaining = line[...]

        while !remaining.isEmpty {
            // Skip whitespace
            if remaining.first?.isWhitespace == true {
                var ws = ""
                while let char = remaining.first, char.isWhitespace {
                    ws.append(char)
                    remaining = remaining.dropFirst()
                }
                attributedParts.append((ws, .primary))
                continue
            }

            // Comment
            if remaining.hasPrefix("//") {
                attributedParts.append((String(remaining), .commentColor))
                break
            }

            // String literal
            if remaining.hasPrefix("\"") {
                var str = "\""
                remaining = remaining.dropFirst()
                while let char = remaining.first {
                    str.append(char)
                    remaining = remaining.dropFirst()
                    if char == "\"" && !str.hasSuffix("\\\"") {
                        break
                    }
                }
                attributedParts.append((str, .stringColor))
                continue
            }

            // Number (hex or decimal)
            if remaining.first?.isNumber == true || (remaining.hasPrefix("0x")) {
                var num = ""
                if remaining.hasPrefix("0x") {
                    num = "0x"
                    remaining = remaining.dropFirst(2)
                    while let char = remaining.first, char.isHexDigit {
                        num.append(char)
                        remaining = remaining.dropFirst()
                    }
                } else {
                    while let char = remaining.first, char.isNumber {
                        num.append(char)
                        remaining = remaining.dropFirst()
                    }
                }
                attributedParts.append((num, .immediateColor))
                continue
            }

            // Identifier or keyword
            if remaining.first?.isLetter == true || remaining.first == "_" {
                var ident = ""
                while let char = remaining.first, char.isLetter || char.isNumber || char == "_" {
                    ident.append(char)
                    remaining = remaining.dropFirst()
                }

                if keywords.contains(ident) {
                    attributedParts.append((ident, .keywordColor))
                } else if types.contains(ident) {
                    attributedParts.append((ident, .typeColor))
                } else if ident.hasPrefix("arg") || ident.hasPrefix("var_") || ident.hasPrefix("result") {
                    attributedParts.append((ident, .registerColor))
                } else if ident.hasPrefix("sub_") || ident.hasPrefix("loc_") {
                    attributedParts.append((ident, .accent))
                } else {
                    attributedParts.append((ident, .primary))
                }
                continue
            }

            // Operators and punctuation
            let char = remaining.first!
            attributedParts.append((String(char), .operatorColor))
            remaining = remaining.dropFirst()
        }

        return HStack(spacing: 0) {
            ForEach(Array(attributedParts.enumerated()), id: \.offset) { _, part in
                Text(part.0)
                    .font(.system(size: fontSize, design: .monospaced))
                    .foregroundColor(part.1)
            }
        }
    }
}

// MARK: - Character Extensions

extension Character {
    var isHexDigit: Bool {
        isNumber || ("a"..."f").contains(lowercased().first!) || ("A"..."F").contains(self)
    }
}
