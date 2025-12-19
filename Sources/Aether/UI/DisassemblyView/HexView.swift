import SwiftUI

struct HexView: View {
    @EnvironmentObject var appState: AppState
    @State private var data: Data = Data()
    @State private var baseAddress: UInt64 = 0
    @State private var bytesPerRow = 16

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "number")
                    .foregroundColor(.accent)
                Text("Hex View")
                    .font(.headline)
                Spacer()

                // Bytes per row selector
                Picker("", selection: $bytesPerRow) {
                    Text("8").tag(8)
                    Text("16").tag(16)
                    Text("32").tag(32)
                }
                .pickerStyle(.segmented)
                .frame(width: 120)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color.sidebar)

            Divider()

            // Hex content
            if data.isEmpty {
                EmptyStateView(
                    icon: "number.square",
                    title: "No Data",
                    message: "Select a section to view hex dump"
                )
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            // Column headers
                            HexHeaderRow(bytesPerRow: bytesPerRow)

                            // Data rows
                            ForEach(0..<rowCount, id: \.self) { rowIndex in
                                HexRow(
                                    data: data,
                                    baseAddress: baseAddress,
                                    rowIndex: rowIndex,
                                    bytesPerRow: bytesPerRow,
                                    selectedAddress: appState.selectedAddress
                                )
                                .id(rowAddress(for: rowIndex))
                            }
                        }
                        .padding(4)
                    }
                    .onChange(of: appState.selectedAddress) { _, newAddress in
                        let rowAddress = (newAddress / UInt64(bytesPerRow)) * UInt64(bytesPerRow)
                        withAnimation {
                            proxy.scrollTo(rowAddress, anchor: .center)
                        }
                    }
                }
            }
        }
        .background(Color.background)
        .onChange(of: appState.selectedSection) { _, section in
            if let section = section {
                data = section.data
                baseAddress = section.address
            } else {
                data = Data()
                baseAddress = 0
            }
        }
        .onAppear {
            if let section = appState.selectedSection {
                data = section.data
                baseAddress = section.address
            }
        }
    }

    private var rowCount: Int {
        (data.count + bytesPerRow - 1) / bytesPerRow
    }

    private func rowAddress(for index: Int) -> UInt64 {
        baseAddress + UInt64(index * bytesPerRow)
    }
}

// MARK: - Hex Header Row

struct HexHeaderRow: View {
    let bytesPerRow: Int

    var body: some View {
        HStack(spacing: 0) {
            // Address column
            Text("Address")
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 80, alignment: .leading)

            // Byte columns
            HStack(spacing: 4) {
                ForEach(0..<bytesPerRow, id: \.self) { i in
                    Text(String(format: "%02X", i))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.secondary)
                        .frame(width: 20)
                }
            }

            Spacer()
                .frame(width: 16)

            // ASCII column
            Text("ASCII")
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Color.sidebar.opacity(0.5))
    }
}

// MARK: - Hex Row

struct HexRow: View {
    let data: Data
    let baseAddress: UInt64
    let rowIndex: Int
    let bytesPerRow: Int
    let selectedAddress: UInt64

    private var rowAddress: UInt64 {
        baseAddress + UInt64(rowIndex * bytesPerRow)
    }

    private var rowData: [UInt8] {
        let start = rowIndex * bytesPerRow
        let end = min(start + bytesPerRow, data.count)
        return Array(data[start..<end])
    }

    private var isSelected: Bool {
        let rowStart = rowAddress
        let rowEnd = rowStart + UInt64(bytesPerRow)
        return selectedAddress >= rowStart && selectedAddress < rowEnd
    }

    var body: some View {
        HStack(spacing: 0) {
            // Address
            Text(String(format: "%08llX", rowAddress))
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.addressColor)
                .frame(width: 80, alignment: .leading)

            // Hex bytes
            HStack(spacing: 4) {
                ForEach(0..<bytesPerRow, id: \.self) { i in
                    if i < rowData.count {
                        let byteAddress = rowAddress + UInt64(i)
                        let isHighlighted = byteAddress == selectedAddress

                        Text(String(format: "%02X", rowData[i]))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(isHighlighted ? .accent : byteColor(rowData[i]))
                            .frame(width: 20)
                            .background(isHighlighted ? Color.accent.opacity(0.3) : Color.clear)
                            .cornerRadius(2)
                    } else {
                        Text("  ")
                            .font(.system(.caption, design: .monospaced))
                            .frame(width: 20)
                    }
                }
            }

            Spacer()
                .frame(width: 16)

            // ASCII representation
            HStack(spacing: 0) {
                ForEach(0..<rowData.count, id: \.self) { i in
                    Text(asciiChar(rowData[i]))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(isPrintable(rowData[i]) ? .primary : .secondary)
                }
            }
            .frame(width: CGFloat(bytesPerRow) * 8, alignment: .leading)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 1)
        .background(isSelected ? Color.accent.opacity(0.1) : Color.clear)
    }

    private func byteColor(_ byte: UInt8) -> Color {
        if byte == 0 {
            return .secondary.opacity(0.5)
        } else if isPrintable(byte) {
            return .immediateColor
        } else {
            return .primary
        }
    }

    private func isPrintable(_ byte: UInt8) -> Bool {
        byte >= 0x20 && byte <= 0x7E
    }

    private func asciiChar(_ byte: UInt8) -> String {
        if isPrintable(byte) {
            return String(UnicodeScalar(byte))
        }
        return "."
    }
}
