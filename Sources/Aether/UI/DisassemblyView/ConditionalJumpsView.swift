import SwiftUI

// MARK: - Conditional Jump Patcher

struct ConditionalJumpInfo: Identifiable {
    let id = UUID()
    let address: UInt64
    let originalOpcode: UInt8
    let flippedOpcode: UInt8
    let originalMnemonic: String
    let flippedMnemonic: String
    let targetAddress: UInt64
    let isLongJump: Bool  // 0F 8x vs 7x
    var isPatched: Bool = false

    static let jumpPairs: [(UInt8, UInt8, String, String)] = [
        // Short jumps (7x)
        (0x70, 0x71, "jo", "jno"),
        (0x71, 0x70, "jno", "jo"),
        (0x72, 0x73, "jb", "jae"),
        (0x73, 0x72, "jae", "jb"),
        (0x74, 0x75, "jz", "jnz"),
        (0x75, 0x74, "jnz", "jz"),
        (0x76, 0x77, "jbe", "ja"),
        (0x77, 0x76, "ja", "jbe"),
        (0x78, 0x79, "js", "jns"),
        (0x79, 0x78, "jns", "js"),
        (0x7A, 0x7B, "jp", "jnp"),
        (0x7B, 0x7A, "jnp", "jp"),
        (0x7C, 0x7D, "jl", "jge"),
        (0x7D, 0x7C, "jge", "jl"),
        (0x7E, 0x7F, "jle", "jg"),
        (0x7F, 0x7E, "jg", "jle"),
        // Long jumps (0F 8x) - second byte
        (0x80, 0x81, "jo", "jno"),
        (0x81, 0x80, "jno", "jo"),
        (0x82, 0x83, "jb", "jae"),
        (0x83, 0x82, "jae", "jb"),
        (0x84, 0x85, "jz", "jnz"),
        (0x85, 0x84, "jnz", "jz"),
        (0x86, 0x87, "jbe", "ja"),
        (0x87, 0x86, "ja", "jbe"),
        (0x88, 0x89, "js", "jns"),
        (0x89, 0x88, "jns", "js"),
        (0x8A, 0x8B, "jp", "jnp"),
        (0x8B, 0x8A, "jnp", "jp"),
        (0x8C, 0x8D, "jl", "jge"),
        (0x8D, 0x8C, "jge", "jl"),
        (0x8E, 0x8F, "jle", "jg"),
        (0x8F, 0x8E, "jg", "jle"),
    ]

    static func getFlippedOpcode(_ opcode: UInt8) -> (UInt8, String, String)? {
        for (orig, flipped, origMnem, flippedMnem) in jumpPairs {
            if opcode == orig {
                return (flipped, origMnem, flippedMnem)
            }
        }
        return nil
    }
}

// MARK: - Conditional Jumps View

struct ConditionalJumpsView: View {
    let instructions: [Instruction]
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    @State private var jumps: [ConditionalJumpInfo] = []
    @State private var searchText = ""
    @State private var showPatchedOnly = false
    @State private var patchStatus: String = ""

    var filteredJumps: [ConditionalJumpInfo] {
        var result = jumps
        if showPatchedOnly {
            result = result.filter { $0.isPatched }
        }
        if !searchText.isEmpty {
            result = result.filter {
                $0.originalMnemonic.localizedCaseInsensitiveContains(searchText) ||
                String(format: "0x%llX", $0.address).localizedCaseInsensitiveContains(searchText)
            }
        }
        return result
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "arrow.triangle.swap")
                    .foregroundColor(.orange)
                Text("Conditional Jumps Patcher")
                    .font(.headline)

                Spacer()

                Text("\(jumps.count) jumps, \(jumps.filter { $0.isPatched }.count) patched")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Button("Done") {
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            // Search and filter
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Search...", text: $searchText)
                    .textFieldStyle(.plain)

                Toggle("Patched only", isOn: $showPatchedOnly)
                    .toggleStyle(.checkbox)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)

            Divider()

            // Status
            if !patchStatus.isEmpty {
                HStack {
                    Image(systemName: "info.circle.fill")
                        .foregroundColor(.blue)
                    Text(patchStatus)
                        .font(.caption)
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.vertical, 4)
                .background(Color.blue.opacity(0.1))
            }

            // Table header
            HStack {
                Text("Address")
                    .frame(width: 100, alignment: .leading)
                Text("Original")
                    .frame(width: 80, alignment: .leading)
                Text("→")
                    .frame(width: 20)
                Text("Flipped")
                    .frame(width: 80, alignment: .leading)
                Text("Target")
                    .frame(width: 100, alignment: .leading)
                Spacer()
                Text("Action")
                    .frame(width: 80)
            }
            .font(.caption.bold())
            .foregroundColor(.secondary)
            .padding(.horizontal)
            .padding(.vertical, 6)
            .background(Color.secondary.opacity(0.1))

            // List
            ScrollView {
                LazyVStack(spacing: 1) {
                    ForEach(Array(filteredJumps.enumerated()), id: \.element.id) { index, jump in
                        ConditionalJumpRow(jump: jump) {
                            flipJump(at: index)
                        }
                    }
                }
            }
        }
        .frame(minWidth: 600, minHeight: 400)
        .onAppear {
            analyzeJumps()
        }
    }

    private func analyzeJumps() {
        jumps = []

        for insn in instructions {
            guard insn.type == .conditionalJump else { continue }

            // Get opcode from instruction bytes
            guard let firstByte = insn.bytes.first else { continue }

            let isLongJump = firstByte == 0x0F
            let opcodeToCheck: UInt8

            if isLongJump {
                guard insn.bytes.count > 1 else { continue }
                opcodeToCheck = insn.bytes[1]
            } else {
                opcodeToCheck = firstByte
            }

            // Find flipped opcode
            if let (flipped, origMnem, flippedMnem) = ConditionalJumpInfo.getFlippedOpcode(opcodeToCheck) {
                jumps.append(ConditionalJumpInfo(
                    address: insn.address,
                    originalOpcode: opcodeToCheck,
                    flippedOpcode: flipped,
                    originalMnemonic: origMnem,
                    flippedMnemonic: flippedMnem,
                    targetAddress: insn.branchTarget ?? 0,
                    isLongJump: isLongJump
                ))
            }
        }
    }

    private func flipJump(at index: Int) {
        guard index < jumps.count else { return }
        let jump = jumps[index]

        // Calculate file offset
        guard let binary = appState.currentFile,
              let section = binary.sections.first(where: { $0.contains(address: jump.address) }) else {
            patchStatus = "Error: Cannot find section for address"
            return
        }

        let sectionOffset = Int(jump.address - section.address)
        let byteOffset = jump.isLongJump ? sectionOffset + 1 : sectionOffset

        // Update status
        let oldMnem = jump.isPatched ? jump.flippedMnemonic : jump.originalMnemonic
        let newMnem = jump.isPatched ? jump.originalMnemonic : jump.flippedMnemonic
        patchStatus = "Flipped \(oldMnem.uppercased()) → \(newMnem.uppercased()) at 0x\(String(format: "%llX", jump.address))"

        // Toggle patched state
        jumps[index].isPatched.toggle()

        // TODO: Actually patch the binary in memory
        // For now just visual feedback
    }
}

// MARK: - Jump Row

struct ConditionalJumpRow: View {
    let jump: ConditionalJumpInfo
    let onFlip: () -> Void

    var body: some View {
        HStack {
            // Address
            Text(String(format: "0x%llX", jump.address))
                .font(.system(.caption, design: .monospaced))
                .frame(width: 100, alignment: .leading)

            // Original mnemonic
            Text(jump.isPatched ? jump.flippedMnemonic.uppercased() : jump.originalMnemonic.uppercased())
                .font(.system(.caption, design: .monospaced).bold())
                .foregroundColor(jump.isPatched ? .green : .primary)
                .frame(width: 80, alignment: .leading)

            // Arrow
            Image(systemName: "arrow.right")
                .font(.caption2)
                .foregroundColor(.secondary)
                .frame(width: 20)

            // Flipped mnemonic
            Text(jump.isPatched ? jump.originalMnemonic.uppercased() : jump.flippedMnemonic.uppercased())
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 80, alignment: .leading)

            // Target
            Text(String(format: "0x%llX", jump.targetAddress))
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.blue)
                .frame(width: 100, alignment: .leading)

            Spacer()

            // Flip button
            Button {
                onFlip()
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.triangle.swap")
                    Text(jump.isPatched ? "Revert" : "Flip")
                }
                .font(.caption)
            }
            .buttonStyle(.bordered)
            .tint(jump.isPatched ? .orange : .blue)
            .frame(width: 80)
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
        .background(jump.isPatched ? Color.green.opacity(0.1) : Color.clear)
    }
}
