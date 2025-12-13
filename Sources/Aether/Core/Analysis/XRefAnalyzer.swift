import Foundation

/// Analyzes cross-references between code and data
class XRefAnalyzer {

    /// Analyze binary and build cross-references
    func analyze(
        binary: BinaryFile,
        functions: [Function],
        disassembler: DisassemblerEngine
    ) async -> [CrossReference] {
        var xrefs: [CrossReference] = []

        // Build function address lookup
        let functionAddresses = Set(functions.map { $0.startAddress })

        // Analyze each code section
        for section in binary.sections where section.containsCode {
            let instructions = await disassembler.disassemble(
                data: section.data,
                address: section.address,
                architecture: binary.architecture
            )

            for insn in instructions {
                // Call references
                if insn.type == .call, let target = insn.branchTarget {
                    xrefs.append(CrossReference(
                        fromAddress: insn.address,
                        toAddress: target,
                        type: .call
                    ))
                }

                // Jump references
                if insn.type == .jump || insn.type == .conditionalJump,
                   let target = insn.branchTarget {
                    xrefs.append(CrossReference(
                        fromAddress: insn.address,
                        toAddress: target,
                        type: .jump
                    ))
                }

                // Data references (RIP-relative addressing, etc.)
                if let dataRef = extractDataReference(insn: insn, binary: binary) {
                    xrefs.append(CrossReference(
                        fromAddress: insn.address,
                        toAddress: dataRef,
                        type: .data
                    ))
                }
            }
        }

        // Remove duplicates
        var seen = Set<String>()
        xrefs = xrefs.filter { xref in
            let key = "\(xref.fromAddress)-\(xref.toAddress)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }

        // Sort by source address
        xrefs.sort { $0.fromAddress < $1.fromAddress }

        return xrefs
    }

    /// Find all references to a specific address
    func findReferencesTo(address: UInt64, in xrefs: [CrossReference]) -> [CrossReference] {
        return xrefs.filter { $0.toAddress == address }
    }

    /// Find all references from a specific address
    func findReferencesFrom(address: UInt64, in xrefs: [CrossReference]) -> [CrossReference] {
        return xrefs.filter { $0.fromAddress == address }
    }

    // MARK: - Data Reference Extraction

    private func extractDataReference(insn: Instruction, binary: BinaryFile) -> UInt64? {
        // Look for memory references in operands
        let operands = insn.operands.lowercased()

        // RIP-relative addressing (x86_64)
        if operands.contains("[rip") {
            // Try to parse the target address from the operand string
            // Format: [rip + 0xABCD] or similar
            if let match = operands.range(of: "\\[rip \\+ 0x[0-9a-f]+\\]", options: .regularExpression) {
                let addrStr = operands[match]
                    .replacingOccurrences(of: "[rip + ", with: "")
                    .replacingOccurrences(of: "]", with: "")
                if let addr = UInt64(addrStr.dropFirst(2), radix: 16) {
                    // The address in the operand string is already the absolute address
                    return addr
                }
            }
        }

        // Absolute address references
        if let match = operands.range(of: "0x[0-9a-f]{6,16}", options: .regularExpression) {
            let addrStr = String(operands[match])
            if let addr = UInt64(addrStr.dropFirst(2), radix: 16) {
                // Check if this address is within the binary
                if binary.section(containing: addr) != nil {
                    return addr
                }
            }
        }

        // PC-relative addressing (ARM64)
        if insn.architecture == .arm64 || insn.architecture == .arm64e {
            // ADR, ADRP instructions have embedded addresses
            if insn.mnemonic == "adr" || insn.mnemonic == "adrp" {
                // Parse target from operands
                if let match = operands.range(of: "0x[0-9a-f]+", options: .regularExpression) {
                    let addrStr = String(operands[match])
                    if let addr = UInt64(addrStr.dropFirst(2), radix: 16) {
                        return addr
                    }
                }
            }
        }

        return nil
    }
}
