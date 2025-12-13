import Foundation

/// Analyzes binary to identify functions
class FunctionAnalyzer {

    /// Analyze binary and identify functions
    func analyze(binary: BinaryFile, disassembler: DisassemblerEngine) async -> [Function] {
        var functions: [Function] = []
        var functionAddresses = Set<UInt64>()

        // 1. Get functions from symbols
        for symbol in binary.symbols where symbol.type == .function && symbol.address != 0 {
            if !functionAddresses.contains(symbol.address) {
                functionAddresses.insert(symbol.address)
                functions.append(Function(
                    name: symbol.name,
                    startAddress: symbol.address,
                    endAddress: symbol.address + max(symbol.size, 4)
                ))
            }
        }

        // 2. Add entry point
        if binary.entryPoint != 0 && !functionAddresses.contains(binary.entryPoint) {
            functionAddresses.insert(binary.entryPoint)
            functions.append(Function(
                name: "_start",
                startAddress: binary.entryPoint,
                endAddress: binary.entryPoint + 4
            ))
        }

        // 3. Scan code sections for function prologues and call targets
        for section in binary.sections where section.containsCode {
            let instructions = await disassembler.disassemble(
                data: section.data,
                address: section.address,
                architecture: binary.architecture
            )

            // Find call targets
            for insn in instructions {
                if insn.type == .call, let target = insn.branchTarget {
                    if !functionAddresses.contains(target) &&
                       section.contains(address: target) {
                        functionAddresses.insert(target)
                        functions.append(Function(
                            name: "",
                            startAddress: target,
                            endAddress: target + 4
                        ))
                    }
                }
            }

            // Find function prologues
            let prologueAddresses = findFunctionPrologues(
                instructions: instructions,
                architecture: binary.architecture
            )

            for addr in prologueAddresses {
                if !functionAddresses.contains(addr) {
                    functionAddresses.insert(addr)
                    functions.append(Function(
                        name: "",
                        startAddress: addr,
                        endAddress: addr + 4
                    ))
                }
            }
        }

        // 4. Sort by address
        functions.sort { $0.startAddress < $1.startAddress }

        // 5. Calculate function end addresses
        for i in 0..<functions.count {
            if i + 1 < functions.count {
                // End at next function start
                functions[i].endAddress = functions[i + 1].startAddress
            } else {
                // Last function - find the section end
                if let section = binary.sections.first(where: { $0.contains(address: functions[i].startAddress) }) {
                    functions[i].endAddress = section.address + section.size
                }
            }

            // Refine end address by finding return instructions
            if let section = binary.sections.first(where: { $0.contains(address: functions[i].startAddress) }) {
                let refinedEnd = await findFunctionEnd(
                    function: functions[i],
                    section: section,
                    disassembler: disassembler,
                    architecture: binary.architecture
                )
                if refinedEnd > functions[i].startAddress {
                    functions[i].endAddress = min(functions[i].endAddress, refinedEnd)
                }
            }
        }

        // 6. Build basic blocks for each function
        for i in 0..<functions.count {
            functions[i].basicBlocks = await buildBasicBlocks(
                function: functions[i],
                binary: binary,
                disassembler: disassembler
            )

            // Determine if function is a leaf (doesn't call other functions)
            functions[i].isLeaf = !functions[i].basicBlocks.flatMap(\.instructions).contains { $0.type == .call }
        }

        return functions
    }

    // MARK: - Prologue Detection

    private func findFunctionPrologues(instructions: [Instruction], architecture: Architecture) -> [UInt64] {
        var prologues: [UInt64] = []

        switch architecture {
        case .x86_64, .i386:
            // Look for: push rbp; mov rbp, rsp
            for i in 0..<instructions.count - 1 {
                let insn = instructions[i]
                if insn.mnemonic == "push" &&
                   (insn.operands == "rbp" || insn.operands == "ebp") {
                    let next = instructions[i + 1]
                    if next.mnemonic == "mov" &&
                       (next.operands.contains("rbp, rsp") || next.operands.contains("ebp, esp")) {
                        prologues.append(insn.address)
                    }
                }
                // Also look for: sub rsp, imm (without push rbp)
                if insn.mnemonic == "sub" && insn.operands.hasPrefix("rsp") {
                    // Check if previous instruction is not part of another function
                    if i == 0 || instructions[i - 1].type == .return {
                        prologues.append(insn.address)
                    }
                }
            }

        case .arm64, .arm64e:
            // Look for: stp x29, x30, [sp, #-N]!
            // Or: sub sp, sp, #N
            for i in 0..<instructions.count {
                let insn = instructions[i]
                if insn.mnemonic == "stp" && insn.operands.contains("x29") && insn.operands.contains("x30") {
                    prologues.append(insn.address)
                }
                // PACIBSP (pointer authentication) indicates function start
                if insn.mnemonic == "pacibsp" {
                    prologues.append(insn.address)
                }
            }

        case .armv7:
            // Look for: push {r4-rN, lr} or push {fp, lr}
            for insn in instructions {
                if insn.mnemonic == "push" && insn.operands.contains("lr") {
                    prologues.append(insn.address)
                }
            }

        case .jvm:
            // JVM bytecode - methods are defined by class structure, not prologues
            // Each method starts with its bytecode, no standard prologue pattern
            for insn in instructions {
                // Look for aload_0 which often starts instance methods
                if insn.mnemonic == "aload_0" {
                    // Check if previous is return or start
                    prologues.append(insn.address)
                }
            }

        case .unknown:
            break
        }

        return prologues
    }

    // MARK: - Function End Detection

    private func findFunctionEnd(
        function: Function,
        section: Section,
        disassembler: DisassemblerEngine,
        architecture: Architecture
    ) async -> UInt64 {
        let maxSize = min(function.endAddress - function.startAddress, 0x10000)
        let offset = Int(function.startAddress - section.address)

        guard offset >= 0 && offset < section.data.count else {
            return function.endAddress
        }

        let endOffset = min(offset + Int(maxSize), section.data.count)
        let data = section.data[offset..<endOffset]

        let instructions = await disassembler.disassemble(
            data: Data(data),
            address: function.startAddress,
            architecture: architecture
        )

        // Find the last return instruction
        var lastReturn: UInt64 = function.startAddress

        for insn in instructions {
            if insn.type == .return {
                lastReturn = insn.address + UInt64(insn.size)
            }
            // Stop at unconditional jump to outside the function (tail call)
            if insn.type == .jump, let target = insn.branchTarget {
                if target < function.startAddress || target >= function.endAddress {
                    return insn.address + UInt64(insn.size)
                }
            }
        }

        return lastReturn > function.startAddress ? lastReturn : function.endAddress
    }

    // MARK: - Basic Block Building

    private func buildBasicBlocks(
        function: Function,
        binary: BinaryFile,
        disassembler: DisassemblerEngine
    ) async -> [BasicBlock] {
        guard let section = binary.sections.first(where: { $0.contains(address: function.startAddress) }) else {
            return []
        }

        let offset = Int(function.startAddress - section.address)
        let size = Int(function.size)

        guard offset >= 0 && offset + size <= section.data.count else {
            return []
        }

        let data = section.data[offset..<(offset + size)]
        let instructions = await disassembler.disassemble(
            data: Data(data),
            address: function.startAddress,
            architecture: binary.architecture
        )

        guard !instructions.isEmpty else {
            return []
        }

        // Find block leaders (start of basic blocks)
        var leaders = Set<UInt64>()
        leaders.insert(function.startAddress)  // First instruction is a leader

        for insn in instructions {
            // Target of a branch is a leader
            if let target = insn.branchTarget, function.contains(address: target) {
                leaders.insert(target)
            }
            // Instruction after a branch is a leader
            if insn.endsBasicBlock {
                let nextAddr = insn.address + UInt64(insn.size)
                if function.contains(address: nextAddr) {
                    leaders.insert(nextAddr)
                }
            }
        }

        // Build basic blocks
        var blocks: [BasicBlock] = []
        let sortedLeaders = leaders.sorted()

        for (i, leaderAddr) in sortedLeaders.enumerated() {
            let endAddr: UInt64
            if i + 1 < sortedLeaders.count {
                endAddr = sortedLeaders[i + 1]
            } else {
                endAddr = function.endAddress
            }

            var block = BasicBlock(
                startAddress: leaderAddr,
                endAddress: endAddr
            )

            // Collect instructions for this block
            block.instructions = instructions.filter {
                $0.address >= leaderAddr && $0.address < endAddr
            }

            // Determine block type and successors
            if leaderAddr == function.startAddress {
                block.type = .entry
            }

            if let lastInsn = block.instructions.last {
                switch lastInsn.type {
                case .return:
                    block.type = .exit
                case .conditionalJump:
                    block.type = .conditional
                    // Fall-through successor
                    let fallThrough = lastInsn.address + UInt64(lastInsn.size)
                    if function.contains(address: fallThrough) {
                        block.successors.append(fallThrough)
                    }
                    // Branch target successor
                    if let target = lastInsn.branchTarget, function.contains(address: target) {
                        block.successors.append(target)
                    }
                case .jump:
                    if let target = lastInsn.branchTarget, function.contains(address: target) {
                        block.successors.append(target)
                    }
                default:
                    // Fall through to next block
                    if i + 1 < sortedLeaders.count {
                        block.successors.append(sortedLeaders[i + 1])
                    }
                }
            }

            blocks.append(block)
        }

        // Build predecessor lists
        for i in 0..<blocks.count {
            for j in 0..<blocks.count where i != j {
                if blocks[j].successors.contains(blocks[i].startAddress) {
                    blocks[i].predecessors.append(blocks[j].startAddress)
                }
            }
        }

        // Detect loops
        for i in 0..<blocks.count {
            for successor in blocks[i].successors {
                if successor <= blocks[i].startAddress {
                    blocks[i].type = .loop
                }
            }
        }

        return blocks
    }
}
