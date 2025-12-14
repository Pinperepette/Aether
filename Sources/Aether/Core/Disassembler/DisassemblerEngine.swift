import Foundation

/// Main disassembly engine
/// Uses Capstone when available, falls back to native implementation
actor DisassemblerEngine {

    // MARK: - Disassembly

    /// Disassemble binary data
    func disassemble(
        data: Data,
        address: UInt64,
        architecture: Architecture
    ) async -> [Instruction] {
        switch architecture {
        case .x86_64:
            return disassembleX86_64(data: data, address: address)
        case .arm64, .arm64e:
            return disassembleARM64(data: data, address: address)
        case .i386:
            return disassembleX86(data: data, address: address)
        case .armv7:
            return disassembleARM(data: data, address: address)
        case .jvm:
            return disassembleJVM(data: data, address: address)
        case .unknown:
            return []
        }
    }

    // MARK: - x86_64 Disassembly

    private func disassembleX86_64(data: Data, address: UInt64) -> [Instruction] {
        var instructions: [Instruction] = []
        var offset = 0
        var currentAddress = address

        let maxInstructions = 100000
        while offset < data.count && instructions.count < maxInstructions {
            let remaining = data.count - offset
            guard remaining > 0 else { break }
            let endIdx = min(offset + 15, data.count)
            guard offset < endIdx else { break }
            let bytes = Array(data[offset..<endIdx])
            guard !bytes.isEmpty else { break }

            guard let (mnemonic, operands, size, type, target) = decodeX86_64Instruction(bytes: bytes, address: currentAddress) else {
                // Unknown instruction, skip one byte
                instructions.append(Instruction(
                    address: currentAddress,
                    size: 1,
                    bytes: [bytes[0]],
                    mnemonic: "db",
                    operands: String(format: "0x%02X", bytes[0]),
                    architecture: .x86_64,
                    type: .other
                ))
                offset += 1
                currentAddress += 1
                continue
            }

            let actualSize = min(size, bytes.count)
            var instruction = Instruction(
                address: currentAddress,
                size: actualSize,
                bytes: Array(bytes[0..<actualSize]),
                mnemonic: mnemonic,
                operands: operands,
                architecture: .x86_64,
                type: type
            )
            instruction.branchTarget = target

            instructions.append(instruction)
            offset += actualSize
            currentAddress += UInt64(actualSize)
        }

        return instructions
    }

    private func decodeX86_64Instruction(bytes: [UInt8], address: UInt64) -> (String, String, Int, InstructionType, UInt64?)? {
        guard bytes.count >= 1 else { return nil }

        var idx = 0
        var hasRex = false
        var rexW = false
        var rexR = false
        var rexX = false
        var rexB = false

        // Check for REX prefix (0x40-0x4F)
        if bytes[idx] >= 0x40 && bytes[idx] <= 0x4F {
            hasRex = true
            rexW = (bytes[idx] & 0x08) != 0
            rexR = (bytes[idx] & 0x04) != 0
            rexX = (bytes[idx] & 0x02) != 0
            rexB = (bytes[idx] & 0x01) != 0
            idx += 1
            guard idx < bytes.count else { return nil }
        }

        let opcode = bytes[idx]
        idx += 1

        // Decode based on opcode
        switch opcode {
        // NOP
        case 0x90:
            return ("nop", "", 1 + (hasRex ? 1 : 0), .nop, nil)

        // RET
        case 0xC3:
            return ("ret", "", 1 + (hasRex ? 1 : 0), .return, nil)

        // RET imm16
        case 0xC2:
            guard idx + 1 < bytes.count else { return nil }
            let imm = UInt16(bytes[idx]) | (UInt16(bytes[idx + 1]) << 8)
            return ("ret", String(format: "0x%X", imm), 3 + (hasRex ? 1 : 0), .return, nil)

        // PUSH r64
        case 0x50...0x57:
            let reg = registerName64(Int(opcode - 0x50) + (rexB ? 8 : 0))
            return ("push", reg, 1 + (hasRex ? 1 : 0), .push, nil)

        // POP r64
        case 0x58...0x5F:
            let reg = registerName64(Int(opcode - 0x58) + (rexB ? 8 : 0))
            return ("pop", reg, 1 + (hasRex ? 1 : 0), .pop, nil)

        // MOV r64, imm64
        case 0xB8...0xBF:
            let reg = registerName64(Int(opcode - 0xB8) + (rexB ? 8 : 0), wide: rexW)
            if rexW {
                guard idx + 7 < bytes.count else { return nil }
                var imm: UInt64 = 0
                for i in 0..<8 {
                    imm |= UInt64(bytes[idx + i]) << (i * 8)
                }
                return ("mov", "\(reg), \(formatImmediate(imm))", 10, .move, nil)
            } else {
                guard idx + 3 < bytes.count else { return nil }
                var imm: UInt32 = 0
                for i in 0..<4 {
                    imm |= UInt32(bytes[idx + i]) << (i * 8)
                }
                return ("mov", "\(reg), \(formatImmediate(UInt64(imm)))", 5 + (hasRex ? 1 : 0), .move, nil)
            }

        // CALL rel32
        case 0xE8:
            guard idx + 3 < bytes.count else { return nil }
            var rel: Int32 = 0
            for i in 0..<4 {
                rel |= Int32(bytes[idx + i]) << (i * 8)
            }
            let target = UInt64(Int64(address) + Int64(5 + (hasRex ? 1 : 0)) + Int64(rel))
            return ("call", formatAddress(target), 5 + (hasRex ? 1 : 0), .call, target)

        // JMP rel32
        case 0xE9:
            guard idx + 3 < bytes.count else { return nil }
            var rel: Int32 = 0
            for i in 0..<4 {
                rel |= Int32(bytes[idx + i]) << (i * 8)
            }
            let target = UInt64(Int64(address) + Int64(5 + (hasRex ? 1 : 0)) + Int64(rel))
            return ("jmp", formatAddress(target), 5 + (hasRex ? 1 : 0), .jump, target)

        // JMP rel8
        case 0xEB:
            guard idx < bytes.count else { return nil }
            let rel = Int8(bitPattern: bytes[idx])
            let target = UInt64(Int64(address) + Int64(2 + (hasRex ? 1 : 0)) + Int64(rel))
            return ("jmp", formatAddress(target), 2 + (hasRex ? 1 : 0), .jump, target)

        // Conditional jumps (rel8)
        case 0x70...0x7F:
            guard idx < bytes.count else { return nil }
            let rel = Int8(bitPattern: bytes[idx])
            let target = UInt64(Int64(address) + Int64(2 + (hasRex ? 1 : 0)) + Int64(rel))
            let cond = conditionCode(Int(opcode - 0x70))
            return ("j\(cond)", formatAddress(target), 2 + (hasRex ? 1 : 0), .conditionalJump, target)

        // Two-byte opcodes (0x0F prefix)
        case 0x0F:
            guard idx < bytes.count else { return nil }
            let opcode2 = bytes[idx]
            idx += 1

            switch opcode2 {
            // Conditional jumps (rel32)
            case 0x80...0x8F:
                guard idx + 3 < bytes.count else { return nil }
                var rel: Int32 = 0
                for i in 0..<4 {
                    rel |= Int32(bytes[idx + i]) << (i * 8)
                }
                let target = UInt64(Int64(address) + Int64(6 + (hasRex ? 1 : 0)) + Int64(rel))
                let cond = conditionCode(Int(opcode2 - 0x80))
                return ("j\(cond)", formatAddress(target), 6 + (hasRex ? 1 : 0), .conditionalJump, target)

            // SYSCALL
            case 0x05:
                return ("syscall", "", 2 + (hasRex ? 1 : 0), .syscall, nil)

            // NOP (multi-byte)
            case 0x1F:
                // Variable length NOP, simplified handling
                return ("nop", "", 3 + (hasRex ? 1 : 0), .nop, nil)

            default:
                return nil
            }

        // INT 3
        case 0xCC:
            return ("int3", "", 1, .interrupt, nil)

        // INT imm8
        case 0xCD:
            guard idx < bytes.count else { return nil }
            return ("int", String(format: "0x%X", bytes[idx]), 2, .interrupt, nil)

        // LEA, MOV, ADD, SUB, etc. with ModR/M
        case 0x8D, 0x89, 0x8B, 0x01, 0x03, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B:
            guard idx < bytes.count else { return nil }
            let modrm = bytes[idx]
            let mod = (modrm >> 6) & 0x03
            let reg = (modrm >> 3) & 0x07
            let rm = modrm & 0x07
            idx += 1

            let regName = registerName64(Int(reg) + (rexR ? 8 : 0), wide: rexW || opcode == 0x8D)
            var size = 2 + (hasRex ? 1 : 0)
            var rmOperand = ""

            if mod == 0x03 {
                // Register direct
                rmOperand = registerName64(Int(rm) + (rexB ? 8 : 0), wide: rexW || opcode == 0x8D)
            } else {
                // Memory operand (simplified)
                if rm == 0x04 {
                    // SIB byte follows
                    guard idx < bytes.count else { return nil }
                    idx += 1
                    size += 1
                }

                if mod == 0x00 && rm == 0x05 {
                    // RIP-relative
                    guard idx + 3 < bytes.count else { return nil }
                    var disp: Int32 = 0
                    for i in 0..<4 {
                        disp |= Int32(bytes[idx + i]) << (i * 8)
                    }
                    size += 4
                    let targetAddr = UInt64(Int64(address) + Int64(size) + Int64(disp))
                    rmOperand = String(format: "[rip + 0x%llX]", targetAddr)
                } else if mod == 0x01 {
                    // 8-bit displacement
                    guard idx < bytes.count else { return nil }
                    let disp = Int(Int8(bitPattern: bytes[idx]))  // Convert to Int to avoid overflow
                    size += 1
                    let baseReg = registerName64(Int(rm) + (rexB ? 8 : 0))
                    if disp >= 0 {
                        rmOperand = "[\(baseReg) + \(disp)]"
                    } else {
                        rmOperand = "[\(baseReg) - \(-disp)]"
                    }
                } else if mod == 0x02 {
                    // 32-bit displacement
                    guard idx + 3 < bytes.count else { return nil }
                    var disp: Int32 = 0
                    for i in 0..<4 {
                        disp |= Int32(bytes[idx + i]) << (i * 8)
                    }
                    size += 4
                    let baseReg = registerName64(Int(rm) + (rexB ? 8 : 0))
                    rmOperand = "[\(baseReg) + \(String(format: "0x%X", disp))]"
                } else {
                    rmOperand = "[\(registerName64(Int(rm) + (rexB ? 8 : 0)))]"
                }
            }

            let mnemonic: String
            let instType: InstructionType
            var operands: String

            switch opcode {
            case 0x8D:
                mnemonic = "lea"
                instType = .move
                operands = "\(regName), \(rmOperand)"
            case 0x89:
                mnemonic = "mov"
                instType = .move
                operands = "\(rmOperand), \(regName)"
            case 0x8B:
                mnemonic = "mov"
                instType = .move
                operands = "\(regName), \(rmOperand)"
            case 0x01:
                mnemonic = "add"
                instType = .arithmetic
                operands = "\(rmOperand), \(regName)"
            case 0x03:
                mnemonic = "add"
                instType = .arithmetic
                operands = "\(regName), \(rmOperand)"
            case 0x29:
                mnemonic = "sub"
                instType = .arithmetic
                operands = "\(rmOperand), \(regName)"
            case 0x2B:
                mnemonic = "sub"
                instType = .arithmetic
                operands = "\(regName), \(rmOperand)"
            case 0x31:
                mnemonic = "xor"
                instType = .logic
                operands = "\(rmOperand), \(regName)"
            case 0x33:
                mnemonic = "xor"
                instType = .logic
                operands = "\(regName), \(rmOperand)"
            case 0x39:
                mnemonic = "cmp"
                instType = .compare
                operands = "\(rmOperand), \(regName)"
            case 0x3B:
                mnemonic = "cmp"
                instType = .compare
                operands = "\(regName), \(rmOperand)"
            default:
                return nil
            }

            return (mnemonic, operands, size, instType, nil)

        default:
            return nil
        }
    }

    // MARK: - ARM64 Disassembly

    private func disassembleARM64(data: Data, address: UInt64) -> [Instruction] {
        var instructions: [Instruction] = []
        var offset = 0
        var currentAddress = address

        while offset + 3 < data.count {
            let bytes = Array(data[offset..<(offset + 4)])
            let insn = UInt32(bytes[0]) | (UInt32(bytes[1]) << 8) |
                       (UInt32(bytes[2]) << 16) | (UInt32(bytes[3]) << 24)

            let (mnemonic, operands, type, target) = decodeARM64Instruction(insn: insn, address: currentAddress)

            var instruction = Instruction(
                address: currentAddress,
                size: 4,
                bytes: bytes,
                mnemonic: mnemonic,
                operands: operands,
                architecture: .arm64,
                type: type
            )
            instruction.branchTarget = target

            instructions.append(instruction)
            offset += 4
            currentAddress += 4
        }

        return instructions
    }

    private func decodeARM64Instruction(insn: UInt32, address: UInt64) -> (String, String, InstructionType, UInt64?) {
        // Extract common fields
        let op0 = (insn >> 25) & 0xF

        // NOP
        if insn == 0xD503201F {
            return ("nop", "", .nop, nil)
        }

        // RET
        if (insn & 0xFFFFFC1F) == 0xD65F0000 {
            let rn = (insn >> 5) & 0x1F
            if rn == 30 {
                return ("ret", "", .return, nil)
            } else {
                return ("ret", "x\(rn)", .return, nil)
            }
        }

        // BL (Branch with Link)
        if (insn & 0xFC000000) == 0x94000000 {
            let imm26 = insn & 0x03FFFFFF
            let offset = signExtend(imm26, bits: 26) * 4
            let target = UInt64(Int64(address) + Int64(offset))
            return ("bl", formatAddress(target), .call, target)
        }

        // B (Unconditional branch)
        if (insn & 0xFC000000) == 0x14000000 {
            let imm26 = insn & 0x03FFFFFF
            let offset = signExtend(imm26, bits: 26) * 4
            let target = UInt64(Int64(address) + Int64(offset))
            return ("b", formatAddress(target), .jump, target)
        }

        // B.cond (Conditional branch)
        if (insn & 0xFF000010) == 0x54000000 {
            let imm19 = (insn >> 5) & 0x7FFFF
            let cond = insn & 0xF
            let offset = signExtend(imm19, bits: 19) * 4
            let target = UInt64(Int64(address) + Int64(offset))
            let condStr = arm64ConditionCode(Int(cond))
            return ("b.\(condStr)", formatAddress(target), .conditionalJump, target)
        }

        // CBZ/CBNZ
        if (insn & 0x7E000000) == 0x34000000 {
            let sf = (insn >> 31) & 1
            let op = (insn >> 24) & 1
            let imm19 = (insn >> 5) & 0x7FFFF
            let rt = insn & 0x1F
            let offset = signExtend(imm19, bits: 19) * 4
            let target = UInt64(Int64(address) + Int64(offset))
            let reg = sf == 1 ? "x\(rt)" : "w\(rt)"
            let mnemonic = op == 0 ? "cbz" : "cbnz"
            return (mnemonic, "\(reg), \(formatAddress(target))", .conditionalJump, target)
        }

        // TBZ/TBNZ
        if (insn & 0x7E000000) == 0x36000000 {
            let b5 = (insn >> 31) & 1
            let op = (insn >> 24) & 1
            let b40 = (insn >> 19) & 0x1F
            let imm14 = (insn >> 5) & 0x3FFF
            let rt = insn & 0x1F
            let bit = (b5 << 5) | b40
            let offset = signExtend(imm14, bits: 14) * 4
            let target = UInt64(Int64(address) + Int64(offset))
            let reg = bit >= 32 ? "x\(rt)" : "w\(rt)"
            let mnemonic = op == 0 ? "tbz" : "tbnz"
            return (mnemonic, "\(reg), #\(bit), \(formatAddress(target))", .conditionalJump, target)
        }

        // BLR (Branch with Link to Register)
        if (insn & 0xFFFFFC1F) == 0xD63F0000 {
            let rn = (insn >> 5) & 0x1F
            return ("blr", "x\(rn)", .call, nil)
        }

        // BR (Branch to Register)
        if (insn & 0xFFFFFC1F) == 0xD61F0000 {
            let rn = (insn >> 5) & 0x1F
            return ("br", "x\(rn)", .jump, nil)
        }

        // SVC (Supervisor Call)
        if (insn & 0xFFE0001F) == 0xD4000001 {
            let imm16 = (insn >> 5) & 0xFFFF
            return ("svc", String(format: "#0x%X", imm16), .syscall, nil)
        }

        // MOV (register) - ORR with zero register
        if (insn & 0x7F2003E0) == 0x2A0003E0 {
            let sf = (insn >> 31) & 1
            let rm = (insn >> 16) & 0x1F
            let rd = insn & 0x1F
            let destReg = sf == 1 ? "x\(rd)" : "w\(rd)"
            let srcReg = sf == 1 ? "x\(rm)" : "w\(rm)"
            return ("mov", "\(destReg), \(srcReg)", .move, nil)
        }

        // MOV (immediate) - MOVZ
        if (insn & 0x7F800000) == 0x52800000 {
            let sf = (insn >> 31) & 1
            let hw = (insn >> 21) & 0x3
            let imm16 = (insn >> 5) & 0xFFFF
            let rd = insn & 0x1F
            let shift = hw * 16
            let value = UInt64(imm16) << shift
            let reg = sf == 1 ? "x\(rd)" : "w\(rd)"
            return ("mov", "\(reg), #\(formatImmediate(value))", .move, nil)
        }

        // LDR (immediate)
        if (insn & 0x3B000000) == 0x39000000 {
            let size = (insn >> 30) & 0x3
            let rt = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let imm12 = (insn >> 10) & 0xFFF
            let scale = 1 << size
            let offset = Int(imm12) * scale
            let reg = size == 3 ? "x\(rt)" : "w\(rt)"
            let baseReg = "x\(rn)"
            if offset == 0 {
                return ("ldr", "\(reg), [\(baseReg)]", .load, nil)
            } else {
                return ("ldr", "\(reg), [\(baseReg), #\(offset)]", .load, nil)
            }
        }

        // STR (immediate)
        if (insn & 0x3B000000) == 0x39000000 && (insn & 0x00C00000) == 0x00000000 {
            let size = (insn >> 30) & 0x3
            let rt = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let imm12 = (insn >> 10) & 0xFFF
            let scale = 1 << size
            let offset = Int(imm12) * scale
            let reg = size == 3 ? "x\(rt)" : "w\(rt)"
            let baseReg = "x\(rn)"
            if offset == 0 {
                return ("str", "\(reg), [\(baseReg)]", .store, nil)
            } else {
                return ("str", "\(reg), [\(baseReg), #\(offset)]", .store, nil)
            }
        }

        // ADD/SUB (immediate)
        if (insn & 0x1F000000) == 0x11000000 {
            let sf = (insn >> 31) & 1
            let op = (insn >> 30) & 1
            let sh = (insn >> 22) & 1
            let imm12 = (insn >> 10) & 0xFFF
            let rn = (insn >> 5) & 0x1F
            let rd = insn & 0x1F

            let destReg = sf == 1 ? "x\(rd)" : "w\(rd)"
            let srcReg = sf == 1 ? "x\(rn)" : "w\(rn)"
            let value = sh == 1 ? imm12 << 12 : imm12
            let mnemonic = op == 0 ? "add" : "sub"

            return (mnemonic, "\(destReg), \(srcReg), #\(value)", .arithmetic, nil)
        }

        // STP (Store Pair)
        if (insn & 0x7FC00000) == 0x29000000 {
            let rt = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let rt2 = (insn >> 10) & 0x1F
            let imm7 = (insn >> 15) & 0x7F
            let offset = signExtend(imm7, bits: 7) * 8
            return ("stp", "x\(rt), x\(rt2), [x\(rn), #\(offset)]", .store, nil)
        }

        // LDP (Load Pair)
        if (insn & 0x7FC00000) == 0x29400000 {
            let rt = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let rt2 = (insn >> 10) & 0x1F
            let imm7 = (insn >> 15) & 0x7F
            let offset = signExtend(imm7, bits: 7) * 8
            return ("ldp", "x\(rt), x\(rt2), [x\(rn), #\(offset)]", .load, nil)
        }

        // Unknown instruction
        return (String(format: ".word 0x%08X", insn), "", .other, nil)
    }

    // MARK: - 32-bit Disassembly (Simplified)

    private func disassembleX86(data: Data, address: UInt64) -> [Instruction] {
        // Simplified - similar to x86_64 but 32-bit
        var instructions: [Instruction] = []
        var offset = 0
        var currentAddress = address

        while offset < data.count {
            // For now, just mark as data bytes
            instructions.append(Instruction(
                address: currentAddress,
                size: 1,
                bytes: [data[offset]],
                mnemonic: "db",
                operands: String(format: "0x%02X", data[offset]),
                architecture: .i386,
                type: .other
            ))
            offset += 1
            currentAddress += 1
        }

        return instructions
    }

    private func disassembleARM(data: Data, address: UInt64) -> [Instruction] {
        // Simplified ARM32 disassembly
        var instructions: [Instruction] = []
        var offset = 0
        var currentAddress = address

        while offset + 3 < data.count {
            let bytes = Array(data[offset..<(offset + 4)])
            instructions.append(Instruction(
                address: currentAddress,
                size: 4,
                bytes: bytes,
                mnemonic: ".word",
                operands: String(format: "0x%02X%02X%02X%02X", bytes[3], bytes[2], bytes[1], bytes[0]),
                architecture: .armv7,
                type: .other
            ))
            offset += 4
            currentAddress += 4
        }

        return instructions
    }

    // MARK: - JVM Bytecode Disassembly

    private func disassembleJVM(data: Data, address: UInt64) -> [Instruction] {
        var instructions: [Instruction] = []
        var offset = 0
        var currentAddress = address

        while offset < data.count {
            let opcode = data[offset]
            let (mnemonic, operandSize, operands, type, target) = decodeJVMInstruction(
                opcode: opcode,
                data: data,
                offset: offset,
                address: currentAddress
            )

            let size = 1 + operandSize
            let endOffset = min(offset + size, data.count)
            let bytes = Array(data[offset..<endOffset])

            var instruction = Instruction(
                address: currentAddress,
                size: size,
                bytes: bytes,
                mnemonic: mnemonic,
                operands: operands,
                architecture: .jvm,
                type: type
            )
            instruction.branchTarget = target

            instructions.append(instruction)
            offset += size
            currentAddress += UInt64(size)
        }

        return instructions
    }

    private func decodeJVMInstruction(opcode: UInt8, data: Data, offset: Int, address: UInt64) -> (String, Int, String, InstructionType, UInt64?) {
        switch opcode {
        // Constants
        case 0x00: return ("nop", 0, "", .nop, nil)
        case 0x01: return ("aconst_null", 0, "", .move, nil)
        case 0x02: return ("iconst_m1", 0, "", .move, nil)
        case 0x03: return ("iconst_0", 0, "", .move, nil)
        case 0x04: return ("iconst_1", 0, "", .move, nil)
        case 0x05: return ("iconst_2", 0, "", .move, nil)
        case 0x06: return ("iconst_3", 0, "", .move, nil)
        case 0x07: return ("iconst_4", 0, "", .move, nil)
        case 0x08: return ("iconst_5", 0, "", .move, nil)
        case 0x09: return ("lconst_0", 0, "", .move, nil)
        case 0x0A: return ("lconst_1", 0, "", .move, nil)
        case 0x0B: return ("fconst_0", 0, "", .move, nil)
        case 0x0C: return ("fconst_1", 0, "", .move, nil)
        case 0x0D: return ("fconst_2", 0, "", .move, nil)
        case 0x0E: return ("dconst_0", 0, "", .move, nil)
        case 0x0F: return ("dconst_1", 0, "", .move, nil)

        // Push byte/short
        case 0x10:
            let value = offset + 1 < data.count ? Int8(bitPattern: data[offset + 1]) : 0
            return ("bipush", 1, "\(value)", .push, nil)
        case 0x11:
            let value = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            return ("sipush", 2, "\(value)", .push, nil)

        // Load constant
        case 0x12:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("ldc", 1, "#\(index)", .load, nil)
        case 0x13:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("ldc_w", 2, "#\(index)", .load, nil)
        case 0x14:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("ldc2_w", 2, "#\(index)", .load, nil)

        // Loads
        case 0x15:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("iload", 1, "\(index)", .load, nil)
        case 0x16:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("lload", 1, "\(index)", .load, nil)
        case 0x17:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("fload", 1, "\(index)", .load, nil)
        case 0x18:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("dload", 1, "\(index)", .load, nil)
        case 0x19:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("aload", 1, "\(index)", .load, nil)

        // Quick loads (0-3)
        case 0x1A: return ("iload_0", 0, "", .load, nil)
        case 0x1B: return ("iload_1", 0, "", .load, nil)
        case 0x1C: return ("iload_2", 0, "", .load, nil)
        case 0x1D: return ("iload_3", 0, "", .load, nil)
        case 0x1E: return ("lload_0", 0, "", .load, nil)
        case 0x1F: return ("lload_1", 0, "", .load, nil)
        case 0x20: return ("lload_2", 0, "", .load, nil)
        case 0x21: return ("lload_3", 0, "", .load, nil)
        case 0x22: return ("fload_0", 0, "", .load, nil)
        case 0x23: return ("fload_1", 0, "", .load, nil)
        case 0x24: return ("fload_2", 0, "", .load, nil)
        case 0x25: return ("fload_3", 0, "", .load, nil)
        case 0x26: return ("dload_0", 0, "", .load, nil)
        case 0x27: return ("dload_1", 0, "", .load, nil)
        case 0x28: return ("dload_2", 0, "", .load, nil)
        case 0x29: return ("dload_3", 0, "", .load, nil)
        case 0x2A: return ("aload_0", 0, "", .load, nil)
        case 0x2B: return ("aload_1", 0, "", .load, nil)
        case 0x2C: return ("aload_2", 0, "", .load, nil)
        case 0x2D: return ("aload_3", 0, "", .load, nil)

        // Array loads
        case 0x2E: return ("iaload", 0, "", .load, nil)
        case 0x2F: return ("laload", 0, "", .load, nil)
        case 0x30: return ("faload", 0, "", .load, nil)
        case 0x31: return ("daload", 0, "", .load, nil)
        case 0x32: return ("aaload", 0, "", .load, nil)
        case 0x33: return ("baload", 0, "", .load, nil)
        case 0x34: return ("caload", 0, "", .load, nil)
        case 0x35: return ("saload", 0, "", .load, nil)

        // Stores
        case 0x36:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("istore", 1, "\(index)", .store, nil)
        case 0x37:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("lstore", 1, "\(index)", .store, nil)
        case 0x38:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("fstore", 1, "\(index)", .store, nil)
        case 0x39:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("dstore", 1, "\(index)", .store, nil)
        case 0x3A:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("astore", 1, "\(index)", .store, nil)

        // Quick stores (0-3)
        case 0x3B: return ("istore_0", 0, "", .store, nil)
        case 0x3C: return ("istore_1", 0, "", .store, nil)
        case 0x3D: return ("istore_2", 0, "", .store, nil)
        case 0x3E: return ("istore_3", 0, "", .store, nil)
        case 0x3F: return ("lstore_0", 0, "", .store, nil)
        case 0x40: return ("lstore_1", 0, "", .store, nil)
        case 0x41: return ("lstore_2", 0, "", .store, nil)
        case 0x42: return ("lstore_3", 0, "", .store, nil)
        case 0x43: return ("fstore_0", 0, "", .store, nil)
        case 0x44: return ("fstore_1", 0, "", .store, nil)
        case 0x45: return ("fstore_2", 0, "", .store, nil)
        case 0x46: return ("fstore_3", 0, "", .store, nil)
        case 0x47: return ("dstore_0", 0, "", .store, nil)
        case 0x48: return ("dstore_1", 0, "", .store, nil)
        case 0x49: return ("dstore_2", 0, "", .store, nil)
        case 0x4A: return ("dstore_3", 0, "", .store, nil)
        case 0x4B: return ("astore_0", 0, "", .store, nil)
        case 0x4C: return ("astore_1", 0, "", .store, nil)
        case 0x4D: return ("astore_2", 0, "", .store, nil)
        case 0x4E: return ("astore_3", 0, "", .store, nil)

        // Array stores
        case 0x4F: return ("iastore", 0, "", .store, nil)
        case 0x50: return ("lastore", 0, "", .store, nil)
        case 0x51: return ("fastore", 0, "", .store, nil)
        case 0x52: return ("dastore", 0, "", .store, nil)
        case 0x53: return ("aastore", 0, "", .store, nil)
        case 0x54: return ("bastore", 0, "", .store, nil)
        case 0x55: return ("castore", 0, "", .store, nil)
        case 0x56: return ("sastore", 0, "", .store, nil)

        // Stack operations
        case 0x57: return ("pop", 0, "", .pop, nil)
        case 0x58: return ("pop2", 0, "", .pop, nil)
        case 0x59: return ("dup", 0, "", .push, nil)
        case 0x5A: return ("dup_x1", 0, "", .push, nil)
        case 0x5B: return ("dup_x2", 0, "", .push, nil)
        case 0x5C: return ("dup2", 0, "", .push, nil)
        case 0x5D: return ("dup2_x1", 0, "", .push, nil)
        case 0x5E: return ("dup2_x2", 0, "", .push, nil)
        case 0x5F: return ("swap", 0, "", .other, nil)

        // Arithmetic
        case 0x60: return ("iadd", 0, "", .arithmetic, nil)
        case 0x61: return ("ladd", 0, "", .arithmetic, nil)
        case 0x62: return ("fadd", 0, "", .arithmetic, nil)
        case 0x63: return ("dadd", 0, "", .arithmetic, nil)
        case 0x64: return ("isub", 0, "", .arithmetic, nil)
        case 0x65: return ("lsub", 0, "", .arithmetic, nil)
        case 0x66: return ("fsub", 0, "", .arithmetic, nil)
        case 0x67: return ("dsub", 0, "", .arithmetic, nil)
        case 0x68: return ("imul", 0, "", .arithmetic, nil)
        case 0x69: return ("lmul", 0, "", .arithmetic, nil)
        case 0x6A: return ("fmul", 0, "", .arithmetic, nil)
        case 0x6B: return ("dmul", 0, "", .arithmetic, nil)
        case 0x6C: return ("idiv", 0, "", .arithmetic, nil)
        case 0x6D: return ("ldiv", 0, "", .arithmetic, nil)
        case 0x6E: return ("fdiv", 0, "", .arithmetic, nil)
        case 0x6F: return ("ddiv", 0, "", .arithmetic, nil)
        case 0x70: return ("irem", 0, "", .arithmetic, nil)
        case 0x71: return ("lrem", 0, "", .arithmetic, nil)
        case 0x72: return ("frem", 0, "", .arithmetic, nil)
        case 0x73: return ("drem", 0, "", .arithmetic, nil)
        case 0x74: return ("ineg", 0, "", .arithmetic, nil)
        case 0x75: return ("lneg", 0, "", .arithmetic, nil)
        case 0x76: return ("fneg", 0, "", .arithmetic, nil)
        case 0x77: return ("dneg", 0, "", .arithmetic, nil)

        // Shifts
        case 0x78: return ("ishl", 0, "", .logic, nil)
        case 0x79: return ("lshl", 0, "", .logic, nil)
        case 0x7A: return ("ishr", 0, "", .logic, nil)
        case 0x7B: return ("lshr", 0, "", .logic, nil)
        case 0x7C: return ("iushr", 0, "", .logic, nil)
        case 0x7D: return ("lushr", 0, "", .logic, nil)

        // Logic
        case 0x7E: return ("iand", 0, "", .logic, nil)
        case 0x7F: return ("land", 0, "", .logic, nil)
        case 0x80: return ("ior", 0, "", .logic, nil)
        case 0x81: return ("lor", 0, "", .logic, nil)
        case 0x82: return ("ixor", 0, "", .logic, nil)
        case 0x83: return ("lxor", 0, "", .logic, nil)

        // Increment
        case 0x84:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            let value = offset + 2 < data.count ? Int8(bitPattern: data[offset + 2]) : 0
            return ("iinc", 2, "\(index), \(value)", .arithmetic, nil)

        // Conversions
        case 0x85: return ("i2l", 0, "", .other, nil)
        case 0x86: return ("i2f", 0, "", .other, nil)
        case 0x87: return ("i2d", 0, "", .other, nil)
        case 0x88: return ("l2i", 0, "", .other, nil)
        case 0x89: return ("l2f", 0, "", .other, nil)
        case 0x8A: return ("l2d", 0, "", .other, nil)
        case 0x8B: return ("f2i", 0, "", .other, nil)
        case 0x8C: return ("f2l", 0, "", .other, nil)
        case 0x8D: return ("f2d", 0, "", .other, nil)
        case 0x8E: return ("d2i", 0, "", .other, nil)
        case 0x8F: return ("d2l", 0, "", .other, nil)
        case 0x90: return ("d2f", 0, "", .other, nil)
        case 0x91: return ("i2b", 0, "", .other, nil)
        case 0x92: return ("i2c", 0, "", .other, nil)
        case 0x93: return ("i2s", 0, "", .other, nil)

        // Comparisons
        case 0x94: return ("lcmp", 0, "", .compare, nil)
        case 0x95: return ("fcmpl", 0, "", .compare, nil)
        case 0x96: return ("fcmpg", 0, "", .compare, nil)
        case 0x97: return ("dcmpl", 0, "", .compare, nil)
        case 0x98: return ("dcmpg", 0, "", .compare, nil)

        // Conditional branches
        case 0x99:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("ifeq", 2, formatAddress(target), .conditionalJump, target)
        case 0x9A:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("ifne", 2, formatAddress(target), .conditionalJump, target)
        case 0x9B:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("iflt", 2, formatAddress(target), .conditionalJump, target)
        case 0x9C:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("ifge", 2, formatAddress(target), .conditionalJump, target)
        case 0x9D:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("ifgt", 2, formatAddress(target), .conditionalJump, target)
        case 0x9E:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("ifle", 2, formatAddress(target), .conditionalJump, target)
        case 0x9F:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("if_icmpeq", 2, formatAddress(target), .conditionalJump, target)
        case 0xA0:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("if_icmpne", 2, formatAddress(target), .conditionalJump, target)
        case 0xA1:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("if_icmplt", 2, formatAddress(target), .conditionalJump, target)
        case 0xA2:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("if_icmpge", 2, formatAddress(target), .conditionalJump, target)
        case 0xA3:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("if_icmpgt", 2, formatAddress(target), .conditionalJump, target)
        case 0xA4:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("if_icmple", 2, formatAddress(target), .conditionalJump, target)
        case 0xA5:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("if_acmpeq", 2, formatAddress(target), .conditionalJump, target)
        case 0xA6:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("if_acmpne", 2, formatAddress(target), .conditionalJump, target)

        // Unconditional branches
        case 0xA7:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("goto", 2, formatAddress(target), .jump, target)
        case 0xA8:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("jsr", 2, formatAddress(target), .call, target)
        case 0xA9:
            let index = offset + 1 < data.count ? data[offset + 1] : 0
            return ("ret", 1, "\(index)", .return, nil)

        // Switch statements
        case 0xAA: return ("tableswitch", 0, "", .jump, nil)  // Variable length
        case 0xAB: return ("lookupswitch", 0, "", .jump, nil)  // Variable length

        // Returns
        case 0xAC: return ("ireturn", 0, "", .return, nil)
        case 0xAD: return ("lreturn", 0, "", .return, nil)
        case 0xAE: return ("freturn", 0, "", .return, nil)
        case 0xAF: return ("dreturn", 0, "", .return, nil)
        case 0xB0: return ("areturn", 0, "", .return, nil)
        case 0xB1: return ("return", 0, "", .return, nil)

        // Field access
        case 0xB2:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("getstatic", 2, "#\(index)", .load, nil)
        case 0xB3:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("putstatic", 2, "#\(index)", .store, nil)
        case 0xB4:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("getfield", 2, "#\(index)", .load, nil)
        case 0xB5:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("putfield", 2, "#\(index)", .store, nil)

        // Method invocation
        case 0xB6:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("invokevirtual", 2, "#\(index)", .call, nil)
        case 0xB7:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("invokespecial", 2, "#\(index)", .call, nil)
        case 0xB8:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("invokestatic", 2, "#\(index)", .call, nil)
        case 0xB9:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("invokeinterface", 4, "#\(index)", .call, nil)
        case 0xBA:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("invokedynamic", 4, "#\(index)", .call, nil)

        // Object creation
        case 0xBB:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("new", 2, "#\(index)", .other, nil)
        case 0xBC:
            let atype = offset + 1 < data.count ? data[offset + 1] : 0
            let typeName: String
            switch atype {
            case 4: typeName = "boolean"
            case 5: typeName = "char"
            case 6: typeName = "float"
            case 7: typeName = "double"
            case 8: typeName = "byte"
            case 9: typeName = "short"
            case 10: typeName = "int"
            case 11: typeName = "long"
            default: typeName = "\(atype)"
            }
            return ("newarray", 1, typeName, .other, nil)
        case 0xBD:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("anewarray", 2, "#\(index)", .other, nil)
        case 0xBE: return ("arraylength", 0, "", .other, nil)

        // Exceptions
        case 0xBF: return ("athrow", 0, "", .other, nil)

        // Type checking
        case 0xC0:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("checkcast", 2, "#\(index)", .other, nil)
        case 0xC1:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            return ("instanceof", 2, "#\(index)", .compare, nil)

        // Synchronization
        case 0xC2: return ("monitorenter", 0, "", .other, nil)
        case 0xC3: return ("monitorexit", 0, "", .other, nil)

        // Wide prefix
        case 0xC4: return ("wide", 0, "", .other, nil)

        // Multidimensional array
        case 0xC5:
            let index = offset + 2 < data.count ? (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2]) : 0
            let dimensions = offset + 3 < data.count ? data[offset + 3] : 0
            return ("multianewarray", 3, "#\(index), \(dimensions)", .other, nil)

        // Null checks
        case 0xC6:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("ifnull", 2, formatAddress(target), .conditionalJump, target)
        case 0xC7:
            let branchOffset = offset + 2 < data.count ? Int16(bigEndian: Int16(data[offset + 1]) << 8 | Int16(data[offset + 2])) : 0
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("ifnonnull", 2, formatAddress(target), .conditionalJump, target)

        // Wide branches
        case 0xC8:
            var branchOffset: Int32 = 0
            if offset + 4 < data.count {
                branchOffset = Int32(data[offset + 1]) << 24 | Int32(data[offset + 2]) << 16 | Int32(data[offset + 3]) << 8 | Int32(data[offset + 4])
            }
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("goto_w", 4, formatAddress(target), .jump, target)
        case 0xC9:
            var branchOffset: Int32 = 0
            if offset + 4 < data.count {
                branchOffset = Int32(data[offset + 1]) << 24 | Int32(data[offset + 2]) << 16 | Int32(data[offset + 3]) << 8 | Int32(data[offset + 4])
            }
            let target = UInt64(Int64(address) + Int64(branchOffset))
            return ("jsr_w", 4, formatAddress(target), .call, target)

        // Breakpoint and reserved
        case 0xCA: return ("breakpoint", 0, "", .interrupt, nil)
        case 0xFE: return ("impdep1", 0, "", .other, nil)
        case 0xFF: return ("impdep2", 0, "", .other, nil)

        default:
            return (String(format: ".byte 0x%02X", opcode), 0, "", .other, nil)
        }
    }

    // MARK: - Helpers

    private func registerName64(_ reg: Int, wide: Bool = true) -> String {
        if reg == 31 {
            return wide ? "sp" : "esp"
        }
        let regs64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        let regs32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                      "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
        guard reg >= 0 && reg < 16 else {
            return "r\(reg)"
        }
        return wide ? regs64[reg] : regs32[reg]
    }

    private func conditionCode(_ code: Int) -> String {
        let codes = ["o", "no", "b", "nb", "z", "nz", "be", "a",
                     "s", "ns", "p", "np", "l", "ge", "le", "g"]
        guard code >= 0 && code < codes.count else {
            return "cc\(code)"
        }
        return codes[code]
    }

    private func arm64ConditionCode(_ code: Int) -> String {
        let codes = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                     "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
        guard code >= 0 && code < codes.count else {
            return "cc\(code)"
        }
        return codes[code]
    }

    private func formatAddress(_ addr: UInt64) -> String {
        return String(format: "0x%llX", addr)
    }

    private func formatImmediate(_ value: UInt64) -> String {
        if value < 10 {
            return "\(value)"
        }
        return String(format: "0x%llX", value)
    }

    private func signExtend(_ value: UInt32, bits: Int) -> Int64 {
        let signBit = (value >> (bits - 1)) & 1
        if signBit == 1 {
            let mask = UInt64.max << bits
            return Int64(bitPattern: UInt64(value) | mask)
        }
        return Int64(value)
    }
}
