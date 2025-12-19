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

        // SSE/AVX prefix tracking
        var hasOperandSizePrefix = false  // 0x66
        var hasRepnePrefix = false        // 0xF2
        var hasRepPrefix = false          // 0xF3

        // Check for legacy prefixes (0x66, 0xF2, 0xF3)
        while idx < bytes.count {
            switch bytes[idx] {
            case 0x66:
                hasOperandSizePrefix = true
                idx += 1
            case 0xF2:
                hasRepnePrefix = true
                idx += 1
            case 0xF3:
                hasRepPrefix = true
                idx += 1
            case 0x2E, 0x3E, 0x26, 0x64, 0x65, 0x36:  // Segment overrides
                idx += 1
            default:
                break
            }
            if idx >= bytes.count { return nil }
            if bytes[idx] != 0x66 && bytes[idx] != 0xF2 && bytes[idx] != 0xF3 &&
               bytes[idx] != 0x2E && bytes[idx] != 0x3E && bytes[idx] != 0x26 &&
               bytes[idx] != 0x64 && bytes[idx] != 0x65 && bytes[idx] != 0x36 {
                break
            }
        }

        let prefixCount = idx

        // Check for REX prefix (0x40-0x4F)
        if idx < bytes.count && bytes[idx] >= 0x40 && bytes[idx] <= 0x4F {
            hasRex = true
            rexW = (bytes[idx] & 0x08) != 0
            rexR = (bytes[idx] & 0x04) != 0
            rexX = (bytes[idx] & 0x02) != 0
            rexB = (bytes[idx] & 0x01) != 0
            idx += 1
            guard idx < bytes.count else { return nil }
        }

        // Check for VEX prefix (AVX)
        if idx < bytes.count && (bytes[idx] == 0xC4 || bytes[idx] == 0xC5) {
            return decodeVEXInstruction(bytes: bytes, startIdx: idx, address: address)
        }

        let opcode = bytes[idx]
        idx += 1

        // FPU instructions (x87) - 0xD8-0xDF
        if opcode >= 0xD8 && opcode <= 0xDF {
            return decodeFPUInstruction(bytes: bytes, opcodeIdx: idx - 1, prefixCount: prefixCount)
        }

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
                let target = UInt64(Int64(address) + Int64(6 + prefixCount + (hasRex ? 1 : 0)) + Int64(rel))
                let cond = conditionCode(Int(opcode2 - 0x80))
                return ("j\(cond)", formatAddress(target), 6 + prefixCount + (hasRex ? 1 : 0), .conditionalJump, target)

            // SYSCALL
            case 0x05:
                return ("syscall", "", 2 + prefixCount + (hasRex ? 1 : 0), .syscall, nil)

            // NOP (multi-byte)
            case 0x1F:
                // Variable length NOP, simplified handling
                guard idx < bytes.count else { return nil }
                let modrm = bytes[idx]
                let mod = (modrm >> 6) & 0x03
                var nopSize = 3 + prefixCount + (hasRex ? 1 : 0)
                if mod == 0x01 { nopSize += 1 }
                else if mod == 0x02 { nopSize += 4 }
                return ("nop", "", nopSize, .nop, nil)

            // MOVZX r32/64, r/m8
            case 0xB6:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRM(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW, is64: true, rmSize: 8)
                return ("movzx", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVZX r32/64, r/m16
            case 0xB7:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRM(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW, is64: true, rmSize: 16)
                return ("movzx", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVSX r32/64, r/m8
            case 0xBE:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRM(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW, is64: true, rmSize: 8)
                return ("movsx", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVSX r32/64, r/m16
            case 0xBF:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRM(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW, is64: true, rmSize: 16)
                return ("movsx", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // IMUL r, r/m
            case 0xAF:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRM(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW, is64: true)
                return ("imul", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // CMOV conditional moves
            case 0x40...0x4F:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRM(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW, is64: true)
                let cond = conditionCode(Int(opcode2 - 0x40))
                return ("cmov\(cond)", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // SETcc
            case 0x90...0x9F:
                guard idx < bytes.count else { return nil }
                let modrm = bytes[idx]
                let rm = modrm & 0x07
                let cond = conditionCode(Int(opcode2 - 0x90))
                let rmName = registerName8(Int(rm) + (rexB ? 8 : 0))
                return ("set\(cond)", rmName, 3 + prefixCount + (hasRex ? 1 : 0), .other, nil)

            // SSE/SSE2 Instructions
            // MOVAPS/MOVAPD xmm, xmm/m128
            case 0x28:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "movapd" : "movaps"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVAPS/MOVAPD xmm/m128, xmm
            case 0x29:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "movapd" : "movaps"
                return (mnem, "\(rmOp), \(regOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVUPS/MOVUPD xmm, xmm/m128
            case 0x10:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "movss" }
                else if hasRepnePrefix { mnem = "movsd" }
                else if hasOperandSizePrefix { mnem = "movupd" }
                else { mnem = "movups" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVUPS/MOVUPD xmm/m128, xmm
            case 0x11:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "movss" }
                else if hasRepnePrefix { mnem = "movsd" }
                else if hasOperandSizePrefix { mnem = "movupd" }
                else { mnem = "movups" }
                return (mnem, "\(rmOp), \(regOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVLPS/MOVLPD
            case 0x12:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "movlpd" : "movlps"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVHPS/MOVHPD
            case 0x16:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "movhpd" : "movhps"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVD/MOVQ xmm, r/m32/64
            case 0x6E:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmmGpr(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW)
                let mnem = rexW ? "movq" : "movd"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVD/MOVQ r/m32/64, xmm
            case 0x7E:
                guard idx < bytes.count else { return nil }
                if hasRepPrefix {
                    // MOVQ xmm, xmm/m64
                    let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                    return ("movq", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)
                } else {
                    let (regOp, rmOp, size) = decodeModRMXmmGpr(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW)
                    let mnem = rexW ? "movq" : "movd"
                    return (mnem, "\(rmOp), \(regOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)
                }

            // MOVDQA/MOVDQU xmm, xmm/m128
            case 0x6F:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "movdqu" }
                else if hasOperandSizePrefix { mnem = "movdqa" }
                else { mnem = "movq" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // MOVDQA/MOVDQU xmm/m128, xmm
            case 0x7F:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "movdqu" }
                else if hasOperandSizePrefix { mnem = "movdqa" }
                else { mnem = "movq" }
                return (mnem, "\(rmOp), \(regOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .move, nil)

            // ADDPS/ADDPD/ADDSS/ADDSD
            case 0x58:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "addss" }
                else if hasRepnePrefix { mnem = "addsd" }
                else if hasOperandSizePrefix { mnem = "addpd" }
                else { mnem = "addps" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // SUBPS/SUBPD/SUBSS/SUBSD
            case 0x5C:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "subss" }
                else if hasRepnePrefix { mnem = "subsd" }
                else if hasOperandSizePrefix { mnem = "subpd" }
                else { mnem = "subps" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // MULPS/MULPD/MULSS/MULSD
            case 0x59:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "mulss" }
                else if hasRepnePrefix { mnem = "mulsd" }
                else if hasOperandSizePrefix { mnem = "mulpd" }
                else { mnem = "mulps" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // DIVPS/DIVPD/DIVSS/DIVSD
            case 0x5E:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "divss" }
                else if hasRepnePrefix { mnem = "divsd" }
                else if hasOperandSizePrefix { mnem = "divpd" }
                else { mnem = "divps" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // SQRTPS/SQRTPD/SQRTSS/SQRTSD
            case 0x51:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "sqrtss" }
                else if hasRepnePrefix { mnem = "sqrtsd" }
                else if hasOperandSizePrefix { mnem = "sqrtpd" }
                else { mnem = "sqrtps" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // MINPS/MINPD/MINSS/MINSD
            case 0x5D:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "minss" }
                else if hasRepnePrefix { mnem = "minsd" }
                else if hasOperandSizePrefix { mnem = "minpd" }
                else { mnem = "minps" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // MAXPS/MAXPD/MAXSS/MAXSD
            case 0x5F:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "maxss" }
                else if hasRepnePrefix { mnem = "maxsd" }
                else if hasOperandSizePrefix { mnem = "maxpd" }
                else { mnem = "maxps" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // ANDPS/ANDPD
            case 0x54:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "andpd" : "andps"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)

            // ORPS/ORPD
            case 0x56:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "orpd" : "orps"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)

            // XORPS/XORPD
            case 0x57:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "xorpd" : "xorps"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)

            // CMPPS/CMPPD/CMPSS/CMPSD
            case 0xC2:
                guard idx + 1 < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let imm = bytes[idx + size]
                let mnem: String
                if hasRepPrefix { mnem = "cmpss" }
                else if hasRepnePrefix { mnem = "cmpsd" }
                else if hasOperandSizePrefix { mnem = "cmppd" }
                else { mnem = "cmpps" }
                return (mnem, "\(regOp), \(rmOp), \(imm)", 3 + prefixCount + (hasRex ? 1 : 0) + size, .compare, nil)

            // COMISS/COMISD
            case 0x2F:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "comisd" : "comiss"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .compare, nil)

            // UCOMISS/UCOMISD
            case 0x2E:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "ucomisd" : "ucomiss"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .compare, nil)

            // CVTSI2SS/CVTSI2SD
            case 0x2A:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmmGpr(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW)
                let mnem: String
                if hasRepPrefix { mnem = "cvtsi2ss" }
                else if hasRepnePrefix { mnem = "cvtsi2sd" }
                else { mnem = "cvtpi2ps" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)

            // CVTSS2SI/CVTSD2SI
            case 0x2D:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMGprXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW)
                let mnem: String
                if hasRepPrefix { mnem = "cvtss2si" }
                else if hasRepnePrefix { mnem = "cvtsd2si" }
                else { mnem = "cvtps2pi" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)

            // CVTTSS2SI/CVTTSD2SI
            case 0x2C:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMGprXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB, rexW: rexW)
                let mnem: String
                if hasRepPrefix { mnem = "cvttss2si" }
                else if hasRepnePrefix { mnem = "cvttsd2si" }
                else { mnem = "cvttps2pi" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)

            // CVTSS2SD/CVTSD2SS
            case 0x5A:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "cvtss2sd" }
                else if hasRepnePrefix { mnem = "cvtsd2ss" }
                else if hasOperandSizePrefix { mnem = "cvtpd2ps" }
                else { mnem = "cvtps2pd" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)

            // CVTDQ2PS/CVTPS2DQ
            case 0x5B:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem: String
                if hasRepPrefix { mnem = "cvttps2dq" }
                else if hasOperandSizePrefix { mnem = "cvtps2dq" }
                else { mnem = "cvtdq2ps" }
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)

            // PXOR
            case 0xEF:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("pxor", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)

            // POR
            case 0xEB:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("por", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)

            // PAND
            case 0xDB:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("pand", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)

            // PANDN
            case 0xDF:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("pandn", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)

            // PADDB/PADDW/PADDD/PADDQ
            case 0xFC:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("paddb", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)
            case 0xFD:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("paddw", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)
            case 0xFE:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("paddd", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)
            case 0xD4:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("paddq", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // PSUBB/PSUBW/PSUBD/PSUBQ
            case 0xF8:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("psubb", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)
            case 0xF9:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("psubw", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)
            case 0xFA:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("psubd", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)
            case 0xFB:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("psubq", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // PMULLW/PMULLD
            case 0xD5:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("pmullw", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .arithmetic, nil)

            // PCMPEQB/PCMPEQW/PCMPEQD
            case 0x74:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("pcmpeqb", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .compare, nil)
            case 0x75:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("pcmpeqw", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .compare, nil)
            case 0x76:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("pcmpeqd", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .compare, nil)

            // PUNPCKLBW/PUNPCKLWD/PUNPCKLDQ/PUNPCKLQDQ
            case 0x60:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("punpcklbw", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)
            case 0x61:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("punpcklwd", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)
            case 0x62:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("punpckldq", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)
            case 0x6C:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("punpcklqdq", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)

            // PSLLW/PSLLD/PSLLQ
            case 0xF1:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("psllw", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)
            case 0xF2:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("pslld", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)
            case 0xF3:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("psllq", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)

            // PSRLW/PSRLD/PSRLQ
            case 0xD1:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("psrlw", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)
            case 0xD2:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("psrld", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)
            case 0xD3:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                return ("psrlq", "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .logic, nil)

            // SHUFPS/SHUFPD
            case 0xC6:
                guard idx + 1 < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let imm = bytes[idx + size]
                let mnem = hasOperandSizePrefix ? "shufpd" : "shufps"
                return (mnem, "\(regOp), \(rmOp), \(imm)", 3 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)

            // UNPCKLPS/UNPCKLPD
            case 0x14:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "unpcklpd" : "unpcklps"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)

            // UNPCKHPS/UNPCKHPD
            case 0x15:
                guard idx < bytes.count else { return nil }
                let (regOp, rmOp, size) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
                let mnem = hasOperandSizePrefix ? "unpckhpd" : "unpckhps"
                return (mnem, "\(regOp), \(rmOp)", 2 + prefixCount + (hasRex ? 1 : 0) + size, .other, nil)

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

    private func xmmRegisterName(_ reg: Int, useYmm: Bool = false) -> String {
        guard reg >= 0 && reg < 32 else { return "xmm\(reg)" }
        return useYmm ? "ymm\(reg)" : "xmm\(reg)"
    }

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

    private func registerName8(_ reg: Int) -> String {
        let regs = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
                    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
        guard reg >= 0 && reg < regs.count else { return "r\(reg)b" }
        return regs[reg]
    }

    // MARK: - ModRM Decoding for General Purpose Registers

    private func decodeModRM(bytes: [UInt8], idx: Int, rexR: Bool, rexB: Bool, rexW: Bool, is64: Bool, rmSize: Int = 0) -> (String, String, Int) {
        guard idx < bytes.count else { return ("?", "?", 0) }

        let modrm = bytes[idx]
        let mod = (modrm >> 6) & 0x03
        let reg = Int((modrm >> 3) & 0x07) + (rexR ? 8 : 0)
        let rm = Int(modrm & 0x07) + (rexB ? 8 : 0)

        let regName = registerName64(reg, wide: rexW || is64)
        var size = 1

        if mod == 0x03 {
            // Register direct
            let rmName: String
            if rmSize == 8 {
                rmName = registerName8(rm)
            } else if rmSize == 16 {
                rmName = registerName16(rm)
            } else {
                rmName = registerName64(rm, wide: rexW || is64)
            }
            return (regName, rmName, size)
        }

        // Memory operand
        var rmOperand = ""
        let baseRm = Int(modrm & 0x07)

        if baseRm == 0x04 {
            // SIB byte follows
            guard idx + 1 < bytes.count else { return (regName, "[?]", size) }
            let sib = bytes[idx + 1]
            size += 1
            rmOperand = decodeSIB(sib: sib, mod: mod, bytes: bytes, idx: idx + 2, rexB: rexB)
            if mod == 0x01 { size += 1 }
            else if mod == 0x02 { size += 4 }
        } else if mod == 0x00 && baseRm == 0x05 {
            // RIP-relative
            guard idx + 4 < bytes.count else { return (regName, "[rip]", size) }
            var disp: Int32 = 0
            for i in 0..<4 {
                disp |= Int32(bytes[idx + 1 + i]) << (i * 8)
            }
            size += 4
            rmOperand = String(format: "[rip + 0x%X]", disp)
        } else if mod == 0x01 {
            guard idx + 1 < bytes.count else { return (regName, "[?]", size) }
            let disp = Int(Int8(bitPattern: bytes[idx + 1]))
            size += 1
            let baseReg = registerName64(rm)
            if disp >= 0 {
                rmOperand = "[\(baseReg) + \(disp)]"
            } else {
                rmOperand = "[\(baseReg) - \(-disp)]"
            }
        } else if mod == 0x02 {
            guard idx + 4 < bytes.count else { return (regName, "[?]", size) }
            var disp: Int32 = 0
            for i in 0..<4 {
                disp |= Int32(bytes[idx + 1 + i]) << (i * 8)
            }
            size += 4
            let baseReg = registerName64(rm)
            rmOperand = String(format: "[\(baseReg) + 0x%X]", disp)
        } else {
            rmOperand = "[\(registerName64(rm))]"
        }

        return (regName, rmOperand, size)
    }

    private func registerName16(_ reg: Int) -> String {
        let regs = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
        guard reg >= 0 && reg < regs.count else { return "r\(reg)w" }
        return regs[reg]
    }

    private func decodeSIB(sib: UInt8, mod: UInt8, bytes: [UInt8], idx: Int, rexB: Bool) -> String {
        let scale = 1 << ((sib >> 6) & 0x03)
        let index = Int((sib >> 3) & 0x07)
        let base = Int(sib & 0x07) + (rexB ? 8 : 0)

        var result = "["

        if base == 5 && mod == 0x00 {
            // disp32 only
            if idx + 3 < bytes.count {
                var disp: Int32 = 0
                for i in 0..<4 {
                    disp |= Int32(bytes[idx + i]) << (i * 8)
                }
                result += String(format: "0x%X", disp)
            }
        } else {
            result += registerName64(base)
        }

        if index != 4 {
            let indexReg = registerName64(index)
            if result.count > 1 {
                result += " + "
            }
            if scale > 1 {
                result += "\(indexReg)*\(scale)"
            } else {
                result += indexReg
            }
        }

        result += "]"
        return result
    }

    // MARK: - ModRM Decoding for XMM Registers

    private func decodeModRMXmm(bytes: [UInt8], idx: Int, rexR: Bool, rexB: Bool) -> (String, String, Int) {
        guard idx < bytes.count else { return ("xmm?", "xmm?", 0) }

        let modrm = bytes[idx]
        let mod = (modrm >> 6) & 0x03
        let reg = Int((modrm >> 3) & 0x07) + (rexR ? 8 : 0)
        let rm = Int(modrm & 0x07) + (rexB ? 8 : 0)

        let regName = xmmRegisterName(reg)
        var size = 1

        if mod == 0x03 {
            return (regName, xmmRegisterName(rm), size)
        }

        // Memory operand (same as GPR)
        var rmOperand = ""
        let baseRm = Int(modrm & 0x07)

        if baseRm == 0x04 {
            guard idx + 1 < bytes.count else { return (regName, "[?]", size) }
            let sib = bytes[idx + 1]
            size += 1
            rmOperand = decodeSIB(sib: sib, mod: mod, bytes: bytes, idx: idx + 2, rexB: rexB)
            if mod == 0x01 { size += 1 }
            else if mod == 0x02 { size += 4 }
        } else if mod == 0x00 && baseRm == 0x05 {
            guard idx + 4 < bytes.count else { return (regName, "[rip]", size) }
            var disp: Int32 = 0
            for i in 0..<4 {
                disp |= Int32(bytes[idx + 1 + i]) << (i * 8)
            }
            size += 4
            rmOperand = String(format: "[rip + 0x%X]", disp)
        } else if mod == 0x01 {
            guard idx + 1 < bytes.count else { return (regName, "[?]", size) }
            let disp = Int(Int8(bitPattern: bytes[idx + 1]))
            size += 1
            let baseReg = registerName64(Int(modrm & 0x07) + (rexB ? 8 : 0))
            if disp >= 0 {
                rmOperand = "[\(baseReg) + \(disp)]"
            } else {
                rmOperand = "[\(baseReg) - \(-disp)]"
            }
        } else if mod == 0x02 {
            guard idx + 4 < bytes.count else { return (regName, "[?]", size) }
            var disp: Int32 = 0
            for i in 0..<4 {
                disp |= Int32(bytes[idx + 1 + i]) << (i * 8)
            }
            size += 4
            let baseReg = registerName64(Int(modrm & 0x07) + (rexB ? 8 : 0))
            rmOperand = String(format: "[\(baseReg) + 0x%X]", disp)
        } else {
            rmOperand = "[\(registerName64(Int(modrm & 0x07) + (rexB ? 8 : 0)))]"
        }

        return (regName, rmOperand, size)
    }

    private func decodeModRMXmmGpr(bytes: [UInt8], idx: Int, rexR: Bool, rexB: Bool, rexW: Bool) -> (String, String, Int) {
        guard idx < bytes.count else { return ("xmm?", "?", 0) }

        let modrm = bytes[idx]
        let mod = (modrm >> 6) & 0x03
        let reg = Int((modrm >> 3) & 0x07) + (rexR ? 8 : 0)
        let rm = Int(modrm & 0x07) + (rexB ? 8 : 0)

        let xmmName = xmmRegisterName(reg)
        var size = 1

        if mod == 0x03 {
            let gprName = registerName64(rm, wide: rexW)
            return (xmmName, gprName, size)
        }

        // Memory operand
        let (_, rmOperand, extraSize) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
        return (xmmName, rmOperand, extraSize)
    }

    private func decodeModRMGprXmm(bytes: [UInt8], idx: Int, rexR: Bool, rexB: Bool, rexW: Bool) -> (String, String, Int) {
        guard idx < bytes.count else { return ("?", "xmm?", 0) }

        let modrm = bytes[idx]
        let mod = (modrm >> 6) & 0x03
        let reg = Int((modrm >> 3) & 0x07) + (rexR ? 8 : 0)
        let rm = Int(modrm & 0x07) + (rexB ? 8 : 0)

        let gprName = registerName64(reg, wide: rexW)
        var size = 1

        if mod == 0x03 {
            let xmmName = xmmRegisterName(rm)
            return (gprName, xmmName, size)
        }

        // Memory operand
        let (_, rmOperand, extraSize) = decodeModRMXmm(bytes: bytes, idx: idx, rexR: rexR, rexB: rexB)
        return (gprName, rmOperand, extraSize)
    }

    // MARK: - FPU (x87) Instruction Decoding

    private func decodeFPUInstruction(bytes: [UInt8], opcodeIdx: Int, prefixCount: Int) -> (String, String, Int, InstructionType, UInt64?)? {
        guard opcodeIdx + 1 < bytes.count else { return nil }

        let opcode = bytes[opcodeIdx]
        let modrm = bytes[opcodeIdx + 1]
        let mod = (modrm >> 6) & 0x03
        let reg = (modrm >> 3) & 0x07
        let rm = modrm & 0x07

        let baseSize = 2 + prefixCount

        // Register form (mod == 11)
        if mod == 0x03 {
            let stReg = "st(\(rm))"

            switch opcode {
            case 0xD8:
                switch reg {
                case 0: return ("fadd", "st(0), \(stReg)", baseSize, .arithmetic, nil)
                case 1: return ("fmul", "st(0), \(stReg)", baseSize, .arithmetic, nil)
                case 2: return ("fcom", stReg, baseSize, .compare, nil)
                case 3: return ("fcomp", stReg, baseSize, .compare, nil)
                case 4: return ("fsub", "st(0), \(stReg)", baseSize, .arithmetic, nil)
                case 5: return ("fsubr", "st(0), \(stReg)", baseSize, .arithmetic, nil)
                case 6: return ("fdiv", "st(0), \(stReg)", baseSize, .arithmetic, nil)
                case 7: return ("fdivr", "st(0), \(stReg)", baseSize, .arithmetic, nil)
                default: break
                }
            case 0xD9:
                switch reg {
                case 0: return ("fld", stReg, baseSize, .load, nil)
                case 1: return ("fxch", stReg, baseSize, .other, nil)
                case 4:
                    switch rm {
                    case 0: return ("fchs", "", baseSize, .arithmetic, nil)
                    case 1: return ("fabs", "", baseSize, .arithmetic, nil)
                    case 4: return ("ftst", "", baseSize, .compare, nil)
                    case 5: return ("fxam", "", baseSize, .compare, nil)
                    default: break
                    }
                case 5:
                    switch rm {
                    case 0: return ("fld1", "", baseSize, .load, nil)
                    case 1: return ("fldl2t", "", baseSize, .load, nil)
                    case 2: return ("fldl2e", "", baseSize, .load, nil)
                    case 3: return ("fldpi", "", baseSize, .load, nil)
                    case 4: return ("fldlg2", "", baseSize, .load, nil)
                    case 5: return ("fldln2", "", baseSize, .load, nil)
                    case 6: return ("fldz", "", baseSize, .load, nil)
                    default: break
                    }
                case 6:
                    switch rm {
                    case 0: return ("f2xm1", "", baseSize, .arithmetic, nil)
                    case 1: return ("fyl2x", "", baseSize, .arithmetic, nil)
                    case 2: return ("fptan", "", baseSize, .arithmetic, nil)
                    case 3: return ("fpatan", "", baseSize, .arithmetic, nil)
                    case 4: return ("fxtract", "", baseSize, .arithmetic, nil)
                    case 5: return ("fprem1", "", baseSize, .arithmetic, nil)
                    case 6: return ("fdecstp", "", baseSize, .other, nil)
                    case 7: return ("fincstp", "", baseSize, .other, nil)
                    default: break
                    }
                case 7:
                    switch rm {
                    case 0: return ("fprem", "", baseSize, .arithmetic, nil)
                    case 1: return ("fyl2xp1", "", baseSize, .arithmetic, nil)
                    case 2: return ("fsqrt", "", baseSize, .arithmetic, nil)
                    case 3: return ("fsincos", "", baseSize, .arithmetic, nil)
                    case 4: return ("frndint", "", baseSize, .arithmetic, nil)
                    case 5: return ("fscale", "", baseSize, .arithmetic, nil)
                    case 6: return ("fsin", "", baseSize, .arithmetic, nil)
                    case 7: return ("fcos", "", baseSize, .arithmetic, nil)
                    default: break
                    }
                default: break
                }
            case 0xDA:
                switch reg {
                case 0: return ("fcmovb", "st(0), \(stReg)", baseSize, .move, nil)
                case 1: return ("fcmove", "st(0), \(stReg)", baseSize, .move, nil)
                case 2: return ("fcmovbe", "st(0), \(stReg)", baseSize, .move, nil)
                case 3: return ("fcmovu", "st(0), \(stReg)", baseSize, .move, nil)
                case 5:
                    if rm == 1 { return ("fucompp", "", baseSize, .compare, nil) }
                default: break
                }
            case 0xDB:
                switch reg {
                case 0: return ("fcmovnb", "st(0), \(stReg)", baseSize, .move, nil)
                case 1: return ("fcmovne", "st(0), \(stReg)", baseSize, .move, nil)
                case 2: return ("fcmovnbe", "st(0), \(stReg)", baseSize, .move, nil)
                case 3: return ("fcmovnu", "st(0), \(stReg)", baseSize, .move, nil)
                case 4:
                    switch rm {
                    case 2: return ("fclex", "", baseSize, .other, nil)
                    case 3: return ("finit", "", baseSize, .other, nil)
                    default: break
                    }
                case 5: return ("fucomi", "st(0), \(stReg)", baseSize, .compare, nil)
                case 6: return ("fcomi", "st(0), \(stReg)", baseSize, .compare, nil)
                default: break
                }
            case 0xDC:
                switch reg {
                case 0: return ("fadd", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 1: return ("fmul", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 4: return ("fsubr", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 5: return ("fsub", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 6: return ("fdivr", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 7: return ("fdiv", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                default: break
                }
            case 0xDD:
                switch reg {
                case 0: return ("ffree", stReg, baseSize, .other, nil)
                case 2: return ("fst", stReg, baseSize, .store, nil)
                case 3: return ("fstp", stReg, baseSize, .store, nil)
                case 4: return ("fucom", stReg, baseSize, .compare, nil)
                case 5: return ("fucomp", stReg, baseSize, .compare, nil)
                default: break
                }
            case 0xDE:
                switch reg {
                case 0: return ("faddp", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 1: return ("fmulp", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 3:
                    if rm == 1 { return ("fcompp", "", baseSize, .compare, nil) }
                case 4: return ("fsubrp", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 5: return ("fsubp", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 6: return ("fdivrp", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                case 7: return ("fdivp", "\(stReg), st(0)", baseSize, .arithmetic, nil)
                default: break
                }
            case 0xDF:
                switch reg {
                case 4:
                    if rm == 0 { return ("fnstsw", "ax", baseSize, .store, nil) }
                case 5: return ("fucomip", "st(0), \(stReg)", baseSize, .compare, nil)
                case 6: return ("fcomip", "st(0), \(stReg)", baseSize, .compare, nil)
                default: break
                }
            default:
                break
            }
        } else {
            // Memory form
            var memSize = baseSize
            var memOperand = ""

            let baseRm = Int(rm)
            if baseRm == 0x04 {
                memSize += 1  // SIB
            }
            if mod == 0x00 && baseRm == 0x05 {
                memSize += 4  // disp32
                memOperand = "[rip + disp32]"
            } else if mod == 0x01 {
                memSize += 1  // disp8
                memOperand = "[reg + disp8]"
            } else if mod == 0x02 {
                memSize += 4  // disp32
                memOperand = "[reg + disp32]"
            } else {
                memOperand = "[reg]"
            }

            switch opcode {
            case 0xD8:
                switch reg {
                case 0: return ("fadd", "dword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 1: return ("fmul", "dword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 2: return ("fcom", "dword ptr \(memOperand)", memSize, .compare, nil)
                case 3: return ("fcomp", "dword ptr \(memOperand)", memSize, .compare, nil)
                case 4: return ("fsub", "dword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 5: return ("fsubr", "dword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 6: return ("fdiv", "dword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 7: return ("fdivr", "dword ptr \(memOperand)", memSize, .arithmetic, nil)
                default: break
                }
            case 0xD9:
                switch reg {
                case 0: return ("fld", "dword ptr \(memOperand)", memSize, .load, nil)
                case 2: return ("fst", "dword ptr \(memOperand)", memSize, .store, nil)
                case 3: return ("fstp", "dword ptr \(memOperand)", memSize, .store, nil)
                case 4: return ("fldenv", memOperand, memSize, .load, nil)
                case 5: return ("fldcw", "word ptr \(memOperand)", memSize, .load, nil)
                case 6: return ("fnstenv", memOperand, memSize, .store, nil)
                case 7: return ("fnstcw", "word ptr \(memOperand)", memSize, .store, nil)
                default: break
                }
            case 0xDB:
                switch reg {
                case 0: return ("fild", "dword ptr \(memOperand)", memSize, .load, nil)
                case 1: return ("fisttp", "dword ptr \(memOperand)", memSize, .store, nil)
                case 2: return ("fist", "dword ptr \(memOperand)", memSize, .store, nil)
                case 3: return ("fistp", "dword ptr \(memOperand)", memSize, .store, nil)
                case 5: return ("fld", "tbyte ptr \(memOperand)", memSize, .load, nil)
                case 7: return ("fstp", "tbyte ptr \(memOperand)", memSize, .store, nil)
                default: break
                }
            case 0xDC:
                switch reg {
                case 0: return ("fadd", "qword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 1: return ("fmul", "qword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 2: return ("fcom", "qword ptr \(memOperand)", memSize, .compare, nil)
                case 3: return ("fcomp", "qword ptr \(memOperand)", memSize, .compare, nil)
                case 4: return ("fsub", "qword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 5: return ("fsubr", "qword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 6: return ("fdiv", "qword ptr \(memOperand)", memSize, .arithmetic, nil)
                case 7: return ("fdivr", "qword ptr \(memOperand)", memSize, .arithmetic, nil)
                default: break
                }
            case 0xDD:
                switch reg {
                case 0: return ("fld", "qword ptr \(memOperand)", memSize, .load, nil)
                case 1: return ("fisttp", "qword ptr \(memOperand)", memSize, .store, nil)
                case 2: return ("fst", "qword ptr \(memOperand)", memSize, .store, nil)
                case 3: return ("fstp", "qword ptr \(memOperand)", memSize, .store, nil)
                case 4: return ("frstor", memOperand, memSize, .load, nil)
                case 6: return ("fnsave", memOperand, memSize, .store, nil)
                case 7: return ("fnstsw", "word ptr \(memOperand)", memSize, .store, nil)
                default: break
                }
            case 0xDF:
                switch reg {
                case 0: return ("fild", "word ptr \(memOperand)", memSize, .load, nil)
                case 1: return ("fisttp", "word ptr \(memOperand)", memSize, .store, nil)
                case 2: return ("fist", "word ptr \(memOperand)", memSize, .store, nil)
                case 3: return ("fistp", "word ptr \(memOperand)", memSize, .store, nil)
                case 4: return ("fbld", "tbyte ptr \(memOperand)", memSize, .load, nil)
                case 5: return ("fild", "qword ptr \(memOperand)", memSize, .load, nil)
                case 6: return ("fbstp", "tbyte ptr \(memOperand)", memSize, .store, nil)
                case 7: return ("fistp", "qword ptr \(memOperand)", memSize, .store, nil)
                default: break
                }
            default:
                break
            }
        }

        return (String(format: "fpu_%02X_%02X", opcode, modrm), "", baseSize, .other, nil)
    }

    // MARK: - VEX (AVX) Instruction Decoding

    private func decodeVEXInstruction(bytes: [UInt8], startIdx: Int, address: UInt64) -> (String, String, Int, InstructionType, UInt64?)? {
        guard startIdx < bytes.count else { return nil }

        let vexByte = bytes[startIdx]
        var idx = startIdx + 1

        var vexR = true
        var vexX = true
        var vexB = true
        var vexW = false
        var vexL = false   // 0 = 128-bit, 1 = 256-bit
        var vexVVVV = 0
        var mapSelect = 1  // Default to 0F map

        if vexByte == 0xC5 {
            // 2-byte VEX
            guard idx < bytes.count else { return nil }
            let vex1 = bytes[idx]
            idx += 1

            vexR = (vex1 & 0x80) == 0
            vexVVVV = Int((~vex1 >> 3) & 0x0F)
            vexL = (vex1 & 0x04) != 0
            let pp = vex1 & 0x03
            _ = pp  // prefix encoding
        } else if vexByte == 0xC4 {
            // 3-byte VEX
            guard idx + 1 < bytes.count else { return nil }
            let vex1 = bytes[idx]
            let vex2 = bytes[idx + 1]
            idx += 2

            vexR = (vex1 & 0x80) == 0
            vexX = (vex1 & 0x40) == 0
            vexB = (vex1 & 0x20) == 0
            mapSelect = Int(vex1 & 0x1F)

            vexW = (vex2 & 0x80) != 0
            vexVVVV = Int((~vex2 >> 3) & 0x0F)
            vexL = (vex2 & 0x04) != 0
            let pp = vex2 & 0x03
            _ = pp
        } else {
            return nil
        }

        guard idx < bytes.count else { return nil }
        let opcode = bytes[idx]
        idx += 1

        let ymmPrefix = vexL ? "y" : "x"
        let vexSize = idx - startIdx

        // Simplified AVX instruction decoding
        guard idx < bytes.count else { return nil }
        let modrm = bytes[idx]
        let mod = (modrm >> 6) & 0x03
        let reg = Int((modrm >> 3) & 0x07) + (vexR ? 0 : 8)
        let rm = Int(modrm & 0x07) + (vexB ? 0 : 8)

        let destReg = "\(ymmPrefix)mm\(reg)"
        let srcReg = vexVVVV < 16 ? "\(ymmPrefix)mm\(vexVVVV)" : "\(ymmPrefix)mm0"
        let rmReg = mod == 0x03 ? "\(ymmPrefix)mm\(rm)" : "[mem]"

        var instSize = vexSize + 1

        if mod != 0x03 {
            // Memory operand, simplified
            if mod == 0x01 { instSize += 1 }
            else if mod == 0x02 { instSize += 4 }
            if (modrm & 0x07) == 0x04 { instSize += 1 }  // SIB
        }

        // Common AVX instructions
        switch opcode {
        case 0x58: return ("vaddps", "\(destReg), \(srcReg), \(rmReg)", instSize, .arithmetic, nil)
        case 0x59: return ("vmulps", "\(destReg), \(srcReg), \(rmReg)", instSize, .arithmetic, nil)
        case 0x5C: return ("vsubps", "\(destReg), \(srcReg), \(rmReg)", instSize, .arithmetic, nil)
        case 0x5E: return ("vdivps", "\(destReg), \(srcReg), \(rmReg)", instSize, .arithmetic, nil)
        case 0x51: return ("vsqrtps", "\(destReg), \(rmReg)", instSize, .arithmetic, nil)
        case 0x28: return ("vmovaps", "\(destReg), \(rmReg)", instSize, .move, nil)
        case 0x29: return ("vmovaps", "\(rmReg), \(destReg)", instSize, .move, nil)
        case 0x10: return ("vmovups", "\(destReg), \(rmReg)", instSize, .move, nil)
        case 0x11: return ("vmovups", "\(rmReg), \(destReg)", instSize, .move, nil)
        case 0x54: return ("vandps", "\(destReg), \(srcReg), \(rmReg)", instSize, .logic, nil)
        case 0x56: return ("vorps", "\(destReg), \(srcReg), \(rmReg)", instSize, .logic, nil)
        case 0x57: return ("vxorps", "\(destReg), \(srcReg), \(rmReg)", instSize, .logic, nil)
        case 0x6F: return ("vmovdqa", "\(destReg), \(rmReg)", instSize, .move, nil)
        case 0x7F: return ("vmovdqa", "\(rmReg), \(destReg)", instSize, .move, nil)
        case 0xEF: return ("vpxor", "\(destReg), \(srcReg), \(rmReg)", instSize, .logic, nil)
        default:
            return (String(format: "vex_%02X", opcode), "\(destReg), \(srcReg), \(rmReg)", instSize, .other, nil)
        }
    }
}
