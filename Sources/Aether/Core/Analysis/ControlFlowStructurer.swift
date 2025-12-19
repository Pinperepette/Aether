import Foundation

// MARK: - Control Flow Structuring

/// Recovers high-level control flow structures (if/else, while, for, switch)
/// from the CFG using structural analysis
class ControlFlowStructurer {

    // MARK: - Types

    /// High-level control flow structure
    indirect enum ControlStructure: CustomStringConvertible {
        case sequence([ControlStructure])
        case ifThen(condition: Condition, body: ControlStructure)
        case ifThenElse(condition: Condition, thenBody: ControlStructure, elseBody: ControlStructure)
        case whileLoop(condition: Condition, body: ControlStructure)
        case doWhileLoop(body: ControlStructure, condition: Condition)
        case forLoop(init: ControlStructure?, condition: Condition, update: ControlStructure?, body: ControlStructure)
        case switchCase(value: String, cases: [(values: [Int64], body: ControlStructure)], defaultBody: ControlStructure?)
        case block(BasicBlock)
        case breakStmt
        case continueStmt
        case returnStmt(value: String?)
        case goto(UInt64)

        var description: String {
            switch self {
            case .sequence(let items):
                return "Sequence(\(items.count) items)"
            case .ifThen:
                return "If-Then"
            case .ifThenElse:
                return "If-Then-Else"
            case .whileLoop:
                return "While"
            case .doWhileLoop:
                return "Do-While"
            case .forLoop:
                return "For"
            case .switchCase:
                return "Switch"
            case .block(let bb):
                return "Block(0x\(String(format: "%llX", bb.startAddress)))"
            case .breakStmt:
                return "Break"
            case .continueStmt:
                return "Continue"
            case .returnStmt:
                return "Return"
            case .goto(let addr):
                return "Goto(0x\(String(format: "%llX", addr)))"
            }
        }
    }

    /// Represents a condition for control flow
    struct Condition {
        let leftOperand: String
        let comparison: Comparison
        let rightOperand: String
        let isNegated: Bool

        enum Comparison: String {
            case equal = "=="
            case notEqual = "!="
            case lessThan = "<"
            case lessOrEqual = "<="
            case greaterThan = ">"
            case greaterOrEqual = ">="
            case unsigned_lessThan = "<u"  // for unsigned comparison
            case unsigned_lessOrEqual = "<=u"
            case unsigned_greaterThan = ">u"
            case unsigned_greaterOrEqual = ">=u"
        }

        var negated: Condition {
            Condition(
                leftOperand: leftOperand,
                comparison: negateComparison(comparison),
                rightOperand: rightOperand,
                isNegated: !isNegated
            )
        }

        private func negateComparison(_ cmp: Comparison) -> Comparison {
            switch cmp {
            case .equal: return .notEqual
            case .notEqual: return .equal
            case .lessThan: return .greaterOrEqual
            case .lessOrEqual: return .greaterThan
            case .greaterThan: return .lessOrEqual
            case .greaterOrEqual: return .lessThan
            case .unsigned_lessThan: return .unsigned_greaterOrEqual
            case .unsigned_lessOrEqual: return .unsigned_greaterThan
            case .unsigned_greaterThan: return .unsigned_lessOrEqual
            case .unsigned_greaterOrEqual: return .unsigned_lessThan
            }
        }

        func toString() -> String {
            if isNegated {
                return "!(\(leftOperand) \(comparison.rawValue) \(rightOperand))"
            }
            return "\(leftOperand) \(comparison.rawValue) \(rightOperand)"
        }
    }

    /// Region for interval analysis
    struct Region {
        let header: UInt64
        var blocks: Set<UInt64>
        var successors: Set<UInt64>
        var isLoop: Bool = false
        var loopType: LoopType = .none

        enum LoopType {
            case none
            case preTest   // while
            case postTest  // do-while
            case counted   // for
        }
    }

    // MARK: - Analysis State

    private var blocks: [UInt64: BasicBlock] = [:]
    private var dominators: [UInt64: Set<UInt64>] = [:]
    private var postDominators: [UInt64: Set<UInt64>] = [:]
    private var loopHeaders: Set<UInt64> = []
    private var backEdges: [(from: UInt64, to: UInt64)] = []

    // MARK: - Main Entry Point

    /// Structure a function's control flow
    func structure(function: Function) -> ControlStructure {
        guard !function.basicBlocks.isEmpty else {
            return .sequence([])
        }

        // Build block lookup
        blocks = Dictionary(uniqueKeysWithValues: function.basicBlocks.map { ($0.startAddress, $0) })

        // Compute dominators
        computeDominators(function: function)

        // Find loops
        findLoops(function: function)

        // Compute post-dominators for if-then-else structuring
        computePostDominators(function: function)

        // Structure the CFG
        let entryAddr = function.basicBlocks.first!.startAddress
        return structureRegion(entry: entryAddr, exits: [], visited: [])
    }

    // MARK: - Dominator Analysis

    private func computeDominators(function: Function) {
        guard let entry = function.basicBlocks.first else { return }

        // Initialize: entry dominates only itself, others dominated by all
        let allBlocks = Set(function.basicBlocks.map { $0.startAddress })
        dominators[entry.startAddress] = [entry.startAddress]

        for block in function.basicBlocks where block.startAddress != entry.startAddress {
            dominators[block.startAddress] = allBlocks
        }

        // Iterate until fixed point
        var changed = true
        while changed {
            changed = false

            for block in function.basicBlocks where block.startAddress != entry.startAddress {
                // Dom(n) = {n} union (intersection of Dom(p) for all predecessors p)
                var newDom = allBlocks

                for predAddr in block.predecessors {
                    if let predDom = dominators[predAddr] {
                        newDom.formIntersection(predDom)
                    }
                }
                newDom.insert(block.startAddress)

                if newDom != dominators[block.startAddress] {
                    dominators[block.startAddress] = newDom
                    changed = true
                }
            }
        }
    }

    private func computePostDominators(function: Function) {
        // Find exit blocks
        let exitBlocks = function.basicBlocks.filter { $0.type == .exit || $0.successors.isEmpty }
        guard !exitBlocks.isEmpty else { return }

        let allBlocks = Set(function.basicBlocks.map { $0.startAddress })

        // Initialize
        for exit in exitBlocks {
            postDominators[exit.startAddress] = [exit.startAddress]
        }

        for block in function.basicBlocks where !exitBlocks.contains(where: { $0.startAddress == block.startAddress }) {
            postDominators[block.startAddress] = allBlocks
        }

        // Iterate (reverse direction)
        var changed = true
        while changed {
            changed = false

            for block in function.basicBlocks.reversed() {
                guard !exitBlocks.contains(where: { $0.startAddress == block.startAddress }) else { continue }

                var newPostDom = allBlocks

                for succAddr in block.successors {
                    if let succPostDom = postDominators[succAddr] {
                        newPostDom.formIntersection(succPostDom)
                    }
                }
                newPostDom.insert(block.startAddress)

                if newPostDom != postDominators[block.startAddress] {
                    postDominators[block.startAddress] = newPostDom
                    changed = true
                }
            }
        }
    }

    // MARK: - Loop Detection

    private func findLoops(function: Function) {
        // Find back edges (edges to dominating nodes)
        for block in function.basicBlocks {
            for succAddr in block.successors {
                if let dom = dominators[block.startAddress], dom.contains(succAddr) {
                    backEdges.append((from: block.startAddress, to: succAddr))
                    loopHeaders.insert(succAddr)
                }
            }
        }
    }

    /// Identify the type of loop at a header
    private func identifyLoopType(header: BasicBlock, backEdgeSource: UInt64) -> Region.LoopType {
        // Pre-test (while): condition at header
        if header.type == .conditional {
            return .preTest
        }

        // Post-test (do-while): condition at back edge source
        if let sourceBlock = blocks[backEdgeSource], sourceBlock.type == .conditional {
            return .postTest
        }

        // Check for counted loop (for): look for increment pattern
        if let sourceBlock = blocks[backEdgeSource] {
            for insn in sourceBlock.instructions {
                // Look for increment patterns
                if insn.mnemonic.lowercased() == "add" || insn.mnemonic.lowercased() == "inc" {
                    return .counted
                }
            }
        }

        return .preTest  // Default to while
    }

    // MARK: - Structure Recovery

    private func structureRegion(entry: UInt64, exits: Set<UInt64>, visited: Set<UInt64>) -> ControlStructure {
        guard let block = blocks[entry], !visited.contains(entry) else {
            return .goto(entry)
        }

        var newVisited = visited
        newVisited.insert(entry)

        // Check if this is a loop header
        if loopHeaders.contains(entry) {
            return structureLoop(header: block, visited: newVisited)
        }

        // Check block type
        switch block.type {
        case .exit:
            return structureBlock(block)

        case .conditional:
            return structureConditional(block: block, visited: newVisited)

        case .normal, .entry, .loop:
            // Check for sequence
            if block.successors.count == 1, let succAddr = block.successors.first {
                let blockStruct = structureBlock(block)
                let succStruct = structureRegion(entry: succAddr, exits: exits, visited: newVisited)
                return .sequence([blockStruct, succStruct])
            } else if block.successors.isEmpty {
                return structureBlock(block)
            } else {
                // Multiple successors without conditional - could be switch
                return structureSwitch(block: block, visited: newVisited) ?? structureBlock(block)
            }
        }
    }

    private func structureBlock(_ block: BasicBlock) -> ControlStructure {
        // Check for return
        if let lastInsn = block.instructions.last, lastInsn.type == .return {
            // Extract return value if present
            if !lastInsn.operands.isEmpty {
                return .returnStmt(value: lastInsn.operands)
            }
            return .returnStmt(value: nil)
        }

        return .block(block)
    }

    private func structureConditional(block: BasicBlock, visited: Set<UInt64>) -> ControlStructure {
        guard block.successors.count == 2 else {
            return structureBlock(block)
        }

        let condition = extractCondition(from: block)

        let trueTarget = block.successors[1]  // Branch taken
        let falseTarget = block.successors[0] // Fall through

        // Find the join point (immediate post-dominator)
        let joinPoint = findJoinPoint(block: block)

        // Check if one branch leads directly to join point (if-then)
        if let jp = joinPoint, falseTarget == jp {
            let thenBody = structureRegion(entry: trueTarget, exits: [jp], visited: visited)
            let continuation = blocks[jp].map { structureRegion(entry: $0.startAddress, exits: [], visited: visited) }

            let ifStruct = ControlStructure.ifThen(condition: condition, body: thenBody)

            if let cont = continuation {
                return .sequence([structureBlock(block), ifStruct, cont])
            }
            return .sequence([structureBlock(block), ifStruct])
        }

        if let jp = joinPoint, trueTarget == jp {
            let elseBody = structureRegion(entry: falseTarget, exits: [jp], visited: visited)
            let continuation = blocks[jp].map { structureRegion(entry: $0.startAddress, exits: [], visited: visited) }

            let ifStruct = ControlStructure.ifThen(condition: condition.negated, body: elseBody)

            if let cont = continuation {
                return .sequence([structureBlock(block), ifStruct, cont])
            }
            return .sequence([structureBlock(block), ifStruct])
        }

        // Full if-then-else
        var thenExits: Set<UInt64> = []
        var elseExits: Set<UInt64> = []
        if let jp = joinPoint {
            thenExits.insert(jp)
            elseExits.insert(jp)
        }

        let thenBody = structureRegion(entry: trueTarget, exits: thenExits, visited: visited)
        let elseBody = structureRegion(entry: falseTarget, exits: elseExits, visited: visited)

        let ifElseStruct = ControlStructure.ifThenElse(
            condition: condition,
            thenBody: thenBody,
            elseBody: elseBody
        )

        // Add continuation if there's a join point
        if let jp = joinPoint, !visited.contains(jp) {
            var newVisited = visited
            newVisited.insert(trueTarget)
            newVisited.insert(falseTarget)
            let continuation = structureRegion(entry: jp, exits: [], visited: newVisited)
            return .sequence([structureBlock(block), ifElseStruct, continuation])
        }

        return .sequence([structureBlock(block), ifElseStruct])
    }

    private func structureLoop(header: BasicBlock, visited: Set<UInt64>) -> ControlStructure {
        // Find the back edge for this loop
        guard let backEdge = backEdges.first(where: { $0.to == header.startAddress }) else {
            return structureBlock(header)
        }

        let loopType = identifyLoopType(header: header, backEdgeSource: backEdge.from)

        // Find loop body blocks
        let loopBlocks = findLoopBlocks(header: header.startAddress, backEdgeSource: backEdge.from)

        switch loopType {
        case .preTest:
            // while loop: condition at header
            let condition = extractCondition(from: header)

            // Structure the body (excluding header)
            var bodyVisited = visited
            bodyVisited.insert(header.startAddress)

            let bodyEntry = header.successors.first { loopBlocks.contains($0) }
            let body: ControlStructure

            if let entry = bodyEntry {
                body = structureLoopBody(entry: entry, loopBlocks: loopBlocks, visited: bodyVisited)
            } else {
                body = .sequence([])
            }

            // Find exit and structure continuation
            let exitTarget = header.successors.first { !loopBlocks.contains($0) }
            let whileStruct = ControlStructure.whileLoop(condition: condition, body: body)

            if let exit = exitTarget {
                var newVisited = visited
                newVisited.formUnion(loopBlocks)
                let continuation = structureRegion(entry: exit, exits: [], visited: newVisited)
                return .sequence([whileStruct, continuation])
            }

            return whileStruct

        case .postTest:
            // do-while loop: condition at back edge source
            guard let latchBlock = blocks[backEdge.from] else {
                return structureBlock(header)
            }

            let condition = extractCondition(from: latchBlock)

            // Structure body
            var bodyVisited = visited
            let body = structureLoopBody(entry: header.startAddress, loopBlocks: loopBlocks.subtracting([backEdge.from]), visited: bodyVisited)

            let doWhileStruct = ControlStructure.doWhileLoop(body: body, condition: condition)

            // Find exit
            let exitTarget = latchBlock.successors.first { !loopBlocks.contains($0) }
            if let exit = exitTarget {
                var newVisited = visited
                newVisited.formUnion(loopBlocks)
                let continuation = structureRegion(entry: exit, exits: [], visited: newVisited)
                return .sequence([doWhileStruct, continuation])
            }

            return doWhileStruct

        case .counted:
            // for loop: look for init, condition, update
            let condition = extractCondition(from: header)

            // Try to find initialization (predecessor of header outside loop)
            let initBlock = header.predecessors.first { !loopBlocks.contains($0) }.flatMap { blocks[$0] }
            let initStruct: ControlStructure? = initBlock.map { structureBlock($0) }

            // Update is in the latch block
            let updateBlock = blocks[backEdge.from]
            let updateStruct: ControlStructure? = updateBlock.map { structureBlock($0) }

            // Body is everything else in the loop
            var bodyBlocks = loopBlocks
            bodyBlocks.remove(header.startAddress)
            bodyBlocks.remove(backEdge.from)

            let bodyEntry = header.successors.first { bodyBlocks.contains($0) }
            let body: ControlStructure

            if let entry = bodyEntry {
                var bodyVisited = visited
                bodyVisited.insert(header.startAddress)
                bodyVisited.insert(backEdge.from)
                body = structureLoopBody(entry: entry, loopBlocks: bodyBlocks, visited: bodyVisited)
            } else {
                body = .sequence([])
            }

            let forStruct = ControlStructure.forLoop(
                init: initStruct,
                condition: condition,
                update: updateStruct,
                body: body
            )

            // Find exit
            let exitTarget = header.successors.first { !loopBlocks.contains($0) }
            if let exit = exitTarget {
                var newVisited = visited
                newVisited.formUnion(loopBlocks)
                let continuation = structureRegion(entry: exit, exits: [], visited: newVisited)
                return .sequence([forStruct, continuation])
            }

            return forStruct

        case .none:
            return structureBlock(header)
        }
    }

    private func structureLoopBody(entry: UInt64, loopBlocks: Set<UInt64>, visited: Set<UInt64>) -> ControlStructure {
        guard loopBlocks.contains(entry), let block = blocks[entry] else {
            return .sequence([])
        }

        var structures: [ControlStructure] = []
        var current: UInt64? = entry
        var bodyVisited = visited

        while let addr = current, loopBlocks.contains(addr), !bodyVisited.contains(addr) {
            guard let blk = blocks[addr] else { break }
            bodyVisited.insert(addr)

            structures.append(structureBlock(blk))

            // Find next block in loop body
            current = blk.successors.first { loopBlocks.contains($0) && !bodyVisited.contains($0) }
        }

        if structures.count == 1 {
            return structures[0]
        }
        return .sequence(structures)
    }

    private func structureSwitch(block: BasicBlock, visited: Set<UInt64>) -> ControlStructure? {
        // Look for jump table pattern
        guard block.successors.count > 2 else { return nil }

        // Check if last instruction is an indirect jump
        guard let lastInsn = block.instructions.last,
              lastInsn.type == .jump,
              lastInsn.operands.contains("[") else {
            return nil
        }

        // Try to extract the switch value
        let switchValue = extractSwitchValue(from: block)

        // Structure cases
        var cases: [(values: [Int64], body: ControlStructure)] = []
        var defaultBody: ControlStructure?

        for (i, succAddr) in block.successors.enumerated() {
            let caseBody = structureRegion(entry: succAddr, exits: [], visited: visited)

            if i == block.successors.count - 1 {
                defaultBody = caseBody
            } else {
                cases.append((values: [Int64(i)], body: caseBody))
            }
        }

        return .switchCase(value: switchValue, cases: cases, defaultBody: defaultBody)
    }

    // MARK: - Helper Methods

    private func findJoinPoint(block: BasicBlock) -> UInt64? {
        guard let postDom = postDominators[block.startAddress] else { return nil }

        // Immediate post-dominator is the smallest post-dominator that's not the block itself
        let candidates = postDom.filter { $0 != block.startAddress }
        return candidates.min()
    }

    private func findLoopBlocks(header: UInt64, backEdgeSource: UInt64) -> Set<UInt64> {
        // Natural loop: all blocks from which back edge source is reachable without going through header
        var loopBlocks: Set<UInt64> = [header]
        var worklist: [UInt64] = [backEdgeSource]

        while !worklist.isEmpty {
            let block = worklist.removeFirst()
            if loopBlocks.contains(block) { continue }

            loopBlocks.insert(block)

            // Add predecessors
            if let blk = blocks[block] {
                for predAddr in blk.predecessors where !loopBlocks.contains(predAddr) {
                    worklist.append(predAddr)
                }
            }
        }

        return loopBlocks
    }

    private func extractCondition(from block: BasicBlock) -> Condition {
        // Find compare instruction and conditional jump
        var compareInsn: Instruction?
        var jumpInsn: Instruction?

        for insn in block.instructions.reversed() {
            if insn.type == .conditionalJump {
                jumpInsn = insn
            } else if insn.type == .compare {
                compareInsn = insn
            }

            if compareInsn != nil && jumpInsn != nil {
                break
            }
        }

        // Parse comparison
        var leftOp = "var"
        var rightOp = "0"

        if let cmp = compareInsn {
            let parts = cmp.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count >= 2 {
                leftOp = mapRegisterToVariable(parts[0])
                rightOp = parts[1]
            }
        }

        // Map jump condition to comparison
        let comparison = jumpToComparison(jumpInsn?.mnemonic ?? "jne")

        return Condition(leftOperand: leftOp, comparison: comparison, rightOperand: rightOp, isNegated: false)
    }

    private func jumpToComparison(_ mnemonic: String) -> Condition.Comparison {
        switch mnemonic.lowercased() {
        case "je", "jz", "b.eq", "beq":
            return .equal
        case "jne", "jnz", "b.ne", "bne":
            return .notEqual
        case "jl", "jnge", "b.lt", "blt":
            return .lessThan
        case "jle", "jng", "b.le", "ble":
            return .lessOrEqual
        case "jg", "jnle", "b.gt", "bgt":
            return .greaterThan
        case "jge", "jnl", "b.ge", "bge":
            return .greaterOrEqual
        case "jb", "jnae", "b.lo":
            return .unsigned_lessThan
        case "jbe", "jna", "b.ls":
            return .unsigned_lessOrEqual
        case "ja", "jnbe", "b.hi":
            return .unsigned_greaterThan
        case "jae", "jnb", "b.hs":
            return .unsigned_greaterOrEqual
        default:
            return .notEqual
        }
    }

    private func extractSwitchValue(from block: BasicBlock) -> String {
        // Look for the register used in the comparison/jump
        for insn in block.instructions.reversed() {
            if insn.type == .compare {
                let parts = insn.operands.split(separator: ",")
                if let first = parts.first {
                    return mapRegisterToVariable(String(first).trimmingCharacters(in: .whitespaces))
                }
            }
        }
        return "switch_val"
    }

    private func mapRegisterToVariable(_ reg: String) -> String {
        let regMap: [String: String] = [
            "rax": "result", "eax": "result",
            "rdi": "arg1", "edi": "arg1", "x0": "arg1", "w0": "arg1",
            "rsi": "arg2", "esi": "arg2", "x1": "arg2", "w1": "arg2",
            "rdx": "arg3", "edx": "arg3", "x2": "arg3", "w2": "arg3",
            "rcx": "arg4", "ecx": "arg4", "x3": "arg4", "w3": "arg4",
            "r8": "arg5", "r8d": "arg5", "x4": "arg5", "w4": "arg5",
            "r9": "arg6", "r9d": "arg6", "x5": "arg6", "w5": "arg6",
        ]
        return regMap[reg.lowercased()] ?? reg
    }
}

// MARK: - Pretty Printer for Structured Code

/// Converts structured control flow to readable pseudo-C code
class StructuredCodePrinter {

    private let dataFlow: AdvancedDataFlowAnalyzer.DataFlowResult?
    private let binary: BinaryFile?
    private var indentLevel = 0

    init(dataFlow: AdvancedDataFlowAnalyzer.DataFlowResult? = nil, binary: BinaryFile? = nil) {
        self.dataFlow = dataFlow
        self.binary = binary
    }

    func print(_ structure: ControlFlowStructurer.ControlStructure) -> String {
        return printStructure(structure)
    }

    private func printStructure(_ structure: ControlFlowStructurer.ControlStructure) -> String {
        switch structure {
        case .sequence(let items):
            return items.map { printStructure($0) }.joined(separator: "\n")

        case .ifThen(let condition, let body):
            var result = indent() + "if (\(condition.toString())) {\n"
            indentLevel += 1
            result += printStructure(body)
            indentLevel -= 1
            result += "\n" + indent() + "}"
            return result

        case .ifThenElse(let condition, let thenBody, let elseBody):
            var result = indent() + "if (\(condition.toString())) {\n"
            indentLevel += 1
            result += printStructure(thenBody)
            indentLevel -= 1
            result += "\n" + indent() + "} else {\n"
            indentLevel += 1
            result += printStructure(elseBody)
            indentLevel -= 1
            result += "\n" + indent() + "}"
            return result

        case .whileLoop(let condition, let body):
            var result = indent() + "while (\(condition.toString())) {\n"
            indentLevel += 1
            result += printStructure(body)
            indentLevel -= 1
            result += "\n" + indent() + "}"
            return result

        case .doWhileLoop(let body, let condition):
            var result = indent() + "do {\n"
            indentLevel += 1
            result += printStructure(body)
            indentLevel -= 1
            result += "\n" + indent() + "} while (\(condition.toString()));"
            return result

        case .forLoop(let initStmt, let condition, let update, let body):
            let initStr = initStmt.map { printInlineStructure($0) } ?? ""
            let updateStr = update.map { printInlineStructure($0) } ?? ""

            var result = indent() + "for (\(initStr); \(condition.toString()); \(updateStr)) {\n"
            indentLevel += 1
            result += printStructure(body)
            indentLevel -= 1
            result += "\n" + indent() + "}"
            return result

        case .switchCase(let value, let cases, let defaultBody):
            var result = indent() + "switch (\(value)) {\n"

            for caseItem in cases {
                let valueStrs = caseItem.values.map { String($0) }.joined(separator: ", ")
                result += indent() + "case \(valueStrs):\n"
                indentLevel += 1
                result += printStructure(caseItem.body)
                result += "\n" + indent() + "break;\n"
                indentLevel -= 1
            }

            if let defBody = defaultBody {
                result += indent() + "default:\n"
                indentLevel += 1
                result += printStructure(defBody)
                result += "\n" + indent() + "break;\n"
                indentLevel -= 1
            }

            result += indent() + "}"
            return result

        case .block(let basicBlock):
            return printBasicBlock(basicBlock)

        case .breakStmt:
            return indent() + "break;"

        case .continueStmt:
            return indent() + "continue;"

        case .returnStmt(let value):
            if let v = value {
                return indent() + "return \(v);"
            }
            return indent() + "return;"

        case .goto(let addr):
            return indent() + String(format: "goto loc_%llX;", addr)
        }
    }

    private func printInlineStructure(_ structure: ControlFlowStructurer.ControlStructure) -> String {
        if case .block(let bb) = structure {
            // Return just the last statement without semicolon
            return printBasicBlockInline(bb)
        }
        return ""
    }

    private func printBasicBlock(_ block: BasicBlock) -> String {
        var lines: [String] = []

        for insn in block.instructions {
            if insn.type == .nop { continue }
            if insn.type == .conditionalJump || insn.type == .jump { continue }  // Handled by structure

            let line = decompileInstruction(insn)
            if !line.isEmpty && !line.hasPrefix("//") {
                lines.append(indent() + line)
            }
        }

        return lines.joined(separator: "\n")
    }

    private func printBasicBlockInline(_ block: BasicBlock) -> String {
        // Get last meaningful instruction
        for insn in block.instructions.reversed() {
            if insn.type == .nop || insn.type == .conditionalJump || insn.type == .jump { continue }
            let line = decompileInstruction(insn)
            return line.replacingOccurrences(of: ";", with: "")
        }
        return ""
    }

    private func decompileInstruction(_ insn: Instruction) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }

        switch insn.type {
        case .move:
            guard parts.count >= 2 else { return "" }
            let dest = mapRegister(parts[0])
            let src = mapOperand(parts[1])
            return "\(dest) = \(src);"

        case .arithmetic:
            guard parts.count >= 2 else { return "" }
            let dest = mapRegister(parts[0])
            let op = arithmeticOperator(insn.mnemonic)

            if parts.count == 2 {
                let src = mapOperand(parts[1])
                return "\(dest) \(op)= \(src);"
            } else if parts.count >= 3 {
                let src1 = mapOperand(parts[1])
                let src2 = mapOperand(parts[2])
                return "\(dest) = \(src1) \(op) \(src2);"
            }
            return ""

        case .call:
            var funcName = "unknown"
            if let target = insn.branchTarget {
                if let sym = binary?.symbols.first(where: { $0.address == target }) {
                    funcName = sym.displayName
                } else {
                    funcName = String(format: "sub_%llX", target)
                }
            }
            return "\(funcName)();"

        case .return:
            return "return;"

        case .load:
            guard parts.count >= 2 else { return "" }
            let dest = mapRegister(parts[0])
            let src = mapMemoryOperand(parts[1])
            return "\(dest) = \(src);"

        case .store:
            guard parts.count >= 2 else { return "" }
            let dest = mapMemoryOperand(parts[0])
            let src = mapOperand(parts[1])
            return "\(dest) = \(src);"

        case .compare:
            return ""  // Handled by condition extraction

        default:
            return ""
        }
    }

    private func mapRegister(_ reg: String) -> String {
        let regMap: [String: String] = [
            "rax": "result", "eax": "result",
            "rdi": "arg1", "edi": "arg1", "x0": "arg1", "w0": "arg1",
            "rsi": "arg2", "esi": "arg2", "x1": "arg2", "w1": "arg2",
            "rdx": "arg3", "edx": "arg3", "x2": "arg3", "w2": "arg3",
            "rcx": "arg4", "ecx": "arg4", "x3": "arg4", "w3": "arg4",
        ]
        return regMap[reg.lowercased()] ?? reg
    }

    private func mapOperand(_ op: String) -> String {
        var o = op
        if o.hasPrefix("#") { o = String(o.dropFirst()) }
        return mapRegister(o)
    }

    private func mapMemoryOperand(_ op: String) -> String {
        if op.hasPrefix("[") && op.hasSuffix("]") {
            let inner = String(op.dropFirst().dropLast())
            return "*(\(mapRegister(inner)))"
        }
        return "*\(mapRegister(op))"
    }

    private func arithmeticOperator(_ mnemonic: String) -> String {
        switch mnemonic.lowercased() {
        case "add": return "+"
        case "sub": return "-"
        case "mul", "imul": return "*"
        case "div", "idiv": return "/"
        case "and": return "&"
        case "or": return "|"
        case "xor": return "^"
        case "shl", "sal": return "<<"
        case "shr", "sar": return ">>"
        default: return mnemonic
        }
    }

    private func indent() -> String {
        String(repeating: "    ", count: indentLevel)
    }
}
