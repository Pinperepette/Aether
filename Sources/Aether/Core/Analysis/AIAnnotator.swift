import Foundation

// MARK: - AI-Assisted Annotation Engine

/// Provides intelligent suggestions for function names, comments, and analysis
class AIAnnotator {

    // MARK: - Types

    struct Suggestion {
        let type: SuggestionType
        let target: UInt64            // Address of the target
        let suggestion: String        // The suggested text
        let confidence: Double        // 0.0 - 1.0
        let reasoning: String         // Why this suggestion was made
    }

    enum SuggestionType {
        case functionName
        case functionComment
        case parameterName
        case variableName
        case blockComment
        case vulnerabilityWarning
        case optimizationHint
    }

    struct FunctionBehavior {
        let category: FunctionCategory
        let subcategory: String?
        let traits: Set<FunctionTrait>
        let confidence: Double
    }

    enum FunctionCategory: String {
        case initialization = "Initialization"
        case cleanup = "Cleanup"
        case allocation = "Memory Allocation"
        case deallocation = "Memory Deallocation"
        case io = "I/O Operation"
        case networking = "Networking"
        case crypto = "Cryptography"
        case parsing = "Parsing"
        case validation = "Validation"
        case conversion = "Conversion"
        case search = "Search"
        case sort = "Sort"
        case calculation = "Calculation"
        case callback = "Callback"
        case handler = "Handler"
        case getter = "Getter"
        case setter = "Setter"
        case factory = "Factory"
        case utility = "Utility"
        case unknown = "Unknown"
    }

    enum FunctionTrait {
        case readsFromNetwork
        case writesToNetwork
        case readsFile
        case writesFile
        case allocatesMemory
        case freesMemory
        case usesStrings
        case performsCrypto
        case hasLoop
        case isRecursive
        case hasErrorHandling
        case isLeaf
        case isThunk
        case accessesGlobals
        case modifiesState
    }

    // MARK: - Analysis

    /// Analyze a function and generate naming/comment suggestions
    func analyze(function: Function, binary: BinaryFile, context: AnalysisContext) -> [Suggestion] {
        var suggestions: [Suggestion] = []

        // Analyze function behavior
        let behavior = analyzeBehavior(function: function, binary: binary, context: context)

        // Generate function name suggestion
        if let nameSuggestion = suggestFunctionName(function: function, behavior: behavior, binary: binary) {
            suggestions.append(nameSuggestion)
        }

        // Generate function comment
        if let commentSuggestion = suggestFunctionComment(function: function, behavior: behavior, binary: binary) {
            suggestions.append(commentSuggestion)
        }

        // Generate parameter name suggestions
        suggestions.append(contentsOf: suggestParameterNames(function: function, behavior: behavior, binary: binary))

        // Generate variable name suggestions
        suggestions.append(contentsOf: suggestVariableNames(function: function, binary: binary))

        // Check for potential vulnerabilities
        suggestions.append(contentsOf: checkVulnerabilities(function: function, binary: binary))

        return suggestions
    }

    /// Analyze function behavior based on its code
    func analyzeBehavior(function: Function, binary: BinaryFile, context: AnalysisContext) -> FunctionBehavior {
        var traits = Set<FunctionTrait>()
        var category: FunctionCategory = .unknown

        let instructions = function.basicBlocks.flatMap(\.instructions)
        let callees = function.callees

        // Check for memory operations
        if callees.contains(where: { context.isMallocLike($0, binary: binary) }) {
            traits.insert(.allocatesMemory)
            category = .allocation
        }

        if callees.contains(where: { context.isFreeLike($0, binary: binary) }) {
            traits.insert(.freesMemory)
            if category == .unknown { category = .deallocation }
        }

        // Check for I/O operations
        if callees.contains(where: { context.isFileIO($0, binary: binary) }) {
            traits.insert(.readsFile)
            traits.insert(.writesFile)
            category = .io
        }

        if callees.contains(where: { context.isNetworkIO($0, binary: binary) }) {
            traits.insert(.readsFromNetwork)
            traits.insert(.writesToNetwork)
            category = .networking
        }

        // Check for crypto operations
        if callees.contains(where: { context.isCrypto($0, binary: binary) }) {
            traits.insert(.performsCrypto)
            category = .crypto
        }

        // Check for string operations
        if callees.contains(where: { context.isStringOp($0, binary: binary) }) {
            traits.insert(.usesStrings)
        }

        // Check for loops
        if function.basicBlocks.contains(where: { $0.type == .loop }) {
            traits.insert(.hasLoop)
        }

        // Check if leaf function
        if function.isLeaf {
            traits.insert(.isLeaf)
        }

        // Check if thunk
        if function.isThunk {
            traits.insert(.isThunk)
        }

        // Determine category from name hints
        let nameLower = function.name.lowercased()
        if nameLower.contains("init") {
            category = .initialization
        } else if nameLower.contains("deinit") || nameLower.contains("destroy") || nameLower.contains("cleanup") {
            category = .cleanup
        } else if nameLower.contains("get") && !nameLower.contains("forget") {
            category = .getter
        } else if nameLower.contains("set") && !nameLower.contains("reset") && !nameLower.contains("offset") {
            category = .setter
        } else if nameLower.contains("create") || nameLower.contains("make") || nameLower.contains("new") {
            category = .factory
        } else if nameLower.contains("parse") {
            category = .parsing
        } else if nameLower.contains("valid") || nameLower.contains("check") || nameLower.contains("verify") {
            category = .validation
        } else if nameLower.contains("convert") || nameLower.contains("to") {
            category = .conversion
        } else if nameLower.contains("find") || nameLower.contains("search") || nameLower.contains("lookup") {
            category = .search
        } else if nameLower.contains("sort") || nameLower.contains("order") {
            category = .sort
        } else if nameLower.contains("calc") || nameLower.contains("compute") {
            category = .calculation
        } else if nameLower.contains("callback") || nameLower.contains("handler") || nameLower.contains("delegate") {
            category = .callback
        }

        // Calculate confidence
        let confidence = traits.isEmpty ? 0.3 : min(0.9, 0.5 + Double(traits.count) * 0.1)

        return FunctionBehavior(
            category: category,
            subcategory: nil,
            traits: traits,
            confidence: confidence
        )
    }

    // MARK: - Name Suggestions

    private func suggestFunctionName(function: Function, behavior: FunctionBehavior, binary: BinaryFile) -> Suggestion? {
        // Don't suggest if already named
        guard function.name.isEmpty || function.name.hasPrefix("sub_") else { return nil }

        var suggestedName: String
        var reasoning: String

        // Generate name based on behavior
        switch behavior.category {
        case .initialization:
            suggestedName = "initialize_\(guessObjectType(function: function, binary: binary))"
            reasoning = "Function appears to initialize data structures"
        case .cleanup:
            suggestedName = "cleanup_\(guessObjectType(function: function, binary: binary))"
            reasoning = "Function appears to clean up resources"
        case .allocation:
            suggestedName = "allocate_\(guessObjectType(function: function, binary: binary))"
            reasoning = "Function allocates memory"
        case .deallocation:
            suggestedName = "free_\(guessObjectType(function: function, binary: binary))"
            reasoning = "Function deallocates memory"
        case .io:
            suggestedName = behavior.traits.contains(.readsFile) ? "read_file" : "write_file"
            reasoning = "Function performs file I/O"
        case .networking:
            suggestedName = behavior.traits.contains(.readsFromNetwork) ? "recv_data" : "send_data"
            reasoning = "Function performs network I/O"
        case .crypto:
            suggestedName = "crypto_operation"
            reasoning = "Function performs cryptographic operations"
        case .parsing:
            suggestedName = "parse_\(guessObjectType(function: function, binary: binary))"
            reasoning = "Function parses input data"
        case .validation:
            suggestedName = "validate_\(guessObjectType(function: function, binary: binary))"
            reasoning = "Function validates data"
        case .getter:
            suggestedName = "get_\(guessPropertyName(function: function, binary: binary))"
            reasoning = "Function appears to be a getter"
        case .setter:
            suggestedName = "set_\(guessPropertyName(function: function, binary: binary))"
            reasoning = "Function appears to be a setter"
        case .factory:
            suggestedName = "create_\(guessObjectType(function: function, binary: binary))"
            reasoning = "Function creates objects"
        case .callback:
            suggestedName = "handle_\(guessEventType(function: function, binary: binary))"
            reasoning = "Function appears to be a callback handler"
        default:
            // Generate generic name based on characteristics
            if behavior.traits.contains(.isLeaf) && function.size < 50 {
                suggestedName = "helper_\(String(format: "%04X", function.startAddress & 0xFFFF))"
                reasoning = "Small leaf function, likely a utility helper"
            } else {
                return nil
            }
        }

        return Suggestion(
            type: .functionName,
            target: function.startAddress,
            suggestion: suggestedName,
            confidence: behavior.confidence,
            reasoning: reasoning
        )
    }

    private func suggestFunctionComment(function: Function, behavior: FunctionBehavior, binary: BinaryFile) -> Suggestion? {
        var comment = ""

        // Add category
        comment = "[\(behavior.category.rawValue)]"

        // Add traits
        var traitDescriptions: [String] = []

        if behavior.traits.contains(.allocatesMemory) {
            traitDescriptions.append("allocates memory")
        }
        if behavior.traits.contains(.freesMemory) {
            traitDescriptions.append("frees memory")
        }
        if behavior.traits.contains(.readsFromNetwork) {
            traitDescriptions.append("reads from network")
        }
        if behavior.traits.contains(.writesToNetwork) {
            traitDescriptions.append("writes to network")
        }
        if behavior.traits.contains(.performsCrypto) {
            traitDescriptions.append("performs cryptographic operations")
        }
        if behavior.traits.contains(.hasLoop) {
            traitDescriptions.append("contains loops")
        }
        if behavior.traits.contains(.isRecursive) {
            traitDescriptions.append("recursive")
        }

        if !traitDescriptions.isEmpty {
            comment += " " + traitDescriptions.joined(separator: ", ")
        }

        // Add caller/callee info
        if !function.callers.isEmpty {
            comment += "\nCalled by \(function.callers.count) function(s)"
        }
        if !function.callees.isEmpty {
            comment += "\nCalls \(function.callees.count) function(s)"
        }

        return Suggestion(
            type: .functionComment,
            target: function.startAddress,
            suggestion: comment,
            confidence: behavior.confidence,
            reasoning: "Auto-generated comment based on function analysis"
        )
    }

    // MARK: - Parameter Name Suggestions

    private func suggestParameterNames(function: Function, behavior: FunctionBehavior, binary: BinaryFile) -> [Suggestion] {
        var suggestions: [Suggestion] = []

        // Suggest based on function category
        switch behavior.category {
        case .allocation:
            suggestions.append(Suggestion(
                type: .parameterName,
                target: function.startAddress,
                suggestion: "size",
                confidence: 0.8,
                reasoning: "First parameter to allocation function is typically size"
            ))

        case .io, .networking:
            suggestions.append(Suggestion(
                type: .parameterName,
                target: function.startAddress,
                suggestion: "buffer",
                confidence: 0.7,
                reasoning: "I/O functions typically take a buffer parameter"
            ))
            suggestions.append(Suggestion(
                type: .parameterName,
                target: function.startAddress,
                suggestion: "length",
                confidence: 0.7,
                reasoning: "I/O functions typically take a length parameter"
            ))

        case .parsing:
            suggestions.append(Suggestion(
                type: .parameterName,
                target: function.startAddress,
                suggestion: "input",
                confidence: 0.7,
                reasoning: "Parse functions typically take input data"
            ))
            suggestions.append(Suggestion(
                type: .parameterName,
                target: function.startAddress,
                suggestion: "output",
                confidence: 0.6,
                reasoning: "Parse functions may have output parameter"
            ))

        case .validation:
            suggestions.append(Suggestion(
                type: .parameterName,
                target: function.startAddress,
                suggestion: "value",
                confidence: 0.8,
                reasoning: "Validation functions check a value"
            ))

        case .search:
            suggestions.append(Suggestion(
                type: .parameterName,
                target: function.startAddress,
                suggestion: "needle",
                confidence: 0.7,
                reasoning: "Search functions look for something"
            ))
            suggestions.append(Suggestion(
                type: .parameterName,
                target: function.startAddress,
                suggestion: "haystack",
                confidence: 0.6,
                reasoning: "Search functions search in something"
            ))

        default:
            break
        }

        return suggestions
    }

    // MARK: - Variable Name Suggestions

    private func suggestVariableNames(function: Function, binary: BinaryFile) -> [Suggestion] {
        var suggestions: [Suggestion] = []

        // Analyze local variables by their usage pattern
        for local in function.localVariables {
            var suggestedName: String?
            var confidence = 0.5

            // Check size for type hints
            switch local.size {
            case 1:
                suggestedName = "byte_\(abs(local.stackOffset))"
            case 2:
                suggestedName = "short_\(abs(local.stackOffset))"
            case 4:
                suggestedName = "int_\(abs(local.stackOffset))"
            case 8:
                suggestedName = "long_\(abs(local.stackOffset))"
            default:
                if local.size > 8 {
                    suggestedName = "buffer_\(abs(local.stackOffset))"
                    confidence = 0.6
                }
            }

            if let name = suggestedName {
                suggestions.append(Suggestion(
                    type: .variableName,
                    target: function.startAddress + UInt64(abs(local.stackOffset)),
                    suggestion: name,
                    confidence: confidence,
                    reasoning: "Name suggested based on variable size and stack position"
                ))
            }
        }

        return suggestions
    }

    // MARK: - Vulnerability Detection

    private func checkVulnerabilities(function: Function, binary: BinaryFile) -> [Suggestion] {
        var suggestions: [Suggestion] = []

        let instructions = function.basicBlocks.flatMap(\.instructions)

        // Check for dangerous function calls
        let dangerousFunctions = [
            "strcpy": "Use strncpy or strlcpy instead",
            "strcat": "Use strncat or strlcat instead",
            "sprintf": "Use snprintf instead",
            "gets": "Use fgets instead - gets has no bounds checking",
            "scanf": "Ensure format string has width specifier",
        ]

        for insn in instructions where insn.type == .call {
            if let target = insn.branchTarget,
               let symbol = binary.symbols.first(where: { $0.address == target }) {
                for (dangerous, fix) in dangerousFunctions {
                    if symbol.name.contains(dangerous) {
                        suggestions.append(Suggestion(
                            type: .vulnerabilityWarning,
                            target: insn.address,
                            suggestion: "Potential buffer overflow: \(symbol.name) - \(fix)",
                            confidence: 0.8,
                            reasoning: "\(dangerous) is known to be unsafe"
                        ))
                    }
                }
            }
        }

        // Check for format string vulnerabilities
        for insn in instructions where insn.type == .call {
            if let target = insn.branchTarget,
               let symbol = binary.symbols.first(where: { $0.address == target }) {
                if symbol.name.contains("printf") && !symbol.name.contains("snprintf") {
                    // Check if format string is user-controlled
                    suggestions.append(Suggestion(
                        type: .vulnerabilityWarning,
                        target: insn.address,
                        suggestion: "Potential format string vulnerability - verify format string is not user-controlled",
                        confidence: 0.5,
                        reasoning: "printf-family functions can be vulnerable to format string attacks"
                    ))
                }
            }
        }

        return suggestions
    }

    // MARK: - Helpers

    private func guessObjectType(function: Function, binary: BinaryFile) -> String {
        // Try to guess what type of object this function deals with
        // based on called functions and string references

        // Check for type hints in called functions
        for calleeAddr in function.callees {
            if let symbol = binary.symbols.first(where: { $0.address == calleeAddr }) {
                let name = symbol.name.lowercased()
                if name.contains("string") { return "string" }
                if name.contains("array") { return "array" }
                if name.contains("dict") { return "dict" }
                if name.contains("list") { return "list" }
                if name.contains("buffer") { return "buffer" }
                if name.contains("socket") { return "socket" }
                if name.contains("file") { return "file" }
            }
        }

        return "object"
    }

    private func guessPropertyName(function: Function, binary: BinaryFile) -> String {
        // For getter/setter, try to guess the property name
        let name = function.name.lowercased()

        // Remove common prefixes
        var property = name
        for prefix in ["get_", "set_", "get", "set"] {
            if property.hasPrefix(prefix) {
                property = String(property.dropFirst(prefix.count))
                break
            }
        }

        return property.isEmpty ? "value" : property
    }

    private func guessEventType(function: Function, binary: BinaryFile) -> String {
        let name = function.name.lowercased()

        if name.contains("click") { return "click" }
        if name.contains("key") { return "key" }
        if name.contains("mouse") { return "mouse" }
        if name.contains("touch") { return "touch" }
        if name.contains("timer") { return "timer" }
        if name.contains("network") { return "network" }
        if name.contains("notification") { return "notification" }

        return "event"
    }
}

// MARK: - Analysis Context

/// Provides context about known functions and symbols
class AnalysisContext {
    private var knownMallocFunctions: Set<String> = ["malloc", "calloc", "realloc", "_malloc", "_calloc", "_realloc"]
    private var knownFreeFunctions: Set<String> = ["free", "_free"]
    private var knownFileIOFunctions: Set<String> = ["fopen", "fclose", "fread", "fwrite", "fprintf", "fscanf", "fgets", "fputs"]
    private var knownNetworkFunctions: Set<String> = ["socket", "connect", "bind", "listen", "accept", "send", "recv", "sendto", "recvfrom"]
    private var knownCryptoFunctions: Set<String> = ["EVP_", "AES_", "SHA", "MD5", "RSA_", "crypto_"]
    private var knownStringFunctions: Set<String> = ["strlen", "strcpy", "strcat", "strcmp", "strstr", "memcpy", "memset", "memmove"]

    func isMallocLike(_ address: UInt64, binary: BinaryFile) -> Bool {
        guard let symbol = binary.symbols.first(where: { $0.address == address }) else { return false }
        return knownMallocFunctions.contains { symbol.name.contains($0) }
    }

    func isFreeLike(_ address: UInt64, binary: BinaryFile) -> Bool {
        guard let symbol = binary.symbols.first(where: { $0.address == address }) else { return false }
        return knownFreeFunctions.contains { symbol.name.contains($0) }
    }

    func isFileIO(_ address: UInt64, binary: BinaryFile) -> Bool {
        guard let symbol = binary.symbols.first(where: { $0.address == address }) else { return false }
        return knownFileIOFunctions.contains { symbol.name.contains($0) }
    }

    func isNetworkIO(_ address: UInt64, binary: BinaryFile) -> Bool {
        guard let symbol = binary.symbols.first(where: { $0.address == address }) else { return false }
        return knownNetworkFunctions.contains { symbol.name.contains($0) }
    }

    func isCrypto(_ address: UInt64, binary: BinaryFile) -> Bool {
        guard let symbol = binary.symbols.first(where: { $0.address == address }) else { return false }
        return knownCryptoFunctions.contains { symbol.name.contains($0) }
    }

    func isStringOp(_ address: UInt64, binary: BinaryFile) -> Bool {
        guard let symbol = binary.symbols.first(where: { $0.address == address }) else { return false }
        return knownStringFunctions.contains { symbol.name.contains($0) }
    }
}
