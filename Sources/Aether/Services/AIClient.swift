import Foundation

/// Client for interacting with the AI API
class AIClient {
    private let baseURL = "https://api.anthropic.com/v1/messages"
    private let model = "claude-sonnet-4-20250514"

    /// Analyze code for security issues
    func analyzeSecurityAsync(
        functionName: String,
        decompiledCode: String,
        disassembly: String,
        strings: [String],
        imports: [String],
        apiKey: String
    ) async throws -> SecurityAnalysisResult {
        let prompt = buildSecurityPrompt(
            functionName: functionName,
            decompiledCode: decompiledCode,
            disassembly: disassembly,
            strings: strings,
            imports: imports
        )

        let response = try await sendMessage(prompt: prompt, apiKey: apiKey)
        return parseSecurityResponse(response)
    }

    /// Analyze entire binary for security issues
    func analyzeBinaryAsync(
        binaryName: String,
        functions: [String],
        strings: [String],
        imports: [String],
        exports: [String],
        apiKey: String
    ) async throws -> SecurityAnalysisResult {
        let prompt = buildBinaryAnalysisPrompt(
            binaryName: binaryName,
            functions: functions,
            strings: strings,
            imports: imports,
            exports: exports
        )

        let response = try await sendMessage(prompt: prompt, apiKey: apiKey)
        return parseSecurityResponse(response)
    }

    /// Generate Frida script using AI
    func generateFridaScriptAsync(
        functionName: String,
        decompiledCode: String,
        disassembly: String,
        securityFindings: [String],
        bypassTechniques: [String],
        platform: String,
        hookType: String,
        apiKey: String
    ) async throws -> AIFridaScriptResult {
        let prompt = buildFridaPrompt(
            functionName: functionName,
            decompiledCode: decompiledCode,
            disassembly: disassembly,
            securityFindings: securityFindings,
            bypassTechniques: bypassTechniques,
            platform: platform,
            hookType: hookType
        )

        let response = try await sendMessage(prompt: prompt, apiKey: apiKey)
        return parseFridaResponse(response)
    }

    // MARK: - Chat with AI

    /// Chat with AI about the binary
    func chatAsync(
        messages: [ChatMessage],
        context: BinaryContext,
        apiKey: String
    ) async throws -> String {
        let systemPrompt = buildChatSystemPrompt(context: context)
        let response = try await sendMessageWithHistory(
            systemPrompt: systemPrompt,
            messages: messages,
            apiKey: apiKey
        )
        return response
    }

    // MARK: - Explain Code

    /// Explain what a function does in natural language
    func explainCodeAsync(
        functionName: String,
        decompiledCode: String,
        disassembly: String,
        apiKey: String
    ) async throws -> CodeExplanation {
        let prompt = buildExplainPrompt(
            functionName: functionName,
            decompiledCode: decompiledCode,
            disassembly: disassembly
        )
        let response = try await sendMessage(prompt: prompt, apiKey: apiKey)
        return parseExplainResponse(response)
    }

    // MARK: - Variable Renaming

    /// Suggest meaningful variable names
    func suggestVariableNamesAsync(
        decompiledCode: String,
        functionName: String,
        apiKey: String
    ) async throws -> [VariableRename] {
        let prompt = buildRenamePrompt(
            decompiledCode: decompiledCode,
            functionName: functionName
        )
        let response = try await sendMessage(prompt: prompt, apiKey: apiKey)
        return parseRenameResponse(response)
    }

    // MARK: - Private Methods

    private func sendMessage(prompt: String, apiKey: String) async throws -> String {
        guard let url = URL(string: baseURL) else {
            throw AIClientError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")

        let body: [String: Any] = [
            "model": model,
            "max_tokens": 4096,
            "messages": [
                ["role": "user", "content": prompt]
            ]
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw AIClientError.invalidResponse
        }

        if httpResponse.statusCode == 401 {
            throw AIClientError.invalidAPIKey
        }

        if httpResponse.statusCode != 200 {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw AIClientError.apiError(statusCode: httpResponse.statusCode, message: errorBody)
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let content = json["content"] as? [[String: Any]],
              let firstContent = content.first,
              let text = firstContent["text"] as? String else {
            throw AIClientError.parseError
        }

        return text
    }

    private func sendMessageWithHistory(
        systemPrompt: String,
        messages: [ChatMessage],
        apiKey: String
    ) async throws -> String {
        guard let url = URL(string: baseURL) else {
            throw AIClientError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")

        // Convert ChatMessages to API format
        let apiMessages = messages.map { msg -> [String: String] in
            ["role": msg.role, "content": msg.content]
        }

        let body: [String: Any] = [
            "model": model,
            "max_tokens": 4096,
            "system": systemPrompt,
            "messages": apiMessages
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw AIClientError.invalidResponse
        }

        if httpResponse.statusCode == 401 {
            throw AIClientError.invalidAPIKey
        }

        if httpResponse.statusCode != 200 {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw AIClientError.apiError(statusCode: httpResponse.statusCode, message: errorBody)
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let content = json["content"] as? [[String: Any]],
              let firstContent = content.first,
              let text = firstContent["text"] as? String else {
            throw AIClientError.parseError
        }

        return text
    }

    private func buildChatSystemPrompt(context: BinaryContext) -> String {
        var prompt = """
        You are an expert reverse engineer and binary analyst assistant. You are helping the user analyze a binary file.

        ## Binary Context:
        - Name: \(context.name)
        - Architecture: \(context.architecture)
        - Total functions: \(context.functionCount)
        """

        if let currentFunction = context.currentFunction {
            prompt += "\n- Currently selected function: \(currentFunction)"
        }

        if let code = context.decompiledCode, !code.isEmpty {
            prompt += """

            ### Current Decompiled Code:
            ```c
            \(code.prefix(4000))
            ```
            """
        }

        if !context.relevantStrings.isEmpty {
            prompt += """

            ### Relevant Strings in Binary:
            \(context.relevantStrings.prefix(20).joined(separator: "\n"))
            """
        }

        prompt += """

        ## Instructions:
        - Answer questions about the binary, functions, and code
        - Explain what code does when asked
        - Help identify security issues, vulnerabilities, or interesting patterns
        - Suggest bypass techniques or patches when appropriate
        - Be concise but thorough
        - If you don't have enough context, ask for clarification
        """

        return prompt
    }

    private func buildExplainPrompt(
        functionName: String,
        decompiledCode: String,
        disassembly: String
    ) -> String {
        return """
        You are an expert reverse engineer. Explain what the following function does in clear, simple language.

        ## Function: \(functionName)

        ### Decompiled Code:
        ```c
        \(decompiledCode.prefix(6000))
        ```

        ### Assembly (first 100 instructions):
        ```asm
        \(disassembly.prefix(4000))
        ```

        ## Provide your analysis in JSON format:
        ```json
        {
            "summary": "One-sentence summary of what this function does",
            "detailed": "Detailed explanation (2-3 paragraphs) of the function's purpose, logic flow, and behavior",
            "complexity": "simple|medium|high",
            "patterns": ["List of recognized patterns like 'string manipulation', 'file I/O', 'encryption', 'network', 'license check', etc."]
        }
        ```

        Focus on:
        1. The main purpose of the function
        2. Key operations and logic flow
        3. What data it processes
        4. Any security implications
        5. Common patterns (crypto, network, file I/O, etc.)
        """
    }

    private func buildRenamePrompt(
        decompiledCode: String,
        functionName: String
    ) -> String {
        return """
        You are an expert reverse engineer. Analyze the following decompiled code and suggest meaningful names for variables and parameters.

        ## Function: \(functionName)

        ### Decompiled Code:
        ```c
        \(decompiledCode.prefix(6000))
        ```

        ## Task:
        Identify generic variable names (like var1, var2, arg0, arg1, v0, a0, etc.) and suggest meaningful names based on their usage.

        Provide your suggestions in JSON format:
        ```json
        {
            "renames": [
                {
                    "original": "var1",
                    "suggested": "bufferSize",
                    "reason": "Used as size parameter for memory allocation"
                },
                {
                    "original": "arg0",
                    "suggested": "inputString",
                    "reason": "Passed to string manipulation functions"
                }
            ]
        }
        ```

        Guidelines:
        1. Only rename generic/meaningless variable names
        2. Keep names concise but descriptive
        3. Use camelCase naming convention
        4. Provide clear reasoning for each rename
        5. Focus on the most important variables (max 15 suggestions)
        """
    }

    private func parseExplainResponse(_ response: String) -> CodeExplanation {
        var jsonString = response

        // Find JSON block
        if let jsonStart = response.range(of: "```json"),
           let jsonEnd = response.range(of: "```", range: jsonStart.upperBound..<response.endIndex) {
            jsonString = String(response[jsonStart.upperBound..<jsonEnd.lowerBound])
        } else if let jsonStart = response.range(of: "{"),
                  let jsonEnd = response.range(of: "}", options: .backwards) {
            jsonString = String(response[jsonStart.lowerBound...jsonEnd.upperBound])
        }

        if let data = jsonString.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let summary = json["summary"] as? String ?? "Analysis complete"
            let detailed = json["detailed"] as? String ?? response
            let complexity = json["complexity"] as? String ?? "medium"
            let patterns = json["patterns"] as? [String] ?? []

            return CodeExplanation(
                summary: summary,
                detailed: detailed,
                complexity: complexity,
                patterns: patterns,
                rawResponse: response
            )
        }

        // Fallback
        return CodeExplanation(
            summary: "Analysis complete",
            detailed: response,
            complexity: "unknown",
            patterns: [],
            rawResponse: response
        )
    }

    private func parseRenameResponse(_ response: String) -> [VariableRename] {
        var jsonString = response

        // Find JSON block
        if let jsonStart = response.range(of: "```json"),
           let jsonEnd = response.range(of: "```", range: jsonStart.upperBound..<response.endIndex) {
            jsonString = String(response[jsonStart.upperBound..<jsonEnd.lowerBound])
        } else if let jsonStart = response.range(of: "{"),
                  let jsonEnd = response.range(of: "}", options: .backwards) {
            jsonString = String(response[jsonStart.lowerBound...jsonEnd.upperBound])
        }

        if let data = jsonString.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let renames = json["renames"] as? [[String: String]] {
            return renames.compactMap { rename in
                guard let original = rename["original"],
                      let suggested = rename["suggested"],
                      let reason = rename["reason"] else {
                    return nil
                }
                return VariableRename(
                    originalName: original,
                    suggestedName: suggested,
                    reason: reason
                )
            }
        }

        return []
    }

    private func buildSecurityPrompt(
        functionName: String,
        decompiledCode: String,
        disassembly: String,
        strings: [String],
        imports: [String]
    ) -> String {
        var prompt = """
        You are a security researcher analyzing a binary. Analyze the following code for security vulnerabilities and suspicious behavior.

        ## Function: \(functionName)

        ### Decompiled Code:
        ```c
        \(decompiledCode.prefix(8000))
        ```

        """

        if !disassembly.isEmpty {
            prompt += """

            ### Assembly (first 200 instructions):
            ```asm
            \(disassembly.prefix(6000))
            ```

            """
        }

        if !strings.isEmpty {
            prompt += """

            ### Relevant Strings:
            \(strings.prefix(50).joined(separator: "\n"))

            """
        }

        if !imports.isEmpty {
            prompt += """

            ### Imported Functions:
            \(imports.prefix(100).joined(separator: ", "))

            """
        }

        prompt += """

        ## Analysis Required:

        You are a penetration tester and reverse engineer. Analyze this code with focus on:
        1. **Security mechanisms present** (license checks, anti-tampering, code signing verification, etc.)
        2. **How these protections could be BYPASSED** (specific techniques, patch points, weaknesses)
        3. **Vulnerabilities that could be exploited**

        Be SPECIFIC about bypass techniques: mention exact addresses, patch bytes, or code modifications needed.

        Please provide analysis in the following JSON format:
        ```json
        {
            "summary": "Brief overall security assessment",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
            "findings": [
                {
                    "title": "Finding title",
                    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
                    "description": "Detailed description including HOW TO BYPASS if applicable",
                    "recommendation": "How to fix/strengthen OR how to exploit"
                }
            ],
            "security_mechanisms": ["mechanism1", "mechanism2"],
            "bypass_techniques": ["technique1 with specific details", "technique2"],
            "patch_points": ["address or function to patch"],
            "malware_indicators": ["indicator1", "indicator2"],
            "suspicious_behaviors": ["behavior1", "behavior2"],
            "hardcoded_secrets": ["secret1", "secret2"]
        }
        ```

        Focus on:
        1. **LICENSE/REGISTRATION CHECKS** - How to bypass them (NOP out jumps, patch return values)
        2. **ANTI-TAMPERING** - Code signing, integrity checks, how to defeat them
        3. **ANTI-DEBUGGING** - Detection techniques and how to bypass
        4. **TRIAL LIMITATIONS** - Time checks, feature locks, how to remove them
        5. **NETWORK VALIDATION** - Online checks, how to fake or bypass
        6. Buffer overflows, format string bugs, exploitable vulnerabilities
        7. Hardcoded credentials, API keys, encryption keys
        8. Crypto weaknesses (weak algorithms, hardcoded keys)
        9. Command injection possibilities
        10. Interesting functions to hook or patch

        BE SPECIFIC: Give exact function names, addresses if visible, patch bytes (e.g., "change JZ to JMP", "NOP the call at X").
        """

        return prompt
    }

    private func buildBinaryAnalysisPrompt(
        binaryName: String,
        functions: [String],
        strings: [String],
        imports: [String],
        exports: [String]
    ) -> String {
        return """
        You are a penetration tester and cracker analyzing a binary for security weaknesses and bypass opportunities.

        ## Binary: \(binaryName)

        ### Functions (\(functions.count) total, showing first 100):
        \(functions.prefix(100).joined(separator: "\n"))

        ### Strings (\(strings.count) total, showing first 100):
        \(strings.prefix(100).joined(separator: "\n"))

        ### Imports (\(imports.count) total):
        \(imports.prefix(150).joined(separator: ", "))

        ### Exports (\(exports.count) total):
        \(exports.prefix(50).joined(separator: ", "))

        ## Analysis Required:

        Analyze for:
        1. **LICENSE CHECKS** - Functions that verify registration/license. How to bypass?
        2. **TRIAL LIMITATIONS** - Time/feature restrictions. How to remove?
        3. **ANTI-PIRACY** - Protection mechanisms. Weaknesses?
        4. **INTERESTING FUNCTIONS** - Functions worth patching/hooking
        5. **HARDCODED DATA** - Keys, passwords, URLs that reveal protection logic

        Please provide analysis in JSON format:
        ```json
        {
            "summary": "Brief overall security/bypass assessment",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
            "findings": [
                {
                    "title": "Finding title",
                    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
                    "description": "Detailed description with BYPASS TECHNIQUE if applicable",
                    "recommendation": "How to patch/bypass OR how to strengthen"
                }
            ],
            "security_mechanisms": ["protection1", "protection2"],
            "bypass_techniques": ["specific bypass technique with details"],
            "patch_points": ["function or location to patch"],
            "malware_indicators": ["indicator1", "indicator2"],
            "suspicious_behaviors": ["behavior1", "behavior2"],
            "hardcoded_secrets": ["secret1", "secret2"],
            "interesting_functions": ["func1", "func2"]
        }
        ```

        BE SPECIFIC about:
        - Which functions handle license/registration
        - Exact bypass techniques (NOP, patch jump, change return value)
        - Strings that reveal protection logic
        - Functions to hook for keygen/crack
        """
    }

    private func parseSecurityResponse(_ response: String) -> SecurityAnalysisResult {
        // Try to extract JSON from the response
        var jsonString = response

        // Find JSON block in markdown code fence
        if let jsonStart = response.range(of: "```json"),
           let jsonEnd = response.range(of: "```", range: jsonStart.upperBound..<response.endIndex) {
            jsonString = String(response[jsonStart.upperBound..<jsonEnd.lowerBound])
        } else if let jsonStart = response.range(of: "{"),
                  let jsonEnd = response.range(of: "}", options: .backwards) {
            jsonString = String(response[jsonStart.lowerBound...jsonEnd.upperBound])
        }

        // Try to parse JSON
        if let data = jsonString.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return parseJSON(json, rawResponse: response)
        }

        // Fallback: return raw response
        return SecurityAnalysisResult(
            summary: "Analysis complete",
            severity: .info,
            findings: [
                SecurityFinding(
                    title: "AI Analysis",
                    severity: .info,
                    description: response,
                    recommendation: nil
                )
            ],
            securityMechanisms: [],
            bypassTechniques: [],
            patchPoints: [],
            malwareIndicators: [],
            suspiciousBehaviors: [],
            hardcodedSecrets: [],
            rawResponse: response
        )
    }

    private func parseJSON(_ json: [String: Any], rawResponse: String) -> SecurityAnalysisResult {
        let summary = json["summary"] as? String ?? "Analysis complete"
        let severityString = json["severity"] as? String ?? "INFO"
        let severity = Severity(rawValue: severityString.uppercased()) ?? .info

        var findings: [SecurityFinding] = []
        if let findingsArray = json["findings"] as? [[String: Any]] {
            for finding in findingsArray {
                let title = finding["title"] as? String ?? "Finding"
                let findingSeverity = Severity(rawValue: (finding["severity"] as? String ?? "INFO").uppercased()) ?? .info
                let description = finding["description"] as? String ?? ""
                let recommendation = finding["recommendation"] as? String

                findings.append(SecurityFinding(
                    title: title,
                    severity: findingSeverity,
                    description: description,
                    recommendation: recommendation
                ))
            }
        }

        let securityMechanisms = json["security_mechanisms"] as? [String] ?? []
        let bypassTechniques = json["bypass_techniques"] as? [String] ?? []
        let patchPoints = json["patch_points"] as? [String] ?? []
        let malwareIndicators = json["malware_indicators"] as? [String] ?? []
        let suspiciousBehaviors = json["suspicious_behaviors"] as? [String] ?? []
        let hardcodedSecrets = json["hardcoded_secrets"] as? [String] ?? []

        return SecurityAnalysisResult(
            summary: summary,
            severity: severity,
            findings: findings,
            securityMechanisms: securityMechanisms,
            bypassTechniques: bypassTechniques,
            patchPoints: patchPoints,
            malwareIndicators: malwareIndicators,
            suspiciousBehaviors: suspiciousBehaviors,
            hardcodedSecrets: hardcodedSecrets,
            rawResponse: rawResponse
        )
    }

    // MARK: - Frida Script Generation

    private func buildFridaPrompt(
        functionName: String,
        decompiledCode: String,
        disassembly: String,
        securityFindings: [String],
        bypassTechniques: [String],
        platform: String,
        hookType: String
    ) -> String {
        var prompt = """
        You are an expert Frida hooking specialist for \(platform).
        Generate a complete, working Frida script for the following function.

        ## Function: \(functionName)

        ### Decompiled Code:
        ```c
        \(decompiledCode.prefix(6000))
        ```

        ### Assembly (first 150 instructions):
        ```asm
        \(disassembly.prefix(5000))
        ```

        """

        if !securityFindings.isEmpty {
            prompt += """

            ### Security Findings:
            \(securityFindings.prefix(10).joined(separator: "\n"))

            """
        }

        if !bypassTechniques.isEmpty {
            prompt += """

            ### Bypass Techniques to Implement:
            \(bypassTechniques.joined(separator: "\n"))

            """
        }

        prompt += """

        ### Requirements:
        1. Platform: \(platform)
        2. Hook Type: \(hookType)
        3. Handle ASLR with Module.findBaseAddress() or Process.findModuleByName()
        4. Log all arguments with proper type handling
        5. Implement bypass techniques where applicable
        6. Add error handling and null checks
        7. Include helpful console.log messages

        ### Hook Type Details:
        """

        switch hookType.lowercased() {
        case "trace":
            prompt += """

            - Log all function arguments and their types
            - Log return value
            - Include backtrace
            - Show call context (registers, stack)
            """
        case "bypass":
            prompt += """

            - Modify return value to bypass checks
            - Implement specific bypass techniques from the findings
            - Force success/true returns where needed
            - NOP or skip validation logic
            """
        case "intercept":
            prompt += """

            - Allow modifying arguments before the function runs
            - Allow modifying return value after
            - Include examples of common modifications
            - Show how to replace string arguments
            """
        case "memory dump":
            prompt += """

            - Dump memory at the function address
            - Show hexdump of the function bytes
            - Optionally save to file
            - Dump stack and registers on entry
            """
        case "string patch":
            prompt += """

            - Search for and patch strings in memory
            - Handle ASLR for string addresses
            - Make memory writable before patching
            - Verify patch was applied
            """
        case "anti-debug":
            prompt += """

            - Bypass ptrace PT_DENY_ATTACH
            - Bypass sysctl P_TRACED flag check
            - Bypass getppid parent process check
            - Bypass any debugger detection in the code
            """
        default:
            prompt += """

            - General purpose hook with logging
            - Flexible argument and return value handling
            """
        }

        prompt += """


        Generate output as JSON:
        ```json
        {
            "script": "// Full JavaScript Frida script here\\n...",
            "explanation": "Brief explanation of what the script does",
            "hook_points": ["list of hooked addresses/functions"],
            "bypass_implemented": ["list of bypasses implemented"],
            "warnings": ["any warnings or caveats about the script"]
        }
        ```

        The script should be COMPLETE and READY TO USE with:
        - frida -U -f <app> -l script.js (for iOS)
        - frida -f <app> -l script.js (for macOS)

        Make the script robust with proper error handling.
        """

        return prompt
    }

    private func parseFridaResponse(_ response: String) -> AIFridaScriptResult {
        // Try to extract JSON from the response
        var jsonString = response

        // Find JSON block in markdown code fence
        if let jsonStart = response.range(of: "```json"),
           let jsonEnd = response.range(of: "```", range: jsonStart.upperBound..<response.endIndex) {
            jsonString = String(response[jsonStart.upperBound..<jsonEnd.lowerBound])
        } else if let jsonStart = response.range(of: "{"),
                  let jsonEnd = response.range(of: "}", options: .backwards) {
            jsonString = String(response[jsonStart.lowerBound...jsonEnd.upperBound])
        }

        // Try to parse JSON
        if let data = jsonString.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return parseFridaJSON(json, rawResponse: response)
        }

        // Fallback: Try to extract script from code fence
        var script = response
        if let scriptStart = response.range(of: "```javascript"),
           let scriptEnd = response.range(of: "```", range: scriptStart.upperBound..<response.endIndex) {
            script = String(response[scriptStart.upperBound..<scriptEnd.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        } else if let scriptStart = response.range(of: "```js"),
                  let scriptEnd = response.range(of: "```", range: scriptStart.upperBound..<response.endIndex) {
            script = String(response[scriptStart.upperBound..<scriptEnd.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        }

        return AIFridaScriptResult(
            script: script,
            explanation: "AI-generated Frida script",
            hookPoints: [],
            bypassImplemented: [],
            warnings: ["Response was not in expected JSON format"]
        )
    }

    private func parseFridaJSON(_ json: [String: Any], rawResponse: String) -> AIFridaScriptResult {
        var script = json["script"] as? String ?? ""

        // Clean up the script - handle escaped newlines
        script = script.replacingOccurrences(of: "\\n", with: "\n")
        script = script.trimmingCharacters(in: .whitespacesAndNewlines)

        let explanation = json["explanation"] as? String ?? "AI-generated Frida script"
        let hookPoints = json["hook_points"] as? [String] ?? []
        let bypassImplemented = json["bypass_implemented"] as? [String] ?? []
        let warnings = json["warnings"] as? [String] ?? []

        return AIFridaScriptResult(
            script: script,
            explanation: explanation,
            hookPoints: hookPoints,
            bypassImplemented: bypassImplemented,
            warnings: warnings
        )
    }
}

// MARK: - Models

enum AIClientError: LocalizedError {
    case invalidURL
    case invalidResponse
    case invalidAPIKey
    case apiError(statusCode: Int, message: String)
    case parseError

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid API URL"
        case .invalidResponse:
            return "Invalid response from server"
        case .invalidAPIKey:
            return "Invalid API key. Please check your API key in Settings."
        case .apiError(let statusCode, let message):
            return "API Error (\(statusCode)): \(message)"
        case .parseError:
            return "Failed to parse API response"
        }
    }
}

enum Severity: String, CaseIterable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case info = "INFO"

    var color: String {
        switch self {
        case .critical: return "red"
        case .high: return "orange"
        case .medium: return "yellow"
        case .low: return "blue"
        case .info: return "gray"
        }
    }

    var icon: String {
        switch self {
        case .critical: return "exclamationmark.octagon.fill"
        case .high: return "exclamationmark.triangle.fill"
        case .medium: return "exclamationmark.circle.fill"
        case .low: return "info.circle.fill"
        case .info: return "info.circle"
        }
    }
}

struct SecurityFinding: Identifiable {
    let id = UUID()
    let title: String
    let severity: Severity
    let description: String
    let recommendation: String?
}

struct SecurityAnalysisResult {
    let summary: String
    let severity: Severity
    let findings: [SecurityFinding]
    let securityMechanisms: [String]
    let bypassTechniques: [String]
    let patchPoints: [String]
    let malwareIndicators: [String]
    let suspiciousBehaviors: [String]
    let hardcodedSecrets: [String]
    let rawResponse: String
}

// MARK: - Chat Models

struct ChatMessage: Identifiable, Equatable {
    let id: UUID
    let role: String  // "user" or "assistant"
    let content: String
    let timestamp: Date

    init(id: UUID = UUID(), role: String, content: String, timestamp: Date = Date()) {
        self.id = id
        self.role = role
        self.content = content
        self.timestamp = timestamp
    }
}

struct BinaryContext {
    let name: String
    let architecture: String
    let functionCount: Int
    let currentFunction: String?
    let decompiledCode: String?
    let relevantStrings: [String]
}

// MARK: - Explain Code Models

struct CodeExplanation {
    let summary: String
    let detailed: String
    let complexity: String
    let patterns: [String]
    let rawResponse: String
}

// MARK: - Variable Rename Models

struct VariableRename: Identifiable {
    let id: UUID
    let originalName: String
    let suggestedName: String
    let reason: String
    var isAccepted: Bool

    init(id: UUID = UUID(), originalName: String, suggestedName: String, reason: String, isAccepted: Bool = false) {
        self.id = id
        self.originalName = originalName
        self.suggestedName = suggestedName
        self.reason = reason
        self.isAccepted = isAccepted
    }
}
