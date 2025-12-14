import Foundation

/// Client for interacting with the Claude API
class ClaudeAPIClient {
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

    // MARK: - Private Methods

    private func sendMessage(prompt: String, apiKey: String) async throws -> String {
        guard let url = URL(string: baseURL) else {
            throw ClaudeAPIError.invalidURL
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
            throw ClaudeAPIError.invalidResponse
        }

        if httpResponse.statusCode == 401 {
            throw ClaudeAPIError.invalidAPIKey
        }

        if httpResponse.statusCode != 200 {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw ClaudeAPIError.apiError(statusCode: httpResponse.statusCode, message: errorBody)
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let content = json["content"] as? [[String: Any]],
              let firstContent = content.first,
              let text = firstContent["text"] as? String else {
            throw ClaudeAPIError.parseError
        }

        return text
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
}

// MARK: - Models

enum ClaudeAPIError: LocalizedError {
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
            return "Invalid API key. Please check your Claude API key in Settings."
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
