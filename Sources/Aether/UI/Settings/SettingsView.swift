import SwiftUI
import Security

struct AISettingsTab: View {
    @AppStorage("aiAPIKeyConfigured") private var apiKeyConfigured = false
    @State private var apiKey = ""
    @State private var showAPIKey = false
    @State private var saveStatus: SaveStatus = .none
    @State private var isValidating = false

    enum SaveStatus {
        case none
        case success
        case error(String)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header
            HStack {
                Image(systemName: "brain")
                    .font(.title2)
                    .foregroundColor(.purple)
                VStack(alignment: .leading) {
                    Text("AI Security Analysis")
                        .font(.headline)
                    Text("Analyze code for vulnerabilities with AI")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                if apiKeyConfigured {
                    Label("Active", systemImage: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .font(.caption)
                }
            }

            Divider()

            // API Key Section
            VStack(alignment: .leading, spacing: 8) {
                Text("API Key")
                    .font(.subheadline)
                    .fontWeight(.medium)

                HStack {
                    if showAPIKey {
                        TextField("sk-ant-...", text: $apiKey)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    } else {
                        SecureField("sk-ant-...", text: $apiKey)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    }

                    Button {
                        showAPIKey.toggle()
                    } label: {
                        Image(systemName: showAPIKey ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.plain)
                }

                Text("Get your API key from console.anthropic.com")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            // Actions
            HStack {
                Button("Save Key") {
                    saveAPIKey()
                }
                .buttonStyle(.borderedProminent)
                .disabled(apiKey.isEmpty || isValidating)

                if apiKeyConfigured {
                    Button("Remove") {
                        removeAPIKey()
                    }
                    .foregroundColor(.red)
                }

                if isValidating {
                    ProgressView()
                        .scaleEffect(0.7)
                }

                Spacer()

                switch saveStatus {
                case .success:
                    Label("Saved!", systemImage: "checkmark.circle")
                        .foregroundColor(.green)
                        .font(.caption)
                case .error(let message):
                    Label(message, systemImage: "xmark.circle")
                        .foregroundColor(.red)
                        .font(.caption)
                case .none:
                    EmptyView()
                }
            }

            Divider()

            // Info
            VStack(alignment: .leading, spacing: 6) {
                Label("Analyzes code for security vulnerabilities", systemImage: "shield.lefthalf.filled")
                    .font(.caption)
                Label("API key stored in macOS Keychain", systemImage: "lock.shield")
                    .font(.caption)
                Label("Uses your API credits", systemImage: "dollarsign.circle")
                    .font(.caption)
            }
            .foregroundColor(.secondary)

            Spacer()
        }
        .padding()
        .onAppear {
            loadAPIKey()
        }
    }

    private func saveAPIKey() {
        guard !apiKey.isEmpty else { return }

        isValidating = true
        saveStatus = .none

        // Validate API key format
        guard apiKey.hasPrefix("sk-ant-") else {
            saveStatus = .error("Invalid format")
            isValidating = false
            return
        }

        // Save to Keychain
        let result = KeychainHelper.save(key: "AIAPIKey", value: apiKey)

        isValidating = false

        if result {
            apiKeyConfigured = true
            saveStatus = .success
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                apiKey = String(repeating: "*", count: 20)
            }
        } else {
            saveStatus = .error("Save failed")
        }
    }

    private func loadAPIKey() {
        if let savedKey = KeychainHelper.load(key: "AIAPIKey") {
            apiKey = String(repeating: "*", count: min(savedKey.count, 20))
            apiKeyConfigured = true
        }
    }

    private func removeAPIKey() {
        KeychainHelper.delete(key: "AIAPIKey")
        apiKey = ""
        apiKeyConfigured = false
        saveStatus = .none
    }
}

// MARK: - Keychain Helper

enum KeychainHelper {
    static func save(key: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else { return false }

        // Delete existing item first
        delete(key: key)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aether.disassembler",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    static func load(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aether.disassembler",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }

        return string
    }

    static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aether.disassembler"
        ]

        SecItemDelete(query as CFDictionary)
    }
}
