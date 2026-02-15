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
                    Text(translate("settings.ai.title"))
                        .font(.headline)
                    Text(translate("settings.ai.subtitle"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                if apiKeyConfigured {
                    Label(translate("settings.ai.active"), systemImage: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .font(.caption)
                }
            }

            Divider()

            // API Key Section
            VStack(alignment: .leading, spacing: 8) {
                Text(translate("settings.ai.apiKey"))
                    .font(.subheadline)
                    .fontWeight(.medium)

                HStack {
                    if showAPIKey {
                        TextField(translate("settings.ai.apiKeyPlaceholder"), text: $apiKey)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    } else {
                        SecureField(translate("settings.ai.apiKeyPlaceholder"), text: $apiKey)
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

                Text(translate("settings.ai.apiKeyHelp"))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            // Actions
            HStack {
                Button(translate("settings.ai.saveKey")) {
                    saveAPIKey()
                }
                .buttonStyle(.borderedProminent)
                .disabled(apiKey.isEmpty || isValidating)

                if apiKeyConfigured {
                    Button(translate("settings.ai.remove")) {
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
                    Label(translate("settings.ai.saved"), systemImage: "checkmark.circle")
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
                Label(translate("settings.ai.info.analyzes"), systemImage: "shield.lefthalf.filled")
                    .font(.caption)
                Label(translate("settings.ai.info.keychain"), systemImage: "lock.shield")
                    .font(.caption)
                Label(translate("settings.ai.info.credits"), systemImage: "dollarsign.circle")
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
            saveStatus = .error(translate("settings.ai.error.invalidFormat"))
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
            saveStatus = .error(translate("settings.ai.error.saveFailed"))
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
