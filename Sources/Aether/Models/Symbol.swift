import Foundation

/// Represents a symbol in the binary
struct Symbol: Identifiable, Hashable {
    let id = UUID()
    let name: String
    let address: UInt64
    let size: UInt64
    let type: SymbolType
    let binding: SymbolBinding
    let section: String?

    var isImport: Bool {
        binding == .external && address == 0
    }

    var isExport: Bool {
        binding == .global && address != 0
    }

    var isLocal: Bool {
        binding == .local
    }

    var displayName: String {
        // Demangle if needed
        if name.hasPrefix("_$s") || name.hasPrefix("$s") {
            return demangleSwift(name) ?? name
        } else if name.hasPrefix("__Z") || name.hasPrefix("_Z") {
            return demangleCPP(name) ?? name
        }
        return name.hasPrefix("_") ? String(name.dropFirst()) : name
    }

    /// Basic Swift demangling (simplified)
    private func demangleSwift(_ mangled: String) -> String? {
        // Use swift-demangle if available, otherwise return nil
        // This is a placeholder - real implementation would call swift-demangle
        return nil
    }

    /// Basic C++ demangling (simplified)
    private func demangleCPP(_ mangled: String) -> String? {
        // Use c++filt if available, otherwise return nil
        // This is a placeholder - real implementation would call c++filt
        return nil
    }
}

/// Symbol type
enum SymbolType: String, Codable {
    case function = "Function"
    case data = "Data"
    case object = "Object"
    case section = "Section"
    case file = "File"
    case unknown = "Unknown"

    var icon: String {
        switch self {
        case .function: return "f.square"
        case .data: return "d.square"
        case .object: return "cube"
        case .section: return "square.stack"
        case .file: return "doc"
        case .unknown: return "questionmark.square"
        }
    }
}

/// Symbol binding/visibility
enum SymbolBinding: String, Codable {
    case local = "Local"
    case global = "Global"
    case weak = "Weak"
    case external = "External"
    case undefined = "Undefined"
}
