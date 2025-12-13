import SwiftUI

// MARK: - Color Extensions for Theme

extension Color {
    // Background colors
    static let background = Color(hex: "#1E1E2E")
    static let sidebar = Color(hex: "#181825")

    // Text colors
    static let addressColor = Color(hex: "#A6E3A1")
    static let commentColor = Color(hex: "#6C7086")

    // Instruction colors
    static let callColor = Color(hex: "#F38BA8")
    static let jumpColor = Color(hex: "#FAB387")
    static let returnColor = Color(hex: "#F38BA8")
    static let moveColor = Color(hex: "#89B4FA")
    static let mathColor = Color(hex: "#F9E2AF")
    static let compareColor = Color(hex: "#CBA6F7")
    static let stackColor = Color(hex: "#94E2D5")
    static let memoryColor = Color(hex: "#74C7EC")

    // Operand colors
    static let registerColor = Color(hex: "#FAB387")
    static let immediateColor = Color(hex: "#94E2D5")

    // Pseudo-code colors
    static let keywordColor = Color(hex: "#CBA6F7")
    static let typeColor = Color(hex: "#89B4FA")
    static let stringColor = Color(hex: "#A6E3A1")
    static let operatorColor = Color(hex: "#89DCEB")

    // Accent
    static let accent = Color(hex: "#89B4FA")

    // Initialize from hex string
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (255, 0, 0, 0)
        }

        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}

// MARK: - Font Configuration

struct DisassemblerFont {
    static let code = Font.system(.body, design: .monospaced)
    static let codeSmall = Font.system(.caption, design: .monospaced)
    static let codeTiny = Font.system(.caption2, design: .monospaced)

    static func code(size: CGFloat) -> Font {
        .system(size: size, design: .monospaced)
    }

    static func codeWithName(_ name: String, size: CGFloat) -> Font {
        if let _ = NSFont(name: name, size: size) {
            return .custom(name, size: size)
        }
        return .system(size: size, design: .monospaced)
    }
}

// MARK: - Theme Configuration

struct Theme {
    let name: String
    let background: Color
    let sidebar: Color
    let text: Color
    let accent: Color
    let address: Color
    let instruction: Color
    let register: Color
    let immediate: Color
    let comment: Color

    static let catppuccinMocha = Theme(
        name: "Catppuccin Mocha",
        background: Color(hex: "#1E1E2E"),
        sidebar: Color(hex: "#181825"),
        text: Color(hex: "#CDD6F4"),
        accent: Color(hex: "#89B4FA"),
        address: Color(hex: "#A6E3A1"),
        instruction: Color(hex: "#F38BA8"),
        register: Color(hex: "#FAB387"),
        immediate: Color(hex: "#94E2D5"),
        comment: Color(hex: "#6C7086")
    )

    static let dark = Theme(
        name: "Dark",
        background: Color(hex: "#1E1E1E"),
        sidebar: Color(hex: "#252526"),
        text: Color(hex: "#D4D4D4"),
        accent: Color(hex: "#569CD6"),
        address: Color(hex: "#6A9955"),
        instruction: Color(hex: "#C586C0"),
        register: Color(hex: "#9CDCFE"),
        immediate: Color(hex: "#B5CEA8"),
        comment: Color(hex: "#6A9955")
    )

    static let light = Theme(
        name: "Light",
        background: Color(hex: "#FFFFFF"),
        sidebar: Color(hex: "#F3F3F3"),
        text: Color(hex: "#000000"),
        accent: Color(hex: "#0066CC"),
        address: Color(hex: "#008000"),
        instruction: Color(hex: "#AF00DB"),
        register: Color(hex: "#001080"),
        immediate: Color(hex: "#098658"),
        comment: Color(hex: "#008000")
    )
}

// MARK: - Theme Manager

class ThemeManager: ObservableObject {
    static let shared = ThemeManager()

    @Published var currentTheme: Theme = .catppuccinMocha

    private init() {}

    func setTheme(_ theme: Theme) {
        currentTheme = theme
    }
}
