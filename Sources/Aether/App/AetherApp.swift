import SwiftUI

@main
struct AetherApp: App {
    @StateObject private var appState = AppState()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup {
            MainView()
                .environmentObject(appState)
                .preferredColorScheme(.dark)
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open Binary...") {
                    appState.openFile()
                }
                .keyboardShortcut("o", modifiers: .command)

                Button("Open Project...") {
                    appState.openProject()
                }
                .keyboardShortcut("o", modifiers: [.command, .shift])

                Divider()

                Button("Save Binary As...") {
                    appState.saveFileAs()
                }
                .keyboardShortcut("s", modifiers: .command)
                .disabled(appState.currentFile == nil)

                Button("Save Project As...") {
                    appState.saveProjectAs()
                }
                .keyboardShortcut("s", modifiers: [.command, .shift])
                .disabled(appState.currentFile == nil)

                Divider()

                Button("Close") {
                    appState.closeFile()
                }
                .keyboardShortcut("w", modifiers: .command)
                .disabled(appState.currentFile == nil)
            }

            CommandGroup(replacing: .undoRedo) {
                Button("Undo") {
                    appState.undo()
                }
                .keyboardShortcut("z", modifiers: .command)
                .disabled(!appState.canUndo)

                Button("Redo") {
                    appState.redo()
                }
                .keyboardShortcut("z", modifiers: [.command, .shift])
                .disabled(!appState.canRedo)
            }
            CommandMenu("Analysis") {
                Button("Analyze All") {
                    appState.analyzeAll()
                }
                .keyboardShortcut("a", modifiers: [.command, .shift])
                .disabled(appState.currentFile == nil)

                Button("Find Functions") {
                    appState.findFunctions()
                }
                .keyboardShortcut("f", modifiers: [.command, .shift])
                .disabled(appState.currentFile == nil)

                Divider()

                Button("Show CFG") {
                    appState.showCFG = true
                }
                .keyboardShortcut("g", modifiers: .command)
                .disabled(appState.selectedFunction == nil)

                Button("Decompile") {
                    appState.decompileCurrentFunction()
                }
                .keyboardShortcut("d", modifiers: [.command, .shift])
                .disabled(appState.selectedFunction == nil)

                Button("Generate Pseudo-Code") {
                    appState.generateStructuredCode()
                }
                .keyboardShortcut("p", modifiers: [.command, .shift])
                .disabled(appState.selectedFunction == nil)

                Divider()

                Button("Call Graph") {
                    appState.showCallGraph = true
                }
                .keyboardShortcut("k", modifiers: .command)
                .disabled(appState.currentFile == nil)

                Button("Crypto Detection") {
                    appState.runCryptoDetection()
                }
                .disabled(appState.currentFile == nil)

                Button("Deobfuscation Analysis") {
                    appState.runDeobfuscation()
                }
                .disabled(appState.selectedFunction == nil)

                Button("Type Recovery") {
                    appState.runTypeRecovery()
                }
                .disabled(appState.selectedFunction == nil)

                Button("Idiom Recognition") {
                    appState.runIdiomRecognition()
                }
                .disabled(appState.selectedFunction == nil)

                Divider()

                Button("Show Jump Table") {
                    appState.showJumpTable = true
                }
                .keyboardShortcut("j", modifiers: [.command, .shift])
                .disabled(appState.selectedFunction == nil)
            }

            CommandMenu("Export") {
                Button("Export to IDA Python...") {
                    appState.showExportSheet = true
                }
                .disabled(appState.currentFile == nil)

                Button("Export to Ghidra XML...") {
                    exportWithFormat(.ghidraXML)
                }
                .disabled(appState.currentFile == nil)

                Button("Export to Radare2...") {
                    exportWithFormat(.radare2)
                }
                .disabled(appState.currentFile == nil)

                Button("Export to Binary Ninja...") {
                    exportWithFormat(.binaryNinja)
                }
                .disabled(appState.currentFile == nil)

                Divider()

                Button("Export to JSON...") {
                    exportWithFormat(.json)
                }
                .disabled(appState.currentFile == nil)

                Button("Export to CSV...") {
                    exportWithFormat(.csv)
                }
                .disabled(appState.currentFile == nil)

                Button("Export to HTML Report...") {
                    exportWithFormat(.html)
                }
                .disabled(appState.currentFile == nil)

                Button("Export to Markdown...") {
                    exportWithFormat(.markdown)
                }
                .disabled(appState.currentFile == nil)

                Button("Export C Header...") {
                    exportWithFormat(.cHeader)
                }
                .disabled(appState.currentFile == nil)
            }
            CommandMenu("Navigate") {
                Button("Go to Address...") {
                    appState.showGoToAddress = true
                }
                .keyboardShortcut("g", modifiers: [.command, .shift])

                Button("Search...") {
                    appState.showSearch = true
                }
                .keyboardShortcut("f", modifiers: .command)
            }
        }

        Settings {
            SettingsView()
                .environmentObject(appState)
        }
    }

    private func exportWithFormat(_ format: ExportManager.ExportFormat) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.data]
        panel.nameFieldStringValue = "\(appState.currentFile?.name ?? "export").\(format.fileExtension)"

        if panel.runModal() == .OK, let url = panel.url {
            appState.exportTo(format: format, url: url)
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem {
                    Label("General", systemImage: "gear")
                }

            AppearanceSettingsView()
                .tabItem {
                    Label("Appearance", systemImage: "paintbrush")
                }

            AnalysisSettingsView()
                .tabItem {
                    Label("Analysis", systemImage: "cpu")
                }

            AISettingsTab()
                .tabItem {
                    Label("AI", systemImage: "brain")
                }
        }
        .frame(width: 500, height: 350)
    }
}

struct GeneralSettingsView: View {
    @AppStorage("autoAnalyze") private var autoAnalyze = true
    @AppStorage("showHexView") private var showHexView = true

    var body: some View {
        Form {
            Toggle("Auto-analyze on file open", isOn: $autoAnalyze)
            Toggle("Show Hex View by default", isOn: $showHexView)
        }
        .padding()
    }
}

struct AppearanceSettingsView: View {
    @AppStorage("fontSize") private var fontSize = 13.0
    @AppStorage("fontName") private var fontName = "SF Mono"

    var body: some View {
        Form {
            Picker("Font", selection: $fontName) {
                Text("SF Mono").tag("SF Mono")
                Text("Menlo").tag("Menlo")
                Text("Monaco").tag("Monaco")
                Text("Courier New").tag("Courier New")
            }

            Slider(value: $fontSize, in: 10...20, step: 1) {
                Text("Font Size: \(Int(fontSize))")
            }
        }
        .padding()
    }
}

struct AnalysisSettingsView: View {
    @AppStorage("deepAnalysis") private var deepAnalysis = false
    @AppStorage("analyzeStrings") private var analyzeStrings = true
    @AppStorage("analyzeXRefs") private var analyzeXRefs = true

    var body: some View {
        Form {
            Toggle("Deep analysis (slower)", isOn: $deepAnalysis)
            Toggle("Analyze strings", isOn: $analyzeStrings)
            Toggle("Analyze cross-references", isOn: $analyzeXRefs)
        }
        .padding()
    }
}

// MARK: - App Delegate for Icon

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { @MainActor in
            setAppIcon()
        }
    }

    @MainActor
    private func setAppIcon() {
        let icon = generateAppIcon(size: 512)

        // Set application icon
        NSApp.applicationIconImage = icon

        // Also set dock tile
        if let dockTile = NSApp.dockTile.contentView {
            let imageView = NSImageView(frame: dockTile.bounds)
            imageView.image = icon
            NSApp.dockTile.contentView = imageView
            NSApp.dockTile.display()
        } else {
            let imageView = NSImageView(frame: NSRect(x: 0, y: 0, width: 128, height: 128))
            imageView.image = icon
            NSApp.dockTile.contentView = imageView
            NSApp.dockTile.display()
        }
    }

    private func generateAppIcon(size: Int) -> NSImage {
        let image = NSImage(size: NSSize(width: size, height: size))

        image.lockFocus()

        // Background - dark gradient
        let gradient = NSGradient(colors: [
            NSColor(red: 0.12, green: 0.12, blue: 0.18, alpha: 1.0),
            NSColor(red: 0.18, green: 0.18, blue: 0.25, alpha: 1.0)
        ])!

        let rect = NSRect(x: 0, y: 0, width: size, height: size)
        let cornerRadius = CGFloat(size) * 0.2
        let path = NSBezierPath(roundedRect: rect, xRadius: cornerRadius, yRadius: cornerRadius)
        gradient.draw(in: path, angle: -45)

        // CPU chip body
        let chipSize = CGFloat(size) * 0.5
        let chipX = (CGFloat(size) - chipSize) / 2
        let chipY = (CGFloat(size) - chipSize) / 2
        let chipRect = NSRect(x: chipX, y: chipY, width: chipSize, height: chipSize)

        NSColor(red: 0.2, green: 0.2, blue: 0.3, alpha: 1.0).setFill()
        let chipPath = NSBezierPath(roundedRect: chipRect, xRadius: 4, yRadius: 4)
        chipPath.fill()

        // Chip border - accent blue
        NSColor(red: 0.54, green: 0.71, blue: 0.98, alpha: 1.0).setStroke()
        chipPath.lineWidth = CGFloat(size) * 0.015
        chipPath.stroke()

        // Binary text inside chip
        let fontSize = CGFloat(size) * 0.07
        let font = NSFont.monospacedSystemFont(ofSize: fontSize, weight: .bold)
        let textColor = NSColor(red: 0.54, green: 0.71, blue: 0.98, alpha: 1.0)

        let paragraphStyle = NSMutableParagraphStyle()
        paragraphStyle.alignment = .center

        let attrs: [NSAttributedString.Key: Any] = [
            .font: font,
            .foregroundColor: textColor,
            .paragraphStyle: paragraphStyle
        ]

        let lines = ["01010", "10101", "01010"]
        let lineHeight = fontSize * 1.4
        let startY = chipY + chipSize/2 + lineHeight * 0.5

        for (i, line) in lines.enumerated() {
            let y = startY - CGFloat(i) * lineHeight
            let textRect = NSRect(x: chipX, y: y - fontSize, width: chipSize, height: fontSize * 1.2)
            line.draw(in: textRect, withAttributes: attrs)
        }

        // Pins on all sides
        let pinColor = NSColor(red: 0.6, green: 0.65, blue: 0.75, alpha: 1.0)
        pinColor.setFill()

        let pinWidth = CGFloat(size) * 0.025
        let pinLength = CGFloat(size) * 0.08
        let pinCount = 4
        let pinSpacing = chipSize / CGFloat(pinCount + 1)

        for i in 1...pinCount {
            let offset = pinSpacing * CGFloat(i)

            // Top pins
            NSBezierPath(rect: NSRect(x: chipX + offset - pinWidth/2, y: chipY + chipSize, width: pinWidth, height: pinLength)).fill()
            // Bottom pins
            NSBezierPath(rect: NSRect(x: chipX + offset - pinWidth/2, y: chipY - pinLength, width: pinWidth, height: pinLength)).fill()
            // Left pins
            NSBezierPath(rect: NSRect(x: chipX - pinLength, y: chipY + offset - pinWidth/2, width: pinLength, height: pinWidth)).fill()
            // Right pins
            NSBezierPath(rect: NSRect(x: chipX + chipSize, y: chipY + offset - pinWidth/2, width: pinLength, height: pinWidth)).fill()
        }

        image.unlockFocus()
        return image
    }
}
