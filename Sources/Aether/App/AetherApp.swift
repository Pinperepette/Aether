import SwiftUI

@main
struct AetherApp: App {
    @StateObject private var appState = AppState()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @AppStorage("appLanguage") private var appLanguage = AppLanguage.systemCode

    var body: some Scene {
        WindowGroup {
            MainView()
                .id(appLanguage)
                .environmentObject(appState)
                .environment(\.locale, AppLanguage.fromStored(appLanguage).locale)
                .preferredColorScheme(.dark)
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button(translate("menu.file.openBinary")) {
                    appState.openFile()
                }
                .keyboardShortcut("o", modifiers: .command)

                Button(translate("menu.file.openProject")) {
                    appState.openProject()
                }
                .keyboardShortcut("o", modifiers: [.command, .shift])

                Divider()

                Button(translate("menu.file.saveBinaryAs")) {
                    appState.saveFileAs()
                }
                .keyboardShortcut("s", modifiers: .command)
                .disabled(appState.currentFile == nil)

                Button(translate("menu.file.saveProjectAs")) {
                    appState.saveProjectAs()
                }
                .keyboardShortcut("s", modifiers: [.command, .shift])
                .disabled(appState.currentFile == nil)

                Divider()

                Button(translate("menu.file.close")) {
                    appState.closeFile()
                }
                .keyboardShortcut("w", modifiers: .command)
                .disabled(appState.currentFile == nil)
            }

            CommandGroup(replacing: .undoRedo) {
                Button(translate("menu.edit.undo")) {
                    appState.undo()
                }
                .keyboardShortcut("z", modifiers: .command)
                .disabled(!appState.canUndo)

                Button(translate("menu.edit.redo")) {
                    appState.redo()
                }
                .keyboardShortcut("z", modifiers: [.command, .shift])
                .disabled(!appState.canRedo)
            }
            CommandMenu(translate("menu.analysis.title")) {
                Button(translate("menu.analysis.analyzeAll")) {
                    appState.analyzeAll()
                }
                .keyboardShortcut("a", modifiers: [.command, .shift])
                .disabled(appState.currentFile == nil)

                Button(translate("menu.analysis.findFunctions")) {
                    appState.findFunctions()
                }
                .keyboardShortcut("f", modifiers: [.command, .shift])
                .disabled(appState.currentFile == nil)

                Divider()

                Button(translate("menu.analysis.showCFG")) {
                    appState.showCFG = true
                }
                .keyboardShortcut("g", modifiers: .command)
                .disabled(appState.selectedFunction == nil)

                Button(translate("menu.analysis.decompile")) {
                    appState.decompileCurrentFunction()
                }
                .keyboardShortcut("d", modifiers: [.command, .shift])
                .disabled(appState.selectedFunction == nil)

                Button(translate("menu.analysis.generatePseudoCode")) {
                    appState.generateStructuredCode()
                }
                .keyboardShortcut("p", modifiers: [.command, .shift])
                .disabled(appState.selectedFunction == nil)

                Divider()

                Button(translate("menu.analysis.callGraph")) {
                    appState.showCallGraph = true
                }
                .keyboardShortcut("k", modifiers: .command)
                .disabled(appState.currentFile == nil)

                Button(translate("menu.analysis.cryptoDetection")) {
                    appState.runCryptoDetection()
                }
                .disabled(appState.currentFile == nil)

                Button(translate("menu.analysis.deobfuscation")) {
                    appState.runDeobfuscation()
                }
                .disabled(appState.selectedFunction == nil)

                Button(translate("menu.analysis.typeRecovery")) {
                    appState.runTypeRecovery()
                }
                .disabled(appState.selectedFunction == nil)

                Button(translate("menu.analysis.idiomRecognition")) {
                    appState.runIdiomRecognition()
                }
                .disabled(appState.selectedFunction == nil)

                Divider()

                Button(translate("menu.analysis.showJumpTable")) {
                    appState.showJumpTable = true
                }
                .keyboardShortcut("j", modifiers: [.command, .shift])
                .disabled(appState.selectedFunction == nil)
            }

            CommandMenu(translate("menu.export.title")) {
                Button(translate("menu.export.ida")) {
                    appState.showExportSheet = true
                }
                .disabled(appState.currentFile == nil)

                Button(translate("menu.export.ghidra")) {
                    exportWithFormat(.ghidraXML)
                }
                .disabled(appState.currentFile == nil)

                Button(translate("menu.export.radare2")) {
                    exportWithFormat(.radare2)
                }
                .disabled(appState.currentFile == nil)

                Button(translate("menu.export.binaryNinja")) {
                    exportWithFormat(.binaryNinja)
                }
                .disabled(appState.currentFile == nil)

                Divider()

                Button(translate("menu.export.json")) {
                    exportWithFormat(.json)
                }
                .disabled(appState.currentFile == nil)

                Button(translate("menu.export.csv")) {
                    exportWithFormat(.csv)
                }
                .disabled(appState.currentFile == nil)

                Button(translate("menu.export.html")) {
                    exportWithFormat(.html)
                }
                .disabled(appState.currentFile == nil)

                Button(translate("menu.export.markdown")) {
                    exportWithFormat(.markdown)
                }
                .disabled(appState.currentFile == nil)

                Button(translate("menu.export.cheader")) {
                    exportWithFormat(.cHeader)
                }
                .disabled(appState.currentFile == nil)
            }
            CommandMenu(translate("menu.navigate.title")) {
                Button(translate("menu.navigate.gotoAddress")) {
                    appState.showGoToAddress = true
                }
                .keyboardShortcut("g", modifiers: [.command, .shift])

                Button(translate("menu.navigate.search")) {
                    appState.showSearch = true
                }
                .keyboardShortcut("f", modifiers: .command)
            }
        }

        Settings {
            SettingsView()
                .id(appLanguage)
                .environmentObject(appState)
                .environment(\.locale, AppLanguage.fromStored(appLanguage).locale)
        }
    }

    private func exportWithFormat(_ format: ExportManager.ExportFormat) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.data]
        panel.nameFieldStringValue = "\(appState.currentFile?.name ?? translate("export.defaultFileName")).\(format.fileExtension)"

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
                    Label(translate("settings.tab.general"), systemImage: "gear")
                }

            AppearanceSettingsView()
                .tabItem {
                    Label(translate("settings.tab.appearance"), systemImage: "paintbrush")
                }

            AnalysisSettingsView()
                .tabItem {
                    Label(translate("settings.tab.analysis"), systemImage: "cpu")
                }

            AISettingsTab()
                .tabItem {
                    Label(translate("settings.tab.ai"), systemImage: "brain")
                }
        }
        .frame(width: 500, height: 350)
    }
}

struct GeneralSettingsView: View {
    @AppStorage("autoAnalyze") private var autoAnalyze = true
    @AppStorage("showHexView") private var showHexView = true
    @AppStorage("appLanguage") private var appLanguage = AppLanguage.systemCode

    var body: some View {
        Form {
            Picker(translate("settings.general.language"), selection: $appLanguage) {
                ForEach(AppLanguage.available) { language in
                    Text(language.pickerLabel).tag(language.code)
                }
            }
            Toggle(translate("settings.general.autoAnalyze"), isOn: $autoAnalyze)
            Toggle(translate("settings.general.showHexView"), isOn: $showHexView)
        }
        .padding()
        .onAppear {
            if !AppLanguage.isValidStorageValue(appLanguage) {
                appLanguage = AppLanguage.systemCode
            }
        }
    }
}

struct AppearanceSettingsView: View {
    @AppStorage("fontSize") private var fontSize = 13.0
    @AppStorage("fontName") private var fontName = "SF Mono"

    var body: some View {
        Form {
            Picker(translate("settings.appearance.font"), selection: $fontName) {
                Text("SF Mono").tag("SF Mono")
                Text("Menlo").tag("Menlo")
                Text("Monaco").tag("Monaco")
                Text("Courier New").tag("Courier New")
            }

            Slider(value: $fontSize, in: 10...20, step: 1) {
                Text(translate("settings.appearance.fontSize"))
            }

            HStack {
                Text(translate("settings.appearance.fontSize"))
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text("\(Int(fontSize))")
                    .font(.caption)
                    .foregroundColor(.secondary)
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
            Toggle(translate("settings.analysis.deepAnalysis"), isOn: $deepAnalysis)
            Toggle(translate("settings.analysis.analyzeStrings"), isOn: $analyzeStrings)
            Toggle(translate("settings.analysis.analyzeXrefs"), isOn: $analyzeXRefs)
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
