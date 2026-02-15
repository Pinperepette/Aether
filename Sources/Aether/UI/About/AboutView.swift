import SwiftUI
import CryptoKit
import AppKit

struct AboutView: View {
    @State private var executableSHA256 = translate("about.hash.calculating")
    @State private var isHashing = false
    @State private var showLicenseSheet = false
    @State private var licenseText = translate("about.license.unavailable")
    @State private var didLoad = false

    private let buildInfo = BuildInfo.current
    private let primaryText = Color(red: 0.95, green: 0.97, blue: 1.00)
    private let secondaryText = Color(red: 0.76, green: 0.82, blue: 0.92)
    private let accentText = Color(red: 0.66, green: 0.78, blue: 0.98)

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.08, green: 0.10, blue: 0.16),
                    Color(red: 0.04, green: 0.05, blue: 0.09)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {
                    header
                    buildDetailsCard
                    integrityCard
                    licenseCard
                    verificationNote
                }
                .padding(20)
                .foregroundStyle(primaryText)
            }
        }
        .frame(width: 620, height: 620)
        .preferredColorScheme(.dark)
        .onAppear {
            guard !didLoad else { return }
            didLoad = true
            loadLicenseText()
            refreshExecutableHash()
        }
        .sheet(isPresented: $showLicenseSheet) {
            LicenseTextView(licenseName: buildInfo.license, licenseText: licenseText)
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Group {
                if let appIcon = NSApp.applicationIconImage {
                    Image(nsImage: appIcon)
                        .resizable()
                } else {
                    Image(systemName: "cpu.fill")
                        .resizable()
                        .scaledToFit()
                        .foregroundStyle(.blue)
                        .padding(20)
                }
            }
            .frame(width: 80, height: 80)
            .background(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(Color.white.opacity(0.07))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(Color.white.opacity(0.12), lineWidth: 1)
            )

            VStack(alignment: .leading, spacing: 5) {
                Text("Aether")
                    .font(.system(size: 34, weight: .bold, design: .rounded))
                Text(translate("about.tagline"))
                    .font(.subheadline)
                    .foregroundStyle(secondaryText)
                Text(String(format: translate("about.version.format"), buildInfo.version, buildInfo.build))
                    .font(.system(.headline, design: .monospaced))
                    .foregroundStyle(accentText)
            }

            Spacer(minLength: 0)
        }
        .padding(16)
        .background(cardBackground)
    }

    private var buildDetailsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(translate("about.section.buildDetails"), systemImage: "wrench.and.screwdriver")
                .font(.headline)

            AboutRow(label: translate("about.field.built"), value: buildInfo.timestampDisplay)
            AboutRow(label: translate("about.field.source"), value: buildInfo.commit)
            AboutRow(label: translate("about.field.targetArch"), value: buildInfo.targetArchitecture)
            AboutRow(label: translate("about.field.runningArch"), value: buildInfo.runningArchitecture)
        }
        .padding(16)
        .background(cardBackground)
    }

    private var integrityCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(translate("about.section.integrity"), systemImage: "checkmark.shield")
                .font(.headline)

            Text(executableSHA256)
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color.black.opacity(0.28))
                )

            HStack(spacing: 10) {
                Button(translate("about.action.copySha")) {
                    copyToClipboard(executableSHA256)
                }
                .disabled(isHashing)
                .buttonStyle(.bordered)

                Button(translate("about.action.copyReport")) {
                    copyToClipboard(buildReport)
                }
                .disabled(isHashing)
                .buttonStyle(.bordered)
            }

            if isHashing {
                ProgressView()
                    .progressViewStyle(.circular)
            }
        }
        .padding(16)
        .background(cardBackground)
    }

    private var licenseCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(translate("about.section.license"), systemImage: "doc.text")
                    .font(.headline)
                Spacer(minLength: 0)
                Button(translate("about.action.viewLicense")) {
                    showLicenseSheet = true
                }
                .buttonStyle(.bordered)
            }

            Text(buildInfo.license)
                .font(.callout)
                .foregroundStyle(secondaryText)
        }
        .padding(16)
        .background(cardBackground)
    }

    private var verificationNote: some View {
        Text(translate("about.verification.note"))
            .font(.footnote)
            .foregroundStyle(secondaryText)
            .padding(.horizontal, 4)
    }

    private var buildReport: String {
        """
        \(translate("about.report.title"))
        \(translate("about.report.version")): \(buildInfo.version)
        \(translate("about.report.build")): \(buildInfo.build)
        \(translate("about.report.built")): \(buildInfo.timestampRaw)
        \(translate("about.report.source")): \(buildInfo.commit)
        \(translate("about.report.targetArch")): \(buildInfo.targetArchitecture)
        \(translate("about.report.runningArch")): \(buildInfo.runningArchitecture)
        \(translate("about.report.license")): \(buildInfo.license)
        \(translate("about.report.sha256")): \(executableSHA256)
        """
    }

    private var cardBackground: some View {
        RoundedRectangle(cornerRadius: 14, style: .continuous)
            .fill(Color.white.opacity(0.09))
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(Color.white.opacity(0.14), lineWidth: 1)
            )
    }

    private func refreshExecutableHash() {
        guard !isHashing else { return }
        isHashing = true

        DispatchQueue.global(qos: .utility).async {
            let hash = Self.computeExecutableSHA256() ?? translate("about.hash.unavailable")
            DispatchQueue.main.async {
                executableSHA256 = hash
                isHashing = false
            }
        }
    }

    private func loadLicenseText() {
        guard let licenseURL = Bundle.main.url(forResource: "LICENSE", withExtension: "txt"),
              let text = try? String(contentsOf: licenseURL, encoding: .utf8) else {
            return
        }
        licenseText = text
    }

    private static func computeExecutableSHA256() -> String? {
        guard let executableURL = Bundle.main.executableURL,
              let data = try? Data(contentsOf: executableURL, options: .mappedIfSafe) else {
            return nil
        }

        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func copyToClipboard(_ text: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
    }
}

private struct AboutRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Color(red: 0.76, green: 0.82, blue: 0.92))
                .frame(width: 150, alignment: .leading)

            Text(value)
                .font(.system(.subheadline, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct LicenseTextView: View {
    let licenseName: String
    let licenseText: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 12) {
            HStack {
                Text(licenseName)
                    .font(.title3.bold())
                Spacer()
                Button("Close") {
                    dismiss()
                }
            }

            ScrollView {
                Text(licenseText)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.black.opacity(0.20))
            )
        }
        .padding(16)
        .frame(minWidth: 680, minHeight: 520)
        .background(Color(red: 0.09, green: 0.10, blue: 0.14))
        .preferredColorScheme(.dark)
    }
}

private struct BuildInfo {
    let version: String
    let build: String
    let commit: String
    let timestampRaw: String
    let targetArchitecture: String
    let runningArchitecture: String
    let license: String

    var timestampDisplay: String {
        let formatter = ISO8601DateFormatter()
        guard let date = formatter.date(from: timestampRaw) else {
            return timestampRaw
        }

        let localFormatter = DateFormatter()
        localFormatter.dateStyle = .medium
        localFormatter.timeStyle = .medium
        localFormatter.timeZone = .current
        return "\(localFormatter.string(from: date)) (\(timestampRaw))"
    }

    static var current: BuildInfo {
        let info = Bundle.main.infoDictionary ?? [:]
        return BuildInfo(
            version: info["CFBundleShortVersionString"] as? String ?? "unknown",
            build: info["CFBundleVersion"] as? String ?? "unknown",
            commit: info["AetherBuildCommit"] as? String ?? "unknown",
            timestampRaw: info["AetherBuildTimestamp"] as? String ?? "unknown",
            targetArchitecture: info["AetherBuildTargetArch"] as? String ?? "unknown",
            runningArchitecture: runtimeArchitecture,
            license: info["AetherLicense"] as? String ?? "MIT License"
        )
    }

    private static var runtimeArchitecture: String {
#if arch(arm64)
        "arm64"
#elseif arch(x86_64)
        "x86_64"
#else
        "unknown"
#endif
    }
}
