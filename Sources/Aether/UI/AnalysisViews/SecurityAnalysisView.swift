import SwiftUI

struct SecurityAnalysisView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var appState: AppState

    let result: SecurityAnalysisResult?
    let isLoading: Bool
    let error: String?

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "shield.checkerboard")
                    .foregroundColor(.purple)
                Text("AI Security Analysis")
                    .font(.headline)

                Spacer()

                if let result = result {
                    SeverityBadge(severity: result.severity)
                }

                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            // Content
            if isLoading {
                LoadingView()
            } else if let error = error {
                ErrorView(message: error)
            } else if let result = result {
                ResultsView(result: result)
            } else {
                EmptyView()
            }
        }
        .frame(width: 700, height: 600)
    }
}

// MARK: - Loading View

private struct LoadingView: View {
    @State private var dots = ""
    let timer = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 20) {
            ProgressView()
                .scaleEffect(1.5)

            Text("Analyzing with Claude AI\(dots)")
                .font(.headline)

            Text("This may take a few seconds...")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onReceive(timer) { _ in
            dots = dots.count >= 3 ? "" : dots + "."
        }
    }
}

// MARK: - Error View

private struct ErrorView: View {
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundColor(.orange)

            Text("Analysis Failed")
                .font(.headline)

            Text(message)
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Results View

private struct ResultsView: View {
    let result: SecurityAnalysisResult
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            // Summary
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Summary")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(result.summary)
                        .font(.body)
                }
                Spacer()
            }
            .padding()
            .background(Color.background.opacity(0.5))

            Divider()

            // Tabs
            Picker("", selection: $selectedTab) {
                Text("Findings (\(result.findings.count))").tag(0)
                Text("Indicators").tag(1)
                Text("Raw Response").tag(2)
            }
            .pickerStyle(.segmented)
            .padding()

            // Tab Content
            TabView(selection: $selectedTab) {
                FindingsTab(findings: result.findings)
                    .tag(0)

                IndicatorsTab(result: result)
                    .tag(1)

                RawResponseTab(response: result.rawResponse)
                    .tag(2)
            }
            .tabViewStyle(.automatic)
        }
    }
}

// MARK: - Findings Tab

private struct FindingsTab: View {
    let findings: [SecurityFinding]

    var body: some View {
        if findings.isEmpty {
            VStack(spacing: 12) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 48))
                    .foregroundColor(.green)
                Text("No security issues found")
                    .font(.headline)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                LazyVStack(spacing: 12) {
                    ForEach(findings) { finding in
                        FindingCard(finding: finding)
                    }
                }
                .padding()
            }
        }
    }
}

private struct FindingCard: View {
    let finding: SecurityFinding
    @State private var isExpanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            Button {
                withAnimation {
                    isExpanded.toggle()
                }
            } label: {
                HStack {
                    Image(systemName: finding.severity.icon)
                        .foregroundColor(severityColor(finding.severity))

                    Text(finding.title)
                        .font(.headline)
                        .foregroundColor(.primary)

                    Spacer()

                    SeverityBadge(severity: finding.severity)

                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .foregroundColor(.secondary)
                }
                .padding()
                .background(Color.sidebar)
            }
            .buttonStyle(.plain)

            if isExpanded {
                VStack(alignment: .leading, spacing: 12) {
                    Text(finding.description)
                        .font(.body)
                        .foregroundColor(.primary)

                    if let recommendation = finding.recommendation, !recommendation.isEmpty {
                        Divider()
                        HStack(alignment: .top) {
                            Image(systemName: "lightbulb.fill")
                                .foregroundColor(.yellow)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Recommendation")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Text(recommendation)
                                    .font(.body)
                            }
                        }
                    }
                }
                .padding()
                .background(Color.background.opacity(0.3))
            }
        }
        .background(Color.sidebar.opacity(0.5))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(severityColor(finding.severity).opacity(0.3), lineWidth: 1)
        )
    }

    private func severityColor(_ severity: Severity) -> Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .gray
        }
    }
}

// MARK: - Indicators Tab

private struct IndicatorsTab: View {
    let result: SecurityAnalysisResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Bypass Techniques - Most important for cracking
                if !result.bypassTechniques.isEmpty {
                    IndicatorSection(
                        title: "Bypass Techniques",
                        icon: "lock.open.fill",
                        color: .red,
                        items: result.bypassTechniques
                    )
                }

                // Patch Points
                if !result.patchPoints.isEmpty {
                    IndicatorSection(
                        title: "Patch Points",
                        icon: "pencil.circle.fill",
                        color: .orange,
                        items: result.patchPoints
                    )
                }

                // Security Mechanisms
                if !result.securityMechanisms.isEmpty {
                    IndicatorSection(
                        title: "Security Mechanisms",
                        icon: "shield.fill",
                        color: .blue,
                        items: result.securityMechanisms
                    )
                }

                if !result.hardcodedSecrets.isEmpty {
                    IndicatorSection(
                        title: "Hardcoded Secrets",
                        icon: "key.fill",
                        color: .purple,
                        items: result.hardcodedSecrets
                    )
                }

                if !result.malwareIndicators.isEmpty {
                    IndicatorSection(
                        title: "Malware Indicators",
                        icon: "exclamationmark.shield.fill",
                        color: .red,
                        items: result.malwareIndicators
                    )
                }

                if !result.suspiciousBehaviors.isEmpty {
                    IndicatorSection(
                        title: "Suspicious Behaviors",
                        icon: "eye.trianglebadge.exclamationmark",
                        color: .yellow,
                        items: result.suspiciousBehaviors
                    )
                }

                let hasAnyIndicators = !result.bypassTechniques.isEmpty ||
                    !result.patchPoints.isEmpty ||
                    !result.securityMechanisms.isEmpty ||
                    !result.malwareIndicators.isEmpty ||
                    !result.suspiciousBehaviors.isEmpty ||
                    !result.hardcodedSecrets.isEmpty

                if !hasAnyIndicators {
                    VStack(spacing: 12) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 48))
                            .foregroundColor(.green)
                        Text("No indicators detected")
                            .font(.headline)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .padding()
        }
    }
}

private struct IndicatorSection: View {
    let title: String
    let icon: String
    let color: Color
    let items: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon)
                .font(.headline)
                .foregroundColor(color)

            VStack(alignment: .leading, spacing: 4) {
                ForEach(items, id: \.self) { item in
                    HStack(alignment: .top) {
                        Image(systemName: "chevron.right")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(item)
                            .font(.body)
                    }
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(color.opacity(0.1))
            .cornerRadius(8)
        }
    }
}

// MARK: - Raw Response Tab

private struct RawResponseTab: View {
    let response: String
    @State private var copied = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(response, forType: .string)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        copied = false
                    }
                } label: {
                    Label(copied ? "Copied!" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.bordered)
            }
            .padding(.horizontal)
            .padding(.top, 8)

            ScrollView {
                Text(response)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

// MARK: - Severity Badge

struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        Text(severity.rawValue)
            .font(.caption2)
            .fontWeight(.bold)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(severityColor.opacity(0.2))
            .foregroundColor(severityColor)
            .cornerRadius(4)
    }

    private var severityColor: Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .gray
        }
    }
}
