import SwiftUI

struct AIChatView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    @State private var inputText = ""
    @FocusState private var isInputFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "brain")
                    .font(.title2)
                    .foregroundColor(.purple)

                Text("AI Chat")
                    .font(.headline)

                Spacer()

                if !appState.chatMessages.isEmpty {
                    Button {
                        appState.clearChat()
                    } label: {
                        Label("Clear", systemImage: "trash")
                            .font(.caption)
                    }
                    .buttonStyle(.plain)
                    .foregroundColor(.secondary)
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

            // Context info
            if let binary = appState.currentFile {
                HStack(spacing: 12) {
                    Label(binary.name, systemImage: "doc.fill")
                    Label("\(appState.functions.count) functions", systemImage: "function")
                    if let function = appState.selectedFunction {
                        Label(function.shortDisplayName, systemImage: "target")
                    }
                }
                .font(.caption)
                .foregroundColor(.secondary)
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color.background.opacity(0.5))
            }

            // Messages
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        if appState.chatMessages.isEmpty {
                            emptyStateView
                        } else {
                            ForEach(appState.chatMessages) { message in
                                MessageBubble(message: message)
                                    .id(message.id)
                            }

                            if appState.isChatLoading {
                                loadingBubble
                            }
                        }
                    }
                    .padding()
                }
                .onChange(of: appState.chatMessages.count) { _, _ in
                    if let lastMessage = appState.chatMessages.last {
                        withAnimation {
                            proxy.scrollTo(lastMessage.id, anchor: .bottom)
                        }
                    }
                }
            }

            // Error message
            if let error = appState.chatError {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color.orange.opacity(0.1))
            }

            Divider()

            // Input
            HStack(spacing: 12) {
                TextField("Ask about the binary...", text: $inputText, axis: .vertical)
                    .textFieldStyle(.plain)
                    .lineLimit(1...5)
                    .focused($isInputFocused)
                    .onSubmit {
                        sendMessage()
                    }
                    .submitLabel(.send)

                Button {
                    sendMessage()
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title2)
                        .foregroundColor(canSend ? .purple : .secondary)
                }
                .buttonStyle(.plain)
                .disabled(!canSend)
            }
            .padding()
            .background(Color.sidebar)
        }
        .frame(minWidth: 500, minHeight: 400)
        .frame(idealWidth: 600, idealHeight: 500)
        .onAppear {
            isInputFocused = true
        }
    }

    private var canSend: Bool {
        !inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !appState.isChatLoading
    }

    private func sendMessage() {
        let message = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !message.isEmpty else { return }

        inputText = ""
        appState.sendChatMessage(message)
    }

    private var emptyStateView: some View {
        VStack(spacing: 16) {
            Image(systemName: "bubble.left.and.bubble.right")
                .font(.system(size: 48))
                .foregroundColor(.secondary.opacity(0.5))

            Text("Ask me anything about this binary")
                .font(.headline)
                .foregroundColor(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                suggestionButton("What does this function do?")
                suggestionButton("Find security vulnerabilities")
                suggestionButton("How can I bypass the license check?")
                suggestionButton("Explain the encryption used")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    private func suggestionButton(_ text: String) -> some View {
        Button {
            inputText = text
            sendMessage()
        } label: {
            HStack {
                Image(systemName: "lightbulb")
                    .foregroundColor(.yellow)
                Text(text)
            }
            .font(.caption)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(Color.secondary.opacity(0.1))
            .cornerRadius(16)
        }
        .buttonStyle(.plain)
    }

    private var loadingBubble: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "brain")
                .foregroundColor(.purple)
                .frame(width: 24)

            HStack(spacing: 4) {
                ForEach(0..<3) { i in
                    Circle()
                        .fill(Color.secondary)
                        .frame(width: 6, height: 6)
                        .opacity(0.5)
                        .animation(
                            .easeInOut(duration: 0.6)
                            .repeatForever()
                            .delay(Double(i) * 0.2),
                            value: appState.isChatLoading
                        )
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(Color.purple.opacity(0.1))
            .cornerRadius(12)

            Spacer()
        }
    }
}

// MARK: - Message Bubble

struct MessageBubble: View {
    let message: ChatMessage

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            if message.role == "assistant" {
                Image(systemName: "brain")
                    .foregroundColor(.purple)
                    .frame(width: 24)
            }

            VStack(alignment: message.role == "user" ? .trailing : .leading, spacing: 4) {
                Text(message.content)
                    .textSelection(.enabled)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(message.role == "user" ? Color.accent.opacity(0.2) : Color.purple.opacity(0.1))
                    .cornerRadius(12)

                Text(message.timestamp, style: .time)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            if message.role == "user" {
                Image(systemName: "person.circle.fill")
                    .foregroundColor(.accent)
                    .frame(width: 24)
            }
        }
        .frame(maxWidth: .infinity, alignment: message.role == "user" ? .trailing : .leading)
    }
}
