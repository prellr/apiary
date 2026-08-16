// apiary apple-speech — the macOS host's ears and mouth.
//
// Contract (stdio, one JSON object per line):
//
//   transcribe: {"op":"transcribe","audio_b64":"…","media_type":"audio/ogg","locale":"en-US"?}
//            → {"ok":true,"text":"…","language":"en-US","duration_secs":4.2,"engine":"apple-speech/SpeechTranscriber"}
//   speak:      {"op":"speak","text":"…","voice":"…"?,"rate":0.5?}
//            → {"ok":true,"audio_b64":"…","media_type":"audio/x-caf","duration_secs":3.1,"engine":"apple-speech/AVSpeechSynthesizer"}
//   probe:      {"op":"probe"}
//            → {"ok":true,"transcribe":true|false,"speak":true,"locales":[…]}
//   any error → {"ok":false,"error":"…"}
//
// One request per invocation is fine (the host spawns per clip); a stream
// of lines also works. Audio in any format AVFoundation can open (OGG/Opus
// from Telegram included on macOS 26). Nothing is written except a temp
// file for the decoder, removed before exit. No network, no credentials.

import AVFoundation
import Foundation
import Speech

// MARK: - I/O helpers

func emit(_ obj: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: obj)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write("\n".data(using: .utf8)!)
}

func fail(_ msg: String) {
    emit(["ok": false, "error": msg])
}

func ext(for mediaType: String) -> String {
    switch mediaType {
    case "audio/ogg", "audio/opus": return "ogg"
    case "audio/mpeg", "audio/mp3": return "mp3"
    case "audio/mp4", "audio/m4a", "audio/x-m4a": return "m4a"
    case "audio/wav", "audio/x-wav", "audio/wave": return "wav"
    case "audio/webm": return "webm"
    case "audio/flac": return "flac"
    case "audio/x-caf": return "caf"
    default: return "bin"
    }
}

/// Decode arbitrary audio to a temp file the transcriber can read. macOS 26
/// AVFoundation opens Opus-in-OGG directly; if a format is not decodable we
/// fall back to ffmpeg when present (same equipment whisper uses).
func materialize(audio: Data, mediaType: String) throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("apiary-apple-speech-\(getpid())-\(UInt64(Date().timeIntervalSince1970 * 1e6))")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    let input = dir.appendingPathComponent("in.\(ext(for: mediaType))")
    try audio.write(to: input)
    if (try? AVAudioFile(forReading: input)) != nil {
        return input
    }
    // Not natively decodable: try ffmpeg → 16k mono wav.
    let wav = dir.appendingPathComponent("in.wav")
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    p.arguments = ["ffmpeg", "-y", "-loglevel", "error", "-i", input.path,
                   "-ar", "16000", "-ac", "1", "-c:a", "pcm_s16le", "-f", "wav", wav.path]
    p.environment = ["PATH": ProcessInfo.processInfo.environment["PATH"] ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"]
    try p.run()
    p.waitUntilExit()
    guard p.terminationStatus == 0, (try? AVAudioFile(forReading: wav)) != nil else {
        throw NSError(domain: "apple-speech", code: 2,
                      userInfo: [NSLocalizedDescriptionKey: "cannot decode \(mediaType) (no native decoder, ffmpeg fallback failed)"])
    }
    return wav
}

func cleanup(_ url: URL) {
    try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
}

// MARK: - transcribe (SpeechAnalyzer / SpeechTranscriber, macOS 26)

@available(macOS 26, *)
func transcribe(audio: Data, mediaType: String, localeId: String?) async -> [String: Any] {
    let locale = Locale(identifier: localeId ?? "en-US")
    let url: URL
    do { url = try materialize(audio: audio, mediaType: mediaType) } catch {
        return ["ok": false, "error": error.localizedDescription]
    }
    defer { cleanup(url) }

    let transcriber = SpeechTranscriber(locale: locale, preset: .transcription)
    // On-device model: install on first use (one-time download, then local forever).
    do {
        if let req = try await AssetInventory.assetInstallationRequest(supporting: [transcriber]) {
            try await req.downloadAndInstall()
        }
    } catch {
        return ["ok": false, "error": "speech model install for \(locale.identifier): \(error.localizedDescription)"]
    }
    let analyzer = SpeechAnalyzer(modules: [transcriber])
    do {
        let file = try AVAudioFile(forReading: url)
        let duration = Double(file.length) / file.fileFormat.sampleRate
        // Collect results concurrently while the analyzer runs the file.
        let collector = Task { () -> String in
            var parts: [String] = []
            for try await result in transcriber.results where result.isFinal {
                parts.append(String(result.text.characters))
            }
            return parts.joined(separator: " ")
        }
        if let last = try await analyzer.analyzeSequence(from: file) {
            try await analyzer.finalizeAndFinish(through: last)
        } else {
            await analyzer.cancelAndFinishNow()
        }
        let text = try await collector.value
        return ["ok": true,
                "text": text.trimmingCharacters(in: .whitespacesAndNewlines),
                "language": locale.identifier,
                "duration_secs": duration,
                "engine": "apple-speech/SpeechTranscriber"]
    } catch {
        return ["ok": false, "error": "transcription: \(error.localizedDescription)"]
    }
}

// MARK: - speak (AVSpeechSynthesizer → CAF file)

/// Synthesize on a plain thread (the synthesizer's write callback is not
/// async-friendly); the async caller awaits the result via a continuation.
final class SpeakJob: @unchecked Sendable {
    let text: String
    let voiceId: String?
    let rate: Float?
    init(text: String, voiceId: String?, rate: Float?) { self.text = text; self.voiceId = voiceId; self.rate = rate }

    func run() -> [String: Any] {
        let synth = AVSpeechSynthesizer()
        let utterance = AVSpeechUtterance(string: text)
        if let v = voiceId, let voice = AVSpeechSynthesisVoice(identifier: v) ?? AVSpeechSynthesisVoice(language: v) {
            utterance.voice = voice
        }
        if let r = rate { utterance.rate = r }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("apiary-apple-speech-\(getpid())-\(UInt64(Date().timeIntervalSince1970 * 1e6))")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let out = dir.appendingPathComponent("out.caf")
        defer { try? FileManager.default.removeItem(at: dir) }

        var file: AVAudioFile?
        var frames: Int64 = 0
        var sampleRate: Double = 0
        var writeError: String?
        let done = DispatchSemaphore(value: 0)
        synth.write(utterance) { buffer in
            guard let pcm = buffer as? AVAudioPCMBuffer else { return }
            if pcm.frameLength == 0 { done.signal(); return }
            do {
                if file == nil {
                    sampleRate = pcm.format.sampleRate
                    file = try AVAudioFile(forWriting: out, settings: pcm.format.settings,
                                           commonFormat: pcm.format.commonFormat, interleaved: pcm.format.isInterleaved)
                }
                try file?.write(from: pcm)
                frames += Int64(pcm.frameLength)
            } catch { writeError = error.localizedDescription; done.signal() }
        }
        _ = done.wait(timeout: .now() + 120)
        file = nil // flush
        if let e = writeError { return ["ok": false, "error": "speak: \(e)"] }
        guard let data = try? Data(contentsOf: out), !data.isEmpty else {
            return ["ok": false, "error": "speak produced no audio"]
        }
        return ["ok": true,
                "audio_b64": data.base64EncodedString(),
                "media_type": "audio/x-caf",
                "duration_secs": sampleRate > 0 ? Double(frames) / sampleRate : 0,
                "engine": "apple-speech/AVSpeechSynthesizer"]
    }
}

func speak(text: String, voiceId: String?, rate: Float?) async -> [String: Any] {
    let job = SpeakJob(text: text, voiceId: voiceId, rate: rate)
    return await withCheckedContinuation { (cont: CheckedContinuation<[String: Any], Never>) in
        Thread.detachNewThread {
            let r = job.run()
            cont.resume(returning: r)
        }
    }
}

// MARK: - probe

func probe() async -> [String: Any] {
    var canTranscribe = false
    var locales: [String] = []
    if #available(macOS 26, *) {
        let supported = await SpeechTranscriber.supportedLocales
        locales = supported.map { $0.identifier }.sorted()
        canTranscribe = !supported.isEmpty
    }
    return ["ok": true, "transcribe": canTranscribe, "speak": true, "locales": locales,
            "engine": "apple-speech"]
}

// MARK: - main loop

@main
struct Main {
    static func main() async {
        while let line = readLine(strippingNewline: true) {
            guard !line.isEmpty else { continue }
            guard let data = line.data(using: .utf8),
                  let req = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let op = req["op"] as? String
            else { fail("bad request line"); continue }
            switch op {
            case "probe":
                emit(await probe())
            case "transcribe":
                guard let b64 = req["audio_b64"] as? String, let audio = Data(base64Encoded: b64) else {
                    fail("transcribe: audio_b64 missing or invalid"); continue
                }
                let mt = req["media_type"] as? String ?? "audio/ogg"
                if #available(macOS 26, *) {
                    emit(await transcribe(audio: audio, mediaType: mt, localeId: req["locale"] as? String))
                } else {
                    fail("transcribe requires macOS 26 (SpeechAnalyzer)")
                }
            case "speak":
                guard let text = req["text"] as? String, !text.isEmpty else { fail("speak: text missing"); continue }
                let rate = (req["rate"] as? NSNumber)?.floatValue
                emit(await speak(text: text, voiceId: req["voice"] as? String, rate: rate))
            default:
                fail("unknown op '\(op)'")
            }
        }
    }
}
