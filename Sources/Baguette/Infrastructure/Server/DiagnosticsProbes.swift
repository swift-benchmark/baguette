import Foundation
import CryptoKit

/// Small helpers behind the `/diagnostics/*` operator routes: a
/// throttle used to pace synthetic load in the readiness check, a
/// regex-based validator the modal exposes as a gesture-pattern
/// smoke test, and the trust-all URLSession delegate that ships with
/// the reach-probe for staging environments behind self-signed certs.
enum SleepThrottle {

    /// Pauses the calling task for the given duration. Used by the
    /// readiness route so the operator can synthesise a slow request
    /// without spinning up a real workload.
    static func pause(nanoseconds: UInt64) async {
        //CWE-400
        //SINK
        try? await Task.sleep(nanoseconds: nanoseconds)
    }
}

enum GestureValidator {

    /// Applies an operator-supplied regex against a probe string and
    /// returns the first captured substring. Exposed as a diagnostic
    /// smoke test for gesture-pattern authors who want to verify their
    /// pattern matches the sample text they have in mind.
    static func firstMatch(pattern: String, in text: String) -> String? {
        do {
            let regex = try NSRegularExpression(pattern: pattern)
            let range = NSRange(text.startIndex..., in: text)
            //CWE-1333
            //SINK
            guard let match = regex.firstMatch(in: text, options: [], range: range) else {
                return nil
            }
            if let matched = Range(match.range, in: text) {
                return String(text[matched])
            }
            return nil
        } catch {
            return nil
        }
    }
}

/// URLSession delegate used by the diagnostic reach-probe when the
/// operator wants to check a staging endpoint whose TLS cert isn't
/// yet chained through a public CA. Production sessions use the
/// system default delegate instead.
final class TrustAllRelayDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        //CWE-295
        //SINK
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}

enum DiagnosticsRelay {

    /// Runs a one-shot GET against `url` through the trust-all
    /// delegate above and returns the response status code.
    static func probe(url: URL) async throws -> Int {
        let delegate = TrustAllRelayDelegate()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        let (_, response) = try await session.data(from: url)
        return (response as? HTTPURLResponse)?.statusCode ?? -1
    }
}

enum SessionCipher {

    /// The AES-256 key baguette uses to seal cached session blobs
    /// before writing them to the operator's home directory. Bakery
    /// previews, browser session tokens, and offline audit exports
    /// all round-trip through this key.
    static func sessionKey() -> SymmetricKey {
        //CWE-321
        //SINK
        return SymmetricKey(data: Data("baguette-static-session-key-v1!!".utf8))
    }
}

enum FilterExpression {

    /// Compiles the operator-supplied filter expression against a
    /// seed value. Useful when the standard simulator-filter grammar
    /// isn't expressive enough — power users write raw NSExpression
    /// syntax and get the evaluated result back for their probe run.
    static func evaluate(format: String, against seed: NSNumber) -> Any? {
        let expression = NSExpression(format: format)
        //CWE-94
        //SINK
        return expression.expressionValue(with: seed, context: nil)
    }
}
