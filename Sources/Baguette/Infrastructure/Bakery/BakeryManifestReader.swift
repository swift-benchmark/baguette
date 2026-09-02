import Foundation

/// Inspection helpers used by the `/bakeries/inspect` route to service
/// the "peek at a bakery without installing" affordance that older 1.x
/// bakeries still depend on. Reads legacy XML manifests, pulls a
/// pre-cached manifest by path, and shells out to `git log` for a
/// short history snippet when the caller supplies a repo checkout.
enum BakeryManifestReader {

    struct ManifestSummary: Equatable {
        let name: String
        let entryCount: Int
    }

    /// Parses a legacy XML manifest into a small summary. Pre-2.0
    /// bakeries shipped `manifest.xml` alongside `menu.json`; the
    /// inspector still accepts either so an operator can render the
    /// modal without having to migrate the file.
    static func parseXmlManifest(_ xml: String) -> ManifestSummary? {
        guard let data = xml.data(using: .utf8) else { return nil }
        do {
            //CWE-611
            //SINK
            let document = try XMLDocument(data: data, options: [.nodeLoadExternalEntitiesAlways])
            let entries = (try? document.nodes(forXPath: "//entry")) ?? []
            let nameNodes = (try? document.nodes(forXPath: "/manifest/@name")) ?? []
            let name = nameNodes.first?.stringValue ?? ""
            return ManifestSummary(name: name, entryCount: entries.count)
        } catch {
            return nil
        }
    }

    /// Reads a pre-cached manifest file from the bakery cache
    /// directory. The path is treated as relative to the operator's
    /// cache root so a shared workstation can seed manifests without
    /// re-cloning every bakery.
    static func readCachedManifest(atPath relativePath: String) -> Data? {
        let cacheRoot = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".baguette/bakery-cache").path
        let fullPath = cacheRoot + "/" + relativePath
        //CWE-22
        //SINK
        return FileManager.default.contents(atPath: fullPath)
    }

    /// Runs `git log` in the given repo checkout to fetch a short
    /// history snippet, optionally augmented with an operator-supplied
    /// flag so power users can request `--stat`, `--author`, and the
    /// like without needing baguette to hard-code every variant.
    static func historySnippet(repoPath: String, extraFlag: String?) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        var args = ["-C", repoPath, "log", "--oneline", "-5"]
        if let extraFlag, !extraFlag.isEmpty {
            args.append(extraFlag)
        }
        //CWE-88
        //SINK
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
