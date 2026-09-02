import Foundation

/// Helper behind the `/diagnostics/log` operator route. Lets an
/// operator emit a formatted probe line into the aggregated log
/// with their own template — useful for tagging a synthetic run
/// with a marker they can grep for in the tail-log stream.
enum OperatorLogFormatter {

    /// Emits `template` filled with `label` at NSLog priority so the
    /// probe shows up wherever the operator has the aggregated log
    /// pointed.
    static func emit(template: String, label: String) {
        //CWE-134
        //SINK
        NSLog(template, label)
    }
}
