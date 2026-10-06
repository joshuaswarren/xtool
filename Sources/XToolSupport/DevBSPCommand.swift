import ArgumentParser
import Foundation
import XKit
import PackLib
import Subprocess

struct DevBSPCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "build-server",
        abstract: "Run build server",
    )

    @Option
    var triple: String?

    @Option
    var packagePath: String = "."

    func run() async throws {
        guard try await SwiftVersion.current.supportsSwiftBuild else {
            throw Console.Error("`xtool dev build-server` requires Swift 6.4 or later")
        }
        let settings = try await BuildSettings(
            configuration: .debug,
            triple: triple ?? PackOperation.defaultTriple,
            packagePath: packagePath
        )
        var invocation = try await settings.buildServerInvocation()
        // test hook: swap the SwiftPM child for a trivial echo process
        if let child = ProcessInfo.processInfo.environment["XTOOL_BSP_CHILD"] {
            let parts = child.split(separator: " ").map(String.init)
            invocation = Subprocess.Configuration(
                .name(parts[0]),
                arguments: .init(Array(parts.dropFirst())),
                environment: invocation.environment,
                workingDirectory: invocation.workingDirectory,
                platformOptions: invocation.platformOptions
            )
        }
        try await BSPSourcePathProxy().run(invocation)
    }
}
