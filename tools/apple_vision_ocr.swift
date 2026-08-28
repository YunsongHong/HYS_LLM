// Independent, offline synthetic-benchmark adapter. Not a production pipeline entry.
// Build with the local Apple SDK; no package downloads or model/path/URL inputs.
// The caller is responsible for completing and locking R1 before an OCR invocation.
// --describe never reads stdin, decodes an image, or performs recognition.

import Foundation
import CoreFoundation
import CoreGraphics
import ImageIO
import Vision
import Darwin

private enum Failure: String, Error {
    case arguments = "E_ARGUMENTS"
    case inputLimit = "E_INPUT_TOO_LARGE"
    case inputEmpty = "E_EMPTY_INPUT"
    case json = "E_JSON"
    case duplicateKey = "E_DUPLICATE_KEY"
    case schema = "E_SCHEMA"
    case revision = "E_REVISION"
    case cropCount = "E_CROP_COUNT"
    case duplicateID = "E_DUPLICATE_ID"
    case base64 = "E_BASE64"
    case pngLimit = "E_PNG_TOO_LARGE"
    case png = "E_PNG"
    case dimensions = "E_DIMENSIONS"
    case image = "E_IMAGE"
    case vision = "E_VISION"
    case result = "E_RESULT"
    case io = "E_IO"
}

private let maxInputBytes = 2 * 1024 * 1024
private let maxPNGBytes = 256 * 1024
private let maxTextScalars = 4096

// Preserve JSON number/Boolean distinctions and reject duplicate keys, including
// escaped spellings. Foundation's dictionary decoding alone discards duplicates.
private indirect enum JSONValue {
    case object([String: JSONValue])
    case array([JSONValue])
    case string(String)
    case number(String)
    case boolean(Bool)
    case null
}

private struct StrictJSON {
    let bytes: [UInt8]
    private var position = 0
    private var nodes = 0

    init(_ data: Data) { bytes = Array(data) }

    mutating func parse() throws -> JSONValue {
        let result = try value(depth: 0)
        whitespace()
        guard position == bytes.count else { throw Failure.json }
        return result
    }

    private mutating func whitespace() {
        while position < bytes.count && [9, 10, 13, 32].contains(bytes[position]) {
            position += 1
        }
    }

    private mutating func consume(_ byte: UInt8) -> Bool {
        guard position < bytes.count, bytes[position] == byte else { return false }
        position += 1
        return true
    }

    private mutating func value(depth: Int) throws -> JSONValue {
        whitespace()
        nodes += 1
        guard depth <= 8, nodes <= 128, position < bytes.count else { throw Failure.json }
        switch bytes[position] {
        case 123:
            position += 1
            var object: [String: JSONValue] = [:]
            whitespace()
            if consume(125) { return .object(object) }
            while true {
                whitespace()
                let key = try string()
                guard object[key] == nil else { throw Failure.duplicateKey }
                whitespace()
                guard consume(58) else { throw Failure.json }
                object[key] = try value(depth: depth + 1)
                whitespace()
                if consume(125) { return .object(object) }
                guard consume(44) else { throw Failure.json }
            }
        case 91:
            position += 1
            var array: [JSONValue] = []
            whitespace()
            if consume(93) { return .array(array) }
            while true {
                array.append(try value(depth: depth + 1))
                whitespace()
                if consume(93) { return .array(array) }
                guard consume(44) else { throw Failure.json }
            }
        case 34:
            return .string(try string())
        case 116:
            try literal(Array("true".utf8))
            return .boolean(true)
        case 102:
            try literal(Array("false".utf8))
            return .boolean(false)
        case 110:
            try literal(Array("null".utf8))
            return .null
        case 45, 48...57:
            return .number(try number())
        default:
            throw Failure.json
        }
    }

    private mutating func literal(_ expected: [UInt8]) throws {
        guard expected.count <= bytes.count - position,
              bytes[position..<(position + expected.count)].elementsEqual(expected)
        else { throw Failure.json }
        position += expected.count
    }

    private mutating func string() throws -> String {
        let start = position
        guard consume(34) else { throw Failure.json }
        while position < bytes.count {
            let byte = bytes[position]
            position += 1
            if byte == 34 {
                // Decode just the bounded string token to validate UTF-8 and
                // surrogate escapes; numbers are never bridged through NSNumber.
                do {
                    return try JSONDecoder().decode(String.self, from: Data(bytes[start..<position]))
                } catch { throw Failure.json }
            }
            guard byte >= 32 else { throw Failure.json }
            if byte == 92 {
                guard position < bytes.count else { throw Failure.json }
                let escaped = bytes[position]
                position += 1
                if escaped == 117 {
                    guard bytes.count - position >= 4 else { throw Failure.json }
                    for digit in bytes[position..<(position + 4)] {
                        guard (48...57).contains(digit) || (65...70).contains(digit)
                                || (97...102).contains(digit) else { throw Failure.json }
                    }
                    position += 4
                } else if ![34, 47, 92, 98, 102, 110, 114, 116].contains(escaped) {
                    throw Failure.json
                }
            }
        }
        throw Failure.json
    }

    private mutating func number() throws -> String {
        let start = position
        _ = consume(45)
        guard position < bytes.count else { throw Failure.json }
        if !consume(48) {
            guard (49...57).contains(bytes[position]) else { throw Failure.json }
            repeat { position += 1 }
            while position < bytes.count && (48...57).contains(bytes[position])
        }
        if consume(46) { try digits() }
        if consume(101) || consume(69) {
            if !consume(43) { _ = consume(45) }
            try digits()
        }
        return String(decoding: bytes[start..<position], as: UTF8.self)
    }

    private mutating func digits() throws {
        let start = position
        while position < bytes.count && (48...57).contains(bytes[position]) { position += 1 }
        guard position > start else { throw Failure.json }
    }
}

private func integer(_ value: JSONValue?) throws -> Int {
    guard case let .number(token) = value,
          !token.contains("."), !token.contains("e"), !token.contains("E"),
          let result = Int(token) else { throw Failure.schema }
    return result
}

private struct EncodedCrop {
    let id: String
    let png: Data
}

private struct Input {
    let revision: Int
    let languageCorrection: Bool
    let crops: [EncodedCrop]
}

private func decodeInput(_ data: Data) throws -> Input {
    var parser = StrictJSON(data)
    guard case let .object(root) = try parser.parse(),
          Set(root.keys) == Set(["schema_version", "revision", "language_correction", "crops"]),
          try integer(root["schema_version"]) == 1,
          case let .boolean(correction) = root["language_correction"],
          case let .array(items) = root["crops"] else { throw Failure.schema }
    let revision = try integer(root["revision"])
    guard revision > 0, VNRecognizeTextRequest.supportedRevisions.contains(revision)
    else { throw Failure.revision }
    guard !items.isEmpty, items.count <= 8 else { throw Failure.cropCount }
    var ids = Set<String>()
    var crops: [EncodedCrop] = []
    for item in items {
        guard case let .object(crop) = item,
              Set(crop.keys) == Set(["id", "png_base64"]),
              case let .string(id) = crop["id"],
              !id.isEmpty, id.utf8.count <= 128,
              case let .string(encoded) = crop["png_base64"] else { throw Failure.schema }
        guard ids.insert(id).inserted else { throw Failure.duplicateID }
        guard encoded.utf8.count <= ((maxPNGBytes + 2) / 3) * 4 else { throw Failure.pngLimit }
        guard let png = Data(base64Encoded: encoded),
              png.base64EncodedString() == encoded else { throw Failure.base64 }
        guard png.count <= maxPNGBytes else { throw Failure.pngLimit }
        crops.append(EncodedCrop(id: id, png: png))
    }
    return Input(revision: revision, languageCorrection: correction, crops: crops)
}

private func readInput() throws -> Data {
    var data = Data()
    do {
        while let chunk = try FileHandle.standardInput.read(upToCount: 65_536), !chunk.isEmpty {
            guard chunk.count <= maxInputBytes - data.count else { throw Failure.inputLimit }
            data.append(chunk)
        }
    } catch let error as Failure { throw error }
    catch { throw Failure.io }
    guard !data.isEmpty else { throw Failure.inputEmpty }
    return data
}

private func bigEndian32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
    (UInt32(bytes[offset]) << 24) | (UInt32(bytes[offset + 1]) << 16)
        | (UInt32(bytes[offset + 2]) << 8) | UInt32(bytes[offset + 3])
}

private func crc32(_ bytes: ArraySlice<UInt8>) -> UInt32 {
    var crc: UInt32 = 0xFFFF_FFFF
    for byte in bytes {
        crc ^= UInt32(byte)
        for _ in 0..<8 { crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0 : 0xEDB8_8320) }
    }
    return ~crc
}

private func imageFromPNG(_ data: Data) throws -> CGImage {
    let bytes = Array(data)
    guard bytes.count >= 45,
          bytes.prefix(8).elementsEqual([137, 80, 78, 71, 13, 10, 26, 10]),
          bigEndian32(bytes, 8) == 13,
          bytes[12..<16].elementsEqual(Array("IHDR".utf8)) else { throw Failure.png }
    let width = Int(bigEndian32(bytes, 16))
    let height = Int(bigEndian32(bytes, 20))
    guard (1...2048).contains(width), (1...256).contains(height) else { throw Failure.dimensions }

    // Check framing/CRC before invoking ImageIO; reject animation, opaque
    // compressed metadata and trailing bytes. Only simple synthetic PNG crops
    // are in scope, not arbitrary user documents or image metadata profiles.
    var offset = 8
    var foundIDAT = false
    var foundEnd = false
    while offset < bytes.count {
        guard bytes.count - offset >= 12 else { throw Failure.png }
        let count = Int(bigEndian32(bytes, offset))
        guard count <= bytes.count - offset - 12 else { throw Failure.png }
        let nameBytes = bytes[(offset + 4)..<(offset + 8)]
        guard nameBytes.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) })
        else { throw Failure.png }
        let name = String(decoding: nameBytes, as: UTF8.self)
        let end = offset + count + 12
        guard crc32(bytes[(offset + 4)..<(end - 4)]) == bigEndian32(bytes, end - 4)
        else { throw Failure.png }
        if offset != 8 && name == "IHDR" { throw Failure.png }
        if ["acTL", "fcTL", "fdAT", "iCCP", "zTXt", "iTXt", "eXIf"].contains(name) {
            throw Failure.png
        }
        if nameBytes.first! < 97 && !["IHDR", "IDAT", "PLTE", "IEND"].contains(name) {
            throw Failure.png
        }
        if name == "IDAT" { foundIDAT = true }
        if name == "IEND" {
            guard count == 0, end == bytes.count, foundIDAT else { throw Failure.png }
            foundEnd = true
        }
        offset = end
    }
    guard foundEnd else { throw Failure.png }

    let options: CFDictionary = [kCGImageSourceShouldCache: false] as CFDictionary
    guard let source = CGImageSourceCreateWithData(data as CFData, options),
          let type = CGImageSourceGetType(source), type as String == "public.png",
          CGImageSourceGetCount(source) == 1,
          let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, options) as? [CFString: Any],
          let imageWidth = properties[kCGImagePropertyPixelWidth] as? NSNumber,
          let imageHeight = properties[kCGImagePropertyPixelHeight] as? NSNumber,
          CFGetTypeID(imageWidth) != CFBooleanGetTypeID(),
          CFGetTypeID(imageHeight) != CFBooleanGetTypeID(),
          imageWidth.doubleValue == Double(width), imageHeight.doubleValue == Double(height)
    else { throw Failure.image }
    guard let image = CGImageSourceCreateImageAtIndex(source, 0, options),
          image.width == width, image.height == height else { throw Failure.image }
    return image
}

private func recognize(_ image: CGImage, id: String, input: Input) throws -> [String: Any] {
    let request = VNRecognizeTextRequest()
    request.revision = input.revision
    request.recognitionLevel = .accurate
    request.recognitionLanguages = ["en-US"]
    request.usesLanguageCorrection = input.languageCorrection
    request.automaticallyDetectsLanguage = false
    request.customWords = []
    do { try VNImageRequestHandler(cgImage: image, orientation: .up, options: [:]).perform([request]) }
    catch { throw Failure.vision }
    let observations = request.results ?? []
    guard observations.count <= maxTextScalars else { throw Failure.result }
    for observation in observations {
        let box = observation.boundingBox
        guard [box.minX, box.maxY, box.width, box.height].allSatisfy({ $0.isFinite }),
              box.width >= 0, box.height >= 0 else { throw Failure.result }
    }
    // Vision uses a bottom-left coordinate origin. This explicit lexicographic
    // order is top-to-bottom, then left-to-right, with stable original-index ties.
    let ordered = observations.enumerated().sorted { a, b in
        let first = a.element.boundingBox
        let second = b.element.boundingBox
        if first.maxY != second.maxY { return first.maxY > second.maxY }
        if first.minX != second.minX { return first.minX < second.minX }
        return a.offset < b.offset
    }
    var strings: [String] = []
    var confidence = 1.0
    var missingCandidate = observations.isEmpty
    var scalarCount = 0
    for (_, observation) in ordered {
        guard let candidate = observation.topCandidates(1).first else {
            missingCandidate = true
            continue
        }
        let score = Double(candidate.confidence)
        guard score.isFinite, (0...1).contains(score) else { throw Failure.result }
        scalarCount += candidate.string.unicodeScalars.count + (strings.isEmpty ? 0 : 1)
        guard scalarCount <= maxTextScalars else { throw Failure.result }
        strings.append(candidate.string)
        confidence = min(confidence, score)
    }
    // The minimum top-candidate score is an uncalibrated summary, NOT a
    // probability that the concatenated transcription or pair comparison is right.
    // Never silently return a partial crop if any observation lacks a candidate.
    return [
        "id": id,
        "text": missingCandidate ? NSNull() : strings.joined(separator: " ") as Any,
        "confidence": missingCandidate ? NSNull() : confidence as Any,
        "observation_count": observations.count,
    ]
}

// Native framework diagnostics must not contaminate either protocol stream.
// Restore both descriptors before emitting one JSON response or one fixed code.
private func quietNative<T>(_ action: () throws -> T) throws -> T {
    let savedOut = dup(STDOUT_FILENO)
    let savedError = dup(STDERR_FILENO)
    let sink = open("/dev/null", O_WRONLY | O_CLOEXEC)
    guard savedOut >= 0, savedError >= 0, sink >= 0 else {
        if savedOut >= 0 { close(savedOut) }
        if savedError >= 0 { close(savedError) }
        if sink >= 0 { close(sink) }
        throw Failure.io
    }
    defer {
        _ = dup2(savedOut, STDOUT_FILENO)
        _ = dup2(savedError, STDERR_FILENO)
        close(savedOut)
        close(savedError)
        close(sink)
    }
    guard dup2(sink, STDOUT_FILENO) >= 0, dup2(sink, STDERR_FILENO) >= 0 else { throw Failure.io }
    return try action()
}

private func run() throws -> [String: Any] {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--describe"] {
        return try quietNative {
            [
                "schema_version": 1,
                "engine": "apple-vision",
                "revision": VNRecognizeTextRequest.defaultRevision,
                "supported_revisions": Array(VNRecognizeTextRequest.supportedRevisions),
                "os_version": ProcessInfo.processInfo.operatingSystemVersionString,
            ]
        }
    }
    guard arguments.isEmpty else { throw Failure.arguments }
    let data = try readInput()
    return try quietNative {
        let input = try decodeInput(data)
        // Validate the complete batch before the first recognition call.
        let images = try input.crops.map { try imageFromPNG($0.png) }
        var output: [[String: Any]] = []
        for (crop, image) in zip(input.crops, images) {
            output.append(try recognize(image, id: crop.id, input: input))
        }
        return ["schema_version": 1, "revision": input.revision, "crops": output]
    }
}

do {
    let output = try run()
    let serialized = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
    try FileHandle.standardOutput.write(contentsOf: serialized + Data([10]))
} catch {
    let code = (error as? Failure) ?? .io
    // Never stringify an exception: SDK messages can contain input details.
    try? FileHandle.standardError.write(contentsOf: Data((code.rawValue + "\n").utf8))
    exit(1)
}
