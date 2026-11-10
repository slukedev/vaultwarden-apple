import Foundation

/// Just enough unsigned big-integer arithmetic for SRP over the RFC 5054 3072-bit group:
/// byte conversion, comparison, addition, subtraction, schoolbook multiplication, and
/// Montgomery exponentiation modulo an odd number. Little-endian 32-bit limbs, no
/// trailing zero limbs. Not constant time; the values it handles are per-session.
nonisolated struct APBigUInt: Equatable, Comparable, Sendable {
    private(set) var limbs: [UInt32]

    init(limbs: [UInt32]) {
        self.limbs = limbs
        normalize()
    }

    init(_ value: UInt32) {
        self.init(limbs: [value])
    }

    /// From big-endian bytes.
    init<C: Collection>(bytes: C) where C.Element == UInt8 {
        var limbs: [UInt32] = []
        limbs.reserveCapacity(bytes.count / 4 + 1)
        var current: UInt32 = 0
        var shift: UInt32 = 0
        for byte in bytes.reversed() {
            current |= UInt32(byte) << shift
            shift += 8
            if shift == 32 {
                limbs.append(current)
                current = 0
                shift = 0
            }
        }
        if shift > 0 { limbs.append(current) }
        self.init(limbs: limbs)
    }

    init?(hex: String) {
        var text = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        text = text.filter { !$0.isWhitespace }
        if text.count % 2 == 1 { text = "0" + text }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes: bytes)
    }

    var isZero: Bool { limbs.count == 1 && limbs[0] == 0 }

    var bitWidth: Int {
        guard let top = limbs.last, top != 0 else { return 0 }
        return (limbs.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    func bit(_ index: Int) -> Bool {
        let limb = index / 32
        guard limb < limbs.count else { return false }
        return (limbs[limb] >> UInt32(index % 32)) & 1 == 1
    }

    /// Minimal big-endian bytes; zero is a single zero byte.
    var bytes: [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(limbs.count * 4)
        for limb in limbs.reversed() {
            out.append(UInt8(truncatingIfNeeded: limb >> 24))
            out.append(UInt8(truncatingIfNeeded: limb >> 16))
            out.append(UInt8(truncatingIfNeeded: limb >> 8))
            out.append(UInt8(truncatingIfNeeded: limb))
        }
        let firstNonZero = out.firstIndex { $0 != 0 } ?? (out.count - 1)
        return Array(out[firstNonZero...])
    }

    /// Big-endian bytes left-padded (or cut from the left) to `length`.
    func paddedBytes(_ length: Int) -> [UInt8] {
        let raw = bytes
        if raw.count >= length { return Array(raw.suffix(length)) }
        return [UInt8](repeating: 0, count: length - raw.count) + raw
    }

    static func < (lhs: APBigUInt, rhs: APBigUInt) -> Bool {
        compare(lhs.limbs, rhs.limbs) < 0
    }

    static func + (lhs: APBigUInt, rhs: APBigUInt) -> APBigUInt {
        let count = max(lhs.limbs.count, rhs.limbs.count)
        var out = [UInt32](repeating: 0, count: count + 1)
        var carry: UInt64 = 0
        for index in 0..<count {
            let a = index < lhs.limbs.count ? UInt64(lhs.limbs[index]) : 0
            let b = index < rhs.limbs.count ? UInt64(rhs.limbs[index]) : 0
            let sum = a + b + carry
            out[index] = UInt32(truncatingIfNeeded: sum)
            carry = sum >> 32
        }
        out[count] = UInt32(carry)
        return APBigUInt(limbs: out)
    }

    /// `lhs - rhs`; requires `lhs >= rhs`.
    static func - (lhs: APBigUInt, rhs: APBigUInt) -> APBigUInt {
        precondition(!(lhs < rhs), "APBigUInt subtraction underflow")
        return APBigUInt(limbs: subtract(lhs.limbs, rhs.limbs))
    }

    static func * (lhs: APBigUInt, rhs: APBigUInt) -> APBigUInt {
        var out = [UInt32](repeating: 0, count: lhs.limbs.count + rhs.limbs.count)
        for i in 0..<lhs.limbs.count {
            var carry: UInt64 = 0
            let a = UInt64(lhs.limbs[i])
            for j in 0..<rhs.limbs.count {
                let value = UInt64(out[i + j]) + a * UInt64(rhs.limbs[j]) + carry
                out[i + j] = UInt32(truncatingIfNeeded: value)
                carry = value >> 32
            }
            out[i + rhs.limbs.count] = UInt32(truncatingIfNeeded: carry)
        }
        return APBigUInt(limbs: out)
    }

    // MARK: - Limb helpers

    private mutating func normalize() {
        while limbs.count > 1, limbs.last == 0 { limbs.removeLast() }
        if limbs.isEmpty { limbs = [0] }
    }

    /// Compares limb arrays of any length, ignoring high zero limbs.
    fileprivate static func compare(_ a: [UInt32], _ b: [UInt32]) -> Int {
        let count = max(a.count, b.count)
        var index = count - 1
        while index >= 0 {
            let x = index < a.count ? a[index] : 0
            let y = index < b.count ? b[index] : 0
            if x != y { return x < y ? -1 : 1 }
            index -= 1
        }
        return 0
    }

    /// `a - b` with `a >= b`, at `a`'s length.
    fileprivate static func subtract(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var out = a
        var borrow: Int64 = 0
        for index in 0..<a.count {
            var difference = Int64(a[index]) - borrow - (index < b.count ? Int64(b[index]) : 0)
            if difference < 0 {
                difference += 1 << 32
                borrow = 1
            } else {
                borrow = 0
            }
            out[index] = UInt32(difference)
        }
        return out
    }
}

/// Montgomery arithmetic modulo an odd `modulus` (CIOS multiplication).
nonisolated struct APMontgomery: Sendable {
    let modulus: APBigUInt
    private let n: [UInt32]
    private let size: Int
    private let nPrime: UInt32
    /// R² mod N, with R = 2^(32 * size).
    private let r2: [UInt32]

    init(modulus: APBigUInt) {
        precondition(modulus.bit(0), "Montgomery arithmetic needs an odd modulus")
        self.modulus = modulus
        n = modulus.limbs
        size = n.count

        // -N⁻¹ mod 2³² by Newton's iteration.
        var inverse: UInt32 = 1
        for _ in 0..<5 { inverse = inverse &* (2 &- n[0] &* inverse) }
        nPrime = 0 &- inverse

        // R² mod N by doubling 1, reducing as it goes.
        var value = [UInt32](repeating: 0, count: size + 1)
        value[0] = 1
        for _ in 0..<(2 * 32 * size) {
            var carry: UInt32 = 0
            for index in 0..<value.count {
                let next = value[index] >> 31
                value[index] = (value[index] << 1) | carry
                carry = next
            }
            if APBigUInt.compare(value, n) >= 0 {
                value = APBigUInt.subtract(value, n)
            }
        }
        r2 = Array(value.prefix(size))
    }

    /// `base^exponent mod N`; `base` must be below N.
    func power(_ base: APBigUInt, _ exponent: APBigUInt) -> APBigUInt {
        precondition(base < modulus, "base must be reduced")
        let one = padded(APBigUInt(1).limbs)
        let montBase = multiply(padded(base.limbs), r2)
        var accumulator = multiply(one, r2)
        var index = exponent.bitWidth - 1
        while index >= 0 {
            accumulator = multiply(accumulator, accumulator)
            if exponent.bit(index) {
                accumulator = multiply(accumulator, montBase)
            }
            index -= 1
        }
        return APBigUInt(limbs: multiply(accumulator, one))
    }

    /// `a * b mod N` for `a, b < N`.
    func multiplyModulo(_ a: APBigUInt, _ b: APBigUInt) -> APBigUInt {
        precondition(a < modulus && b < modulus, "operands must be reduced")
        let montA = multiply(padded(a.limbs), r2)
        let product = multiply(montA, padded(b.limbs))
        return APBigUInt(limbs: product)
    }

    /// `a - b mod N` for `a, b < N`.
    func subtractModulo(_ a: APBigUInt, _ b: APBigUInt) -> APBigUInt {
        a < b ? (a + modulus) - b : a - b
    }

    private func padded(_ limbs: [UInt32]) -> [UInt32] {
        limbs.count >= size ? Array(limbs.prefix(size)) : limbs + [UInt32](repeating: 0, count: size - limbs.count)
    }

    /// Montgomery product a·b·R⁻¹ mod N.
    private func multiply(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        let s = size
        var t = [UInt32](repeating: 0, count: s + 2)
        for i in 0..<s {
            var carry: UInt64 = 0
            let bi = UInt64(b[i])
            for j in 0..<s {
                let x = UInt64(t[j]) + UInt64(a[j]) * bi + carry
                t[j] = UInt32(truncatingIfNeeded: x)
                carry = x >> 32
            }
            var x = UInt64(t[s]) + carry
            t[s] = UInt32(truncatingIfNeeded: x)
            t[s + 1] = UInt32(truncatingIfNeeded: x >> 32)

            let m = UInt64(t[0] &* nPrime)
            x = UInt64(t[0]) + m * UInt64(n[0])
            carry = x >> 32
            for j in 1..<s {
                x = UInt64(t[j]) + m * UInt64(n[j]) + carry
                t[j - 1] = UInt32(truncatingIfNeeded: x)
                carry = x >> 32
            }
            x = UInt64(t[s]) + carry
            t[s - 1] = UInt32(truncatingIfNeeded: x)
            carry = x >> 32
            t[s] = t[s + 1] &+ UInt32(truncatingIfNeeded: carry)
            t[s + 1] = 0
        }
        var result = Array(t.prefix(s + 1))
        if APBigUInt.compare(result, n) >= 0 {
            result = APBigUInt.subtract(result, n)
        }
        return Array(result.prefix(s))
    }
}
