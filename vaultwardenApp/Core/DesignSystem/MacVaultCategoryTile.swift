import SwiftUI

/// A main section at the top of the Mac and iPad sidebar, as in Passwords: the glyph
/// in a colored circle, the count, and the name. Selected, it fills with the accent.
struct VaultSidebarTile: View {
    let title: String
    let icon: String
    let color: Color
    let count: Int
    let isSelected: Bool
    let action: () -> Void

    #if os(macOS)
    private let circle: CGFloat = 24
    private let glyph: Font = .system(size: 12, weight: .semibold)
    private let padding: CGFloat = 8
    private let radius: CGFloat = 10
    #else
    @ScaledMetric(relativeTo: .body) private var circle: CGFloat = 28
    private let glyph: Font = .subheadline.weight(.semibold)
    private let padding: CGFloat = 10
    private let radius: CGFloat = 12
    #endif

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .center, spacing: 4) {
                    Image(systemName: icon)
                        .font(glyph)
                        .foregroundStyle(isSelected ? AnyShapeStyle(.tint) : AnyShapeStyle(.white))
                        .frame(width: circle, height: circle)
                        .background(isSelected ? AnyShapeStyle(.white) : AnyShapeStyle(color.gradient), in: .circle)
                    Spacer(minLength: 0)
                    Text(count, format: .number)
                        .font(.body.weight(.semibold))
                        .monospacedDigit()
                        .foregroundStyle(isSelected ? AnyShapeStyle(.white) : AnyShapeStyle(.secondary))
                        .contentTransition(.numericText(value: Double(count)))
                }
                Text(title)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(isSelected ? AnyShapeStyle(.white) : AnyShapeStyle(.secondary))
                    .lineLimit(1)
                    .minimumScaleFactor(0.85)
            }
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                isSelected ? AnyShapeStyle(.tint) : AnyShapeStyle(.fill.tertiary),
                in: .rect(cornerRadius: radius, style: .continuous)
            )
            .contentShape(.rect(cornerRadius: radius, style: .continuous))
        }
        .buttonStyle(VaultSidebarTileButtonStyle())
        .accessibilityLabel(title)
        .accessibilityValue(Text(count, format: .number))
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}

private struct VaultSidebarTileButtonStyle: ButtonStyle {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed && !reduceMotion ? 0.97 : 1)
            .brightness(configuration.isPressed ? -0.04 : 0)
            .animation(.snappy(duration: 0.18), value: configuration.isPressed)
    }
}

/// A source-list row on the Mac and iPad: the section's glyph, then its name.
struct VaultSidebarLabel: View {
    let title: String
    let icon: String
    let color: Color

    var body: some View {
        Label {
            Text(title)
                .lineLimit(1)
        } icon: {
            Image(systemName: icon)
                .foregroundStyle(color)
        }
    }
}

/// A smart-section tile on the iPhone home screen, in the manner of Reminders and
/// Passwords: the glyph in a colored circle, the count, and the name.
struct VaultCategoryTile: View {
    let title: String
    let icon: String
    let color: Color
    let count: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                Image(systemName: icon)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.white)
                    .frame(width: 34, height: 34)
                    .background(color.gradient, in: .circle)
                    .accessibilityHidden(true)
                Spacer(minLength: 8)
                Text(count, format: .number)
                    .font(.title2.bold())
                    .fontDesign(.rounded)
                    .monospacedDigit()
                    .foregroundStyle(.primary)
                    .contentTransition(.numericText(value: Double(count)))
            }
            Text(title)
                .font(.headline)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.vaultCard, in: .rect(cornerRadius: 16))
        .contentShape(.rect(cornerRadius: 16))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
        .accessibilityValue(Text(count, format: .number))
    }
}
