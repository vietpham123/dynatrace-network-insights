import Colors from "@dynatrace/strato-design-tokens/colors";

// Theme-aware tokens (resolve to CSS vars that switch light/dark with the tenant).
export const t = {
  card: Colors.Background.Container.Neutral.Default,
  cardSubtle: Colors.Background.Container.Neutral.Subdued,
  emph: Colors.Background.Container.Neutral.Emphasized,
  surface: Colors.Background.Surface.Default,
  border: Colors.Border.Neutral.Default,
  ink: Colors.Text.Neutral.Default,
  subtle: Colors.Text.Neutral.Subdued,
  accent: Colors.Text.Primary.Default,
  accentBg: Colors.Background.Container.Primary.Default,
  up: Colors.Text.Success.Default,
  warn: Colors.Text.Warning.Default,
  down: Colors.Text.Critical.Default,
  upBg: Colors.Background.Container.Success.Default,
  warnBg: Colors.Background.Container.Warning.Default,
  downBg: Colors.Background.Container.Critical.Default,
};

export const mono = {
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
  fontVariantNumeric: "tabular-nums",
} as const;
