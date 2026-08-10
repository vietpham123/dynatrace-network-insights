import { describe, it, expect } from "vitest";
import { classifyProvider, providerHue } from "./providers";

/* This function decides what a customer SEES next to every egress destination on the Investigate
   page, so a wrong answer is a wrong statement about their traffic, not a cosmetic slip. */

describe("classifyProvider", () => {
  it("does NOT claim 'Other' for an unresolved org — the label must read as unknown", () => {
    // Rendering an unresolved lookup as "Other" put it in the same bucket as genuinely
    // categorised-but-minor providers, which is the absence-as-verdict bug in label form: it
    // asserts we looked and found something ordinary, when in fact the lookup never resolved.
    const p = classifyProvider(undefined);
    expect(p.short).toBe("Unresolved");
    expect(p.category).toBe("unknown");
  });

  it("prefers the ASN over the org string when both are present", () => {
    // ASN is authoritative; org text is free-form and inconsistent across registries. If these
    // ever disagree the ASN must win, or one provider renders under two identities.
    const byAsn = classifyProvider("some misleading reseller name", 16509);
    const byName = classifyProvider("Amazon.com, Inc.");
    expect(byAsn.short).toBe(byName.short);
    expect(byAsn.category).toBe(byName.category);
  });

  it("strips registry noise from org strings", () => {
    // Team Cymru returns e.g. "AS16509 - AMAZON-02, US"; the "AS… - " prefix and trailing country
    // are registry formatting, not part of the provider's name.
    expect(classifyProvider("AS16509 - AMAZON-02, US").short).not.toContain(" - ");
    expect(classifyProvider("AS16509 - AMAZON-02, US").short).not.toMatch(/, US$/);
  });

  it("always returns a renderable icon, label and initials", () => {
    // Every field here is rendered unconditionally. An undefined reaching the DOM is a blank chip
    // that reads as "no provider" rather than "unknown provider".
    for (const input of [undefined, "", "Totally Unknown Org Ltd", "Amazon.com, Inc."]) {
      const p = classifyProvider(input);
      expect(p.icon).toBeTruthy();
      expect(p.label).toBeTruthy();
      expect(p.initials).toBeTruthy();
      expect(p.initials).not.toBe("");
    }
  });

  it("derives initials safely from punctuation-only and single-word names", () => {
    expect(classifyProvider("!!!").initials).toBeTruthy();
    expect(classifyProvider("Cloudflare").initials).toHaveLength(2);
  });
});

describe("providerHue", () => {
  it("is stable for the same name — a provider keeps its colour between renders and pages", () => {
    expect(providerHue("Amazon")).toBe(providerHue("Amazon"));
  });

  it("always returns a colour, including for the empty name", () => {
    expect(providerHue("")).toMatch(/^#[0-9a-f]{6}$/i);
  });
});
