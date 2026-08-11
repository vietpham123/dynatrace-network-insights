import React from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Text } from "@dynatrace/strato-components/typography";
import { t } from "../theme";
import { retireDevicePolling, refreshConfigured } from "../lib/provision";
import { useAcknowledgedDevices } from "../lib/lifecycle";

/* ── RETIRE, AND WHY IT LIVES ON THE DEVICE PAGE ─────────────────────────────
   This used to be an inline action on every row of the Devices table — a list people scan,
   filter and sort. Retiring withdraws the monitoring configuration from EVERY extension holding
   the device, so polling stops — and the undo is re-onboarding rather than a click, because the
   app does not retain the credential needed to recreate the configuration.
   One mis-aimed cursor in a dense table was all it took.

   It now lives on the device's own page. To retire something you must open it, which means you
   have necessarily seen its name, address, site, role and current state on the way. That is a
   step BEFORE the decision rather than another dialog after it.

   `hide` deliberately stayed on the row and is now removed entirely — see below.

   WHY NOT ROLE-BASED ACCESS. Considered and rejected as the primary guard. The app function
   authenticates as the APP, so every user of the app already carries its write permission;
   gating the UI by role needs an extra scope and still only hides a button, since the function
   would act if called directly. The risk being managed here is an accidental click, and friction
   is the proportionate answer to that.

   THE ASYMMETRY IS THE POINT. If every action carries the same friction, the friction stops
   meaning anything and people learn to click through it — at which point it protects nothing. */

type Device = { ip: string; name: string; label: string; status: string };

export function RetireAction({ device, onRetired }: { device: Device; onRetired?: () => void }) {
  const [confirming, setConfirming] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [msg, setMsg] = React.useState<{ tone: "ok" | "err"; msg: string } | null>(null);
  const { acknowledge } = useAcknowledgedDevices();

  async function doRetire() {
    setBusy(true);
    const res = await retireDevicePolling({ ip: device.ip, name: device.name });
    setBusy(false);
    setConfirming(false);
    if (!res.ok && !res.removed?.length) {
      setMsg({ tone: "err", msg: res.error || `Could not retire ${device.label}.` });
      return;
    }
    // Acknowledge REGARDLESS of how much intent came off. The configurations are gone or
    // shrinking, the entity cannot be deleted at all (405), and leaving the device on the live
    // fleet after the operator affirmed the retirement is the behaviour this exists to remove.
    //
    // NOTE this is the same flag the removed `hide` button used to set, which is the reason that
    // button could not simply be deleted along with its storage. As a RETIREMENT MARKER, shared
    // state is correct — a withdrawal is a fleet-wide fact, not one person's preference.
    acknowledge(device.ip);
    refreshConfigured();   // intent just changed on the tenant; the 60s cache would hide it
    const n = res.removed?.length ?? 0;
    setMsg(res.partial
      ? { tone: "err", msg: `Withdrawn from ${n} configuration${n === 1 ? "" : "s"}, but ${res.failed?.length} could not be updated — it may still be polled.` }
      : { tone: "ok", msg: `Retired — withdrawn from ${n} configuration${n === 1 ? "" : "s"}. It is on the Retired tab in Devices and can be restored from there.` });
    onRetired?.();
  }

  if (msg) {
    return (
      <div style={{ border: `1px solid ${msg.tone === "ok" ? t.up : t.down}44`,
                    background: msg.tone === "ok" ? t.upBg : t.downBg, borderRadius: 10, padding: "12px 14px" }}>
        <Text style={{ color: msg.tone === "ok" ? t.up : t.down, fontWeight: 600, display: "block" }}>
          {msg.tone === "ok" ? "Retired" : "Partly retired"}
        </Text>
        <Text style={{ color: t.subtle, fontSize: 13 }}>{msg.msg}</Text>
      </div>
    );
  }

  if (confirming) {
    return (
      <div style={{ border: `1px solid ${t.warn}55`, background: t.warnBg, borderRadius: 10, padding: "12px 14px" }}>
        <Flex flexDirection="column" gap={8}>
          <Text style={{ fontWeight: 700, color: t.warn }}>Retire {device.label}?</Text>
          <Text style={{ fontSize: 13, color: t.subtle }}>
            This removes {device.ip} from every monitoring configuration that polls it, so Dynatrace
            stops collecting from the device. It then appears only under <b>Retired</b> — not on
            Fleet, Overview or Topology.
            {device.status === "up" ? " This device is currently UP and reporting." : ""}
          </Text>
          <Text style={{ fontSize: 12.5, color: t.subtle }}>
            Historical data is kept, and the device entity remains in Dynatrace — entities cannot be
            deleted. You can restore it from the Retired tab, though restoring means re-onboarding
            rather than one click.
          </Text>
          <Flex gap={8} style={{ marginTop: 2 }}>
            <button onClick={() => void doRetire()} disabled={busy}
                    style={{ background: t.warn, color: "#fff", border: 0, borderRadius: 6,
                             padding: "6px 14px", fontSize: 13, fontWeight: 600,
                             cursor: busy ? "wait" : "pointer", opacity: busy ? 0.6 : 1 }}>
              {busy ? "Retiring…" : "Yes, retire it"}
            </button>
            <button onClick={() => setConfirming(false)} disabled={busy}
                    style={{ background: "none", border: `1px solid ${t.border}`, borderRadius: 6,
                             color: t.ink, padding: "6px 14px", fontSize: 13, cursor: "pointer" }}>
              Cancel
            </button>
          </Flex>
        </Flex>
      </div>
    );
  }

  return (
    <div style={{ border: `1px solid ${t.down}33`, background: t.downBg, borderRadius: 10, padding: "13px 15px" }}>
      <Text style={{ fontWeight: 700, color: t.down, display: "block", marginBottom: 3 }}>Retire this device</Text>
      <Text style={{ fontSize: 13, color: t.subtle, display: "block", marginBottom: 10 }}>
        Withdraws its monitoring configuration from every extension holding it, so polling stops.
        It stays on the Retired tab and can be restored — but restoring means re-onboarding, not
        one click.
      </Text>
      <button onClick={() => setConfirming(true)}
              style={{ background: "none", border: `1px solid ${t.down}`, borderRadius: 7,
                       color: t.down, padding: "5px 12px", fontSize: 13, cursor: "pointer" }}>
        Retire {device.label}…
      </button>
    </div>
  );
}
