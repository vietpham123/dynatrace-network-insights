/* ============================================================================
   THE ONE DEFINITION OF "IS THIS DEVICE REPORTING".

   Its own module, with NO imports, on purpose. It first lived in data.ts, which
   lifecycle.ts then imported — but data.ts already imports from lifecycle.ts, so that closed a
   cycle. Module-scope constants in lifecycle.ts call this at evaluation time, and on a cycle the
   binding is still undefined when they run: the app died on load with
   "B5e is not a function", shipped as v1.1.0. Type-checking and unit tests both passed, because
   a circular import is a runtime initialisation order problem and nothing here renders the app.

   A leaf module cannot participate in a cycle. Keep it dependency-free.
   ========================================================================= */

// A DEVICE WITHOUT INTERFACES IS STILL A DEVICE.
//
// Keying on `cno.if.oper_status` alone silently defines "the fleet" as "things with an ifTable".
// A UPS or PDU has none — and since the 0.0.14 feature-set migration they are correctly no longer
// polled for one, because a real CyberPower RMCARD answers GetNext in 68 ms and never answers
// GetBulk. So they vanish from any consumer that asks for interfaces.
//
// `cno.device.uptime` is sysUpTime from MIB-II: every SNMP agent answers it and it sits in the
// extension's DEFAULT feature set, so it is the one signal a UPS, a PDU and a switch all emit. It
// cannot simply REPLACE the interface key — API-sourced SD-WAN devices emit `cno.if.oper_status`
// with source=sdwan-api and no uptime at all — so it has to be a union of both.
//
// ALWAYS `append`, NEVER a multi-aggregate `timeseries { a=…, b=… }`. That form inner-joins on the
// by-dimensions and drops any device missing either metric, which is the exact bug this exists to
// fix. It has bitten this codebase five times.
export const livenessUnion = (window: string, by: string, fields: string) =>
  `timeseries upt=count(cno.device.uptime), by:{${by}}, from:${window}
| fields ${fields}, n=arraySum(upt)
| append [ timeseries seen=count(cno.if.oper_status), by:{${by}}, from:${window}
           | fields ${fields}, n=arraySum(seen) ]`;
