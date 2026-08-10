import type { NetflowMode } from "./netflowMode";

/* Generates the OpenTelemetry Collector config for a NetFlow ingest mode. The base mirrors the real
   production Bindplane-managed cno-netflow pipeline (bearertokenauth + persistent sending_queue +
   retry + drop-raw transform + grpc/http); each mode layers on only its one processor. Env-var
   placeholders — never embeds a token. The custom netflow_v9_collector.py decoder must run in front
   (see the header) — it preserves the interface index the stock OTel netflow receiver drops.
   KEEP IN SYNC with scripts/gen_netflow_configs.js (the standalone Desktop generator — same template). */

const ENDPOINT_REF = "${env:DYNATRACE_OTLP_ENDPOINT}";
const TOKEN_REF = "${env:DYNATRACE_API_TOKEN}";

const LABEL: Record<NetflowMode, string> = { full: "FULL (every flow)", sampled: "SAMPLED (1-in-N)" };
const INTRO: Record<NetflowMode, (r: number) => string> = {
  full: () =>
`# Every decoded flow is forwarded — highest fidelity, highest volume/cost. Small fleets / forensics.
# App: NetFlow mode = Full (no extrapolation).`,
  sampled: (r: number) =>
`# Keeps 1 of every ${r} flow records — very high-rate links. Sampling is NOT transparent: the app
# multiplies volumes x${r} to extrapolate (set NetFlow mode = Sampled, rate ${r}). percentage = 100 / N.`,
};

function header(mode: NetflowMode, r: number): string {
  return `# ============================================================================
# NetFlow -> Dynatrace — OpenTelemetry Collector  ·  MODE: ${LABEL[mode]}
# ============================================================================
${INTRO[mode](r)}
#
# DECODER (every mode): run netflow_v9_collector.py IN FRONT — it decodes NetFlow v5/v9 AND IPFIX
#   (v10) on one port, and preserves the INPUT/OUTPUT_SNMP interface index the stock OTel netflow
#   receiver drops (needed for per-interface flows + drill-downs). It also resolves each public
#   destination to ASN / owner / rDNS at ingest, so egress views name real organisations instead
#   of bare addresses. It then POSTs OTLP to the receiver below:
#
#     python3 netflow_v9_collector.py --listen-port 2055 --otlp-host 127.0.0.1 --otlp-port 4318
#
#   Add --no-enrich to disable the ASN/rDNS lookups. They send PUBLIC destination addresses to the
#   host's resolver; private, loopback and link-local addresses are never looked up. Use it if
#   egress DNS is restricted or that lookup is not acceptable in your environment.
#
# Base mirrors the production Bindplane pipeline (bearertokenauth + persistent sending_queue + retry).
# Set as env vars where the collector runs:
#   DYNATRACE_OTLP_ENDPOINT   sprint:  https://<env>.sprint.dynatracelabs.com/api/v2/otlp
#                             SaaS:    https://<env>.live.dynatrace.com/api/v2/otlp
#                             Managed: https://<activegate-host>/e/<env>/api/v2/otlp
#   DYNATRACE_API_TOKEN       API token with scope  logs.ingest
# ============================================================================`;
}

export function collectorFilename(mode: NetflowMode): string {
  return `otel-collector-${mode}.yaml`;
}

export function generateCollectorYaml(mode: NetflowMode, rate: number): string {
  const r = rate > 0 ? Math.round(rate) : 100;
  let procDef = "";
  let procName = "";
  if (mode === "sampled") {
    procDef = `  probabilistic_sampler:\n    sampling_percentage: ${+(100 / r).toFixed(4)}        # = 1-in-${r}\n`;
    procName = "probabilistic_sampler, ";
  }
  return `${header(mode, r)}

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        keepalive:
          server_parameters: { max_connection_age: 1m0s, max_connection_age_grace: 5m0s, max_connection_idle: 1m0s }
        max_recv_msg_size_mib: 20
      http:
        endpoint: 0.0.0.0:4318        # netflow_v9_collector.py POSTs decoded flow here

  # sFlow — a DIFFERENT protocol, not a NetFlow version, so it needs its own receiver on its own
  # port. Packet sampling with XDR encoding rather than a flow cache with templates. Routers and
  # firewalls usually speak NetFlow/IPFIX; switches usually speak sFlow, so a real estate needs
  # both. Decoded natively here — unlike NetFlow, there is no decoder of ours in front of it.
  #
  # WORTH ENABLING BECAUSE IT SEES WHAT A ROUTER CANNOT. Two hosts on the same VLAN are switched
  # and never presented to a router, so no gateway export can ever show that traffic. Measured on
  # the reference deployment: an entire Ceph storage fabric was invisible until a switch exported.
  #
  # TWO COSTS, both worth stating to whoever reads this config. sFlow is ALWAYS sampled, so byte
  # counts are estimates scaled by the stated rate and a low-rate conversation may produce no
  # samples at all. And this receiver DROPS the ingress/egress interface fields, so sFlow yields
  # "this switch saw the conversation", never "on port 4" — the per-interface views stay
  # NetFlow-only unless you put a decoder in front.
  #
  # SWITCH-SIDE TRAPS, every one of which looks identical to "it just does not work":
  #   - the receiver Timeout is a LEASE that counts DOWN; 0 releases it, so an address with
  #     timeout 0 silently exports nothing and the UI looks correctly configured
  #   - the owner string must be set in the SAME apply as a non-zero timeout, or the claim drops
  #   - a sampler pointing at an unclaimed receiver index is REJECTED outright, not ignored
  #   - many switches refuse any sampling rate below 1024
  #   - leave the POLLER interval at 0: it emits interface counters that duplicate SNMP
  netflow/sflow:
    scheme: sflow
    hostname: 0.0.0.0
    port: 6343
    sockets: 1
    workers: 1
    send_raw: false

processors:
${procDef}  # drop the raw-record copy the receiver keeps — pure volume savings
  transform/drop-raw-copy:
    log_statements:
      - context: log
        statements:
          - delete_key(attributes, "log.record.original")

extensions:
  bearertokenauth/dynatrace:
    scheme: Api-Token
    token: ${TOKEN_REF}

exporters:
  otlphttp/dynatrace:
    endpoint: ${ENDPOINT_REF}
    auth:
      authenticator: bearertokenauth/dynatrace
    compression: gzip
    retry_on_failure: { enabled: true, initial_interval: 5s, max_interval: 30s, max_elapsed_time: 300s }
    # in-memory send-queue — survives tenant blips (not collector restarts). For restart-durable
    # buffering, add a file_storage extension with a WRITABLE dir + set  storage: file_storage/queue
    sending_queue:
      enabled: true
      num_consumers: 10
      queue_size: 5000

service:
  extensions: [bearertokenauth/dynatrace]
  pipelines:
    logs:
      receivers: [otlp, netflow/sflow]
      processors: [${procName}transform/drop-raw-copy]
      exporters: [otlphttp/dynatrace]
  telemetry:
    metrics:
      level: normal
      readers:
        # 8889, NOT the OTel default of 8888. Oxidized's web UI also defaults to 8888, and if you
        # co-locate them the collector loses the bind and refuses its ENTIRE config with
        # "failed to create meter provider: ... address already in use" — it then ships nothing
        # at all, which reads as a collector fault rather than a port clash. Hit on the reference
        # deployment 2026-08-03. Change it here or move Oxidized; do not leave both on 8888.
        - pull: { exporter: { prometheus: { host: localhost, port: 8889 } } }
`;
}
