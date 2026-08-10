// Generated from workflows/detectors.json — the detector payloads the Detection card
// installs via the provision function (createDetectors). executionSettings:{} lets the API
// fill the actor, so nothing tenant-specific is baked in. Regenerate from detectors.json.
//
// RECONCILED 2026-07-29: the unified "CNO - Network RCA" workflow now owns all STATE detection —
// device-unreachable, interface-operationally-down, and PDU/power-lost were deleted (redundant,
// and consolidated + root-caused by the workflow instead of firing raw per-signal alerts). What
// remains here is the ONE detector that watches a signal a state model can't see: interface
// ERROR rate (a healthy, up interface throwing CRCs). It needs the extension to emit
// cno.if.in_errors.count.
export const DETECTOR_DEFS: { title: string; signature: string; payload: any }[] = [
  {
    "title": "CNO - Interface error burst",
    "signature": "bad-link",
    "payload": {
      "schemaId": "builtin:davis.anomaly-detectors",
      "scope": "environment",
      "value": {
        "analyzer": {
          "input": [
            {
              "key": "query",
              "value": "timeseries errs=sum(cno.if.in_errors.count, rate:1m), by:{sys_name, if_descr, `device.address`}"
            },
            {
              "key": "threshold",
              "value": "60"
            },
            {
              "key": "alertCondition",
              "value": "ABOVE"
            },
            {
              "key": "alertOnMissingData",
              "value": "false"
            },
            {
              "key": "violatingSamples",
              "value": "3"
            },
            {
              "key": "slidingWindow",
              "value": "5"
            },
            {
              "key": "dealertingSamples",
              "value": "5"
            }
          ],
          "name": "dt.statistics.ui.anomaly_detection.StaticThresholdAnomalyDetectionAnalyzer"
        },
        "description": "Interface accumulating errors at a high rate (dirty optic / CRC). Signature: bad-link.",
        "enabled": true,
        "eventTemplate": {
          "properties": [
            {
              "key": "event.name",
              "value": "Interface error burst"
            },
            {
              "key": "event.description",
              "value": "Interface accumulating errors at a high rate (dirty optic / CRC). Signature: bad-link."
            },
            {
              "key": "event.type",
              "value": "CUSTOM_ALERT"
            },
            {
              "key": "cno.signature",
              "value": "bad-link"
            }
          ]
        },
        "source": "cno",
        "title": "CNO - Interface error burst",
        "executionSettings": {}
      }
    }
  }
];
