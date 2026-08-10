import React from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { t, mono } from "../theme";
import { Panel, StatTile, Tag } from "../components/ui";
import { useDavis, problemLink } from "../lib/data";

const chip = (fg: string, bg: string, label: string) => (
  <span style={{ fontSize: 12, fontWeight: 600, padding: "3px 9px", borderRadius: 6, color: fg, background: bg }}>{label}</span>
);

export const Alerts = () => {
  const q = useDavis();
  const rows: any[] = q.rows;
  const active = rows.filter((r) => r.status === "ACTIVE").length;

  return (
    <Flex flexDirection="column" gap={16} padding={24} style={{ maxWidth: 1100 }}>
      <div>
        <Heading level={2}>Alerts</Heading>
        <Paragraph>One root cause per incident — downstream symptoms suppressed. Last 24h.</Paragraph>
      </div>

      <Flex gap={12} flexWrap="wrap">
        <StatTile label="Active" value={active} sub="open now" accent={active ? t.down : t.up} />
        <StatTile label="Root-caused (24h)" value={rows.length} sub="one per incident" accent={t.accent} />
        <StatTile label="Correlation" value="root cause" sub="symptoms suppressed" accent={t.up} />
      </Flex>

      <Panel title="Root-caused network problems" tag={<Tag>Davis</Tag>}>
        {q.isLoading ? (
          <Text style={{ color: t.subtle }}>Loading…</Text>
        ) : q.error ? (
          <Text style={{ color: t.down }}>Query error: {String((q.error as any)?.message ?? q.error)}</Text>
        ) : rows.length === 0 ? (
          <Text style={{ color: t.subtle }}>All clear — no root-caused network problems in the last 24h.</Text>
        ) : (
          <Flex flexDirection="column">
            {rows.map((r, i) => {
              const isActive = r.status === "ACTIVE";
              return (
                <Flex key={i} gap={12} alignItems="flex-start" style={{ padding: "13px 4px", borderBottom: `1px solid ${t.border}` }}>
                  <div style={{ width: 4, alignSelf: "stretch", borderRadius: 3, background: isActive ? t.down : t.subtle, flex: "none" }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <Text style={{ fontWeight: 650, fontSize: 14 }}>{r.name}</Text>
                    {i === 0 ? (
                      <div style={{ color: t.subtle, fontSize: 13, margin: "4px 0 8px" }}>
                        The root-cause analysis correlated these signals into one problem and named the cause. Downstream devices that lost their uplink are suppressed as symptoms, not paged separately.
                      </div>
                    ) : null}
                    <Flex gap={8} flexWrap="wrap" style={{ marginTop: 6 }}>
                      {r.root ? chip(t.down, t.downBg, `root · ${r.root}`) : null}
                      {chip(isActive ? t.warn : t.subtle, isActive ? t.warnBg : t.cardSubtle, r.status)}
                      {chip(t.subtle, t.cardSubtle, r.cat || "AVAILABILITY")}
                      {problemLink(r.pid) ? (
                        <a href={problemLink(r.pid)} target="_top" style={{ ...mono, fontSize: 12, color: t.accent, alignSelf: "center", textDecoration: "none" }}>{r.id} ↗</a>
                      ) : (
                        <span style={{ ...mono, fontSize: 12, color: t.subtle, alignSelf: "center" }}>{r.id}</span>
                      )}
                    </Flex>
                  </div>
                </Flex>
              );
            })}
          </Flex>
        )}
      </Panel>
      <Text style={{ color: t.subtle, fontSize: 13 }}>
        Related availability events are correlated into a single root-caused problem — downstream devices are suppressed as symptoms, not paged separately.
      </Text>
    </Flex>
  );
};
