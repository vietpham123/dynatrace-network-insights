import React from "react";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { t, mono } from "../theme";
import { Panel, Tag } from "../components/ui";
import { useEvents } from "../lib/data";

import { fmt, badge } from "../lib/format";

export const Events = () => {
  const q = useEvents();
  const rows: any[] = q.rows;

  return (
    <Flex flexDirection="column" gap={16} padding={24} style={{ maxWidth: 1000 }}>
      <div>
        <Heading level={2}>Events — traps · syslog · config</Heading>
        <Paragraph>The fast paging channels, live from Grail — seconds, not the poll interval. Three independent evidence planes.</Paragraph>
      </div>

      <Panel title="Live stream" tag={<Tag>live</Tag>}>
        {q.isLoading ? (
          <Text style={{ color: t.subtle }}>Loading…</Text>
        ) : q.error ? (
          <Text style={{ color: t.down }}>Query error: {String((q.error as any)?.message ?? q.error)}</Text>
        ) : rows.length === 0 ? (
          <Text style={{ color: t.subtle }}>No events in the last 24h.</Text>
        ) : (
          <Flex flexDirection="column">
            {rows.map((r, i) => {
              const [label, color] = badge(r.source);
              return (
                <Flex key={i} gap={12} alignItems="baseline" style={{ padding: "7px 4px", borderBottom: `1px solid ${t.border}` }}>
                  <Text style={{ ...mono, color: t.subtle, fontSize: 13, minWidth: 108 }}>{fmt(r.timestamp)}</Text>
                  <Text style={{ ...mono, color, fontWeight: 700, fontSize: 13, minWidth: 58 }}>{label}</Text>
                  <Text style={{ ...mono, color: t.subtle, fontSize: 14, minWidth: 130 }}>{r.dev}</Text>
                  <Text style={{ ...mono, fontSize: 14 }}>{r.content}</Text>
                </Flex>
              );
            })}
          </Flex>
        )}
      </Panel>
    </Flex>
  );
};
