import { Page } from "@dynatrace/strato-components-preview/layouts";
import { Flex } from "@dynatrace/strato-components/layouts";
import React from "react";
import { Route, Routes } from "react-router-dom";
import { Data } from "./pages/Data";
import { Header } from "./components/Header";
import { Sidebar } from "./components/Sidebar";
import { Overview } from "./pages/Overview";
import { ConfigChanges } from "./pages/ConfigChanges";
import { Devices } from "./pages/Devices";
import { Events } from "./pages/Events";
import { Topology } from "./pages/Topology";
import { Alerts } from "./pages/Alerts";
import { DeviceDetail } from "./pages/DeviceDetail";
import { Configure } from "./pages/Configure";
import { Wizard } from "./pages/Wizard";
import { Configuration } from "./pages/Configuration";
import { NetFlow } from "./pages/NetFlow";
import { Investigate } from "./pages/Investigate";
import { TimeframeProvider, TimeframeBar } from "./lib/timeframe";

export const App = () => {
  return (
    <TimeframeProvider>
    <Page>
      <Page.Header>
        <Header />
      </Page.Header>
      <Page.Main>
        <Flex flexDirection="row" alignItems="stretch">
          <Sidebar />
          <div style={{ flex: 1, minWidth: 0 }}>
            <TimeframeBar />
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/devices" element={<Devices />} />
              <Route path="/device/:name" element={<DeviceDetail />} />
              <Route path="/topology" element={<Topology />} />
              <Route path="/netflow" element={<NetFlow />} />
              <Route path="/investigate" element={<Investigate />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/configuration" element={<Configuration />} />
              <Route path="/setup" element={<Wizard />} />
              <Route path="/configure" element={<Configure />} />
              <Route path="/config" element={<ConfigChanges />} />
              <Route path="/events" element={<Events />} />
              <Route path="/data" element={<Data />} />
            </Routes>
          </div>
        </Flex>
      </Page.Main>
    </Page>
    </TimeframeProvider>
  );
};
