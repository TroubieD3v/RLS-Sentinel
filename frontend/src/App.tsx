import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Shell } from "@/components/Shell";
import { Skeleton } from "@/design-system/ui";
import { AppProvider } from "@/state/app";

const Overview = lazy(() => import("@/pages/Overview"));
const Connections = lazy(() => import("@/pages/Connections"));
const SchemaExplorer = lazy(() => import("@/pages/Schema"));
const PolicyExplorer = lazy(() => import("@/pages/Policies"));
const MatrixPage = lazy(() => import("@/pages/Matrix"));
const GraphPage = lazy(() => import("@/pages/GraphPage"));
const TestStudio = lazy(() => import("@/pages/TestStudio"));
const FindingsPage = lazy(() => import("@/pages/Findings"));
const WhatIfPage = lazy(() => import("@/pages/WhatIfPage"));
const ReportsPage = lazy(() => import("@/pages/ReportsHistorySettings").then((m) => ({ default: m.ReportsPage })));
const HistoryPage = lazy(() => import("@/pages/ReportsHistorySettings").then((m) => ({ default: m.HistoryPage })));
const SettingsPage = lazy(() => import("@/pages/ReportsHistorySettings").then((m) => ({ default: m.SettingsPage })));

const client = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 4000, refetchOnWindowFocus: false } } });

function NotFound() {
  return <div className="card p-8 text-center"><h1 className="text-xl font-bold">Page not found</h1><p className="text-muted mt-1">Use the navigation to continue.</p></div>;
}

export default function App() {
  return (
    <QueryClientProvider client={client}>
      <AppProvider>
        <BrowserRouter>
          <Suspense fallback={<div className="p-6"><Skeleton className="h-8 w-64" /></div>}>
            <Routes>
              <Route element={<Shell />}>
                <Route index element={<Overview />} />
                <Route path="connections" element={<Connections />} />
                <Route path="schema" element={<SchemaExplorer />} />
                <Route path="policies" element={<PolicyExplorer />} />
                <Route path="matrix" element={<MatrixPage />} />
                <Route path="graph" element={<GraphPage />} />
                <Route path="studio" element={<TestStudio />} />
                <Route path="findings" element={<FindingsPage />} />
                <Route path="what-if" element={<WhatIfPage />} />
                <Route path="reports" element={<ReportsPage />} />
                <Route path="history" element={<HistoryPage />} />
                <Route path="settings" element={<SettingsPage />} />
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
          </Suspense>
        </BrowserRouter>
      </AppProvider>
    </QueryClientProvider>
  );
}
