import { Component } from 'react';
import type { ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { Shell } from './components/Shell';
import { WorkspaceProvider } from './components/WorkspaceProvider';
import { PublicAnalytics } from './components/PublicAnalytics';
import { Button, EmptyState, LinkButton, PageHeader } from './components/ui';
import { AlertDetailPage } from './pages/AlertDetailPage';
import { AlertsPage } from './pages/AlertsPage';
import { DashboardPage } from './pages/DashboardPage';
import { EventsPage, EventDetailPage } from './pages/EventsPage';
import { EvidencePage } from './pages/EvidencePage';
import { ReplayPage } from './pages/ReplayPage';
import { RuleDetailPage, RulesPage } from './pages/RulesPage';
import { SigmaPage } from './pages/SigmaPage';
import { TestingPage } from './pages/TestingPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { NotificationsPage, DeliveryDetailPage } from './pages/NotificationsPage';

class RenderBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    if (this.state.failed) {
      return (
        <main className="render-error">
          <h1>This page could not be rendered</h1>
          <p role="alert">
            The application received an unexpected response or encountered a rendering error. No
            success has been assumed. Reload the workspace and check the backend if this continues.
          </p>
          <Button onClick={() => window.location.reload()}>Reload workspace</Button>
        </main>
      );
    }
    return this.props.children;
  }
}

function NotFoundPage() {
  return (
    <>
      <PageHeader
        title="Page not found"
        description="This address does not belong to a SentinelFlow workbench."
      />
      <EmptyState
        title="Return to the investigation"
        description="Use the workspace navigation or return to the overview."
        action={<LinkButton to="/">Open overview</LinkButton>}
      />
    </>
  );
}

function RouteRedirect({ pathname }: { pathname: string }) {
  const location = useLocation();
  return <Navigate replace to={{ pathname, search: location.search }} />;
}

function RuleDetailRoute() {
  const { id } = useParams();
  return <RuleDetailPage key={id} />;
}

export function App() {
  return (
    <RenderBoundary>
      <WorkspaceProvider>
        <PublicAnalytics />
        <Routes>
          <Route element={<Shell />}>
            <Route index element={<DashboardPage />} />
            <Route path="dashboard" element={<RouteRedirect pathname="/" />} />
            <Route path="detections" element={<RouteRedirect pathname="/testing" />} />
            <Route path="events" element={<EventsPage />} />
            <Route path="events/:id" element={<EventDetailPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="alerts/:id" element={<AlertDetailPage />} />
            <Route path="rules" element={<RulesPage />} />
            <Route path="rules/:id" element={<RuleDetailRoute />} />
            <Route path="testing" element={<TestingPage />} />
            <Route path="replay" element={<ReplayPage />} />
            <Route path="sigma" element={<SigmaPage />} />
            <Route path="evidence" element={<EvidencePage />} />
            <Route path="integrations" element={<IntegrationsPage />} />
            <Route path="notifications" element={<NotificationsPage />} />
            <Route path="notifications/:id" element={<DeliveryDetailPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </WorkspaceProvider>
    </RenderBoundary>
  );
}
