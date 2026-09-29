import { useCallback, useEffect, useRef } from 'react';
import { Analytics } from '@vercel/analytics/react';
import type { BeforeSendEvent } from '@vercel/analytics/react';
import { useLocation } from 'react-router-dom';
import { useWorkspace } from '../hooks/workspace';
import {
  analyticsRoute,
  redactAnalyticsPageView,
  safeAnalyticsReferrer,
} from '../services/analytics';

export function PublicAnalytics() {
  const { publicDemo, health } = useWorkspace();
  const { pathname } = useLocation();
  const route = analyticsRoute(pathname);
  const enabled =
    import.meta.env.PROD &&
    import.meta.env.VITE_WEB_ANALYTICS === 'true' &&
    publicDemo &&
    health.data?.status === 'ok' &&
    !health.error &&
    route !== null &&
    safeAnalyticsReferrer(document.referrer);
  const allowed = useRef(false);
  allowed.current = enabled;
  useEffect(
    () => () => {
      allowed.current = false;
    },
    [],
  );
  const beforeSend = useCallback(
    (event: BeforeSendEvent) =>
      allowed.current ? redactAnalyticsPageView(event, window.location.origin) : null,
    [],
  );

  if (!enabled) return null;
  return (
    <Analytics
      mode="production"
      debug={false}
      route={route}
      path={route}
      beforeSend={beforeSend}
      scriptSrc="/_vercel/insights/script.js"
      viewEndpoint="/_vercel/insights/view"
      eventEndpoint="/_vercel/insights/event"
    />
  );
}
