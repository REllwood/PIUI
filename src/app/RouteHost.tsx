import { ActivityRoute } from '../features/activity/ActivityRoute';
import { ConversationRoute } from '../features/conversation/ConversationRoute';
import { SessionsRoute } from '../features/sessions/SessionsRoute';
import { SettingsRoute } from '../features/settings/SettingsRoute';
import { useProduct } from './ProductContext';

export function RouteHost({ approvalRequest = 0 }: Readonly<{ approvalRequest?: number }>) {
  const { route } = useProduct();
  if (route === 'sessions') return <SessionsRoute />;
  if (route === 'activity') return <ActivityRoute />;
  if (route === 'settings') return <SettingsRoute />;
  return <ConversationRoute approvalRequest={approvalRequest} />;
}
