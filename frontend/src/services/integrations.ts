import type { ConnectorType } from '../types/integrations';

export const CONNECTOR_NAMES: Record<ConnectorType, string> = {
  microsoft_sentinel: 'Microsoft Sentinel',
  microsoft_graph: 'Microsoft Entra / Graph',
  windows_wef: 'Windows / AD / WEF',
};
