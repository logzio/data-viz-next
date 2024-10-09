import { useAsync } from 'react-use';

import { PluginMeta } from '@grafana/data';
import { getPluginSettings } from 'app/features/plugins/pluginSettings';

import { PluginID } from '../components/PluginBridge';
import { SupportedPlugin } from '../types/pluginBridges';
interface PluginBridgeHookResponse {
  loading: boolean;
  installed?: boolean;
  error?: Error;
  settings?: PluginMeta<{}>;
}

export function usePluginBridge(plugin: PluginID): PluginBridgeHookResponse {
  if (plugin === SupportedPlugin.OnCall) {
    return { loading: false, installed: false};
  }
  const { loading, error, value } = useAsync(() => getPluginSettings(plugin, { showErrorAlert: false }));

  const installed = value && !error && !loading;
  const enabled = value?.enabled;
  const isLoading = loading && !value;

  if (isLoading) {
    return { loading: true };
  }

  if (!installed || !enabled) {
    return { loading: false, installed: false };
  }

  return { loading, installed: true, settings: value };
}
