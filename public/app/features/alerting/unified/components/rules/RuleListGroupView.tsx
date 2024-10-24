import React, { useEffect, useMemo } from 'react';

import { CombinedRuleNamespace } from 'app/types/unified-alerting';

import { LogMessages, logInfo } from '../../Analytics';
import { AlertingAction } from '../../hooks/useAbilities';
import { isCloudRulesSource, isGrafanaRulesSource } from '../../utils/datasource';
import { Authorize } from '../Authorize';

// import { CloudRules } from './CloudRules'; // LOGZ.IO GRAFANA CHANGE :: hide cloud managed alerts
import { GrafanaRules } from './GrafanaRules';

interface Props {
  namespaces: CombinedRuleNamespace[];
  expandAll: boolean;
}

export const RuleListGroupView = ({ namespaces, expandAll }: Props) => {
  const [grafanaNamespaces /*, cloudNamespaces LOGZ.IO Change */] = useMemo(() => {
    const sorted = namespaces
      .map((namespace) => ({
        ...namespace,
        groups: namespace.groups.sort((a, b) => a.name.localeCompare(b.name)),
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
    return [
      sorted.filter((ns) => isGrafanaRulesSource(ns.rulesSource)),
      sorted.filter((ns) => isCloudRulesSource(ns.rulesSource)),
    ];
  }, [namespaces]);

  useEffect(() => {
    logInfo(LogMessages.loadedList);
  }, []);

  return (
    <>
      <Authorize actions={[AlertingAction.ViewAlertRule]}>
        <GrafanaRules namespaces={grafanaNamespaces} expandAll={expandAll} />
      </Authorize>
      {// LOGZ.IO Changes
      /* <Authorize actions={[AccessControlAction.AlertingRuleExternalRead]}>
        <CloudRules namespaces={cloudNamespaces} expandAll={expandAll} />
      </Authorize> */}
    </>
  );
};
