// LOGZ.IO GRAFANA CHANGE
export let logzioDeprecatedAngularServices: any = (global as any).parent.__logzio__.services;
export let logzioServices: any = (global as any).parent.__logzio__.services;
export const logzioConfigs = new Proxy<any>({}, {
  get(target, prop) {
    return (window as any).logzio?.configs[prop];
  }
})
