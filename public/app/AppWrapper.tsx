import { Action, KBarProvider } from 'kbar';
import React, { ComponentType } from 'react';
import { Provider } from 'react-redux';
import { Router, Redirect, Switch, RouteComponentProps } from 'react-router-dom';
import { CompatRouter, CompatRoute } from 'react-router-dom-v5-compat';

// import { productLoaded  } from '@grafana/data';
import { config, locationService, navigationLogger, reportInteraction } from '@grafana/runtime';
import { ErrorBoundaryAlert, GlobalStyles, ModalRoot, ModalsProvider, PortalContainer } from '@grafana/ui';
import { getAppRoutes } from 'app/routes/routes';
import { store } from 'app/store/store';

import { AngularRoot } from './angular/AngularRoot';
import { loadAndInitAngularIfEnabled } from './angular/loadAndInitAngularIfEnabled';
import { GrafanaApp } from './app';
import { AppChrome } from './core/components/AppChrome/AppChrome';
import { AppNotificationList } from './core/components/AppNotifications/AppNotificationList';
import { GrafanaContext } from './core/context/GrafanaContext';
import { GrafanaRoute } from './core/navigation/GrafanaRoute';
import { RouteDescriptor } from './core/navigation/types';
import { contextSrv } from './core/services/context_srv';
import { ThemeProvider } from './core/utils/ConfigProvider';
import { LiveConnectionWarning } from './features/live/LiveConnectionWarning';

interface AppWrapperProps {
  app: GrafanaApp;
}

interface AppWrapperState {
  ready?: boolean;
}

/** Used by enterprise */
let bodyRenderHooks: ComponentType[] = [];
let pageBanners: ComponentType[] = [];

export function addBodyRenderHook(fn: ComponentType) {
  bodyRenderHooks.push(fn);
}

export function addPageBanner(fn: ComponentType) {
  pageBanners.push(fn);
}

export class AppWrapper extends React.Component<AppWrapperProps, AppWrapperState> {
  constructor(props: AppWrapperProps) {
    super(props);
    this.state = {};
  }

  async componentDidMount() {
    await loadAndInitAngularIfEnabled();
    this.setState({ ready: true });

    // LOGZ.IO GRAFANA CHANGE :: Let app know that grafana loaded successfully
    setTimeout(() => {
      const { resolve } = (window as any).logzio.productLoaded;
      if (resolve) {
        resolve();
      }
    }, 10)
    // LOGZ.IO GRAFANA CHANGE :: end

    $('.preloader').remove();
  }

  renderRoute = (route: RouteDescriptor) => {
    const roles = route.roles ? route.roles() : [];

    return (
      <CompatRoute
        exact={route.exact === undefined ? true : route.exact}
        sensitive={route.sensitive === undefined ? false : route.sensitive}
        path={route.path}
        key={route.path}
        render={(props: RouteComponentProps) => {
          // TODO[Router]: test this logic
          if (roles?.length) {
            if (!roles.some((r: string) => contextSrv.hasRole(r))) {
              return <Redirect to="/" />;
            }
          }

          return <GrafanaRoute {...props} route={route} />;
        }}
      />
    );
  };

  renderRoutes() {
    return <Switch>{getAppRoutes().map((r) => this.renderRoute(r))}</Switch>;
  }

  render() {
    const { app } = this.props;
    const { ready } = this.state;

    navigationLogger('AppWrapper', false, 'rendering');

    const commandPaletteActionSelected = (action: Action) => {
      reportInteraction('command_palette_action_selected', {
        actionId: action.id,
        actionName: action.name,
      });
    };

    return (
      <Provider store={store}>
        <ErrorBoundaryAlert style="page">
          <GrafanaContext.Provider value={app.context}>
            <ThemeProvider value={config.theme2}>
              <KBarProvider
                actions={[]}
                options={{ enableHistory: true, callbacks: { onSelectAction: commandPaletteActionSelected } }}
              >
                <ModalsProvider>
                  <GlobalStyles />
                  <div className="grafana-app">
                    <Router history={locationService.getHistory()}>
                      <CompatRouter>
                        <AppChrome>
                          {pageBanners.map((Banner, index) => (
                            <Banner key={index.toString()} />
                          ))}
                          <AngularRoot />
                          <AppNotificationList />
                          {ready && this.renderRoutes()}
                          {bodyRenderHooks.map((Hook, index) => (
                            <Hook key={index.toString()} />
                          ))}
                        </AppChrome>
                      </CompatRouter>
                    </Router>
                  </div>
                  <LiveConnectionWarning />
                  <ModalRoot />
                  <PortalContainer />
                </ModalsProvider>
              </KBarProvider>
            </ThemeProvider>
          </GrafanaContext.Provider>
        </ErrorBoundaryAlert>
      </Provider>
    );
  }
}
