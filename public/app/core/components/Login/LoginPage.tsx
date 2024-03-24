// Libraries
import { css } from '@emotion/css';
import React from 'react';

// Components
import { GrafanaTheme2 } from '@grafana/data';
import { config } from '@grafana/runtime';
import { Alert, HorizontalGroup, LinkButton, useStyles2 } from '@grafana/ui';
import { Branding } from 'app/core/components/Branding/Branding';
import { t } from 'app/core/internationalization';

import { ChangePassword } from '../ForgottenPassword/ChangePassword';

import LoginCtrl from './LoginCtrl';
import { LoginForm } from './LoginForm';
import { LoginLayout, InnerBox } from './LoginLayout';
import { LoginServiceButtons } from './LoginServiceButtons';
import { UserSignup } from './UserSignup';

export const LoginPage = () => {
  const styles = useStyles2(getStyles);
  document.title = Branding.AppTitle;

  return (
    <LoginCtrl>
      {({
        loginHint,
        passwordHint,
        disableLoginForm,
        disableUserSignUp,
        login,
        isLoggingIn,
        changePassword,
        skipPasswordChange,
        isChangingPassword,
        showDefaultPasswordWarning,
        loginErrorMessage,
      }) => (
        <LoginLayout isChangingPassword={isChangingPassword}>
          {!isChangingPassword && (
            <InnerBox>
              {loginErrorMessage && (
                <Alert className={styles.alert} severity="error" title={t('login.error.title', 'Login failed')}>
                  {loginErrorMessage}
                </Alert>
              )}

              {!disableLoginForm && (
                <LoginForm onSubmit={login} loginHint={loginHint} passwordHint={passwordHint} isLoggingIn={isLoggingIn}>
                  <HorizontalGroup justify="flex-end">
                    {!config.auth.disableLogin && (
                      <LinkButton
                        className={styles.forgottenPassword}
                        fill="text"
                        href={`${config.appSubUrl}/user/password/send-reset-email`}
                      >
                        Forgot your password?
                      </LinkButton>
                    )}
                  </HorizontalGroup>
                </LoginForm>
              )}
              <LoginServiceButtons />
              {!disableUserSignUp && <UserSignup />}
            </InnerBox>
          )}

          {isChangingPassword && (
            <InnerBox>
              <ChangePassword
                showDefaultPasswordWarning={showDefaultPasswordWarning}
                onSubmit={changePassword}
                onSkip={() => skipPasswordChange()}
              />
            </InnerBox>
          )}
        </LoginLayout>
      )}
    </LoginCtrl>
  );
};

const getStyles = (theme: GrafanaTheme2) => {
  return {
    forgottenPassword: css({
      padding: 0,
      marginTop: theme.spacing(0.5),
    }),

    alert: css({
      width: '100%',
    }),
  };
};
