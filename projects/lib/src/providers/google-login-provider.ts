import { BaseLoginProvider } from '../entities/base-login-provider';
import { SocialUser } from '../entities/social-user';
import { EventEmitter } from '@angular/core';
import { BehaviorSubject, map, ReplaySubject } from 'rxjs';
import { filter, skip, take } from 'rxjs/operators';

export interface GoogleInitOptions {
  /**
   * enables the One Tap mechanism, and makes auto-login possible
   */
  oneTapEnabled?: boolean;

  /**
   * Allow the browser to control user sign-in prompts and mediate the
   * sign-in flow between your website and Google. Defaults to false.
   */
  useFedCMForPrompt?: boolean;

  /**
   * list of permission scopes to grant in case we request an access token
   */
  scopes?: string | string[];

  /**
   * Optional, defaults to 'select_account'.
   * A space-delimited, case-sensitive list of prompts to present the
   * user.
   * Possible values are:
   * empty string The user will be prompted only the first time your
   *     app requests access. Cannot be specified with other values.
   * 'none' Do not display any authentication or consent screens. Must
   *     not be specified with other values.
   * 'consent' Prompt the user for consent.
   * 'select_account' Prompt the user to select an account.
   */
  prompt? : '' | 'none' | 'consent' | 'select_account';

  /**
   * Optional, defaults to 'popup'
   * UX mode specified by Google, if using 'redirect' you must have a backend server setup to handle the request
   * Possible values are:
   * popup - Show the login form in a popup window
   * redirect - Show the login form in the same window
   */
  uxMode?: 'popup' | 'redirect'

  /**
   * Sets the title and message in the One Tap prompt
   * Available contexts:
   *   signin "Sign in with Google"
   *   signup "Sign up with Google"
   *   use    "Use with Google"
   */
  context?: 'signin' | 'signup' | 'use';

  /**
   * The URL of your login endpoint.
   * Defaults to the URI of the current page, or the value you
   * specify.
   * Only used when ux_mode: "redirect" is set.
   */
  loginURI?: string;

  /**
   * Optional.
   * If your application knows which user should authorize the
   * request, it can use this property to provide a hint to Google.
   * The email address for the target user. For more information, see
   * the login_hint field in the OpenID Connect docs.
   */
  hint?: string;

  /**
   * Optional.
   * If your application knows the Workspace domain the user belongs
   * to, use this to provide a hint to Google. For more information,
   * see the hd field in the OpenID Connect docs.
   */
  hostedDomain?: string;

  /**
   * Cancels the prompt if the user clicks outside the prompt.
   * Default value is true.
   */
  cancelOnTapOutside?: boolean;

  /**
   * If you need to call One Tap in the parent domain and its
   * subdomains, pass the parent domain to this field so that a single
   * shared cookie is used.
   */
  stateCookieDomain?: string;

  /**
   * The origins that are allowed to embed the intermediate iframe.
   * One Tap will run in the intermediate iframe mode if this field
   * presents.
   */
  allowedParentOrigin?: string | string[];

}

const defaultInitOptions: GoogleInitOptions = {
  oneTapEnabled: true,
};

export class GoogleLoginProvider extends BaseLoginProvider {
  public static readonly PROVIDER_ID: string = 'GOOGLE';

  public readonly tokenClientError = new EventEmitter<any>();
  public readonly changeUser = new EventEmitter<SocialUser | null>();

  private readonly _initialized = new ReplaySubject<boolean>();
  private readonly _socialUser = new BehaviorSubject<SocialUser | null>(null);
  private readonly _accessToken = new BehaviorSubject<string | null>(null);
  private readonly _receivedAccessToken = new EventEmitter<string>();
  private _tokenClient: google.accounts.oauth2.TokenClient | undefined;

  constructor(
    private clientId: string,
    private readonly initOptions?: GoogleInitOptions
  ) {
    super();

    this.initOptions = { ...defaultInitOptions, ...this.initOptions };

    // emit changeUser events but skip initial value from behaviorSubject
    this._socialUser.pipe(skip(1)).subscribe(this.changeUser);

    // emit receivedAccessToken but skip initial value from behaviorSubject
    this._accessToken.pipe(skip(1)).subscribe(this._receivedAccessToken);
  }

  initialize(autoLogin?: boolean): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.loadScript(
          GoogleLoginProvider.PROVIDER_ID,
          'https://accounts.google.com/gsi/client',
          () => {
            google.accounts.id.initialize({
              client_id: this.clientId,
              auto_select: autoLogin,
              callback: ({ credential }) => {
                const socialUser = this.createSocialUser(credential);
                this._socialUser.next(socialUser);
              },
              itp_support: this.initOptions.oneTapEnabled,
              ux_mode: this.initOptions.uxMode || 'popup',
              context: this.initOptions.context || 'use',
              login_uri: this.initOptions.loginURI,
              cancel_on_tap_outside: this.initOptions.cancelOnTapOutside,
              state_cookie_domain: this.initOptions.stateCookieDomain,
              allowed_parent_origin: this.initOptions.allowedParentOrigin,
              use_fedcm_for_prompt: this.initOptions.useFedCMForPrompt,
            });

            this._initialized.next(true);

            if (this.initOptions.oneTapEnabled) {
              this._socialUser
                .pipe(filter((user) => user === null))
                .subscribe(() => google.accounts.id.prompt());
            }

            if (this.initOptions.scopes) {
              const scope =
                this.initOptions.scopes instanceof Array
                  ? this.initOptions.scopes.filter((s) => s).join(' ')
                  : this.initOptions.scopes;


              this._tokenClient = google.accounts.oauth2.initTokenClient({
                client_id: this.clientId,
                scope,
                hint: this.initOptions.hint,
                hosted_domain: this.initOptions.hostedDomain,
                prompt : this.initOptions.prompt,
                error_callback: (error) => {
                  this.tokenClientError.emit(error);
                },
                callback: (tokenResponse) => {
                  if (tokenResponse.error) {
                    this._accessToken.error({
                      code: tokenResponse.error,
                      description: tokenResponse.error_description,
                      uri: tokenResponse.error_uri,
                    });
                  } else {
                    this._accessToken.next(tokenResponse.access_token);
                  }
                },
              });
            }

            resolve();
          }
        );
      } catch (err) {
        reject(err);
      }
    });
  }

  getLoginStatus(): Promise<SocialUser> {
    return new Promise((resolve, reject) => {
      if (this._socialUser.value) {
        resolve(this._socialUser.value);
      } else {
        reject(
          `No user is currently logged in with ${GoogleLoginProvider.PROVIDER_ID}`
        );
      }
    });
  }

  refreshToken(): Promise<SocialUser | null> {
    return new Promise((resolve, reject) => {
      google.accounts.id.revoke(this._socialUser.value.id, (response) => {
        if (response.error) reject(response.error);
        else resolve(this._socialUser.value);
      });
    });
  }

  getAccessToken(): Promise<string> {
    return new Promise((resolve, reject) => {
      if (!this._tokenClient) {
        if (this._socialUser.value) {
          reject(
            'No token client was instantiated, you should specify some scopes.'
          );
        } else {
          reject('You should be logged-in first.');
        }
      } else {
        this._tokenClient.requestAccessToken({
          hint: this._socialUser.value?.email,
        });
        this._receivedAccessToken.pipe(take(1)).subscribe(resolve);
      }
    });
  }

  revokeAccessToken(accessToken?: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this._tokenClient) {
        reject(
          'No token client was instantiated, you should specify some scopes.'
        );
      } else if (!this._accessToken.value && !accessToken) {
        reject('No access token to revoke');
      } else {
        google.accounts.oauth2.revoke(this._accessToken.value || accessToken, () => {
          this._accessToken.next(null);
          resolve();
        });
      }
    });
  }

  signIn(): Promise<SocialUser> {
    return Promise.reject(
      'You should not call this method directly for Google, use "<asl-google-signin-button>" wrapper ' +
        'or generate the button yourself with "google.accounts.id.renderButton()" ' +
        '(https://developers.google.com/identity/gsi/web/guides/display-button#javascript)'
    );
  }

  dismissPrompt() {
    return this._initialized.pipe(
      map(() => {
        return google.accounts.id.cancel();
      })
    )
  }

  setSocialUser(user: SocialUser | string) {
    if (typeof user === 'string') {
      const socialUser = this.createSocialUser(user);
      this._socialUser.next(socialUser);
    } else
      this._socialUser.next(user);
  }

  async signOut(): Promise<void> {
    google.accounts.id.disableAutoSelect();
    this._socialUser.next(null);
  }

  private createSocialUser(idToken: string) {
    const user = new SocialUser();
    user.idToken = idToken;
    const payload = this.decodeJwt(idToken);
    user.id = payload.sub;
    user.name = payload.name;
    user.email = payload.email;
    user.photoUrl = payload.picture;
    user.firstName = payload['given_name'];
    user.lastName = payload['family_name'];
    return user;
  }

  private decodeJwt(idToken: string): Record<string, string | undefined> {
    const base64Url = idToken.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      window.atob(base64)
        .split("")
        .map(function (c) {
          return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join("")
    );
    return JSON.parse(jsonPayload);
  }
}
