<?php

namespace Pterodactyl\Http\Controllers\Auth;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Facades\Activity;
use Illuminate\Contracts\View\View;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Facades\Http;

class LoginController extends AbstractLoginController
{

    public $provider;

    /**
     * LoginController constructor.
     */
    public function __construct(private ViewFactory $view)
    {
        parent::__construct();

          $this->provider = new \League\OAuth2\Client\Provider\GenericProvider([
                    'clientId'                => '',    // The client ID assigned to you by the provider
                    'clientSecret'            => '',    // The client password assigned to you by the provider
                    'redirectUri'             => 'http://localhost:8888/auth/callback',
                    'urlAuthorize'            => 'http://localhost:8000/login/oauth/authorize',
                    'urlAccessToken'          => 'http://casdoor:8000/api/login/oauth/access_token',
                    'urlResourceOwnerDetails' => 'http://casdoor:8000/api/userinfo'
                ]);
    }

    /**
     * Handle all incoming requests for the authentication routes and render the
     * base authentication view component. React will take over at this point and
     * turn the login area into an SPA.
     */
    public function index(): View
    {
        return $this->view->make('templates/auth.core');
    }

    public function oauthLogin(Request $request): JsonResponse
    {


        // If we don't have an authorization code then get one // TODO remove this
        if (empty($request->query('code'))) {

            // Fetch the authorization URL from the provider; this returns the
            // urlAuthorize option and generates and applies any necessary parameters
            // (e.g. state).
            $authorizationUrl = $this->provider->getAuthorizationUrl();

            // Get the state generated for you and store it to the session.
            session(['oauth2state' => $this->provider->getState()]);
            //$_SESSION['oauth2state'] = $this->provider->getState();


            // Optional, only required when PKCE is enabled.
            // Get the PKCE code generated for you and store it to the session.
            //$_SESSION['oauth2pkceCode'] = $this->provider->getPkceCode();
            session(['oauth2pkceCode' => $this->provider->getPkceCode()]);

            // Redirect the user to the authorization URL.
            header('Location: ' . $authorizationUrl); // TODO fix me
            exit;

        // Check given state against previously stored one to mitigate CSRF attack
        } elseif (empty($request->query('state')) || !session()->has('oauth2state') || $request->query('state') !== session('oauth2state')) {

            if (session()->has('oauth2state')) {
                session()->forget('oauth2state');
            }


           return new JsonResponse([
                'data' => [
                    'complete' => false,
                    'error' => 'Invalid state',
                ],
            ]);

        }

        return new JsonResponse([
            'data' => [
                'complete' => true,
            ],
        ]);
    }

    public function oauthRedirect(Request $request): User | JsonResponse
    {
         try {
            $this->provider->setPkceCode(session('oauth2pkceCode'));

            $accessToken = $this->provider->getAccessToken('authorization_code', [
                'code' => $request->query('code')
            ]);
            $req = $this->provider->getAuthenticatedRequest(
                'GET',
                'http://casdoor:8000/api/get-account',
                $accessToken
            );

            $username = json_decode(Http::withHeaders($req->getHeaders())->get($req->getUri())->body(), true)['name'];

            return $this->loginWithUsername($username, $request);


            $resourceOwner = $this->provider->getResourceOwner($accessToken);
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            return new JsonResponse([
                'data' => [
                    'complete' => false,
                    'error' => $e->getMessage(),
                    'request' => $request
                ],
            ]);

        }

        return new JsonResponse([]);
    }

    private function loginWithUsername(String $username, Request $request): User
    {
        try {
            /** @var User $user */
            $user = User::query()->where($this->getField($username), $username)->firstOrFail();
        } catch (ModelNotFoundException) {
            $this->sendFailedLoginResponse($request);
        }

        if (!$user->use_totp) {
            return $this->sendLoginResponse($user, $request);
        }
    }

    /**
     * Handle a login request to the application.
     *
     * @throws \Pterodactyl\Exceptions\DisplayException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request): JsonResponse
    {
        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);
            $this->sendLockoutResponse($request);
        }

        try {
            $username = $request->input('user');

            /** @var User $user */
            $user = User::query()->where($this->getField($username), $username)->firstOrFail();
        } catch (ModelNotFoundException) {
            $this->sendFailedLoginResponse($request);
        }

        // Ensure that the account is using a valid username and password before trying to
        // continue. Previously this was handled in the 2FA checkpoint, however that has
        // a flaw in which you can discover if an account exists simply by seeing if you
        // can proceed to the next step in the login process.
        if (!password_verify($request->input('password'), $user->password)) {
            $this->sendFailedLoginResponse($request, $user);
        }

        if (!$user->use_totp) {
            return $this->sendLoginResponse($user, $request);
        }

        Activity::event('auth:checkpoint')->withRequestMetadata()->subject($user)->log();

        $request->session()->put('auth_confirmation_token', [
            'user_id' => $user->id,
            'token_value' => $token = Str::random(64),
            'expires_at' => CarbonImmutable::now()->addMinutes(5),
        ]);

        return new JsonResponse([
            'data' => [
                'complete' => false,
                'confirmation_token' => $token,
            ],
        ]);
    }
}
