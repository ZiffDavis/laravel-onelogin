<?php

namespace ZiffDavis\Laravel\Onelogin\Controllers;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Event;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;
use Symfony\Component\HttpKernel\Exception\HttpException;
use ZiffDavis\Laravel\Onelogin\Events\OneloginLoginEvent;

class OneLoginController extends Controller
{
    use HasRedirector;

    protected $oneLogin;
    protected $userProvider;
    protected $responseFactory;

    function __construct(Auth $oneLogin, ResponseFactory $responseFactory)
    {
        $this->oneLogin = $oneLogin;
        $this->responseFactory = $responseFactory;
    }

    public function metadata()
    {
        $settings = $this->oneLogin->getSettings();

        try {
            $metadata = $settings->getSPMetadata();
            $errors = $settings->validateMetadata($metadata);
        } catch (\Exception $e) {
            $errors = [$e->getMessage()];
        } finally {
            if ($errors) {
                throw new HttpException(500, 'Onelogin Metadata Errors: ' . implode(',', $errors));
            }
        }

        return $this->responseFactory->make($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    public function login(Request $request)
    {
        $redirect = $this->getRedirectUrl($request, true);

        // prevent logged in users from triggering a onelogin saml flow
        if ($request->user()) {
            return $this->responseFactory->redirectTo($redirect);
        }

        return $this->responseFactory->redirectTo(
            $this->oneLogin->login($redirect, [], false, false, true)
        );
    }

    public function acs(Request $request, AuthManager $auth)
    {
        $this->oneLogin->processResponse();
        $errors = $this->oneLogin->getErrors();

        if (!empty($errors)) {
            $errorString = implode(', ', $errors);
            if ($errorReason = $this->oneLogin->getLastErrorReason()) {
                $errorString .= ' Error Reason: ' . $errorReason;
            }
            throw new \RuntimeException($errorString);
        }

        if(!$this->oneLogin->isAuthenticated()) {
            throw new HttpException(403, 'Unauthorized to use this application');
        }

        $userAttributes = $this->oneLogin->getAttributes();

        $loginEvent = new OneloginLoginEvent($userAttributes);
        $results = Event::fire($loginEvent);

        // from the fired event, grab the first user that was a return value
        $user = Arr::first($results, function ($result) {
            return $result instanceof Authenticatable;
        });

        if (array_search(false, $results, true) !== false) {
            throw new HttpException(403, 'There is no valid user in this application for provided credentials');
        }

        // if there was no Event fired, do the default action
        if (!$user && count($results) === 0) {
            $user = $this->resolveUser($userAttributes);
        }

        if (!$user) {
            throw new HttpException(500, 'A user could not be resolved by the Onelogin Controller');
        }

        $auth->login($user);

        return $this->responseFactory->redirectTo($request->get('RelayState') ?? '/');
    }

    protected function resolveUser(array $userAttributes)
    {
        $userClass = config('onelogin.user_class');

        if (!$userClass) {
            $userClass = config('auth.providers.users.model');
        }

        if (!class_exists($userClass)) {
            throw new HttpException(500, 'A user class was not configured to be used by the laravel-onelogin controller');
        }

        $user = $userClass::firstOrNew(['email' => $userAttributes['User.email'][0]]);

        if (isset($userAttributes['User.FirstName'][0]) && isset($userAttributes['User.LastName'][0])) {
            $user->name = "{$userAttributes['User.FirstName'][0]} {$userAttributes['User.LastName'][0]}";
        }

        $user->save();

        return $user;
    }
}


