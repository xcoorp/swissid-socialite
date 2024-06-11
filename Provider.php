<?php

namespace XCoorp\SwissIDSocialite;

use GuzzleHttp\Exception\GuzzleException;
use XCoorp\SwissIDSocialite\Exceptions\InvalidAccessTokenHash;
use XCoorp\SwissIDSocialite\Exceptions\InvalidAudienceException;
use XCoorp\SwissIDSocialite\Exceptions\InvalidAuthorizationTokenHash;
use XCoorp\SwissIDSocialite\Exceptions\InvalidAuthorizedPartyException;
use XCoorp\SwissIDSocialite\Exceptions\InvalidIssuerException;
use XCoorp\SwissIDSocialite\Exceptions\InvalidJWTAlgorithm;
use XCoorp\SwissIDSocialite\Exceptions\InvalidJWTSignatureException;
use XCoorp\SwissIDSocialite\Exceptions\InvalidNonceException;
use XCoorp\SwissIDSocialite\Exceptions\IssueTokenExpiredException;
use Illuminate\Support\Facades\Cache;
use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'SWISSID';

    /**
     * @inheritDoc
     */
    protected $scopes = [
        'openid',
        'profile',
        'email',
        'phone',
        'address',
    ];

    /**
     * @inheritDoc
     */
    protected $scopeSeparator = ' ';

    /**
     * @inheritDoc
     */
    public static function additionalConfigKeys(): array
    {
        return ['base_url', 'issuer', 'claims', 'requested_authentication'];
    }

    /**
     * @inheritDoc
     *
     * Additionally to getting the access token response wa also validate it directly after
     * @throws GuzzleException
     * @see parseAndValidateAccessTokenResponse
     */
    public function getAccessTokenResponse($code): array
    {
        $response = parent::getAccessTokenResponse($code);

        return $this->parseAndValidateAccessTokenResponse($response, $code);
    }

    protected function getSwissIDUrl(): string
    {
        return rtrim($this->getConfig('base_url'), '/');
    }

    /**
     * @inheritDoc
     *
     * SwissID uses the authorization code flow, so we need to include the nonce in the request
     * to prevent replay attacks, additionally we can include claims and acr_values
     */
    protected function getAuthUrl($state): string
    {
        $this->request->session()->put('nonce', $nonce = $this->getNonce());

        $include = ['nonce' => $nonce];
        $claims = $this->getConfig('claims');
        if ($claims !== null && Arr::accessible($claims)) {
            $include['claims'] = json_encode($claims);
        }

        $requestedAuthentication = $this->getConfig('requested_authentication');
        if ($requestedAuthentication !== null) {
            $include['acr_values'] = $requestedAuthentication;
        }

        return $this->with($include)->buildAuthUrlFromBase($this->getSwissIDUrl().'/authorize', $state);
    }

    /**
     * @inheritDoc
     */
    protected function getTokenUrl(): string
    {
        return $this->getSwissIDUrl().'/access_token';
    }

    /**
     * @inheritDoc
     *
     * SwissID uses basic auth for the client credentials, so we need to include the client id and secret in the headers,
     * this is different from the default implementation
     */
    protected function getTokenHeaders($code): array
    {
        $headers = parent::getTokenHeaders($code);

        $headers['Content-Type'] = 'application/x-www-form-urlencoded';
        $headers['charset'] = 'UTF-8';
        $headers['Authorization'] = 'Basic '.base64_encode($this->clientId.':'.$this->clientSecret);

        return $headers;
    }

    /**
     * @inheritDoc
     *
     * Client id and secret are basic authentication, so we need to remove them from the fields
     * @see getTokenHeaders
     */
    protected function getTokenFields($code): array
    {
        $fields = parent::getTokenFields($code);
        if (isset($fields['client_id'])) {
            unset($fields['client_id']);
        }

        if (isset($fields['client_secret'])) {
            unset($fields['client_secret']);
        }

        return $fields;
    }

    /**
     * @inheritDoc
     *
     * We directly validate the refresh token after getting it
     * @see parseAndValidateAccessTokenResponse
     *
     * @throws GuzzleException
     */
    protected function getRefreshTokenResponse($refreshToken): array
    {
        $response = json_decode($this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS => $this->getTokenHeaders($refreshToken),
            RequestOptions::FORM_PARAMS => [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
            ],
        ])->getBody(), true);

        return $this->parseAndValidateAccessTokenResponse($response);
    }

    /**
     * For security reasons we need to validate the access token response. The following validation checks are performed:
     * - The id_token is valid and signed with the correct key (Grab the key from the SwissID server)
     * - The nonce matches the one we sent in the request
     * - The algorithm is RS256
     * - The at_hash matches the access token
     * - The c_hash matches the auth code
     * - The iat is not older than 5 minutes
     * - The time is before exp
     * - The issuer matches the one we expect
     * - The audience matches the client id
     * - The azp matches the client id
     * - The signature is valid
     *
     * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
     *
     * @param array       $response     The response from the token endpoint
     * @param string|null $code         Access token code, if not passed, this is a refresh token request
     *
     * @return array
     *
     * @throws GuzzleException
     */
    protected function parseAndValidateAccessTokenResponse(array $response, ?string $code = null): array
    {
        $idToken = Arr::get($response, 'id_token');
        $idTokenParts = explode('.', $idToken);

        $idTokenHeader = json_decode(base64_decode(strtr($idTokenParts[0], '-_', '+/')), true);
        $idTokenPayload = json_decode(base64_decode(strtr($idTokenParts[1], '-_', '+/')), true);

        $pubKey = Cache::get('swiss_id_jwt_pub_key_'.$idTokenHeader['kid']);
        if ($pubKey === null) {
            $publicKeyResponse = $this->getHttpClient()->get($this->getSwissIDUrl().'/connect/jwk_uri');
            $publicKeys = $publicKeyResponse->getBody();

            $publicKeys = json_decode((string) $publicKeys, true)['keys'];

            $pubKey = null;
            foreach ($publicKeys as $publicKey) {
                if ($publicKey['kid'] === $idTokenHeader['kid']) {
                    $pubKey = $publicKey;
                    break;
                }
            }

            if ( ! $pubKey) {
                throw new InvalidJWTSignatureException('No key found for the kid in the header.');
            }

            Cache::put('swiss_id_jwt_pub_key_'.$idTokenHeader['kid'], $pubKey, 60 * 60 * 24);
        }

        $signature = base64_decode(strtr($idTokenParts[2], '-_', '+/'));
        $data = $idTokenParts[0].'.'.$idTokenParts[1];

        $certificate = trim(chunk_split($pubKey['x5c'][0], 64));
        $certificate =
<<<EOD
-----BEGIN CERTIFICATE-----
{$certificate}
-----END CERTIFICATE-----
EOD;

        $publicKey = openssl_pkey_get_public($certificate);

        $signatureValid = openssl_verify($data, $signature, $publicKey, 'sha256');
        if ($signatureValid !== 1) {
            throw new InvalidJWTSignatureException('Signature is invalid.');
        }

        if ($code) {
            $nonce = $this->request->session()->pull('nonce');
            if ( ! hash_equals($nonce, $idTokenPayload['nonce'])) {
                throw new InvalidNonceException('Nonce mismatch.');
            }
        }

        if ($idTokenHeader['alg'] !== 'RS256') {
            throw new InvalidJWTAlgorithm('Algorithm must be RS256.');
        }

        if (isset($response['access_token'])) {
            $atHash = $this->computeHash($response['access_token']);
            if (isset($idTokenPayload['at_hash']) && ! hash_equals($atHash, $idTokenPayload['at_hash'])) {
                throw new InvalidAccessTokenHash('Access token hash mismatch.');
            }
        }

        if ($code) {
            $cHash = $this->computeHash($code);
            if (isset($idTokenPayload['c_hash']) & ! hash_equals($cHash, $idTokenPayload['c_hash'])) {
                throw new InvalidAuthorizationTokenHash('Auth code hash mismatch.');
            }

            if ( ! isset($idTokenPayload['iat']) || time() - $idTokenPayload['iat'] > 300) {
                throw new IssueTokenExpiredException('Issued at time is older than 5 minutes.');
            }
        }

        if ( ! isset($idTokenPayload['exp']) || time() >= $idTokenPayload['exp']) {
            throw new IssueTokenExpiredException();
        }

        $this->verifyCommonJWTParts($idTokenPayload, $this->clientId, $this->getConfig('issuer'));

        return $response;
    }

    /**
     * @inheritDoc
     *
     * After getting the userinfo, we immediately validate the JWT, by checking if the signature is valid (client secret is the key).
     *
     * @throws GuzzleException
     */
    protected function getUserByToken($token): array
    {
        $response = $this->getHttpClient()->get($this->getSwissIDUrl().'/userinfo', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);


        $idTokenParts = explode('.', $response->getBody());

        $idTokenHeader = json_decode(base64_decode(strtr($idTokenParts[0], '-_', '+/')), true);
        $idTokenPayload = json_decode(base64_decode(strtr($idTokenParts[1], '-_', '+/')), true);

        if ($idTokenHeader['alg'] !== 'HS256') {
            throw new InvalidJWTAlgorithm('Algorithm must be HS256.');
        }

        $signature = base64_decode(strtr($idTokenParts[2], '-_', '+/'));
        $data = $idTokenParts[0].'.'.$idTokenParts[1];

        $signatureValid = hash_equals(hash_hmac('sha256', $data, $this->clientSecret, true), $signature);

        if ( ! $signatureValid) {
            throw new InvalidJWTSignatureException('Signature is invalid.');
        }

        $this->verifyCommonJWTParts($idTokenPayload, $this->clientId, $this->getConfig('issuer'));

        return $idTokenPayload;
    }

    /**
     * @inheritdoc
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User())->setRaw($user)->map([
            'id' => Arr::get($user, 'sub'),
            'email' => Arr::get($user, 'email'),
            'name' => Arr::get($user, 'urn:swissid:first_name', Arr::get($user, 'given_name')) . ' ' . Arr::get($user, 'family_name'),
        ]);
    }

    /**
     * Verify the common parts of the JWT token
     * which are shared by access and refresh token, as well as the id token. Validates:
     * - Issuer
     * - Audience
     * - Authorized Party
     *
     * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
     * @see https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenValidation
     * @see https://openid.net/specs/openid-connect-core-1_0.html#AccessTokenValidation
     *
     * @param array  $idTokenPayload
     * @param string $clientID
     * @param string $issuer
     *
     * @return void
     */
    protected function verifyCommonJWTParts(array $idTokenPayload, string $clientID, string $issuer): void
    {
        if ($idTokenPayload['iss'] !== $issuer) {
            throw new InvalidIssuerException('Issuer mismatch.');
        }

        if (is_string($idTokenPayload['aud']) && $idTokenPayload['aud'] !== $clientID) {
            throw new InvalidAudienceException('Audience mismatch.');
        }

        if (is_array($idTokenPayload['aud'])) {
            if ( ! in_array($clientID, $idTokenPayload['aud'])) {
                throw new InvalidAudienceException('None of the audiences received match.');
            }

            if ( ! isset($idTokenPayload['azp'])) {
                throw new InvalidAuthorizedPartyException('Multiple audiences but no azp not provided.');
            }
        }

        if (isset($idTokenPayload['azp']) && $idTokenPayload['azp'] !== $clientID) {
            throw new InvalidAuthorizedPartyException('AZP does not match the client id.');
        }
    }

    protected function getNonce(): string
    {
        return Str::random(40);
    }

    protected function computeHash($data): string
    {
        $hash = hash('SHA256', $data, true);
        $leftMostHalf = substr($hash, 0, strlen($hash) / 2);

        return rtrim(strtr(base64_encode($leftMostHalf), '+/', '-_'), '=');
    }
}
