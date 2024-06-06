<?php

namespace XCoorp\SwissIDSocialite;

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

    protected $scopes = [
        'openid',
        'profile',
        'email',
        'phone',
        'address',
    ];

    protected $scopeSeparator = ' ';

    public static function additionalConfigKeys(): array
    {
        return ['base_url', 'issuer', 'claims', 'requested_authentication'];
    }

    public function getAccessTokenResponse($code): array
    {
        $response = parent::getAccessTokenResponse($code);

        return $this->parseAndValidateAccessTokenResponse($response, $code);
    }

    protected function getSwissIDUrl(): string
    {
        return rtrim($this->getConfig('base_url'), '/');
    }

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

    protected function getTokenUrl(): string
    {
        return $this->getSwissIDUrl().'/access_token';
    }

    protected function getTokenHeaders($code): array
    {
        $headers = parent::getTokenHeaders($code);

        $headers['Content-Type'] = 'application/x-www-form-urlencoded';
        $headers['charset'] = 'UTF-8';
        $headers['Authorization'] = 'Basic '.base64_encode($this->clientId.':'.$this->clientSecret);

        return $headers;
    }

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

    protected function parseAndValidateAccessTokenResponse(array $response, ?string $code = null): array
    {
        // Get the id_token from the response and validate it, before returning the response
        // We do this as an additional security measure to make sure the token is valid
        $idToken = Arr::get($response, 'id_token');
        $idTokenParts = explode('.', $idToken);

        $idTokenHeader = json_decode(base64_decode(strtr($idTokenParts[0], '-_', '+/')), true);
        $idTokenPayload = json_decode(base64_decode(strtr($idTokenParts[1], '-_', '+/')), true);

        // If not in the cache we need to download the public key from the SwissID server
        $pubKey = Cache::get('swiss_id_jwt_pub_key_'.$idTokenHeader['kid']);
        if ($pubKey === null) {
            $publicKeyResponse = $this->getHttpClient()->get($this->getSwissIDUrl().'/connect/jwk_uri');
            $publicKeys = $publicKeyResponse->getBody();

            $publicKeys = json_decode((string) $publicKeys, true)['keys'];

            // Now we need to find the key that matches the kid in the header
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

        // Verify the signature
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

        // Validate the nonce first to pull it from the session and prevent replay attacks
        // We check first if a code was present, because that means we are in the authorization code flow
        if ($code) {
            $nonce = $this->request->session()->pull('nonce');
            if ( ! hash_equals($nonce, $idTokenPayload['nonce'])) {
                throw new InvalidNonceException('Nonce mismatch.');
            }
        }

        // Validate the algorithm, swiss id uses RS256 and we enforce it
        if ($idTokenHeader['alg'] !== 'RS256') {
            throw new InvalidJWTAlgorithm('Algorithm must be RS256.');
        }

        // Check if at_hash matches the access token
        if (isset($response['access_token'])) {
            $atHash = $this->computeHash($response['access_token']);
            if (isset($idTokenPayload['at_hash']) && ! hash_equals($atHash, $idTokenPayload['at_hash'])) {
                throw new InvalidAccessTokenHash('Access token hash mismatch.');
            }
        }

        // Check if c_hash matches the auth code
        if ($code) {
            $cHash = $this->computeHash($code);
            if (isset($idTokenPayload['c_hash']) & ! hash_equals($cHash, $idTokenPayload['c_hash'])) {
                throw new InvalidAuthorizationTokenHash('Auth code hash mismatch.');
            }

            // Make sure the iat is not older than 5 minutes
            if ( ! isset($idTokenPayload['iat']) || time() - $idTokenPayload['iat'] > 300) {
                throw new IssueTokenExpiredException('Issued at time is older than 5 minutes.');
            }
        }

        // Make sure time is before exp
        if ( ! isset($idTokenPayload['exp']) || time() >= $idTokenPayload['exp']) {
            throw new IssueTokenExpiredException();
        }

        $this->verifyCommonJWTParts($idTokenPayload);

        return $response;
    }

    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get($this->getSwissIDUrl().'/userinfo', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        $jwtToken = $response->getBody();
        $idTokenParts = explode('.', $jwtToken);

        $idTokenHeader = json_decode(base64_decode(strtr($idTokenParts[0], '-_', '+/')), true);
        $idTokenPayload = json_decode(base64_decode(strtr($idTokenParts[1], '-_', '+/')), true);

        if ($idTokenHeader['alg'] !== 'HS256') {
            throw new InvalidJWTAlgorithm('Algorithm must be HS256.');
        }

        // We verify the HS256 signature here as well, the key is the octets of the UTF-8 representation of the client secret
        $signature = base64_decode(strtr($idTokenParts[2], '-_', '+/'));
        $data = $idTokenParts[0].'.'.$idTokenParts[1];

        $signatureValid = hash_equals(hash_hmac('sha256', $data, $this->clientSecret, true), $signature);

        if ( ! $signatureValid) {
            throw new InvalidJWTSignatureException('Signature is invalid.');
        }

        $this->verifyCommonJWTParts($idTokenPayload);

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

    protected function verifyCommonJWTParts(array $idTokenPayload): void
    {
        // Validate the issuer
        if ($idTokenPayload['iss'] !== $this->getConfig('issuer')) {
            throw new InvalidIssuerException('Issuer mismatch.');
        }

        // Validate the audience
        if (is_string($idTokenPayload['aud']) && $idTokenPayload['aud'] !== $this->clientId) {
            throw new InvalidAudienceException('Audience mismatch.');
        }

        if (is_array($idTokenPayload['aud'])) {
            if ( ! in_array($this->clientId, $idTokenPayload['aud'])) {
                throw new InvalidAudienceException('None of the audiences received match.');
            }

            if ( ! isset($idTokenPayload['azp'])) {
                throw new InvalidAuthorizedPartyException('Multiple audiences but no azp not provided.');
            }
        }

        if (isset($idTokenPayload['azp']) && $idTokenPayload['azp'] !== $this->clientId) {
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
