<?php

declare(strict_types=1);

namespace OkapiAuth;

use League\OAuth1\Client\Server\Server;
use League\OAuth1\Client\Credentials\TokenCredentials;
use League\OAuth1\Client\Server\User;
use League\OAuth1\Client\Signature\SignatureInterface;

class Okapi extends Server
{
    /**
     * @var string
     */
    private $baseUri;

    /**
     * @inheritDoc
     */
    public function urlTemporaryCredentials()
    {
        return $this->baseUri.'services/oauth/request_token';
    }

    /**
     * @inheritDoc
     */
    public function urlAuthorization()
    {
        return $this->baseUri.'services/oauth/authorize';
    }

    /**
     * @inheritDoc
     */
    public function urlTokenCredentials()
    {
        return $this->baseUri.'services/oauth/access_token';
    }

    /**
     * @inheritDoc
     */
    public function urlUserDetails()
    {
        return $this->baseUri.'services/users/user?fields=uuid|username|profile_url|internal_id|date_registered'.
            '|caches_found|caches_notfound|caches_hidden|rcmds_given|rcmds_left|rcmd_founds_needed|home_location';
    }

    /**
     * Create a new server instance.
     *
     * @param array              $clientCredentials
     * @param SignatureInterface $signature
     */
    public function __construct($clientCredentials, SignatureInterface $signature = null)
    {
        $this->baseUri = $clientCredentials['base_uri'];
        parent::__construct($clientCredentials, $signature);
    }

    /**
     * @inheritDoc
     */
    public function userDetails($data, TokenCredentials $tokenCredentials)
    {
        $user = new User();

        if (isset($data['uuid'])) {
            $user->uid = $data['uuid'];
        }
        if (isset($data['username'])) {
            $user->nickname = $data['username'];
        }
        if (isset($data['profile_url'])) {
            $user->urls['profile'] = $data['profile_url'];
        }
        if (isset($data['home_location'])) {
            $user->location = $data['home_location'];
        }

        $used = ['uuid', 'username', 'profile_url', 'home_location'];

        // Save all extra data
        $user->extra = array_diff_key($data, array_flip($used));

        return $user;
    }

    /**
     * @inheritDoc
     */
    public function userUid($data, TokenCredentials $tokenCredentials)
    {
        return $data['uuid'];
    }

    /**
     * @inheritDoc
     */
    public function userEmail($data, TokenCredentials $tokenCredentials)
    {
        return null;
    }

    /**
     * @inheritDoc
     */
    public function userScreenName($data, TokenCredentials $tokenCredentials)
    {
        return $data['username'];
    }
}
