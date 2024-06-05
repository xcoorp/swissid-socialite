<?php

namespace XCoorp\SwissIDSocialite;

use SocialiteProviders\Manager\SocialiteWasCalled;

class SwissIDExtendSocialite
{
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('swissid', Provider::class);
    }
}
