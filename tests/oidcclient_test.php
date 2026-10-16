<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * OIDC client test cases.
 *
 * @package auth_oidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2014 onwards Microsoft, Inc. (http://microsoft.com/)
 */



namespace auth_oidc;

defined('MOODLE_INTERNAL') || die();

global $CFG;

/**
 * Tests oidcclient.
 *
 * @group auth_oidc
 * @group office365
 */
final class oidcclient_test extends \advanced_testcase {
    /**
     * Perform setup before every test. This tells Moodle's phpunit to reset the database after every test.
     */
    protected function setUp(): void {
        parent::setUp();
        $this->resetAfterTest(true);
    }

    /**
     * Test getting and setting credentials.
     *
     * @covers \auth_oidc\tests\mockoidcclient::setcreds
     */
    public function test_creds_getters_and_setters(): void {
        $httpclient = new \auth_oidc\tests\mockhttpclient();
        $client = new \auth_oidc\tests\mockoidcclient($httpclient);

        $this->assertNull($client->get_clientid());
        $this->assertNull($client->get_clientsecret());
        $this->assertNull($client->get_redirecturi());

        $id = 'id';
        $secret = 'secret';
        $redirecturi = 'redirecturi';
        $tokenresource = 'resource';
        $scope = (isset($this->config->oidcscope)) ? $this->config->oidcscope : null;
        $client->setcreds($id, $secret, $redirecturi, $tokenresource, $scope);

        $this->assertEquals($id, $client->get_clientid());
        $this->assertEquals($secret, $client->get_clientsecret());
        $this->assertEquals($redirecturi, $client->get_redirecturi());
        $this->assertEquals($tokenresource, $client->get_tokenresource());
    }

    /**
     * Dataprovider returning endpoints.
     *
     * @return array Array of arrays of test parameters.
     */
    public static function dataprovider_endpoints(): array {
        $tests = [];

        $tests['oneinvalid'] = [
                ['auth' => 100],
                ['Exception', 'Invalid Endpoint URI received.'],
        ];

        $tests['oneinvalidonevalid1'] = [
                ['auth' => 100, 'token' => 'http://example.com/token'],
                ['Exception', 'Invalid Endpoint URI received.'],
        ];

        $tests['oneinvalidonevalid2'] = [
                ['token' => 'http://example.com/token', 'auth' => 100],
                ['Exception', 'Invalid Endpoint URI received.'],
        ];

        $tests['onevalid'] = [
                ['token' => 'http://example.com/token'],
                [],
        ];

        $tests['twovalid'] = [
                ['auth' => 'http://example.com/auth', 'token' => 'http://example.com/token'],
                [],
        ];

        return $tests;
    }

    /**
     * Test setting and getting endpoints.
     *
     * @dataProvider dataprovider_endpoints
     * @covers \auth_oidc\tests\mockoidcclient::setendpoints
     * @param array $endpoints
     * @param array $expectedexception
     */
    public function test_endpoints_getters_and_setters(array $endpoints, array $expectedexception): void {
        if (!empty($expectedexception)) {
            $this->expectException($expectedexception[0]);
            $this->expectExceptionMessage($expectedexception[1]);
        }
        $httpclient = new \auth_oidc\tests\mockhttpclient();
        $client = new \auth_oidc\tests\mockoidcclient($httpclient);
        $client->setendpoints($endpoints);

        foreach ($endpoints as $type => $uri) {
            $this->assertEquals($uri, $client->get_endpoint($type));
        }
    }

    /**
     * Build a mock client configured well enough to make a token request.
     *
     * @param \auth_oidc\tests\mockhttpclient $httpclient
     * @return \auth_oidc\tests\mockoidcclient
     */
    protected function get_configured_client(\auth_oidc\tests\mockhttpclient $httpclient) {
        $client = new \auth_oidc\tests\mockoidcclient($httpclient);
        $client->setcreds('clientid', 'clientsecret', 'https://example.com/auth/oidc/', 'resource', 'openid profile email');
        $client->setendpoints(['auth' => 'https://example.com/auth', 'token' => 'https://example.com/token']);

        return $client;
    }

    /**
     * Return the parameters sent in the given recorded request body.
     *
     * @param \auth_oidc\tests\mockhttpclient $httpclient
     * @param int $index Which recorded request to read.
     * @return array
     */
    protected function get_sent_params(\auth_oidc\tests\mockhttpclient $httpclient, int $index = 0): array {
        $this->assertArrayHasKey($index, $httpclient->requests);
        $sent = [];
        parse_str($httpclient->requests[$index]['options']['CURLOPT_POSTFIELDS'], $sent);

        return $sent;
    }

    /**
     * Test that no PKCE parameters are sent when PKCE is disabled.
     *
     * @covers \auth_oidc\oidcclient::getauthrequestparams
     */
    public function test_authrequest_params_omit_pkce_when_disabled(): void {
        global $DB;

        set_config('pkcemethod', AUTH_OIDC_PKCE_METHOD_DISABLED, 'auth_oidc');

        $client = $this->get_configured_client(new \auth_oidc\tests\mockhttpclient());
        $params = $client->getauthrequestparams();

        $this->assertArrayNotHasKey('code_challenge', $params);
        $this->assertArrayNotHasKey('code_challenge_method', $params);

        $staterec = $DB->get_record('auth_oidc_state', ['state' => $params['state']]);
        $this->assertNull($staterec->codeverifier);
    }

    /**
     * Test that an S256 code challenge is sent and matches the stored code verifier.
     *
     * @covers \auth_oidc\oidcclient::getauthrequestparams
     * @covers \auth_oidc\oidcclient::getnewstate
     */
    public function test_authrequest_params_s256(): void {
        global $DB;

        set_config('pkcemethod', AUTH_OIDC_PKCE_METHOD_S256, 'auth_oidc');

        $client = $this->get_configured_client(new \auth_oidc\tests\mockhttpclient());
        $params = $client->getauthrequestparams();

        $this->assertEquals('S256', $params['code_challenge_method']);
        $this->assertMatchesRegularExpression('#^[A-Za-z0-9\-_]{43}$#', $params['code_challenge']);

        // The challenge must be derivable from the verifier stored against the state record.
        $staterec = $DB->get_record('auth_oidc_state', ['state' => $params['state']]);
        $this->assertNotEmpty($staterec->codeverifier);
        $expected = rtrim(strtr(base64_encode(hash('sha256', $staterec->codeverifier, true)), '+/', '-_'), '=');
        $this->assertEquals($expected, $params['code_challenge']);
    }

    /**
     * Test that a plain code challenge is the code verifier itself.
     *
     * @covers \auth_oidc\oidcclient::getauthrequestparams
     */
    public function test_authrequest_params_plain(): void {
        global $DB;

        set_config('pkcemethod', AUTH_OIDC_PKCE_METHOD_PLAIN, 'auth_oidc');

        $client = $this->get_configured_client(new \auth_oidc\tests\mockhttpclient());
        $params = $client->getauthrequestparams();

        $this->assertEquals('plain', $params['code_challenge_method']);

        $staterec = $DB->get_record('auth_oidc_state', ['state' => $params['state']]);
        $this->assertNotEmpty($staterec->codeverifier);
        $this->assertEquals($staterec->codeverifier, $params['code_challenge']);
    }

    /**
     * Test that the code verifier is sent with the token request, alongside the client secret.
     *
     * @covers \auth_oidc\oidcclient::tokenrequest
     */
    public function test_tokenrequest_sends_code_verifier(): void {
        set_config('clientauthmethod', AUTH_OIDC_AUTH_METHOD_SECRET, 'auth_oidc');

        $httpclient = new \auth_oidc\tests\mockhttpclient();
        $httpclient->set_response(json_encode(['id_token' => 'idtoken', 'access_token' => 'accesstoken']));
        $client = $this->get_configured_client($httpclient);

        $client->tokenrequest('authcode', 'thecodeverifier');

        $sent = $this->get_sent_params($httpclient);
        $this->assertEquals('thecodeverifier', $sent['code_verifier']);
        // PKCE is additive: confidential client authentication must still be sent.
        $this->assertEquals('clientsecret', $sent['client_secret']);
        $this->assertEquals('authorization_code', $sent['grant_type']);
    }

    /**
     * Test that no code verifier is sent with the token request when PKCE is not in use.
     *
     * @covers \auth_oidc\oidcclient::tokenrequest
     */
    public function test_tokenrequest_omits_code_verifier_when_null(): void {
        set_config('clientauthmethod', AUTH_OIDC_AUTH_METHOD_SECRET, 'auth_oidc');

        $httpclient = new \auth_oidc\tests\mockhttpclient();
        $httpclient->set_response(json_encode(['id_token' => 'idtoken', 'access_token' => 'accesstoken']));
        $client = $this->get_configured_client($httpclient);

        $client->tokenrequest('authcode');

        $sent = $this->get_sent_params($httpclient);
        $this->assertArrayNotHasKey('code_verifier', $sent);
    }
}
