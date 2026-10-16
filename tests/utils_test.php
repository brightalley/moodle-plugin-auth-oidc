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

namespace auth_oidc;

use advanced_testcase;

/**
 * Unit tests for \auth_oidc\utils.
 *
 * @package   auth_oidc
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2026 onwards Microsoft, Inc. (http://microsoft.com/)
 * @group auth_oidc
 * @group office365
 */
final class utils_test extends advanced_testcase {
    /**
     * Test that generated PKCE code verifiers meet the requirements of RFC 7636 section 4.1.
     *
     * @covers \auth_oidc\utils::generate_code_verifier
     */
    public function test_generate_code_verifier(): void {
        $verifier = utils::generate_code_verifier();

        // 43-128 characters drawn from the RFC's "unreserved" set.
        $this->assertMatchesRegularExpression('#^[A-Za-z0-9\-._~]{43,128}$#', $verifier);
        $this->assertSame(43, strlen($verifier));

        // Successive calls must not repeat.
        $this->assertNotSame($verifier, utils::generate_code_verifier());
    }

    /**
     * Test the S256 code challenge against the test vector in RFC 7636 appendix B.
     *
     * @covers \auth_oidc\utils::generate_code_challenge
     */
    public function test_generate_code_challenge_s256(): void {
        $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $expected = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

        $this->assertSame($expected, utils::generate_code_challenge($verifier, 'S256'));
    }

    /**
     * Test that the plain code challenge is the code verifier unchanged.
     *
     * @covers \auth_oidc\utils::generate_code_challenge
     */
    public function test_generate_code_challenge_plain(): void {
        $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

        $this->assertSame($verifier, utils::generate_code_challenge($verifier, 'plain'));
    }
}
