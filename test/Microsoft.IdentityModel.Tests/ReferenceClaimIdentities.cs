//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;

namespace Microsoft.IdentityModel.Tests
{
    public class ReferenceClaimsIdentities
    {
        public static TokenClaimsIdentitiesTestSet TokenClaimsIdentitiesSubjectEmptyString
        {
            get
            {
                return new TokenClaimsIdentitiesTestSet
                {
                    SecurityToken = new SamlSecurityToken(new SamlAssertion(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), null, null, new List<SamlStatement> { ReferenceSaml.GetAttributeStatement(new SamlSubject(), Default.Claims) }))
                };
            }
        }

        public static TokenClaimsIdentitiesTestSet TokenClaimsIdentitiesSameSubject
        {
            get
            {
                var claim = new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer);
                claim.Properties[ClaimProperties.SamlAttributeName] = ClaimTypes.Country;
                claim.Properties[ClaimProperties.SamlAttributeNamespace] = ClaimTypes.Country;
                var statement = new SamlAttributeStatement(ReferenceSaml.SamlSubject, new SamlAttribute(ClaimTypes.Country, ClaimTypes.Country, Default.Country));

                var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
                identity.AddClaim(claim);
                identity.AddClaim(claim);
                return new TokenClaimsIdentitiesTestSet
                {
                    Identities = new List<ClaimsIdentity> { identity },
                    SecurityToken = new SamlSecurityToken(new SamlAssertion(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), null, null, new List<SamlStatement> { statement, statement })),
                };
            }
        }

        public static TokenClaimsIdentitiesTestSet TokenClaimsIdentitiesDifferentSubjects
        {
            get
            {
                var claim1 = new Claim(ClaimTypes.Country, Default.Country, ClaimValueTypes.String, Default.Issuer);
                claim1.Properties[ClaimProperties.SamlAttributeName] = ClaimTypes.Country;
                claim1.Properties[ClaimProperties.SamlAttributeNamespace] = ClaimTypes.Country;
                var attrStatement1 = new SamlAttribute(ClaimTypes.Country, ClaimTypes.Country, Default.Country);
                var statement1 = new SamlAttributeStatement(ReferenceSaml.SamlSubject, attrStatement1);
                var identity1 = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
                identity1.AddClaim(claim1);

                // statement2 has different subject with statement1
                var statement2 = new SamlAttributeStatement(new SamlSubject(Default.NameIdentifierFormat, Default.NameQualifier, Default.AttributeName), attrStatement1);
                var identity2 = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
                identity2.AddClaim(claim1);

                var claim2 = new Claim(ClaimTypes.NameIdentifier, Default.AttributeName, ClaimValueTypes.String, Default.Issuer);
                claim2.Properties[ClaimProperties.SamlNameIdentifierFormat] = Default.NameIdentifierFormat;
                claim2.Properties[ClaimProperties.SamlNameIdentifierNameQualifier] = Default.NameQualifier;
                identity2.AddClaim(claim2);

                var claim3 = new Claim(ClaimTypes.AuthenticationMethod, Default.AuthenticationMethod, ClaimValueTypes.String, Default.Issuer);
                var claim4 = new Claim(ClaimTypes.AuthenticationInstant, Default.AuthenticationInstant, ClaimValueTypes.DateTime, Default.Issuer);

                // statement3 has same subject with statement1
                var statement3 = new SamlAuthenticationStatement(ReferenceSaml.SamlSubject, Default.AuthenticationMethod, DateTime.Parse(Default.AuthenticationInstant), null, null, null);
                identity1.AddClaim(claim3);
                identity1.AddClaim(claim4);

                return new TokenClaimsIdentitiesTestSet
                {
                    Identities = new List<ClaimsIdentity> { identity1, identity2 },
                    SecurityToken = new SamlSecurityToken(new SamlAssertion(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), null, null, new List<SamlStatement> { statement1, statement2, statement3 }))
                };
            }
        }
    }
}
