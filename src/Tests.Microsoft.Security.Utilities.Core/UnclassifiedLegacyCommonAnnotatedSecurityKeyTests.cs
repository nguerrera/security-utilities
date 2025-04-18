﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics.CodeAnalysis;

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    [TestClass, ExcludeFromCodeCoverage]
    public class UnclassifiedLegacyCommonAnnotatedSecurityKeyTests
    {
        [TestMethod]
        public void CommonAnnotatedKey_TryCreateWithNonCaskSecret()
        {
            using var _ = new AssertionScope();

            foreach (bool longForm in new[] { true, false })
            {
                string signature = "APIM";

                string caskSecret = IdentifiableSecrets.GenerateCommonAnnotatedKey(signature, customerManagedKey: true, null, null, longForm);
                string legacySecret = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Trim('=');

                foreach (string secret in new[] { caskSecret, legacySecret })
                {
                    var action = () => LegacyCommonAnnotatedSecurityKey.TryCreate(secret, out LegacyCommonAnnotatedSecurityKey cask);
                    action.Should().NotThrow(because: "TryCreate should never throw");
                }
            }
        }
    }
}
