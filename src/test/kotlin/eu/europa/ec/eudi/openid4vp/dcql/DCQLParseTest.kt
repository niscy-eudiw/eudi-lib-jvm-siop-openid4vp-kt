/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp.dcql

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.fail

class DCQLParseTest {

    private val jsonSupport = Json {
        prettyPrint = true
        ignoreUnknownKeys = false
    }

    @Test
    fun whenMsoMdocNamespaceMissesAnExceptionIsRaised() {
        val json = """
            {
              "credentials": [
                {
                  "id": "my_credential",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "org.iso.7367.1.mVRC"
                  },
                  "claims": [
                    {
                      "claim_name": "vehicle_holder"
                    },
                    {
                      "namespace": "org.iso.18013.5.1",
                      "claim_name": "first_name"
                    }
                  ]
                }
              ]
            }
        """.trimIndent()

        try {
            jsonSupport.decodeFromString<DCQL>(json)
            fail("An MsoMdoc query missing namespace was processed")
        } catch (e: Throwable) {
            assertIs<IllegalArgumentException>(e)
        }
    }

    @Test
    fun whenMsoMdocClaimNameMissesAnExceptionIsRaised() {
        val json = """
            {
              "credentials": [
                {
                  "id": "my_credential",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "org.iso.7367.1.mVRC"
                  },
                  "claims": [
                    {
                      "namespace": "org.iso.18013.5.1",
                    }
                  ]
                }
              ]
            }
        """.trimIndent()

        try {
            jsonSupport.decodeFromString<DCQL>(json)
            fail("An MsoMdoc query missing claim_name was processed")
        } catch (e: Throwable) {
            assertIs<IllegalArgumentException>(e)
        }
    }

    @Test
    fun test01() = assertEqualsDCQL(
        json = """
            {
              "credentials": [
                {
                  "id": "my_credential",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "org.iso.7367.1.mVRC"
                  },
                  "claims": [
                    {
                      "namespace": "org.iso.7367.1",
                      "claim_name": "vehicle_holder"
                    },
                    {
                      "namespace": "org.iso.18013.5.1",
                      "claim_name": "first_name"
                    }
                  ]
                }
              ]
            }
        """.trimIndent(),
        expected = DCQL(
            credentials = listOf(
                CredentialQuery.mdoc(
                    id = QueryId("my_credential"),
                    msoMdocMeta = DCQLMetaMsoMdocExtensions(MsoMdocDocType("org.iso.7367.1.mVRC")),
                    claims = listOf(
                        ClaimsQuery.mdoc(
                            namespace = MsoMdocNamespace("org.iso.7367.1"),
                            claimName = MsoMdocClaimName("vehicle_holder"),
                        ),
                        ClaimsQuery.mdoc(
                            namespace = MsoMdocNamespace("org.iso.18013.5.1"),
                            claimName = MsoMdocClaimName("first_name"),
                        ),
                    ),

                ),
            ),
        ),
    )

    @Test
    fun test02() = assertEqualsDCQL(
        json = """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["https://credentials.example.com/identity_credential"]
                  },
                  "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]}
                  ]
                },
                {
                  "id": "mdl",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "org.iso.7367.1.mVRC"
                  },
                  "claims": [
                    {
                      "namespace": "org.iso.7367.1",
                      "claim_name": "vehicle_holder"
                    },
                    {
                      "namespace": "org.iso.18013.5.1",
                      "claim_name": "first_name"
                    }
                  ]
                }
            ]
            }
        """.trimIndent(),
        expected = DCQL(
            credentials = listOf(
                CredentialQuery.sdJwtVc(
                    id = QueryId("pid"),
                    sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(vctValues = listOf("https://credentials.example.com/identity_credential")),
                    claims = listOf(
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("given_name")),
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("family_name")),
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("address").claim("street_address")),
                    ),
                ),
                CredentialQuery.mdoc(
                    id = QueryId("mdl"),
                    msoMdocMeta = DCQLMetaMsoMdocExtensions(MsoMdocDocType("org.iso.7367.1.mVRC")),
                    claims = listOf(
                        ClaimsQuery.mdoc(
                            namespace = MsoMdocNamespace("org.iso.7367.1"),
                            claimName = MsoMdocClaimName("vehicle_holder"),
                        ),
                        ClaimsQuery.mdoc(
                            namespace = MsoMdocNamespace("org.iso.18013.5.1"),
                            claimName = MsoMdocClaimName("first_name"),
                        ),
                    ),
                ),
            ),
        ),

    )

    @Test
    fun test03() = assertEqualsDCQL(
        json = """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["https://credentials.example.com/identity_credential"]
                  },
                  "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]}
                  ]
                },
                {
                  "id": "other_pid",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["https://othercredentials.example/pid"]
                  },
                  "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]}
                  ]
                },
                {
                  "id": "pid_reduced_cred_1",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
                  },
                  "claims": [
                    {"path": ["family_name"]},
                    {"path": ["given_name"]}
                  ]
                },
                {
                  "id": "pid_reduced_cred_2",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["https://cred.example/residence_credential"]
                  },
                  "claims": [
                    {"path": ["postal_code"]},
                    {"path": ["locality"]},
                    {"path": ["region"]}
                  ]
                },
                {
                  "id": "nice_to_have",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["https://company.example/company_rewards"]
                  },
                  "claims": [
                    {"path": ["rewards_number"]}
                  ]
                }
              ],
              "credential_sets": [
                {
                  "purpose": "Identification",
                  "options": [
                    [ "pid" ],
                    [ "other_pid" ],
                    [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                  ]
                },
                {
                  "purpose": "Show your rewards card",
                  "required": false,
                  "options": [
                    [ "nice_to_have" ]
                  ]
                }
              ]
            }
        """.trimIndent(),
        expected = DCQL(
            credentials = listOf(
                CredentialQuery.sdJwtVc(
                    id = QueryId("pid"),
                    sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(vctValues = listOf("https://credentials.example.com/identity_credential")),
                    claims = listOf(
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("given_name")),
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("family_name")),
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("address").claim("street_address")),
                    ),
                ),
                CredentialQuery.sdJwtVc(
                    id = QueryId("other_pid"),
                    sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(vctValues = listOf("https://othercredentials.example/pid")),
                    claims = listOf(
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("given_name")),
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("family_name")),
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("address").claim("street_address")),
                    ),
                ),
                CredentialQuery.sdJwtVc(
                    id = QueryId("pid_reduced_cred_1"),
                    sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(
                        vctValues = listOf("https://credentials.example.com/reduced_identity_credential"),
                    ),
                    claims = listOf(
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("family_name")),
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("given_name")),
                    ),
                ),
                CredentialQuery.sdJwtVc(
                    id = QueryId("pid_reduced_cred_2"),
                    sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(vctValues = listOf("https://cred.example/residence_credential")),
                    claims = listOf(
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("postal_code")),
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("locality")),
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("region")),
                    ),
                ),
                CredentialQuery.sdJwtVc(
                    id = QueryId("nice_to_have"),
                    sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(vctValues = listOf("https://company.example/company_rewards")),
                    claims = listOf(
                        ClaimsQuery.sdJwtVc(path = ClaimPath.claim("rewards_number")),
                    ),
                ),
            ),
            credentialSets = listOf(
                CredentialSetQuery(
                    purpose = JsonPrimitive("Identification"),
                    options = listOf(
                        setOf(QueryId("pid")),
                        setOf(QueryId("other_pid")),
                        setOf(QueryId("pid_reduced_cred_1"), QueryId("pid_reduced_cred_2")),
                    ),
                ),
                CredentialSetQuery(
                    purpose = JsonPrimitive("Show your rewards card"),
                    required = false,
                    options = listOf(
                        setOf(QueryId("nice_to_have")),
                    ),
                ),
            ),
        ),
    )

    @Test
    fun test04() = assertEqualsDCQL(
        json = """
            {
              "credentials": [
                {
                  "id": "mdl-id",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL"
                  },
                  "claims": [
                    {
                      "id": "given_name",
                      "namespace": "org.iso.18013.5.1",
                      "claim_name": "given_name"
                    },
                    {
                      "id": "family_name",
                      "namespace": "org.iso.18013.5.1",
                      "claim_name": "family_name"
                    },
                    {
                      "id": "portrait",
                      "namespace": "org.iso.18013.5.1",
                      "claim_name": "portrait"
                    }
                  ]
                },
                {
                  "id": "mdl-address",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL"
                  },
                  "claims": [
                    {
                      "id": "resident_address",
                      "namespace": "org.iso.18013.5.1",
                      "claim_name": "resident_address"
                    },
                    {
                      "id": "resident_country",
                      "namespace": "org.iso.18013.5.1",
                      "claim_name": "resident_country"
                    }
                  ]
                },
                {
                  "id": "photo_card-id",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "org.iso.23220.photoid.1"
                  },
                  "claims": [
                    {
                      "id": "given_name",
                      "namespace": "org.iso.23220.1",
                      "claim_name": "given_name"
                    },
                    {
                      "id": "family_name",
                      "namespace": "org.iso.23220.1",
                      "claim_name": "family_name"
                    },
                    {
                      "id": "portrait",
                      "namespace": "org.iso.23220.1",
                      "claim_name": "portrait"
                    }
                  ]
                },
                {
                  "id": "photo_card-address",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "org.iso.23220.photoid.1"
                  },
                  "claims": [
                    {
                      "id": "resident_address",
                      "namespace": "org.iso.23220.1",
                      "claim_name": "resident_address"
                    },
                    {
                      "id": "resident_country",
                      "namespace": "org.iso.23220.1",
                      "claim_name": "resident_country"
                    }
                  ]
                }
              ],
              "credential_sets": [
                {
                  "purpose": "Identification",
                  "options": [
                    [ "mdl-id" ],
                    [ "photo_card-id" ]
                  ]
                },
                {
                  "purpose": "Proof of address",
                  "required": false,
                  "options": [
                    [ "mdl-address" ],
                    [ "photo_card-address" ]
                  ]
                }
              ]
            }
        """.trimIndent(),
        expected = DCQL(
            credentials = listOf(
                CredentialQuery.mdoc(
                    id = QueryId("mdl-id"),
                    msoMdocMeta = DCQLMetaMsoMdocExtensions(MsoMdocDocType("org.iso.18013.5.1.mDL")),
                    claims = listOf(
                        ClaimsQuery.mdoc(
                            id = ClaimId("given_name"),
                            namespace = MsoMdocNamespace("org.iso.18013.5.1"),
                            claimName = MsoMdocClaimName("given_name"),
                        ),
                        ClaimsQuery.mdoc(
                            id = ClaimId("family_name"),
                            namespace = MsoMdocNamespace("org.iso.18013.5.1"),
                            claimName = MsoMdocClaimName("family_name"),
                        ),
                        ClaimsQuery.mdoc(
                            id = ClaimId("portrait"),
                            namespace = MsoMdocNamespace("org.iso.18013.5.1"),
                            claimName = MsoMdocClaimName("portrait"),
                        ),
                    ),
                ),
                CredentialQuery.mdoc(
                    id = QueryId("mdl-address"),
                    msoMdocMeta = DCQLMetaMsoMdocExtensions(MsoMdocDocType("org.iso.18013.5.1.mDL")),
                    claims = listOf(
                        ClaimsQuery.mdoc(
                            id = ClaimId("resident_address"),
                            namespace = MsoMdocNamespace("org.iso.18013.5.1"),
                            claimName = MsoMdocClaimName("resident_address"),
                        ),
                        ClaimsQuery.mdoc(
                            id = ClaimId("resident_country"),
                            namespace = MsoMdocNamespace("org.iso.18013.5.1"),
                            claimName = MsoMdocClaimName("resident_country"),
                        ),
                    ),
                ),
                CredentialQuery.mdoc(
                    id = QueryId("photo_card-id"),
                    msoMdocMeta = DCQLMetaMsoMdocExtensions(MsoMdocDocType("org.iso.23220.photoid.1")),
                    claims = listOf(
                        ClaimsQuery.mdoc(
                            id = ClaimId("given_name"),
                            namespace = MsoMdocNamespace("org.iso.23220.1"),
                            claimName = MsoMdocClaimName("given_name"),
                        ),
                        ClaimsQuery.mdoc(
                            id = ClaimId("family_name"),
                            namespace = MsoMdocNamespace("org.iso.23220.1"),
                            claimName = MsoMdocClaimName("family_name"),
                        ),
                        ClaimsQuery.mdoc(
                            id = ClaimId("portrait"),
                            namespace = MsoMdocNamespace("org.iso.23220.1"),
                            claimName = MsoMdocClaimName("portrait"),
                        ),
                    ),
                ),
                CredentialQuery.mdoc(
                    id = QueryId("photo_card-address"),
                    msoMdocMeta = DCQLMetaMsoMdocExtensions(MsoMdocDocType("org.iso.23220.photoid.1")),
                    claims = listOf(
                        ClaimsQuery.mdoc(
                            id = ClaimId("resident_address"),
                            namespace = MsoMdocNamespace("org.iso.23220.1"),
                            claimName = MsoMdocClaimName("resident_address"),
                        ),
                        ClaimsQuery.mdoc(
                            id = ClaimId("resident_country"),
                            namespace = MsoMdocNamespace("org.iso.23220.1"),
                            claimName = MsoMdocClaimName("resident_country"),
                        ),
                    ),
                ),
            ),
            credentialSets = listOf(
                CredentialSetQuery(
                    purpose = JsonPrimitive("Identification"),
                    options = listOf(
                        setOf(QueryId("mdl-id")),
                        setOf(QueryId("photo_card-id")),
                    ),
                ),
                CredentialSetQuery(
                    purpose = JsonPrimitive("Proof of address"),
                    required = false,
                    options = listOf(
                        setOf(QueryId("mdl-address")),
                        setOf(QueryId("photo_card-address")),
                    ),
                ),
            ),
        ),
    )

    @Test
    fun test05() = assertEqualsDCQL(
        json = """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": [ "https://credentials.example.com/identity_credential" ]
                  },
                  "claims": [
                    {"id": "a", "path": ["last_name"]},
                    {"id": "b", "path": ["postal_code"]},
                    {"id": "c", "path": ["locality"]},
                    {"id": "d", "path": ["region"]},
                    {"id": "e", "path": ["date_of_birth"]}
                  ],
                  "claim_sets": [
                    ["a", "c", "d", "e"],
                    ["a", "b", "e"]
                  ]
                }
              ]
            }
        """.trimIndent(),
        expected = DCQL(
            credentials = listOf(
                CredentialQuery.sdJwtVc(
                    id = QueryId("pid"),
                    sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(vctValues = listOf("https://credentials.example.com/identity_credential")),
                    claims = listOf(
                        ClaimsQuery.sdJwtVc(id = ClaimId("a"), path = ClaimPath.claim("last_name")),
                        ClaimsQuery.sdJwtVc(id = ClaimId("b"), path = ClaimPath.claim("postal_code")),
                        ClaimsQuery.sdJwtVc(id = ClaimId("c"), path = ClaimPath.claim("locality")),
                        ClaimsQuery.sdJwtVc(id = ClaimId("d"), path = ClaimPath.claim("region")),
                        ClaimsQuery.sdJwtVc(id = ClaimId("e"), path = ClaimPath.claim("date_of_birth")),
                    ),
                    claimSets = listOf(
                        setOf(ClaimId("a"), ClaimId("c"), ClaimId("d"), ClaimId("e")),
                        setOf(ClaimId("a"), ClaimId("b"), ClaimId("e")),
                    ),
                ),
            ),
        ),
    )

    private fun assertEqualsDCQL(expected: DCQL, json: String) {
        assertEquals(expected, jsonSupport.decodeFromString(json))
    }
}