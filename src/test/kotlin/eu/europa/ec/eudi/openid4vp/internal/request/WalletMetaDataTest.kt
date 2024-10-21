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
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Verifier
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class WalletMetaDataTest {

    @Test
    fun `basic test`() {
        val config = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns.NoValidation),
            vpConfiguration = VPConfiguration(
                presentationDefinitionUriSupported = false,
                knownPresentationDefinitionsPerScope = emptyMap(),
                vpFormats = VpFormats(
                    VpFormat.MsoMdoc,
                    VpFormat.sdJwtVc(
                        sdJwtAlgorithms = listOf(JWSAlgorithm.ES256),
                        kbJwtAlgorithms = listOf(JWSAlgorithm.ES256),
                    ),
                ),
            ),
            jarmConfiguration = JarmConfiguration.encryptionOnly(
                supportedAlgorithms = JWEAlgorithm.Family.ECDH_ES.toList(),
                supportedMethods = listOf(EncryptionMethod.A256GCM),
                keyGenerationConfig = KeyGenerationConfig.ecOnly(Verifier.jarmEncryptionECKeyPair.curve),
            ),
        )
        assertMetadata(config)
    }

    @Test
    fun `without JARM encryption or signing option`() {
        val config = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns.NoValidation),
            vpConfiguration = VPConfiguration(
                presentationDefinitionUriSupported = false,
                knownPresentationDefinitionsPerScope = emptyMap(),
                vpFormats = VpFormats(
                    VpFormat.MsoMdoc,
                    VpFormat.SdJwtVc.ES256,
                ),
            ),
            jarmConfiguration = JarmConfiguration.NotSupported,
        )
        assertMetadata(config)
    }
}

private fun assertMetadata(config: SiopOpenId4VPConfig) {
    val walletMetaData = walletMetaData(config).also {
        println(jsonSupport.encodeToString(it))
    }
    assertExpectedVpFormats(config.vpConfiguration.vpFormats, walletMetaData)
    assertJarmEncryption(config.jarmConfiguration.encryptionCapability(), walletMetaData)
    assertJarmSigning(config.jarmConfiguration.signingCapability(), walletMetaData)
    assertClientIdScheme(config.supportedClientIdSchemes, walletMetaData)
    assertPresentationDefinitionUriSupported(config.vpConfiguration, walletMetaData)
    assertJarSigning(config.jarConfiguration.signingCapability(), walletMetaData)
    assertJarEncryption(config.jarConfiguration.encryptionCapability(), walletMetaData)
}

private fun assertJarSigning(
    signingCapability: JwtSigningEncryptionCapability.Signing?,
    walletMetaData: JsonObject,
) = assertSigning(walletMetaData["request_object_signing_alg_values_supported"], signingCapability)

private fun assertJarmSigning(
    signingCapability: JwtSigningEncryptionCapability.Signing?,
    walletMetaData: JsonObject,
) = assertSigning(walletMetaData["authorization_signing_alg_values_supported"], signingCapability)

private fun assertSigning(
    algsJsonElement: JsonElement?,
    signingConfig: JwtSigningEncryptionCapability.Signing?,
) {
    if (signingConfig != null) {
        assertIs<JsonArray>(algsJsonElement)
        assertContentEquals(
            signingConfig.supportedAlgorithms.map { it.name },
            algsJsonElement.mapNotNull { it.jsonPrimitive.contentOrNull },
        )
    } else {
        assertNull(algsJsonElement)
    }
}

private fun assertPresentationDefinitionUriSupported(vpConfiguration: VPConfiguration, walletMetaData: JsonObject) {
    val value = walletMetaData["presentation_definition_uri_supported"]
    if (vpConfiguration.presentationDefinitionUriSupported) {
        assertIs<JsonPrimitive>(value)
        assertTrue { value.boolean }
    } else {
        assertTrue {
            value == null || (value is JsonPrimitive && !value.boolean)
        }
    }
}

private fun assertClientIdScheme(
    supportedClientIdSchemes: List<SupportedClientIdScheme>,
    walletMetaData: JsonObject,
) {
    val schemes = walletMetaData["client_id_schemes_supported"]
    if (supportedClientIdSchemes.isNotEmpty()) {
        assertIs<JsonArray>(schemes)
        assertContentEquals(
            supportedClientIdSchemes.map { it.scheme().value() },
            schemes.mapNotNull { it.jsonPrimitive.contentOrNull },
        )
    } else {
        assertNull(schemes)
    }
}

private fun assertJarmEncryption(
    expectedEncryption: JwtSigningEncryptionCapability.Encryption?,
    walletMetaData: JsonObject,
) {
    val encAlgs = walletMetaData["authorization_encryption_alg_values_supported"]
    val encMethods = walletMetaData["authorization_encryption_enc_values_supported"]

    assertEncryption(encAlgs, encMethods, expectedEncryption)
}

private fun assertJarEncryption(
    expectedEncryption: JwtSigningEncryptionCapability.Encryption?,
    walletMetaData: JsonObject,
) {
    val encAlgs = walletMetaData["request_object_encryption_alg_values_supported"]
    val encMethods = walletMetaData["request_object_encryption_enc_values_supported"]

    assertEncryption(encAlgs, encMethods, expectedEncryption)
}

private fun assertEncryption(
    encAlgsJsonElement: JsonElement?,
    encMethodsJsonElement: JsonElement?,
    expectedEncryption: JwtSigningEncryptionCapability.Encryption?,
) {
    if (expectedEncryption != null) {
        assertIs<JsonArray>(encAlgsJsonElement)
        assertContentEquals(
            expectedEncryption.supportedAlgorithms.map { it.name },
            encAlgsJsonElement.mapNotNull { it.jsonPrimitive.contentOrNull },
        )

        assertIs<JsonArray>(encMethodsJsonElement)
        assertContentEquals(
            expectedEncryption.supportedEncMethods.map { it.name },
            encMethodsJsonElement.mapNotNull { it.jsonPrimitive.contentOrNull },
        )
    } else {
        assertNull(encAlgsJsonElement)
        assertNull(encMethodsJsonElement)
    }
}

private fun assertExpectedVpFormats(
    expectedVpFormats: VpFormats,
    walletMetaData: JsonObject,
) {
    val vpFormats = assertIs<JsonObject>(
        walletMetaData["vp_formats_supported"],
        "Missing vp_formats_supported",
    )
    assertEquals(vpFormats.size, vpFormats.size)
    if (VpFormat.MsoMdoc in expectedVpFormats) {
        val msoMdoc = assertNotNull(vpFormats["mso_mdoc"])
        assertIs<JsonObject>(msoMdoc)
        assertTrue { msoMdoc.isEmpty() }
    }
    val sdJwtVcSupport = expectedVpFormats.values.filterIsInstance<VpFormat.SdJwtVc>().firstOrNull()
    if (sdJwtVcSupport != null) {
        val sdJwtVc = assertNotNull(vpFormats["vc+sd-jwt"])
        assertIs<JsonObject>(sdJwtVc)
        val sdJwtAlgs = sdJwtVc["sd-jwt_alg_values"]
        if (sdJwtVcSupport.sdJwtAlgorithms.isNotEmpty()) {
            assertNotNull(sdJwtAlgs)
            assertIs<JsonArray>(sdJwtAlgs)
            assertContentEquals(
                sdJwtVcSupport.sdJwtAlgorithms.map { it.name },
                sdJwtAlgs.map { it.jsonPrimitive.content },
            )
        } else {
            assertNull(sdJwtAlgs)
        }

        val kbJwtAlgs = sdJwtVc["kb-jwt_alg_values"]
        if (sdJwtVcSupport.kbJwtAlgorithms.isNotEmpty()) {
            assertNotNull(kbJwtAlgs)
            assertIs<JsonArray>(kbJwtAlgs)
            assertContentEquals(
                sdJwtVcSupport.kbJwtAlgorithms.map { it.name },
                kbJwtAlgs.map { it.jsonPrimitive.content },
            )
        } else {
            assertNull(kbJwtAlgs)
        }
    }
}

private val jsonSupport = Json { prettyPrint = true }
