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
package eu.europa.ec.eudi.openid4vp.internal.dispatch

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.AuthorizationResponsePayload
import eu.europa.ec.eudi.openid4vp.JarmSpec
import java.util.*

internal object ResponseSignerEncryptor {

    fun signEncryptResponse(spec: JarmSpec, data: AuthorizationResponsePayload): String {
        return when (spec) {
            is JarmSpec.SignedResponse -> sign(spec, data)
            is JarmSpec.EncryptedResponse -> encrypt(spec, data)
            is JarmSpec.SignedAndEncryptedResponse -> signAndEncrypt(spec, data)
        }
    }

    private fun sign(spec: JarmSpec.SignedResponse, data: AuthorizationResponsePayload): String {
        return dataAsSignedJWT(data, spec.responseSigningAlg, spec.signingKeySet, spec.holderId).serialize()
    }

    private fun encrypt(spec: JarmSpec.EncryptedResponse, data: AuthorizationResponsePayload): String {
        val jweEncrypter = deductEncryptor(spec.responseEncryptionAlg, spec.encryptionKeySet)
        val jweHeader = JWEHeader(spec.responseEncryptionAlg, spec.responseEncryptionEnc)
        val dataAsJWT = DirectPostForm.of(data).asJWT(spec.holderId)
        val encryptedJWT = EncryptedJWT(jweHeader, dataAsJWT)
        return with(encryptedJWT) {
            encrypt(jweEncrypter)
            serialize()
        }
    }

    private fun signAndEncrypt(
        spec: JarmSpec.SignedAndEncryptedResponse,
        data: AuthorizationResponsePayload,
    ): String {
        val signedJwt = dataAsSignedJWT(data, spec.responseSigningAlg, spec.signingKeySet, spec.holderId)
        val jweEncrypter = deductEncryptor(spec.responseEncryptionAlg, spec.encryptionKeySet)
        val jweObject = JWEObject(
            JWEHeader(spec.responseEncryptionAlg, spec.responseEncryptionEnc),
            Payload(signedJwt),
        )
        return with(jweObject) {
            encrypt(jweEncrypter)
            serialize()
        }
    }

    private fun dataAsSignedJWT(
        data: AuthorizationResponsePayload,
        signingAlg: JWSAlgorithm,
        signingKeySet: JWKSet,
        holderId: String,
    ): SignedJWT {
        val jwsSigner = deductSigner(signingAlg, signingKeySet)
        val header = JWSHeader.Builder(signingAlg)
            .keyID("") // TODO: keyId
            .build()
        val dataAsJWT = DirectPostForm.of(data).asJWT(holderId)
        val signedJWT = SignedJWT(header, dataAsJWT)
        signedJWT.sign(jwsSigner)
        return signedJWT
    }

    private fun deductSigner(
        signingAlg: JWSAlgorithm,
        signingKeySet: JWKSet,
    ): JWSSigner = when {
        JWSAlgorithm.Family.EC.contains(signingAlg) -> createECSigner(signingKeySet)
        JWSAlgorithm.Family.RSA.contains(signingAlg) -> createRSASigner(signingKeySet)
        else -> throw UnsupportedOperationException(
            "Unsupported signing algorithm $signingKeySet. Currently supported signing " +
                "algorithm families are [EC, RSA]",
        )
    }

    private fun deductEncryptor(
        responseEncryptionAlg: JWEAlgorithm,
        encryptionKeySet: JWKSet,
    ): JWEEncrypter = when {
        JWEAlgorithm.Family.ECDH_ES.any { it.name.equals(responseEncryptionAlg.name) } -> createECDHEncrypter(encryptionKeySet)
        JWEAlgorithm.Family.RSA.any { it.name.equals(responseEncryptionAlg.name) } -> createRSAEncrypter(encryptionKeySet)
        else -> throw UnsupportedOperationException(
            "Unsupported encryption algorithm $responseEncryptionAlg." +
                " Currently supported encryption algorithm families are [ECDH_ES, RSA]",
        )
    }

    private fun createECDHEncrypter(keySet: JWKSet): ECDHEncrypter {
        // Look for a EC key in JWKSet
        val ecJWK = keySet.keys.first { it.keyType.value.equals(KeyType.EC.value) }
            ?: throw RuntimeException("No EC encryption key found in the provided key set")
        return ECDHEncrypter(ECKey.parse(ecJWK.toJSONObject()))
    }

    private fun createECSigner(keySet: JWKSet): JWSSigner {
        val ecJWK = keySet.keys.first { it.keyType.value.equals(KeyType.EC.value) }
            ?: throw RuntimeException("No EC signing key found in the provided key set")
        return ECDSASigner(ECKey.parse(ecJWK.toJSONObject()))
    }

    private fun createRSAEncrypter(keySet: JWKSet): RSAEncrypter {
        val rsaJWK = keySet.keys.first { it.keyType.value.equals(KeyType.RSA.value) }
            ?: throw RuntimeException("No RSA encryption key found in the provided key set")
        return RSAEncrypter(RSAKey.parse(rsaJWK.toJSONObject()))
    }

    private fun createRSASigner(keySet: JWKSet): JWSSigner {
        val rsaJWK = keySet.keys.first { it.keyType.value.equals(KeyType.RSA.value) }
            ?: throw RuntimeException("No RSA signing key found in the provided key set")
        return RSASSASigner(RSAKey.parse(rsaJWK.toJSONObject()))
    }

    private fun Map<String, String>.asJWT(holderId: String): JWTClaimsSet {
        return with(JWTClaimsSet.Builder()) {
            issuer(holderId)
            issueTime(Date())
            this@asJWT.entries.map { claim(it.key, it.value) }
            build()
        }
    }
}