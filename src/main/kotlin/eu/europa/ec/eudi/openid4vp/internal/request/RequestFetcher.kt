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

import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import java.net.URL
import java.text.ParseException

internal class RequestFetcher(
    private val httpClient: HttpClient,
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
) {
    /**
     * Fetches the authorization request, if needed
     */
    suspend fun fetchRequest(request: UnvalidatedRequest): FetchedRequest = when (request) {
        is UnvalidatedRequest.Plain -> FetchedRequest.Plain(request.requestObject)
        is UnvalidatedRequest.JwtSecured -> {
            ensure(siopOpenId4VPConfig.jarConfiguration is JarConfiguration.Supported) {
                error("Wallet does not support JWT-Secured Authorization Requests")
            }
            val (jwt, walletNonce) = when (request) {
                is UnvalidatedRequest.JwtSecured.PassByValue -> request.jwt to null
                is UnvalidatedRequest.JwtSecured.PassByReference -> jwt(request)
            }
            val signedJwt = jwt.parseJwt()

            with(siopOpenId4VPConfig) {
                ensureSupportedSigningAlgorithm(signedJwt)
            }
            val clientId = with(request) {
                ensureSameClientId(signedJwt)
            }

            if (walletNonce != null) {
                ensureSameWalletNonce(walletNonce, signedJwt)
            }

            FetchedRequest.JwtSecured(clientId, signedJwt)
        }
    }

    private suspend fun jwt(
        request: UnvalidatedRequest.JwtSecured.PassByReference,
    ): Pair<Jwt, Nonce?> {
        val (_, requestUri, requestUriMethod) = request
        ensure(siopOpenId4VPConfig.jarConfiguration is JarConfiguration.Supported) {
            error("Wallet does not support JWT-Secured Authorization Requests")
        }
        val supportedMethods = siopOpenId4VPConfig.jarConfiguration.supportedRequestUriMethods
        return when (requestUriMethod) {
            null, RequestUriMethod.GET -> {
                ensure(supportedMethods.isGetSupported()) {
                    unsupportedRequestUriMethod(RequestUriMethod.GET)
                }
                jwtUsingGet(requestUri) to null
            }

            RequestUriMethod.POST -> {
                val postOptions = ensureNotNull(supportedMethods.isPostSupported()) {
                    unsupportedRequestUriMethod(RequestUriMethod.POST)
                }

                jwtUsingPost(requestUri, postOptions)
            }
        }
    }

    private suspend fun jwtUsingGet(requestUri: URL): Jwt =
        httpClient.get(requestUri) { addAcceptContentTypeJwt() }.body()

    private suspend fun jwtUsingPost(
        requestUri: URL,
        postOptions: SupportedRequestUriMethods.Post,
    ): Pair<Jwt, Nonce?> {
        val walletNonce = when (val nonceOption = postOptions.useWalletNonce) {
            is NonceOption.Use -> Nonce(nonceOption.byteLength)
            NonceOption.DoNotUse -> null
        }

        val encryptionKey = canSupportEncryptedJar()
        val walletMetaData = if (postOptions.includeWalletMetadata) {
            walletMetaData(siopOpenId4VPConfig).appendEncryptionKey(encryptionKey)
        } else null

        val form =
            parameters {
                walletNonce?.let { append(WALLET_NONCE_FORM_PARAM, it.toString()) }
                walletMetaData?.let { append(WALLET_METADATA_FORM_PARAM, Json.encodeToString(it)) }
            }

        val jarResponse = httpClient.submitForm(requestUri.toString(), form) { addAcceptContentTypeJwt() }
        check(jarResponse.status.isSuccess()) {
            "Failed to get JAR with POST method"
        }
        return maybeEncryptedJar(jarResponse, encryptionKey)
    }

    private fun canSupportEncryptedJar(): JWK? {
        val encryptionCapability = siopOpenId4VPConfig.jarConfiguration.encryptionCapability()
        return encryptionCapability?.let { encryptionCapability.generateEncryptionSpec() }
    }

    /**
     * If JAR configuration has encryption capability, create encryption key and include public key as 'jwk' in metadata
     */
    private fun JsonObject.appendEncryptionKey(jwk: JWK?): JsonObject =
        if (jwk != null) {
            val jwkSet = JWKSet(jwk.toPublicJWK())
            JsonObject(this + ("jwks" to Json.encodeToJsonElement(jwkSet)))
        } else {
            this
        }

    private fun JwtSigningEncryptionCapability.Encryption.generateEncryptionSpec(): JWK? =
        keyGenerationConfig?.let {
            KeyGenerator.genKeyIfSupported(it, supportedAlgorithms[0])!!
        }

    private suspend fun maybeEncryptedJar(jarResponse: HttpResponse, jwk: JWK?): Pair<Jwt, Nonce?> {
        val responseStr = jarResponse.body<String>()
        val encrypted = responseStr.parseAsJwe()
        val signedJwt = if (encrypted != null) {
            requireNotNull(jwk) { "No encryption key specified to decrypted the encrypted JAR" }
            decryptJAR(encrypted, jwk)
        } else {
            responseStr.parseJwt()
        }
        val nonce = signedJwt.jwtClaimsSet.getStringClaim("wallet_nonce")?.let { Nonce(it) }
        return responseStr to nonce
    }

    private fun decryptJAR(encrypted: JWEObject, key: JWK): SignedJWT {
        with(siopOpenId4VPConfig) {
            ensureSupportedEncryptionAlgAndMethod(encrypted)
        }
        val decrypter =
            when (key) {
                is RSAKey -> RSADecrypter(key)
                is ECKey -> ECDHDecrypter(key)
                else -> error("unsupported 'kty': '${key.keyType.value}'")
            }
        encrypted.decrypt(decrypter)
        return encrypted.payload.toSignedJWT()
    }
}

private fun String.parseJwt(): SignedJWT = try {
    SignedJWT.parse(this)
} catch (pe: ParseException) {
    throw invalidJar("JAR JWT parse error")
}

private fun String.parseAsJwe(): JWEObject? = try {
    JWEObject.parse(this)
} catch (e: ParseException) {
    null
}

private fun ensureSameWalletNonce(expectedWalletNonce: Nonce, signedJwt: SignedJWT) {
    val walletNonce = signedJwt.jwtClaimsSet.getStringClaim(WALLET_NONCE_FORM_PARAM)
    ensure(expectedWalletNonce.toString() == walletNonce) {
        invalidJar("Mismatch of wallet_nonce. Expected $expectedWalletNonce, actual $walletNonce")
    }
}

private fun SiopOpenId4VPConfig.ensureSupportedSigningAlgorithm(signedJwt: SignedJWT) {
    val signingAlg = ensureNotNull(signedJwt.header.algorithm) {
        invalidJar("JAR is missing alg claim from header")
    }
    ensure(
        jarConfiguration.signingCapability() != null &&
            signingAlg in jarConfiguration.signingCapability()!!.supportedAlgorithms,
    ) {
        invalidJar("JAR is signed with ${signingAlg.name} which is not supported")
    }
}

private fun SiopOpenId4VPConfig.ensureSupportedEncryptionAlgAndMethod(encrypted: JWEObject) {
    val encryptionCapability = jarConfiguration.encryptionCapability()
    requireNotNull(encryptionCapability) { "Encrypted responses not supported" }
    ensure(encrypted.header.algorithm in encryptionCapability.supportedAlgorithms) {
        invalidJar("Jar is encrypted with ${encrypted.header.algorithm} algorithm that is not supported")
    }
    ensure(encrypted.header.encryptionMethod in encryptionCapability.supportedEncMethods) {
        invalidJar("Jar is encrypted with ${encrypted.header.encryptionMethod} method that is not supported")
    }
}

private fun UnvalidatedRequest.JwtSecured.ensureSameClientId(signedJwt: SignedJWT): String {
    val jarClientId = signedJwt.jwtClaimsSet.getStringClaim("client_id")
    ensure(clientId == jarClientId) {
        invalidJar("ClientId mismatch. JAR request $clientId, jwt $jarClientId")
    }
    return clientId
}

private fun invalidJar(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidJarJwt(cause).asException()

private fun unsupportedRequestUriMethod(m: RequestUriMethod): AuthorizationRequestException =
    RequestValidationError.UnsupportedRequestUriMethod(m).asException()

private const val APPLICATION_JWT = "application/jwt"
private const val APPLICATION_OAUTH_AUTHZ_REQ_JWT = "application/oauth-authz-req+jwt"
private const val WALLET_NONCE_FORM_PARAM = "wallet_nonce"
private const val WALLET_METADATA_FORM_PARAM = "wallet_metadata"

private fun HttpRequestBuilder.addAcceptContentTypeJwt() {
    accept(ContentType.parse(APPLICATION_OAUTH_AUTHZ_REQ_JWT))
    accept(ContentType.parse(APPLICATION_JWT))
}
