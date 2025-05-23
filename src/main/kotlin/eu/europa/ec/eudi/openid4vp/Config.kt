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
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.oauth2.sdk.id.Issuer
import eu.europa.ec.eudi.openid4vp.JarmConfiguration.*
import eu.europa.ec.eudi.openid4vp.SiopOpenId4VPConfig.Companion.SelfIssued
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration

sealed interface JwkSetSource {
    data class ByValue(val jwks: JsonObject) : JwkSetSource
    data class ByReference(val jwksUri: URI) : JwkSetSource
}

/**
 * The out-of-band knowledge of a Verifier, used in [SupportedClientIdScheme.Preregistered]

 * @param clientId the client id of a trusted verifier
 * @param legalName the name of the trusted verifier
 * @param jarConfig in case, verifier communicates his request using JAR, the signing algorithm
 * that is uses to sign his request and a [way][JwkSetSource] to get his public key
 *
 */
data class PreregisteredClient(
    val clientId: OriginalClientId,
    val legalName: String,
    val jarConfig: Pair<JWSAlgorithm, JwkSetSource>? = null,
)

fun interface X509CertificateTrust {
    fun isTrusted(chain: List<X509Certificate>): Boolean
}

fun interface LookupPublicKeyByDIDUrl {
    suspend fun resolveKey(didUrl: URI): PublicKey?
}

/**
 * The Client identifier scheme supported (or trusted) by the wallet.
 */
sealed interface SupportedClientIdScheme {

    /**
     * The Client Identifier is known to the Wallet in advance of the Authorization Request.
     */
    data class Preregistered(val clients: Map<OriginalClientId, PreregisteredClient>) : SupportedClientIdScheme {
        constructor(vararg clients: PreregisteredClient) : this(clients.toList().associateBy { it.clientId })
    }

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is a URI and
     * match a uniformResourceIdentifier Subject Alternative Name (SAN) RFC5280 entry in the
     * leaf certificate passed with the request.
     *
     * In this scheme, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanUri(val trust: X509CertificateTrust) : SupportedClientIdScheme {
        companion object {
            internal val NoValidation: X509SanUri = X509SanUri { _ -> true }
        }
    }

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is a DNS name and
     * matches a dNSName Subject Alternative Name (SAN) RFC5280 entry in the
     * leaf certificate passed with the request.
     *
     * In this scheme, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanDns(val trust: X509CertificateTrust) : SupportedClientIdScheme {
        companion object {
            internal val NoValidation: X509SanDns = X509SanDns { _ -> true }
        }
    }

    /**
     * Wallet trusts verifiers that present an authorization request having a redirect URI
     * equal to the value of the Client Identifier.
     *
     * In this scheme, Verifier must NOT sign his request
     */
    data object RedirectUri : SupportedClientIdScheme

    /**
     * Wallet trusts verifiers that are able to present a client identifier which is a DID
     *
     * In this scheme, Verifier must always sign his request (JAR), signed by a key
     * that can be referenced via the DID
     *
     * @param lookup a function for getting the public key of the verifier by
     * resolving a given DID URL
     */
    data class DID(val lookup: LookupPublicKeyByDIDUrl) : SupportedClientIdScheme

    /**
     * Wallet trust verifiers that are able to present a signed Verifier Attestation, which
     * is issued by a party trusted by the Wallet
     *
     * In this scheme, Verifier must always sign his request (JAR), having in its JOSE
     * header a Verifier Attestation JWT under `jwt` claim
     *
     * @param trust a function for verifying the digital signature of the Verifier Attestation JWT.
     * @param clockSkew max acceptable skew between wallet and attestation issuer
     */
    data class VerifierAttestation(
        val trust: JWSVerifier,
        val clockSkew: Duration = Duration.ofSeconds(15L),
    ) : SupportedClientIdScheme

    fun scheme(): ClientIdScheme = when (this) {
        is DID -> ClientIdScheme.DID
        is Preregistered -> ClientIdScheme.PreRegistered
        RedirectUri -> ClientIdScheme.RedirectUri
        is VerifierAttestation -> ClientIdScheme.VERIFIER_ATTESTATION
        is X509SanDns -> ClientIdScheme.X509_SAN_DNS
        is X509SanUri -> ClientIdScheme.X509_SAN_URI
    }
}

data class VpFormats(
    val sdJwtVc: VpFormat.SdJwtVc? = null,
    val msoMdoc: VpFormat.MsoMdoc? = null,
) {
    init {
        require(sdJwtVc != null || msoMdoc != null) {
            "At least one format must be specified."
        }
    }

    companion object {

        operator fun invoke(vararg formats: VpFormat) = VpFormats(formats.toList())

        operator fun invoke(formats: List<VpFormat>) {
            require(formats.isNotEmpty()) { "At least one format must be specified." }
            ensureUniquePerFormat(formats)
            val sdJwt = formats.filterIsInstance<VpFormat.SdJwtVc>().firstOrNull()
            val msoMdoc = formats.filterIsInstance<VpFormat.MsoMdoc>().firstOrNull()
            VpFormats(sdJwt, msoMdoc)
        }

        fun intersect(thiz: VpFormats, that: VpFormats): VpFormats? {
            val scg = thiz.sdJwtVc?.intersect(that.sdJwtVc)
            val mcg = thiz.msoMdoc?.intersect(that.msoMdoc)
            return if (scg != null || mcg != null) {
                VpFormats(scg, mcg)
            } else null
        }

        private fun ensureUniquePerFormat(formats: Iterable<VpFormat>) {
            formats
                .groupBy { it.formatName() }
                .forEach { (formatName, instances) ->
                    require(instances.size == 1) {
                        "Multiple instances ${instances.size} found for $formatName."
                    }
                }
        }

        private enum class FormatName {
            MSO_MDOC, SD_JWT_VC
        }

        private fun VpFormat.formatName() = when (this) {
            is VpFormat.MsoMdoc -> FormatName.MSO_MDOC
            is VpFormat.SdJwtVc -> FormatName.SD_JWT_VC
        }
    }
}

/**
 * A type of Transaction Data supported by the Wallet.
 */
data class SupportedTransactionDataType(
    val type: TransactionDataType,
    val hashAlgorithms: Set<HashAlgorithm>,
) {
    init {
        require(hashAlgorithms.isNotEmpty()) { "hashAlgorithms cannot be empty" }
        require(HashAlgorithm.SHA_256 in hashAlgorithms) { "'${HashAlgorithm.SHA_256.name}' must be a supported hash algorithm" }
    }
}

/**
 * Configurations options for OpenId4VP
 *
 * @param presentationDefinitionUriSupported indicates whether wallet should fetch a presentation definition
 * which is communicated by the verifier by reference using `presentation_definition_uri`.
 * @param knownPresentationDefinitionsPerScope a set of presentation definitions that a verifier may request via
 * a pre-agreed scope (instead of explicitly using presentation_definition or presentation_definition_uri)
 * @param knownDCQLQueriesPerScope a set of DCQL queries that a verifier may request via a pre-agreed scope
 * @param vpFormats The formats the wallet supports
 * @param supportedTransactionDataTypes the types of Transaction Data that are supported by the wallet
 */
data class VPConfiguration(
    val presentationDefinitionUriSupported: Boolean = true,
    val knownPresentationDefinitionsPerScope: Map<String, PresentationDefinition> = emptyMap(),
    val knownDCQLQueriesPerScope: Map<String, DCQL> = emptyMap(),
    val vpFormats: VpFormats,
    val supportedTransactionDataTypes: List<SupportedTransactionDataType> = emptyList(),
)

interface JarmSigner : JWSSigner {
    fun getKeyId(): String

    companion object {
        operator fun invoke(rsaKey: RSAKey): JarmSigner =
            object : JarmSigner, JWSSigner by RSASSASigner(rsaKey) {
                override fun getKeyId(): String = rsaKey.keyID
            }

        operator fun invoke(rsaKey: ECKey): JarmSigner =
            object : JarmSigner, JWSSigner by ECDSASigner(rsaKey) {
                override fun getKeyId(): String = rsaKey.keyID
            }
    }
}

/**
 * Configurations options for encrypting and/or signing an authorization response via JARM,
 * if requested by the verifier.
 *
 * The library can be configured to:
 *
 * - Support only [signing][Signing] the authorization response
 * - Support only [encrypting][Encryption] the authorization response
 * - Support both singing and encrypting [SigningAndEncryption] the authorization response
 * - Not support JARM
 *
 * OpenId4VP recommends supporting [encrypting][Encryption] the authorization response
 */
sealed interface JarmConfiguration {

    /**
     * The wallet supports only signed authorization responses
     *
     * @param signer the JWS algorithms that the wallet can use when signing a JARM response
     * @param ttl the time the signed authorization response can live
     */
    data class Signing(
        val signer: JarmSigner,
        val ttl: Duration? = Duration.ofMinutes(10),
    ) : JarmConfiguration {
        init {
            require(signer.supportedJWSAlgorithms().isNotEmpty()) { "At least a algorithm must be provided" }
        }
    }

    /**
     * The wallet supports only encrypted authorization responses
     * @param supportedAlgorithms the JWE algorithms that the wallet can use when encrypting a JARM response
     * @param supportedMethods the JWE encryption methods that the wallet can use when encrypting a JARM
     * response
     */
    data class Encryption(
        val supportedAlgorithms: List<JWEAlgorithm>,
        val supportedMethods: List<EncryptionMethod>,
    ) : JarmConfiguration {
        init {
            require(supportedAlgorithms.isNotEmpty()) { "At least an encryption algorithm must be provided" }
            require(supportedMethods.isNotEmpty()) { "At least an encryption method must be provided" }
        }
    }

    /**
     * The wallet supports any kind of JARM response, signed, encrypted and/or signed and then encrypted
     *
     * @param signing the singing options
     * @param encryption the encryption options
     */
    data class SigningAndEncryption(val signing: Signing, val encryption: Encryption) : JarmConfiguration {

        constructor(
            signer: JarmSigner,
            supportedEncryptionAlgorithms: List<JWEAlgorithm>,
            supportedEncryptionMethods: List<EncryptionMethod>,
        ) : this(
            Signing(signer),
            Encryption(supportedEncryptionAlgorithms, supportedEncryptionMethods),
        )
    }

    /**
     * Wallet doesn't support replying using JARM
     */
    data object NotSupported : JarmConfiguration
}

fun JarmConfiguration.signingConfig(): Signing? = when (this) {
    is Signing -> this
    is Encryption -> null
    is SigningAndEncryption -> signing
    NotSupported -> null
}

fun JarmConfiguration.encryptionConfig(): Encryption? = when (this) {
    is Signing -> null
    is Encryption -> this
    is SigningAndEncryption -> encryption
    NotSupported -> null
}

sealed interface VpFormat : java.io.Serializable {
    data class SdJwtVc(
        val sdJwtAlgorithms: List<JWSAlgorithm>,
        val kbJwtAlgorithms: List<JWSAlgorithm>,
    ) : VpFormat {
        init {
            require(sdJwtAlgorithms.isNotEmpty()) { "SD-JWT algorithms cannot be empty" }
        }

        fun intersect(that: SdJwtVc?): SdJwtVc? {
            if (that == null) return null

            val kbJwtAlgs = kbJwtAlgorithms.intersect(that.kbJwtAlgorithms.toSet())
            val sdJwtAlgs = sdJwtAlgorithms.intersect(that.sdJwtAlgorithms.toSet())
            return if (sdJwtAlgs.isNotEmpty() && kbJwtAlgs.isNotEmpty())
                SdJwtVc(sdJwtAlgs.toList(), kbJwtAlgs.toList())
            else null
        }

        companion object {
            val ES256 = SdJwtVc(listOf(JWSAlgorithm.ES256), listOf(JWSAlgorithm.ES256))
        }
    }

    data class MsoMdoc(val algorithms: List<JWSAlgorithm>) : VpFormat {
        init {
            require(algorithms.isNotEmpty()) { "Mso-doc algorithms cannot be empty" }
        }

        fun intersect(that: MsoMdoc?): MsoMdoc? {
            if (that == null) return null

            val algs = algorithms.intersect(that.algorithms.toSet())
            return if (algs.isNotEmpty())
                MsoMdoc(algs.toList())
            else null
        }

        companion object {
            val ES256 = MsoMdoc(listOf(JWSAlgorithm.ES256))
        }
    }
}

sealed interface NonceOption {
    data object DoNotUse : NonceOption

    @JvmInline
    value class Use(val byteLength: Int = 32) : NonceOption {
        init {
            require(byteLength > 1) { "Byte length should be greater than 1" }
        }
    }
}

/**
 * Wallet articulated encryption requirements.
 */
sealed interface EncryptionRequirement : java.io.Serializable {

    /**
     * Encryption is not required.
     */
    data object NotRequired : EncryptionRequirement {
        private fun readResolve(): Any = NotRequired
    }

    /**
     * Encryption is required.
     *
     * @property supportedEncryptionAlgorithms encryption algorithms supported by the Wallet, only asymmetric JWEAlgorithms are supported
     * @property supportedEncryptionMethods encryption methods supported by the Wallet, [EncryptionMethod.XC20P] requires the usage
     * of [com.google.crypto.tink:tink](https://central.sonatype.com/artifact/com.google.crypto.tink/tink)
     * @property ephemeralEncryptionKeyCurve the [Curve] to use for generating the ephemeral encryption key
     */
    data class Required(
        val supportedEncryptionAlgorithms: List<JWEAlgorithm>,
        val supportedEncryptionMethods: List<EncryptionMethod>,
        val ephemeralEncryptionKeyCurve: Curve,
    ) : EncryptionRequirement {
        init {
            require(supportedEncryptionAlgorithms.isNotEmpty()) { "supportedEncryptionAlgorithms cannot be empty" }
            require(SUPPORTED_ENCRYPTION_ALGORITHMS.containsAll(supportedEncryptionAlgorithms)) {
                "only the following JWEAlgorithms are supported: $SUPPORTED_ENCRYPTION_ALGORITHMS"
            }
            require(supportedEncryptionMethods.isNotEmpty()) { "supportedEncryptionMethods cannot be empty" }
            require(SUPPORTED_ENCRYPTION_METHODS.containsAll(supportedEncryptionMethods)) {
                "only the following EncryptionMethods are supported: $SUPPORTED_ENCRYPTION_METHODS"
            }
            require(ephemeralEncryptionKeyCurve in SUPPORTED_EPHEMERAL_ENCRYPTION_KEY_CURVES) {
                "only the following Curves are supported: $SUPPORTED_EPHEMERAL_ENCRYPTION_KEY_CURVES"
            }
        }

        companion object {
            val SUPPORTED_ENCRYPTION_ALGORITHMS: List<JWEAlgorithm> get() = ECDHDecrypter.SUPPORTED_ALGORITHMS.toList()
            val SUPPORTED_ENCRYPTION_METHODS: List<EncryptionMethod> get() = ECDHDecrypter.SUPPORTED_ENCRYPTION_METHODS.toList()
            val SUPPORTED_EPHEMERAL_ENCRYPTION_KEY_CURVES: List<Curve> get() = ECDHDecrypter.SUPPORTED_ELLIPTIC_CURVES.toList()
        }
    }
}

/**
 * Which of the `request_uri_method` are supported by the wallet
 */
sealed interface SupportedRequestUriMethods {

    /**
     * Indicates support to `request_uri_method` `get`
     */
    data object Get : SupportedRequestUriMethods

    /**
     * Options related to `request_uri_method` equal to `post`
     *
     * @param includeWalletMetadata whether to include wallet metadata or not
     * @param jarEncryption whether to request JAR be encrypted or not
     * @param useWalletNonce whether to use wallet_nonce
     */
    data class Post(
        val includeWalletMetadata: Boolean = true,
        val jarEncryption: EncryptionRequirement = EncryptionRequirement.NotRequired,
        val useWalletNonce: NonceOption = NonceOption.Use(),
    ) : SupportedRequestUriMethods {
        init {
            require(EncryptionRequirement.NotRequired == jarEncryption || includeWalletMetadata) {
                "Wallet Metadata must be included when JAR encryption is required"
            }
        }
    }

    /**
     * Both methods are supported
     */
    data class Both(val post: Post) : SupportedRequestUriMethods

    fun isGetSupported(): Boolean = when (this) {
        is Both, Get -> true
        is Post -> false
    }

    fun isPostSupported(): Post? = when (this) {
        is Both -> post
        Get -> null
        is Post -> this
    }

    companion object {
        /**
         * The default option is to support both `get` and `post` and in the later case,
         * include `wallet_metadata` and `wallet_nonce`, and NOT require JAR be encrypted
         */
        val Default: SupportedRequestUriMethods = Both(post = Post())
    }
}

/**
 * Options related to JWT-Secured authorization requests
 *
 * @param supportedAlgorithms the algorithms supported for the signature of the JAR
 * @param supportedRequestUriMethods which of the `request_uri_method` methods are supported
 */
data class JarConfiguration(
    val supportedAlgorithms: List<JWSAlgorithm>,
    val supportedRequestUriMethods: SupportedRequestUriMethods = SupportedRequestUriMethods.Default,
) {
    init {
        require(supportedAlgorithms.isNotEmpty()) { "JAR signing algorithms cannot be empty" }
    }

    companion object {
        /**
         * The default JAR configuration list as trusted algorithms ES256, ES384, and ES512.
         * Also, both `request_uri_method` are supported.
         *
         * @see SupportedRequestUriMethods.Default
         */
        val Default = JarConfiguration(
            supportedAlgorithms = listOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512),
            supportedRequestUriMethods = SupportedRequestUriMethods.Default,
        )
    }
}

/**
 * Wallets policy regarding error dispatching.
 */
enum class ErrorDispatchPolicy : java.io.Serializable {

    /**
     * Allow dispatching of errors to all clients, regardless of authentication status.
     */
    AllClients,

    /**
     * Allow dispatching of errors only to authenticated clients.
     */
    OnlyAuthenticatedClients,
}

/**
 * Wallet configuration options for SIOP & OpenId4VP protocols.
 *
 * At minimum, a wallet configuration should define at least a [supportedClientIdSchemes]
 *
 * @param issuer an optional id for the wallet. If not provided defaults to [SelfIssued].
 * @param jarConfiguration options related to JWT Secure authorization requests.
 * If not provided, it will default to [JarConfiguration.Default]
 * @param jarmConfiguration whether wallet supports JARM. If not specified, it takes the default value
 * [JarmConfiguration.NotSupported].
 * @param vpConfiguration options about OpenId4VP.
 * @param clock the system Clock. If not provided system's default clock will be used.
 * @param jarClockSkew max acceptable skew between wallet and verifier
 * @param supportedClientIdSchemes the client id schemes that are supported/trusted by the wallet
 * @param errorDispatchPolicy wallet's policy regarding error dispatching. Defaults to [ErrorDispatchPolicy.OnlyAuthenticatedClients].
 */
data class SiopOpenId4VPConfig(
    val issuer: Issuer? = SelfIssued,
    val jarConfiguration: JarConfiguration = JarConfiguration.Default,
    val jarmConfiguration: JarmConfiguration = NotSupported,
    val vpConfiguration: VPConfiguration,
    val clock: Clock = Clock.systemDefaultZone(),
    val jarClockSkew: Duration = Duration.ofSeconds(15L),
    val supportedClientIdSchemes: List<SupportedClientIdScheme>,
    val errorDispatchPolicy: ErrorDispatchPolicy = ErrorDispatchPolicy.OnlyAuthenticatedClients,
) {
    init {
        require(supportedClientIdSchemes.isNotEmpty()) { "At least a supported client id scheme must be provided" }
    }

    constructor(
        issuer: Issuer? = SelfIssued,
        jarConfiguration: JarConfiguration = JarConfiguration.Default,
        jarmConfiguration: JarmConfiguration = NotSupported,
        vpConfiguration: VPConfiguration,
        clock: Clock = Clock.systemDefaultZone(),
        jarClockSkew: Duration = Duration.ofSeconds(15L),
        errorDispatchPolicy: ErrorDispatchPolicy = ErrorDispatchPolicy.OnlyAuthenticatedClients,
        vararg supportedClientIdSchemes: SupportedClientIdScheme,
    ) : this(
        issuer,
        jarConfiguration,
        jarmConfiguration,
        vpConfiguration,
        clock,
        jarClockSkew,
        supportedClientIdSchemes.toList(),
        errorDispatchPolicy,
    )

    companion object {
        /**
         * Identifies the wallet as `https://self-issued.me/v2`
         */
        val SelfIssued = Issuer(URI.create("https://self-issued.me/v2"))
    }
}

internal fun SiopOpenId4VPConfig.supportedClientIdScheme(scheme: ClientIdScheme): SupportedClientIdScheme? =
    supportedClientIdSchemes.firstOrNull { it.scheme() == scheme }
