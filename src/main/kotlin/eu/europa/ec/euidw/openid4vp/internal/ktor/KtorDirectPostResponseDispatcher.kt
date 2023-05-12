package eu.europa.ec.euidw.openid4vp.internal.ktor

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse.DirectPostResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponseDispatcher
import eu.europa.ec.euidw.openid4vp.HttpFormPost
import eu.europa.ec.euidw.openid4vp.ManagedAuthorizationResponseDispatcher
import io.ktor.client.*

class KtorDirectPostResponseDispatcher<in A : DirectPostResponse>(
    proxyFactory: (HttpFormPost<Unit>) -> AuthorizationResponseDispatcher<A, Unit>
) : ManagedAuthorizationResponseDispatcher<A> {

    /**
     * The ktor http client
     */
    private val httpClient: HttpClient by lazy { HttpKtorAdapter.createKtorClient() }

    /**
     * The actual or proxied [AuthorizationResponseDispatcher]
     */
    private val proxy: AuthorizationResponseDispatcher<A, Unit> by lazy {
        proxyFactory(HttpKtorAdapter.httpFormPost(httpClient))
    }

    override suspend fun dispatch(response: A) = proxy.dispatch(response)

    override fun close() = httpClient.close()


}


