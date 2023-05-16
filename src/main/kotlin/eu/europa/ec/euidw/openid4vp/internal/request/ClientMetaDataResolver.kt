package eu.europa.ec.euidw.openid4vp.internal.request

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.internal.mapError
import java.net.URL


internal class ClientMetaDataResolver(
    private val getClientMetaData: HttpGet<ClientMetaData>
) {

    suspend fun resolve(clientMetaDataSource: ClientMetaDataSource): Result<OIDCClientMetadata> {

        val clientMetaData = when (clientMetaDataSource) {
            is ClientMetaDataSource.PassByValue -> clientMetaDataSource.metaData
            is ClientMetaDataSource.FetchByReference -> fetch(clientMetaDataSource.url).getOrThrow()

        }
        return ClientMetadataValidator.validate(clientMetaData)
    }

    private suspend fun fetch(url: URL): Result<ClientMetaData> =
        getClientMetaData.get(url)
            .mapError { ResolutionError.UnableToFetchClientMetadata(it).asException() }

}

