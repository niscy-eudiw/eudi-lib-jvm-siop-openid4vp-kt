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
package eu.europa.ec.eudi.openid4vp.internal.response

import eu.europa.ec.eudi.openid4vp.AuthorizationRequestError
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.ErrorDispatchDetails
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.openid4vp.internal.response.AuthorizationResponse.*

internal fun AuthorizationRequestError.responseWith(
    di: ErrorDispatchDetails,
    encryptionParameters: EncryptionParameters?,
): AuthorizationResponse {
    val payload = AuthorizationResponsePayload.InvalidRequest(
        error = this,
        state = di.state,
        nonce = di.nonce,
        clientId = di.clientId,
        encryptionParameters = encryptionParameters,
    )
    return responseWith(di, payload)
}

private fun responseWith(
    di: ErrorDispatchDetails,
    data: AuthorizationResponsePayload.InvalidRequest,
): AuthorizationResponse {
    fun jarmOption() = checkNotNull(di.jarmRequirement)

    return when (val mode = di.responseMode) {
        is ResponseMode.DirectPost -> DirectPost(mode.responseURI, data)
        is ResponseMode.DirectPostJwt -> DirectPostJwt(mode.responseURI, data, jarmOption())
        is ResponseMode.Fragment -> Fragment(mode.redirectUri, data)
        is ResponseMode.FragmentJwt -> FragmentJwt(mode.redirectUri, data, jarmOption())
        is ResponseMode.Query -> Query(mode.redirectUri, data)
        is ResponseMode.QueryJwt -> QueryJwt(mode.redirectUri, data, jarmOption())
        ResponseMode.DCApi -> DCApi(data)
        ResponseMode.DCApiJwt -> DCApiJwt(data, jarmOption())
    }
}
