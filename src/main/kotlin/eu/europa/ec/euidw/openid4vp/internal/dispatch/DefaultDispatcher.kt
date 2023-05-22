package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.prex.PresentationSubmission
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

internal class DefaultDispatcher(
    private val httpFormPost: HttpFormPost<DispatchOutcome.VerifierResponse>
) : Dispatcher {
    override suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome =
        when (response) {
            is AuthorizationResponse.DirectPost -> directPost(response)
            is AuthorizationResponse.DirectPostJwt -> directPostJwt(response)
            is AuthorizationResponse.RedirectResponse -> redirectURI(response)
        }

    private suspend fun directPost(response: AuthorizationResponse.DirectPost): DispatchOutcome.VerifierResponse =
        withContext(Dispatchers.IO) {
            val formParameters = DirectPostForm.of(response.data)
            httpFormPost.post(response.responseUri, formParameters)
        }


    private suspend fun directPostJwt(response: AuthorizationResponse.DirectPostJwt): DispatchOutcome.VerifierResponse =
        withContext(Dispatchers.IO) {
            TODO("")
        }

    private fun redirectURI(response: AuthorizationResponse.RedirectResponse): DispatchOutcome.RedirectURI =
        when (response) {
            is AuthorizationResponse.Fragment -> TODO()
            is AuthorizationResponse.FragmentJwt -> TODO()
            is AuthorizationResponse.Query -> TODO()
            is AuthorizationResponse.QueryJwt -> TODO()
        }
}


private object DirectPostForm {

    private const val PRESENTATION_SUBMISSION_FORM_PARAM = "presentation_submission"
    private const val VP_TOKEN_FORM_PARAM = "vp_token"
    private const val STATE_FORM_PARAM = "state"
    private const val ID_TOKEN_FORM_PARAM = "id_token"
    private const val ERROR_FORM_PARAM = "error"
    private const val ERROR_DESCRIPTION_FORM_PARAM = "error_description"

    fun of(p: AuthorizationResponsePayload): Map<String, String> {
        fun ps(ps: PresentationSubmission) =  Json.encodeToString<PresentationSubmission>(ps)
        fun vpToken(vcs: List<Jwt>) = Json.encodeToString<List<Jwt>>(vcs)
        return when (p) {
            is AuthorizationResponsePayload.SiopAuthenticationResponse -> mapOf(
                ID_TOKEN_FORM_PARAM to p.idToken,
                STATE_FORM_PARAM to p.state
            )

            is AuthorizationResponsePayload.OpenId4VPAuthorizationResponse -> mapOf(
                VP_TOKEN_FORM_PARAM to vpToken(p.verifiableCredential),
                PRESENTATION_SUBMISSION_FORM_PARAM to ps(p.presentationSubmission),
                STATE_FORM_PARAM to p.state
            )

            is AuthorizationResponsePayload.SiopOpenId4VPAuthenticationResponse -> mapOf(
                ID_TOKEN_FORM_PARAM to p.idToken,
                VP_TOKEN_FORM_PARAM to vpToken(p.verifiableCredential),
                PRESENTATION_SUBMISSION_FORM_PARAM to ps(p.presentationSubmission),
                STATE_FORM_PARAM to p.state
            )

            is AuthorizationResponsePayload.InvalidRequest -> mapOf(
                ERROR_FORM_PARAM to AuthorizationRequestErrorCode.fromError(p.error).code,
                ERROR_DESCRIPTION_FORM_PARAM to "${p.error}",
                STATE_FORM_PARAM to p.state
            )


            is AuthorizationResponsePayload.NoConsensusResponseData -> mapOf(
                ERROR_FORM_PARAM to AuthorizationRequestErrorCode.USER_CANCELLED.code,
                STATE_FORM_PARAM to p.state
            )
        }
    }
}

