import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

public class CognitoAuthenticationAuthorizationHandler implements RequestHandler<Map<String, Object>, ApiGatewayResponse> {


    //Stating aws region
    private String userPoolId = "";

    //Interface for creating default implementation
    private AWSCognitoIdentityProvider cognito = AWSCognitoIdentityProviderClientBuilder.defaultClient();

    //Getting all userpools and their names by ID
    List<UserPoolDescriptionType> userPools =
            cognito.listUserPools(new ListUserPoolsRequest().
                    withMaxResults(20)).getUserPools();


    @Override
    public ApiGatewayResponse handleRequest(Map<String, Object> input, Context context) {

        try {
            String userName = "";
            String password = "";
            JsonNode body = new ObjectMapper().readTree((String) input.get("body"));
            if (body != null && body.hasNonNull("username") && body.hasNonNull("password")) {
                userName = body.get("username").asText();
                password = body.get("password").asText();
            }


            userPoolId = System.getenv("userPoolId");


            ListUserPoolClientsResult response =
                    cognito.listUserPoolClients(new ListUserPoolClientsRequest().
                            withUserPoolId(userPoolId).withMaxResults(1));

            UserPoolClientType userPool =
                    cognito.describeUserPoolClient(new DescribeUserPoolClientRequest().
                            withUserPoolId(userPoolId).withClientId(response.getUserPoolClients().
                            get(0).getClientId())).getUserPoolClient();


            //Authenticating the user and pass username and password
            Map<String, String> authParams = new HashMap<>(2);
            authParams.put("USERNAME", userName);
            authParams.put("PASSWORD", password);
            AdminInitiateAuthRequest authRequest =
                    new AdminInitiateAuthRequest().withClientId(userPool.getClientId()).
                            withUserPoolId(userPool.getUserPoolId()).withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH).
                            withAuthParameters(authParams);
            AdminInitiateAuthResult result = cognito.adminInitiateAuth(authRequest);
            AuthenticationResultType auth = result.getAuthenticationResult();
            context.getLogger().log(auth.getAccessToken());

            return ApiGatewayResponse.builder()
                    .setStatusCode(200)
                    .setObjectBody(auth.getAccessToken())
                    .build();

        } catch (final Exception exception) {

            exception.printStackTrace();

            return ApiGatewayResponse.builder()
                    .setStatusCode(501)
                    .setObjectBody(exception.toString())
                    .build();

        }

    }

}