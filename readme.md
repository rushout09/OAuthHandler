Create an "EnableServiceProvider" endpoint that first verifies login creds and get user's id.
It also gets as input API_KEY, API_SECRET, CLIENT_ID, CLIENT_SECRET, SCOPES.
It will be documented to use a generic redirect_url "authorization-success" for that service provider.
It will store this information as a field-value pair with key being user's id.
It will return success.

Create an "AuthorizeServiceProvider" endpoint that first verifies login creds and get user's id.
It also gets as input the end_user_id in the above request.
Then this function generates a state and store it as a field in a field-value pair with key being "STATE".
The value for above state field would be concatenation of user_id and end_user_id.

Create an "authorization-success" endpoint. When the user approves the request, Service provider will hit this.
It will get the state and code information from the Service Provider.
It will generate the access and refresh tokens for that particular end-user.
It will save above details in a field:value pair with user_id_end_user_id key.

Create a "get_access_token" for each service provider. It first verifies login creds and get user's id.
It also gets as input end_user_id key.
It will use this info to get access_token and return it to the user.