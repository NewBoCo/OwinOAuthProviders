using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.CanvasLMS.Provider;

namespace Owin.Security.Providers.CanvasLMS
{
    public class CanvasAuthenticationHandler : AuthenticationHandler<CanvasAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public CanvasAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;
                var values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var response = await RequestToken("authorization_code", code, "code");
                var context = await Authenticate(response, properties);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failure.", ex);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null) return Task.FromResult<object>(null);
            var baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
                Request.PathBase;

            var currentUri =
                baseUri +
                Request.Path +
                Request.QueryString;

            var redirectUri =
                baseUri +
                Options.CallbackPath;

            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            // comma separated
            var scope = string.Join(" ", Options.Scopes);

            var state = Options.StateDataFormat.Protect(properties);

            var authorizationEndpoint =
                Options.EndpointBase(Context) +
                Options.Endpoints.AuthorizationPath +
                "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                "&response_type=" + Uri.EscapeDataString("code") +
                "&scopes=" + Uri.EscapeDataString(scope) +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&purpose=" + Uri.EscapeDataString(Options.Purpose ?? "") +
                "&state=" + Uri.EscapeDataString(state);

            Response.Redirect(authorizationEndpoint);

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync() || await RefreshAccessTokenAsync();
        }

        private async Task<bool> RefreshAccessTokenAsync()
        {
            var accessTokenExpiration = ParseExpiration();
            if (accessTokenExpiration > DateTimeOffset.Now.AddMinutes(1))
                return false;

            var refreshToken = Context.Authentication.User?.FindFirst(Constants.CanvasRefreshToken)?.Value;
            if (string.IsNullOrEmpty(refreshToken))
                return false;

            _logger.WriteInformation("Requesting new access token.");

            try
            {
                var response = await RequestToken("refresh_token", refreshToken);
                var identity = Context.Authentication.User.Identities
                    .FirstOrDefault(ci => ci.AuthenticationType == Options.SignInAsAuthenticationType);

                var context = await Authenticate(response, refreshToken: refreshToken);

                if (identity == null)
                {
                    identity = context.Identity;
                }
                else
                {
                    var claims = identity.Claims.ToList();
                    foreach (var c in claims)
                        identity.RemoveClaim(c);

                    identity.AddClaims(context.Identity.Claims);
                }

                Context.Authentication.SignIn(identity);
                return false;
            }
            catch (Exception ex)
            {
                _logger.WriteError("Could not refresh access token.", ex);
                Response.StatusCode = 500;
                return true;
            }
        }

        DateTimeOffset ParseExpiration()
        {
            var expiration = Context.Authentication.User?.FindFirst(Constants.CanvasAccessTokenExpiration)?.Value;
            if (string.IsNullOrEmpty(expiration))
                return DateTimeOffset.MinValue;

            return DateTimeOffset.ParseExact(expiration, "u", CultureInfo.InvariantCulture);
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path) return false;
            // TODO: error responses

            var ticket = await AuthenticateAsync();
            if (ticket == null && Request.Query["error"] != "access_denied")
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new CanvasReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket?.Properties.RedirectUri,
            };

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null &&
                context.Identity != null)
            {
                var grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, grantIdentity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null) return context.IsRequestCompleted;
            var redirectUri = context.RedirectUri;
            if (context.Identity == null)
            {
                // add a redirect hint that sign-in failed in some way
                redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
            }
            Response.Redirect(redirectUri);
            context.RequestCompleted();

            return context.IsRequestCompleted;
        }

        private async Task<object> RequestToken(string grantType, string grantToken, string grantTokenParameterName = null)
        {
            var requestPrefix = Request.Scheme + Uri.SchemeDelimiter + Request.Host;
            var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

            // Build up the body for the token request
            var body = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>(grantTokenParameterName ?? grantType, grantToken),
                new KeyValuePair<string, string>("grant_type", grantType),
                new KeyValuePair<string, string>("client_id", Options.ClientId),
                new KeyValuePair<string, string>("redirect_uri", redirectUri)
            };

            // Request the token
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.EndpointBase(Context) + Options.Endpoints.TokenPath);
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                new Base64TextEncoder().Encode(Encoding.ASCII.GetBytes(Options.ClientId + ":" + Options.ClientSecret)));
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = new FormUrlEncodedContent(body);

            var tokenResponse = await _httpClient.SendAsync(requestMessage);
            tokenResponse.EnsureSuccessStatusCode();

            var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();
            return JObject.Parse(tokenResponseContent);
        }

        private async Task<CanvasAuthenticatedContext> Authenticate(dynamic response, AuthenticationProperties properties = null, string refreshToken = null)
        {
            var accessToken = (string)response.access_token;
            refreshToken = (string)response.refresh_token ?? refreshToken;
            var expiresIn = (int?)response.expires_in;

            // Get the user info
            var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, Options.EndpointBase(Context) + Options.Endpoints.UserPath);
            userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            userInfoRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var userInfoResponse = await _httpClient.SendAsync(userInfoRequest);
            userInfoResponse.EnsureSuccessStatusCode();
            var userInfoResponseContent = await userInfoResponse.Content.ReadAsStringAsync();
            var user = JObject.Parse(userInfoResponseContent);

            var context = new CanvasAuthenticatedContext(Context, user, accessToken, refreshToken, expiresIn)
            {
                Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType)
            };
            if (!string.IsNullOrEmpty(context.Id))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString,
                    Options.AuthenticationType));
            }
            if (!string.IsNullOrEmpty(context.Name))
            {
                context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name, XmlSchemaString,
                    Options.AuthenticationType));
            }
            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                context.Identity.AddClaim(new Claim(Constants.CanvasAccessToken, context.AccessToken));
            }
            if (!string.IsNullOrEmpty(context.RefreshToken))
            {
                context.Identity.AddClaim(new Claim(Constants.CanvasRefreshToken, context.RefreshToken));
            }
            context.Identity.AddClaim(new Claim(Constants.CanvasAccessTokenExpiration,
                context.AccessTokenExpiration.ToString("u", CultureInfo.InvariantCulture)));

            context.Properties = properties;

            await Options.Provider.Authenticated(context);

            return context;
        }
    }
}