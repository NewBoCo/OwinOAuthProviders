﻿namespace Owin.Security.Providers.Imgur
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Newtonsoft.Json;

    using Owin.Security.Providers.Imgur.Provider;

    public class ImgurAuthenticationHandler : AuthenticationHandler<ImgurAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public ImgurAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            if (httpClient == null)
            {
                throw new ArgumentNullException("httpClient");
            }

            if (logger == null)
            {
                throw new ArgumentNullException("logger");
            }

            this.httpClient = httpClient;
            this.logger = logger;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (this.Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = this.Helper.LookupChallenge(this.Options.AuthenticationType, this.Options.AuthenticationMode);

            if (challenge == null)
            {
                return Task.FromResult<object>(null);
            }

            var currentUri = this.Request.Uri.AbsoluteUri;

            if (string.IsNullOrWhiteSpace(challenge.Properties.RedirectUri))
            {
                challenge.Properties.RedirectUri = currentUri;
            }

            this.GenerateCorrelationId(challenge.Properties);

            var state = this.Options.StateDataFormat.Protect(challenge.Properties);

            var authorizationUri = ImgurAuthenticationDefaults.AuthorizationUri;
            authorizationUri = WebUtilities.AddQueryString(authorizationUri, ImgurAuthenticationDefaults.ClientIdParameter, Uri.EscapeDataString(this.Options.ClientId));
            authorizationUri = WebUtilities.AddQueryString(authorizationUri, ImgurAuthenticationDefaults.ResponseTypeParameter, ImgurAuthenticationDefaults.CodeResponseType);
            authorizationUri = WebUtilities.AddQueryString(authorizationUri, ImgurAuthenticationDefaults.StateParameter, Uri.EscapeDataString(state));

            this.Response.Redirect(authorizationUri);

            return Task.FromResult<object>(null);
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            if (this.Request.Query.Get(ImgurAuthenticationDefaults.ErrorParameter) != null)
            {
                return new AuthenticationTicket(null, null);
            }

            var code = this.Request.Query.Get(ImgurAuthenticationDefaults.CodeParameter);
            var state = this.Request.Query.Get(ImgurAuthenticationDefaults.StateParameter);
            var properties = this.Options.StateDataFormat.Unprotect(state);

            if (properties == null)
            {
                return new AuthenticationTicket(null, null);
            }

            if (!this.ValidateCorrelationId(properties, this.logger))
            {
                return new AuthenticationTicket(null, properties);
            }

            AuthenticationResponse authenticationResponse;

            using (var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, ImgurAuthenticationDefaults.TokenUri))
            {
                httpRequestMessage.Content =
                    new FormUrlEncodedContent(
                        new []
                        {
                            new KeyValuePair<string, string>(ImgurAuthenticationDefaults.ClientIdParameter, this.Options.ClientId),
                            new KeyValuePair<string, string>(ImgurAuthenticationDefaults.ClientSecretParameter, this.Options.ClientSecret),
                            new KeyValuePair<string, string>(ImgurAuthenticationDefaults.GrantTypeParameter, ImgurAuthenticationDefaults.AuthorizationCodeGrantType),
                            new KeyValuePair<string, string>(ImgurAuthenticationDefaults.CodeParameter, code)
                        });

                using (var httpResponseMessage = await this.httpClient.SendAsync(httpRequestMessage, this.Request.CallCancelled))
                {
                    if (!httpResponseMessage.IsSuccessStatusCode)
                    {
                        throw new Exception(ImgurAuthenticationDefaults.CommunicationFailureMessage);
                    }

                    using (var stream = await httpResponseMessage.Content.ReadAsStreamAsync())
                    {
                        var jsonSerializer = new JsonSerializer();

                        using (var streamReader = new StreamReader(stream))
                        {
                            using (var jsonTextReader = new JsonTextReader(streamReader))
                            {
                                authenticationResponse = jsonSerializer.Deserialize<AuthenticationResponse>(jsonTextReader);
                            }
                        }
                    }
                }
            }

            if (authenticationResponse == null)
            {
                throw new Exception(ImgurAuthenticationDefaults.DeserializationFailureMessage);
            }

            var identity = new ClaimsIdentity(this.Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            identity.AddClaim(new Claim(ClaimTypes.Name, authenticationResponse.AccountUsername, ImgurAuthenticationDefaults.XmlSchemaString, this.Options.AuthenticationType));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, authenticationResponse.AccountId.ToString(ImgurAuthenticationDefaults.Int32Format, CultureInfo.InvariantCulture), ImgurAuthenticationDefaults.XmlSchemaString, this.Options.AuthenticationType));
            identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, authenticationResponse.AccountUsername, ImgurAuthenticationDefaults.XmlSchemaString, this.Options.AuthenticationType));

            var context = new ImgurAuthenticatedContext(this.Context, this.Options);
            context.AccessToken = authenticationResponse.AccessToken;
            context.AccountId = authenticationResponse.AccountId;
            context.AccountUsername = authenticationResponse.AccountUsername;
            context.ExpiresIn = authenticationResponse.ExpiresIn;
            context.Identity = identity;
            context.Properties = properties;
            context.RefreshToken = authenticationResponse.RefreshToken;
            context.Scope = authenticationResponse.Scope;
            context.TokenType = authenticationResponse.TokenType;

            await this.Options.Provider.Authenticated(context);

            return new AuthenticationTicket(context.Identity, context.Properties);
        }

        public override async Task<bool> InvokeAsync()
        {
            if (!this.Options.CallbackPath.HasValue)
            {
                return false;
            }

            if (!this.Options.CallbackPath.Value.Equals(this.Request.Path.Value, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var ticket = await this.AuthenticateAsync();

            if (ticket == null)
            {
                throw new Exception(ImgurAuthenticationDefaults.InvalidAuthenticationTicketMessage);
            }

            var context = new ImgurReturnEndpointContext(this.Context, ticket);
            context.SignInAsAuthenticationType = this.Options.SignInAsAuthenticationType;
            context.RedirectUri = ticket.Properties.RedirectUri;

            await this.Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                var identity = context.Identity;

                if (!identity.AuthenticationType.Equals(context.SignInAsAuthenticationType, StringComparison.OrdinalIgnoreCase))
                {
                    identity = new ClaimsIdentity(identity.Claims, context.SignInAsAuthenticationType, identity.NameClaimType, identity.RoleClaimType);
                }

                this.Context.Authentication.SignIn(context.Properties, identity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null)
            {
                return context.IsRequestCompleted;
            }

            var location = context.RedirectUri;

            if (context.Identity == null)
            {
                location = WebUtilities.AddQueryString(location, ImgurAuthenticationDefaults.ErrorParameter, ImgurAuthenticationDefaults.AccessDeniedErrorMessage);
            }

            this.Response.Redirect(location);

            context.RequestCompleted();

            return context.IsRequestCompleted;
        }

        private class AuthenticationResponse
        {
            [JsonProperty(PropertyName = ImgurAuthenticationDefaults.AccessTokenPropertyName)]
            public string AccessToken { get; set; }

            [JsonProperty(PropertyName = ImgurAuthenticationDefaults.AccountIdPropertyName)]
            public int AccountId { get; set; }

            [JsonProperty(PropertyName = ImgurAuthenticationDefaults.AccountUsernamePropertyName)]
            public string AccountUsername { get; set; }

            [JsonProperty(PropertyName = ImgurAuthenticationDefaults.ExpiresInPropertyName)]
            public int ExpiresIn { get; set; }

            [JsonProperty(PropertyName = ImgurAuthenticationDefaults.RefreshInPropertyName)]
            public string RefreshToken { get; set; }

            [JsonProperty(PropertyName = ImgurAuthenticationDefaults.ScopePropertyName)]
            public string Scope { get; set; }

            [JsonProperty(PropertyName = ImgurAuthenticationDefaults.TokenTypePropertyName)]
            public string TokenType { get; set; }
        }
    }
}
