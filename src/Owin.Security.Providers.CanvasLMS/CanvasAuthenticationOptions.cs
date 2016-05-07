using System;
using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.CanvasLMS.Provider;

namespace Owin.Security.Providers.CanvasLMS
{
    public class CanvasAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Endpoints for Canvas LMS authentication, as described at
        /// https://canvas.instructure.com/doc/api/file.oauth_endpoints.html
        /// </summary>
        public class CanvasAuthenticationEndpoints
        {
            /// <summary>
            /// Path which is used to redirect users to request Canvas access
            /// </summary>
            /// <remarks>
            /// Defaults to /login/oauth2/auth
            /// </remarks>
            public string AuthorizationPath { get; set; }

            /// <summary>
            /// Path which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to /login/oauth2/token
            /// </remarks>
            public string TokenPath { get; set; }

            /// <summary>
            /// Path which is used to request details about the authenticated user
            /// </summary>
            /// <remarks>
            /// Defaults to /api/v1/users/self
            /// </remarks>
            public string UserPath { get; set; }
        }

        private const string AuthorizationPath = "/login/oauth2/auth";
        private const string TokenPath = "/login/oauth2/token";
        private const string UserPath = "/api/v1/users/self";

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Canvas.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-canvas".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        ///     Gets or sets the Canvas supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Canvas supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets the base Canvas endpoint URL
        /// </summary>
        public string EndpointBase { get; private set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against Canvas.
        /// </summary>
        public CanvasAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="ICanvasAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public ICanvasAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request. (optional)
        /// </summary>
        /// <remarks>
        /// This can be used to specify what information the access token will provide access to.
        /// By default an access token will have access to all api calls that a user can make.
        /// The only other accepted value for this at present is '/auth/userinfo', which can be used to obtain the current canvas user's identity.
        /// </remarks>
        public IList<string> Scopes { get; private set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the purpose of this Canvas application. (optional)
        /// </summary>
        /// <remarks>
        /// This can be used to help the user identify which instance of an application this token is for. For example, a mobile device application could provide the name of the device.
        /// </remarks>
        public string Purpose { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="CanvasAuthenticationOptions" />
        /// </summary>
        /// <param name="endpointBase">The base Canvas endpoint URL, e.g. https://canvas.instructure.com</param>
        public CanvasAuthenticationOptions(string endpointBase)
            : base(Constants.DefaultAuthenticationType)
        {
            if (endpointBase == null)
                throw new ArgumentNullException(nameof(endpointBase));

            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-canvas");
            AuthenticationMode = AuthenticationMode.Passive;
            Scopes = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            EndpointBase = endpointBase;
            Endpoints = new CanvasAuthenticationEndpoints
            {
                AuthorizationPath = AuthorizationPath,
                TokenPath = TokenPath,
                UserPath = UserPath,
            };
        }
    }
}