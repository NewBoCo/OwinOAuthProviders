using System;

namespace Owin.Security.Providers.CanvasLMS
{
    public static class CanvasAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Canvas LMS by Instructure
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseCanvasAuthentication(this IAppBuilder app,
            CanvasAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(CanvasAuthenticationMiddleware), app, options);

            return app;
        }

        /// <summary>
        /// Authenticate users using Canvas LMS by Instructure
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="clientId">The Canvas supplied Client ID</param>
        /// <param name="clientSecret">The Canvas supplied Client Secret</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseCanvasAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseCanvasAuthentication(new CanvasAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}