using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace SeekSafe
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Home", action = "Index", id = UrlParameter.Optional }
            );

            // Custom route for handling authenticated vs. anonymous users
            routes.MapRoute(
                name: "CustomHome",
                url: "Home/{action}",
                defaults: new { controller = "Home", action = "Home" },
                constraints: new { authenticated = new AuthenticatedRouteConstraint() }
            );

            routes.MapRoute(
                name: "Error",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Home", action = "NotFound", id = UrlParameter.Optional }
            );

            routes.MapRoute(
                name: "CatchAll",
                url: "{*url}",
                defaults: new { controller = "Home", action = "NotFound" }
            );

            routes.MapRoute(
                name: "InternalServerError",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Home", action = "InternalServerError", id = UrlParameter.Optional }
            );
        }
        public class AuthenticatedRouteConstraint : IRouteConstraint
        {
            public bool Match(HttpContextBase httpContext, Route route, string parameterName, RouteValueDictionary values, RouteDirection routeDirection)
            {
                // Check if the user is authenticated
                return httpContext.User.Identity.IsAuthenticated;
            }
        }
    }
}
