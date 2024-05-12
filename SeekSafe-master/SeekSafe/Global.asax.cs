using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace SeekSafe
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            RouteConfig.RegisterRoutes(RouteTable.Routes);
        }

        //protected void Application_Error()
        //{
        //    // Sets 404 HTTP exceptions to be handled via IIS (behavior is specified in the "httpErrors" section in the Web.config file)
        //    var error = Server.GetLastError();
        //    if ((error as HttpException)?.GetHttpCode() == 404)
        //    {
        //        Server.ClearError();
        //        Response.StatusCode = 404;
        //    }
        //}

        protected void Application_Error(object sender, EventArgs e)
        {
            Exception exception = Server.GetLastError();
            Response.Clear();

            HttpException httpException = exception as HttpException;

            if (httpException != null && httpException.GetHttpCode() == 404)
            {
                Response.StatusCode = 404;
                Server.ClearError();
                Response.Redirect("/Home/NotFound");
            }
            else if (httpException != null && httpException.GetHttpCode() == 500)
            {
                // Handle other server errors (e.g., 500 Internal Server Error)
                Response.StatusCode = 500;
                Server.ClearError();
                Response.Redirect("/Home/InternalServerError");
            }
        }
    }
}
