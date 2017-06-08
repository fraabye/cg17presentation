using System;
using System.Configuration;
using ASP;
using Owin;
using Umbraco.Web;

public class AzureADOwinStartup : UmbracoDefaultOwinStartup
{
    private readonly static string clientId = ConfigurationManager.AppSettings["clientId"];    
    private readonly static string tenantId = ConfigurationManager.AppSettings["tenantId"];    
    private readonly static string loginUrl = ConfigurationManager.AppSettings["backOfficeUrl"];

    public override void Configuration(IAppBuilder app)
    {
        //ensure the default options are configured
        base.Configuration(app);

        app.ConfigureBackOfficeAzureActiveDirectoryAuth(tenantId, clientId, loginUrl, new Guid(tenantId));
    }
}