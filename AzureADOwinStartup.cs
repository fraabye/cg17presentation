using System;
using System.Configuration;
using Dubex.Core;
using Owin;
using Umbraco.Web;

public class AzureADOwinStartup : UmbracoDefaultOwinStartup
{
    private static readonly string clientId = ConfigurationManager.AppSettings["ClientId"];
    private static readonly string tenantId = ConfigurationManager.AppSettings["TenantId"];
    private static readonly string loginUrl = ConfigurationManager.AppSettings["BackOfficeUrl"];

    public override void Configuration(IAppBuilder app)
    {
        //ensure the default options are configured
        base.Configuration(app);

        app.ConfigureBackOfficeAzureActiveDirectoryAuth(tenantId, clientId, loginUrl, new Guid(tenantId));
    }
}
