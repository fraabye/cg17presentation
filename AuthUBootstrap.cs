using Our.Umbraco.AuthU;
using Our.Umbraco.AuthU.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Umbraco.Core;

/// <summary>
/// Summary description for AuthUBootstrap
/// </summary>
public class AuthUBootstrap : ApplicationEventHandler
{
    public AuthUBootstrap()
    {
            
    }
    protected override void ApplicationStarted(UmbracoApplicationBase umbracoApplication, ApplicationContext applicationContext)
    {
        OAuth.ConfigureEndpoint("/oauth/token", new OAuthOptions
        {
            UserService = new UmbracoMembersOAuthUserService(),
            SymmetricKey = "856FECBA3B06519C8DDDBC80BB080553",
            AccessTokenLifeTime = 20, // Minutes
            AllowInsecureHttp = true // During development only
        });
    }
}
