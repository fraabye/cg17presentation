using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Owin;
using Umbraco.Core;
using Umbraco.Core.Security;
using Umbraco.Web.Security.Identity;
using Microsoft.Owin.Security.OpenIdConnect;
using Umbraco.Core.Models.Identity;
using Umbraco.Core.Models.Membership;
using Umbraco.Core.Persistence.Mappers;

namespace Dubex.Core
{
    public static class UmbracoAzureADAuthExtensions
    {

        ///  <summary>
        ///  Configure ActiveDirectory sign-in
        ///  </summary>
        ///  <param name="app"></param>
        ///  <param name="tenant"></param>
        ///  <param name="clientId"></param>
        ///  <param name="postLoginRedirectUri">
        ///  The URL that will be redirected to after login is successful, example: http://mydomain.com/umbraco/;
        ///  </param>
        ///  <param name="issuerId">
        /// 
        ///  This is the "Issuer Id" for you Azure AD application. This a GUID value and can be found
        ///  in the Azure portal when viewing your configured application and clicking on 'View endpoints'
        ///  which will list all of the API endpoints. Each endpoint will contain a GUID value, this is
        ///  the Issuer Id which must be used for this value.        
        /// 
        ///  If this value is not set correctly then accounts won't be able to be detected 
        ///  for un-linking in the back office. 
        /// 
        ///  </param>
        /// <param name="caption"></param>
        /// <param name="style"></param>
        /// <param name="icon"></param>
        /// <remarks>
        ///  ActiveDirectory account documentation for ASP.Net Identity can be found:
        ///  https://github.com/AzureADSamples/WebApp-WebAPI-OpenIDConnect-DotNet
        ///  </remarks>
        public static void ConfigureBackOfficeAzureActiveDirectoryAuth(this IAppBuilder app,
            string tenant, string clientId, string postLoginRedirectUri, Guid issuerId,
            string caption = "Azure Active Directory", string style = "btn-microsoft", string icon = "fa-windows")
        {
            var authority = string.Format(
                CultureInfo.InvariantCulture,
                "https://login.windows.net/{0}",
                tenant);

            var adOptions = new OpenIdConnectAuthenticationOptions
            {
                SignInAsAuthenticationType = Constants.Security.BackOfficeExternalAuthenticationType,
                ClientId = clientId,
                Authority = authority,
                RedirectUri = postLoginRedirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async context =>
                    {
                        var userService = ApplicationContext.Current.Services.UserService;
                        var userManager = context.OwinContext.GetBackOfficeUserManager();

                        var umbracoRoles = new List<string> { "admin", "editor", "writer", "translator" };

                        string email;

                        // Only users with an Office 365 license will have an "email" claim passed. We utilise that the Azure AD user name (upn) will always be a valid email address.
                        if (!context.JwtSecurityToken.Claims.Any(x => x.Type == "email") && context.JwtSecurityToken.Claims.Any(x => x.Type == "upn"))
                        {
                            email = context.JwtSecurityToken.Claims.First(x => x.Type == "upn").Value;
                        }
                        else
                        {
                            email = context.JwtSecurityToken.Claims.First(x => x.Type == "email").Value;
                        }

                        var issuer = context.JwtSecurityToken.Claims.First(x => x.Type == "iss").Value;
                        var providerKey = context.JwtSecurityToken.Claims.First(x => x.Type == "sub").Value;
                        var name = context.JwtSecurityToken.Claims.First(x => x.Type == "name").Value;
                        var roles = context.JwtSecurityToken.Claims.Where(x => x.Type == "roles").Select(x => x.Value);

                        var user = userService.GetByEmail(email);

                        // Abort if the user is not assigned a relevant role in Azure AD.
                        if (!roles.Intersect(umbracoRoles).Any())
                        {
                            return;
                        }

                        var userGroup = userService.GetUserGroupsByAlias(GetUmbracoRoleWithMostPrivileges(roles)).FirstOrDefault();

                        if (user == null)
                        {
                            // The user was not found in Umbraco but Azure AD grants access to one or more roles.                                                                                 
                            user = userService.CreateUserWithIdentity(email, email);
                            //userService.AssignUserGroupPermission(1,);
                            userService.Save(user);
                        }

                        // Clear any existing groups and force apply membership from Azure AD.
                        user.ClearGroups();
                        user.AddGroup((IReadOnlyUserGroup)userGroup);

                        userService.Save(user);

                        var identity = await userManager.FindByEmailAsync(email);

                        // If the current/newly created user is not linked to Azure AD, do it.
                        if (identity.Logins.All(x => x.ProviderKey != providerKey))
                        {
                            identity.Logins.Add(new IdentityUserLogin(issuer, providerKey, user.Id));
                            identity.Name = name;
                            await userManager.UpdateAsync(identity);
                        }
                    }
                }
            };

            adOptions.ForUmbracoBackOffice(style, icon);
            adOptions.Caption = caption;

            //Need to set the auth type as the issuer path
            adOptions.AuthenticationType = string.Format(CultureInfo.InvariantCulture, "https://sts.windows.net/{0}/", issuerId);

            //adOptions.SetExternalSignInAutoLinkOptions(new ExternalSignInAutoLinkOptions(autoLinkExternalAccount: true));
            app.UseOpenIdConnectAuthentication(adOptions);
        }

        private static string GetUmbracoRoleWithMostPrivileges(IEnumerable<string> roles)
        {
            if (roles.Contains("admin"))
                return "admin";

            if (roles.Contains("editor"))
                return "editor";

            if (roles.Contains("writer"))
                return "writer";

            if (roles.Contains("translator"))
                return "translator";

            throw new Exception("The list of roles does not contain any Umbraco roles.");
        }
    }

}
