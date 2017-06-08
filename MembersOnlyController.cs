using Our.Umbraco.AuthU.Web.WebApi;
using System.Web.Http;
using Umbraco.Web.WebApi;

namespace CloudyGarden.Web.App_Code
{
    [OAuth]
    public class MembersOnlyController : UmbracoApiController
    {
        [HttpGet]
        [Authorize]
        public string HelloWorld()
        {
            return "Hello " + Members.GetCurrentMember().Name;
        }
    }
}