# cg17presentation
Presentation and code snippets from my #cg17 talk about external authentication with Umbraco.

# Web.config additions for the Azure AD and AuthU samples to work
```
<appSettings>
...
  <!-- AzureADOwinStartup configuration begin -->
  <add key="TenantId" value="xxxxxxxx-xxxx-xxx-xxxx-xxxxxxxxxxxxx" />
  <add key="ClientId" value="xxxxxxxx-xxxx-xxx-xxxx-xxxxxxxxxxxxx" />
  <add key="BackOfficeUrl" value="http://localhost:xxxx/umbraco" />
  <!-- AzureADOwinStartup configuration end -->
  
  <!-- Basic AuthU configuration of an oauth endpoint for members -->
  <add key="umbracoReservedPaths" value="~/umbraco,~/install/,~/oauth/" />
 
</appSettings>
```
# Azure AD app manifest additions for adding Umbraco roles and sending group membership claims
```
"groupMembershipClaims": "SecurityGroup",

"appRoles": [
      {"allowedMemberTypes": [
        "User"
      ],
      "displayName": "Administrator",
      "id": "eb4280a8-41c7-4958-b50f-9eb6286219d0",
      "isEnabled": true,
      "description": "Administrators have full access to the Umbraco installation.",
      "value": "admin"
    },
      {"allowedMemberTypes": [
        "User"
      ],
      "displayName": "Editor",
      "id": "1ea251bf-86bb-4a37-8fb8-9e55c6422c41",
      "isEnabled": true,
      "description": "Editors have the ability to edit and publish content.",
      "value": "editor"
    },
    {
      "allowedMemberTypes": [
        "User"
      ],
      "displayName": "Writer",
      "id": "27d87ddd-0352-4a79-b0d6-e6c60706d07b",
      "isEnabled": true,
      "description": "Writers have the ability to edit content but not to publish it.",
      "value": "writer"
    },
    {
      "allowedMemberTypes": [
        "User"
      ],
      "displayName": "Translator",
      "id": "edca5eac-906e-493b-88dc-04e035c07656",
      "isEnabled": true,
      "description": "Translators will be able to access  the translation section of the backoffice only.",
      "value": "translator"
    }
]
```
