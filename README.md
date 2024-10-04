# CA-TerraformIaC

Create conditional access policies from json templates/exports using Terraform.

POC using the Conditional Access templates provided by Microsoft. Allows to store the policies as json which is easily exported using Graph and generate your IaC using Terraform.

May be some bugs. Tested using azuread 3.0.1. Some preview features not available. 


### Note:
There is a bug in the provider that affects policies that have a require password change and session control in the same policy. Reccomended workaround until fixed is to use the import command in the registry to get the policy into state.

Not reccomended for production. Due to the provider not being 1:1 parity. Heavily depends on the naming as of 3.0.1 and may change/break regularly with new versions.
