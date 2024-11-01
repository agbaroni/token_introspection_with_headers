
# APIcast Token Introspection With Headers Policy

This policy is an evolution of the token introspection policy which allows to extract some claims from the response and put in HTTP headers.

## OpenShift

To install this on OpenShift you can use provided template:

```shell
oc new-app -f openshift.yml --param AMP_RELEASE=2.10
```

The template creates a new ***ImageStream*** for storing the custom images containing this policy.
Then it creates two ***BuildConfigs***: one for building an image to ```apicast-policy``` ImageStream and second one for creating new APIcast image copying just the necessary code from the previous image.

## Configuration

The configuration is built over two section:

- introspection section
- headers section

### Introspection section

the configuration parameters are the same of the original Token Introspection policy:

|Parameter name| Description | Default value | Allowed Values | Required |
|----|----|----|----|----|
|auth_type|Specify the auth credentials location| client_id+client_secret |**use_3scale_oidc_issuer_endpoint** for using 3Scale configured parameter<br>**client_id+client_secret** for specifying different token introspection parameters|true|
|client_id|Client ID for the Token Introspection Endpoint| | |true if client_id+client_secret is specified|
|client_secret|Client Secret for the Token Introspection Endpoint| | |true if client_id+client_secret is specified|
|introspection_url|Introspection Endpoint URL| | |true if client_id+client_secret is specified|
|max_ttl_tokens|Max TTL for cached tokens| |integer between 1 and 3600|false|
|max_cached_tokens|Max number of tokens to cache| |integer between 0 and 10000|false|

more informations about the parameters can be found in [3Scale APICast documentation](https://access.redhat.com/documentation/en-us/red_hat_3scale_api_management/2.10/html/administering_the_api_gateway/apicast_policies#token_introspection)

### Headers section

the headers section allows multiple **header** elements:

|Parameter name| Description | Default value | Allowed Values | Required |
|----|----|----|----|----|
|op|Operation to be applied||**add**: Add a value to an existing header<br>**set**: Create the header when not set, replace its value when set.<br>**push**:Create the header when not set, add the value when set.|true|
|header|Header to be modified|||true|
|value|Identifies the claim to be extracted from the introspection response and put into the header|||false|
|value_type|How to evaluate 'value'|plain|**plain**:Evaluate 'value' as plain text.<br>**liquid**: Evaluate 'value' as liquid.| false|
|is_array|Claims 'value' to be an array|false|| false|

# Openshift Operator configuration

Add the following line to the APICast spec in the Operator CR replacing &lt;Project Name&gt; with the name of the project where the ImageStream resides:

```yaml
image: 'image-registry.openshift-image-registry.svc:5000/<Project 
Name>/amp-apicast:custom'
```

**Note:** is important to change both the 3Scale managed and the external APICasts images since the 3Scale managed Staging APICast is being used by 3Scale Admin as policy repository. If the component isn't updated the policy won't be available in 3Scale console.

# License

MIT
