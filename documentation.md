---
layout: page
title: Documentation
permalink: /docs/
---
## Defining a `RestEndpoint`

The following section will document the `spec` of a `RestEndpoint`.

For more completes examples please see the [one in the repo](https://github.com/sebt3/kuberest/tree/main/examples)

### Availability of the *values* for both *handlebars* templates and *rhai* scripts

The following values are populated in the order of the documented flow:
![workflow diagram](../kuberest_flow.png "Workflow")
- `input`
- `init`
- `pre`
- `read`
- `write`
- `post`

Which mean `write` is empty when computing the reads instructions. But `read` is fully populated when running the writes.

All these keys will have sub-keys based on the names of their definition.

{% raw %}
### `input` from Secret and ConfigMap

The following definition:
```yaml
spec:
  inputs:
  - name: mySecret
    secretRef:
      name: secret-name
```
Will populate the value `input.mySecret` with the whole definition of the secret `secret-name`. Which mean `input.mySecret.metadata.name` is a string with the value `secret-name` if the said secret do exist.

Please note that the object is provided as-is. So the data from a secret *will* be base64 encoded. The `base64_decode` helper for handlebars and the same rhai method are there to accomodate you.

If your definition can accomodate the absence of the Secret (or ConfigMap), use the `optional: true` key as bellow :
```yaml
spec:
  inputs:
  - name: myOptConfig
    configMapRef:
      optional: true
      name: secret-name
```
Any referenced Secret or ConfigMap missing without that `optional: true` key will stop the process. A kubernetes event will be produced, and a conditions in the status will explain the missing piece(s).

> notes: kuberest do *not* watch changes on theses Secret/ConfigMap. So change will be reflected on the next verification loop. Hence, using kuberest as a secret-copier is a bad abuse: the dedicated operators doing this use watch, so the changes are reflected immediately.


### `input` from rendered handlebars templates

This is an helper to help you save a value to be reused multiple time later in the *RestEndpoint* definition and be sure the value will be the same.

```yaml
spec:
  inputs:
  - name: uuid
    handleBarsRender: "{{ uuid_new_v7 }}"
```
will put a generated uuid in `input.uuid`.

Going further, JSON object are also supported:
```yaml
spec:
  inputs:
  - name: config
    handleBarsRender: |-
      {{#to_json format="yaml"}}
      merge_method: ff
      issues_enabled: false
      {{/to_json}}
```
Set `input.config.merge_method` to `"ff"`.

### `input` from a Password Generator

> :warn: While the kuberest do provide the feature, it is probably advised to use a dedicated operator like [kubernetes-secret-generator](https://github.com/mittwald/kubernetes-secret-generator) if you need a lot of them and maintain them. Use with **caution**.

This feature is mainly provided to set strong default password for technical users within the manipulated endpoint. Do not overuse this ;)

```yaml
spec:
  inputs:
  - name: password
    passwordGenerator:
      length: 32
      weightAlphas:  60
      weightNumbers: 20
      weightSymbols: 20
```
Will set a generated password with default configuration for `input.password`. The following would have defined the same thing.
```yaml
spec:
  inputs:
  - name: password
    passwordGenerator: {}
```

The default configuration create a 32 charaters long password with 60% of letters (capitalized or otherwise) 20% of numbers and 20% of symbols.

### Configuring the REST client
```yaml
spec:
  client:
    baseurl: "https://gitlab.com/api/v4"
```
Is a strict minimum for any `RestEndpoint` definition and set the rest client base url to use Gitlab REST endpoints.

#### Authentication

Since no REST endpoint come without any form of authentication, a more complete definition would be:
```yaml
spec:
  inputs:
  - name: token
    secretRef:
      name: my-personal-gitlab-token
  client:
    baseurl: "https://gitlab.com/api/v4"
    headers:
      Authorization: "Bearer {{ base64_decode input.token.data.gitlab_token }}"
```

Basic authentication is also possible:

```yaml
spec:
  inputs:
  - name: admin
    secretRef:
      name: gitea-admin-user
  client:
    baseurl: "https://gitea.your-company.com/api/v1"
    headers:
      Authorization: "{{ header_basic (base64_decode input.admin.data.username) (base64_decode input.admin.data.password) }}"
```

#### Others headers

You can define any other needed `headers` as you please. The following headers are already set for you, but you can overwrite them (with all the implied consequenses: kuberest will still expect json data and will still send the http body as json encoded)
```yaml
spec:
  client:
    headers:
      Content-Type: "application/json; charset=utf-8"
      Accept: "application/json"
```

#### Further client configuration

Here are the other availables options for the `client` and their default value:
```yaml
spec:
  client:
    keyName: id
    teardown: true
    updateMethod: Put
```

| key | default | description |
|---  |---      |--- |
|keyName  | id | the key in the returned object that identify the object
|teardown | true | Should the created objects (writes section) be deleted when then `RestEndpoint` is deleted
|updateMethod | `Put` | Updating the objects with which HTTP primitive. Available values: `Put`, `Patch` and `Post`.

All theses 3 keys can be overwritten per "write group" if needed.

### Defines `read` from HTTP `Get`

All reads will use the client definition
```yaml
spec:
  client:
    baseurl: "https://gitlab.com/api/v4"
  reads:
  - name: projects
    path: "users/123456"
    items:
    - name: list
      key: "projects"
```
Would define `read.projects.list` from the result of the following command: `curl https://gitlab.com/api/v4/users/123456/projects`.
Which mean, the URL used is defined by `<client.baseurl>/<read_group.name>/<item.key>`.

You can defined as many read groups and item as needed.

> Hint: item key can be empty, so you can make this a little less awkward:

```yaml
spec:
  reads:
  - name: seb
    path: "users/123456/projects"
    items: [{"name": "list", "key": ""}]
  - name: paul
    path: "users/654321/projects"
    items: [{"name": "list", "key": ""}]
```

Which would set `read.seb.list` and `read.paul.list`. Alternatively, you can:

```yaml
spec:
  reads:
  - name: projects
    path: "users"
    items:
    - name: seb
      key: 123456/projects
    - name: paul
      key: 654321/projects
```

Which would set `read.projects.seb` and `read.projects.paul` with the same value as in the previous example.

### Create REST objects and get their definitions set in `write`

The URL construction for writes work exactly the same as for reads. The actual key for each created object will be stored and kept to reuse on updates.

```yaml
spec:
  client:
    baseurl: "https://gitea.your-company.com/api/v1"
  writes:
  - name: application
    path: user/applications/oauth2
    items:
    - name: woodpecker
      values: |-
        confidential_client: true
        name: woodpecker
        redirect_uris:
        - "https://woodpecker.your-company.com/authorize"
```

So the initial call here would make a POST to "https://gitea.your-company.com/api/v1/user/applications/oauth2" while the later scheduled updates will do a PUT to "https://gitea.your-company.com/api/v1/user/applications/oauth2/&lt;id&gt;" where &lt;id&gt; is the obtained "id" on the initial POST response.

`values` is an HandleBars template that return a YAML formated object.

#### Further writes configuration

You can overwrite the behaviour of the controller for a single REST endpoint using:
```yaml
spec:
  writes:
  - name: application
    keyName: id
    teardown: true
    updateMethod: Put
```

| key | default | description |
|---  |---      |--- |
|keyName  | id | the key in the returned object that identify the object
|teardown | true | Should the created objects (writes section) be deleted when then `RestEndpoint` is deleted
|updateMethod | `Put` | Updating the objects with which HTTP primitive. Available values: `Put`, `Patch` and `Post`.

## Saving the results with outputs

Saving the results is straightforward:
```yaml
spec:
  outputs:
  - kind: ConfigMap
    metadata:
      name: set-all-projects-merge-method
    data:
      result.yaml: |-
        ---
        {{ json_to_str post.results format="yaml" }}
```
Availables kind: `ConfigMap` and `Secret`.

Availables metedata fields: `name`, `labels`, `annotations` and `namespace` (if multi-tenancy is disabled).

Data values are also handlebars templates.

> *note*: Secret data is passed to the cluster as `stringData`, so the cluster **will** base64 encode the secret values for us. No need to mess with base64_encode here.

```yaml
spec:
  outputs:
  - kind: Secret
    metadata:
      name: woodpecker-gitea-openid
    data:
      WOODPECKER_GITEA_CLIENT: "{{ write.application.woodpecker.client_id }}"
      WOODPECKER_GITEA_SECRET: "{{ write.application.woodpecker.client_secret }}"
```


## Available helpers for *handlebars* templates

### From dependencies

kuberest use the [handlebars_misc_helpers](https://github.com/davidB/handlebars_misc_helpers) crate which provide a lot of others helpers see the documentation on that page for the complete list.

### From this package

|Helper         | Arguments             | Description   | Example
|---            |---                    |---            |---
|base64_decode  | base64_encoded_string | Decode a base64 encode string (usefull for Secret values)  | `base64_decode input.secret.data.some_key`
|base64_encode  | string_to_encode      | Encode a string/buffer with the base64 encoding  | `base64_encode "username:password"`
|gen_password   | length                | Generate a password if specified length  | `gen_password 32`
|gen_password_alphanum| length          | Generate a password if specified length without any specials characters | `gen_password_alphanum 8 `
|header_basic   | username, password    | Generate a "Basic *encoded_auth*" value to set with a "Authorization" header | `header_basic (base64_decode input.secret.data.username) (base64_decode input.secret.data.password)`
|argon_hash   | password    | Hash a password using the Argon2 algorithm | `argon_hash (base64_decode input.secret.data.password)`
|bcrypt_hash   | password    | Hash a password using the BCrypt algorithm | `bcrypt_hash (base64_decode input.secret.data.password)`


## *rhai* scripts

[Rhai](https://rhai.rs/) is a memory-safe scripting engine. It is a very pleasant language to play with. Have a look at their [examples](https://rhai.rs/book/start/examples/scripts.html) to learn the language capabilities.

The only reason why this ability exist is: many of the apps we love have configuration endpoints that do *not* comply with REST (Grafana, SonarQube to name a few). Provoding this ability come with risk of abuses. Dont, for your own cluster safety ;)

All rhai scripts (init/pre/post/teardown) are expected to return a `Map`, so the most minimal script is:
```rhai
#{}
```
This is an empty `Map` in the rhai language. Failing to return a `Map` will stop the process. Errors are documented in the conditions of the `RestEndpoint`.

### `pre` script usage

Templating/Preparing data for later stage(s):

```rhai
fn genValues(name) {
  #{
    name: name,
    other: "properties",
    to: #{
      configure: "your",
      way: name+"-test"
    }
  }
}
#{
  pierre: genValues("pierre"),
  paul: genValues("paul"),
  jacques: genValues("jacques"),
}
```

### `post` script usage

Some api endpoints are not REST friendly, use your scripting skillz for these.
> **warning** You're on your own. Using this mean kuberest wont handle the teardown process for you. Before using this, write your teardown script. Or you'll leave garbage behind you.


### `teardown` script usage
{% endraw %}
![workflow diagram](../kuberest_teardown_flow.png "Workflow")

It's meant to undo your changes in the `post` script.

If your `writes` use the `pre` variables in the templates, then the teardown needs to provides the sames values. YAML allow to duplicate strings, use it:
```yaml
spec:
  pre: &genValues |-
    #{
      some: "values"
    }
  teardown: *genValues
```

## Available methods for *rhai* scripts

|Method         | Arguments             | Return | Description   | Example |
|---            |---                    |---     |---            |---      |
| gen_password  | length (number)       | string | Generate a password of requested length | `let passwd = gen_password(32);` |
| gen_password_alphanum | length (number) | string | Generate a password of requested length without any special characters | `let weak_passwd = gen_password_alphanum(8);` |
|base64_decode  | base64_encoded_data (string) | string | Decode a base64 encode string (usefull for Secret values)  | `letdecoded = base64_decode(input.secret.data.some_key);`
|base64_encode  | string_to_encode      | string | Encode a string/buffer with the base64 encoding  | `let encoded = base64_encode("username:password");`
| json_encode | data (any) | string | Convert any data to their JSON representation string | `let encoded = json_encode(#{test: "value"});`
| json_decode | encoded_data (string) | any | convert any json formated data to their rhai object/array/... conterpart | `let data = json_decode("{\\"name\\":\\"paul\\"}");`
| yaml_encode | data (any) | string | Convert any data to their YAML representation string | `let encoded = yaml_encode(#{test: "value"});`
| yaml_decode | encoded_data (string) | any | convert any YAML formated data to their rhai object/array/... conterpart | `let data = yaml_decode("name: paul");`
| yaml_decode_multi | encoded_data (string) | array | convert a multi-document yaml string into an array of the corresponding object/array/... | `let data = yaml_decode_multi("name: paul");`
| bcrypt_hash | password | string | hash a clear-text password using the bcrypt algorithm | `let hash = bcrypt_hash("my_secret_password");`
| new_argon().hash | password | string | hash a clear-text password using the Argon2 algorithm | `let hasher = new_argon();let hash = hasher.hash("my_secret_password");`

### The `hbs` object

From rhai you have a complete access to the HandleBars templating environement using the `hbs` object :

|Method         | Arguments             | Return | Description   | Example |
|---            |---                    |---     |---            |---      |
| render_from  | template(string), values (object) | string | Generate a password of requested length | `let passwd = hbs.render_from("{{> passwd }}", values);` |

### The `client` object

From rhai you have a complete access to the REST client used in kuberest using the `client` object:

|Method         | Arguments             | Return | Description   | Example |
|---            |---                    |---     |---            |---      |
| head  | path(string) | object | do an HTTP HEAD on `path` | `let res = client.head("projects");` |
| get  | path(string) | object | do an HTTP GET on `path` | `let res = client.get("projects");` |
| delete  | path(string) | object | do an HTTP DELETE on `path` | `let res = client.delete("projects/1345/groups/43");` |
| patch  | path(string), values (object) | object | do an HTTP PATCH on `path` | `let res = client.patch("projects/1345/groups/43", #{name: "test"});` |
| post  | path(string), values (object) | object | do an HTTP POST on `path` | `let res = client.post("projects/1345/groups/43", #{name: "test"});` |
| put  | path(string), values (object) | object | do an HTTP PUT on `path` | `let res = client.put("projects/1345/groups/43", #{name: "test"});` |

In the context of duplicating data to an other service, you can create an other client:
```rhai
let target = new_client("https://gitlab.com/api/v4");
target.add_header("add_header", "Bearer "+base64_decode(input.gitlab.data.token));
target.add_header_json();
let prjs = target.get("projects");
...
```

|Method         | Arguments             | Description   |
|---            |---                    |---            |
| new_client    | baseurl(string)  | Create a new http client |
| set_baseurl  | baseurl(string) | Change the basepath of the client |
| set_server_ca  | PEM_certificate (string) | Configure the serverCA certificate (for self-signed target) |
| set_mtls_cert_key  | PEM_certificate (string),PEM_key (string) | Configure Client certificate and key for mTLS authentification |
| add_header  | key (string), value (string) | Set a header for the client |
| add_header_bearer  | token(string) | Add an `Authorization: Bearer` header |
| add_header_basic | username(string), password(string) | Add an `Authorization: Basic` header |
| add_header_json  | null | Set the Accept and Content-Type headers to json |
| headers_reset | null | Remove all stored headers on the client |


> **warning** do not forget to write the teardown script.