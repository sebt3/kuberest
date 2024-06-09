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
- `pre`
- `read`
- `change`
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


## *rhai* scripts

[Rhai](https://rhai.rs/) is a memory-safe scripting engine. It is a very pleasant language to play with. Have a look at their [examples](https://rhai.rs/book/start/examples/scripts.html) to learn the language capabilities.

The only reason why this ability exist is: many of the apps we love have configuration endpoints that do *not* comply with REST (Grafana, SonarQube to name a few). Provoding this ability come with risk of abuses. Dont, for your own cluster safety ;)

All rhai scripts (pre/change/post/teardown) are expected to return a `Map`, so the most minimal script is:
```rhai
#{}
```
This is an empty `Map` in the rhai language. Failing to return a `Map` will stop the process. Errors are documented in the conditions of the `RestEndpoint`.

### `pre` script usages

#### 2 stages authentication process

```rhai
```

#### Templating/Preparing data for later stage(s)

```rhai
```

### `change` script usages

#### Duplicating data between 2 endpoints

```rhai
```

#### Non-REST friendly api-endpoints

```rhai
```

### `post` script usages

#### Templating/Preparing data for outputs

### `teardown` script usages
{% endraw %}
![workflow diagram](../kuberest_teardown_flow.png "Workflow")


If you used a `pre` script for 2-stages authentification or any of the `change` scripts usages scenarios, a teardown script will be required to help the `DELETE` to happen correctly.

## Available methods for *rhai* scripts

|Method         | Arguments             | Description   | Example
|---            |---                    |---            |---
