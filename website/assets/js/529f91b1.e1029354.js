"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[3053],{3905:function(e,t,a){a.d(t,{Zo:function(){return d},kt:function(){return c}});var n=a(7294);function r(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function i(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,n)}return a}function o(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?i(Object(a),!0).forEach((function(t){r(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):i(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function l(e,t){if(null==e)return{};var a,n,r=function(e,t){if(null==e)return{};var a,n,r={},i=Object.keys(e);for(n=0;n<i.length;n++)a=i[n],t.indexOf(a)>=0||(r[a]=e[a]);return r}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)a=i[n],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(r[a]=e[a])}return r}var s=n.createContext({}),p=function(e){var t=n.useContext(s),a=t;return e&&(a="function"==typeof e?e(t):o(o({},t),e)),a},d=function(e){var t=p(e.components);return n.createElement(s.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var a=e.components,r=e.mdxType,i=e.originalType,s=e.parentName,d=l(e,["components","mdxType","originalType","parentName"]),m=p(a),c=r,k=m["".concat(s,".").concat(c)]||m[c]||u[c]||i;return a?n.createElement(k,o(o({ref:t},d),{},{components:a})):n.createElement(k,o({ref:t},d))}));function c(e,t){var a=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var i=a.length,o=new Array(i);o[0]=m;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l.mdxType="string"==typeof e?e:r,o[1]=l;for(var p=2;p<i;p++)o[p]=a[p];return n.createElement.apply(null,o)}return n.createElement.apply(null,a)}m.displayName="MDXCreateElement"},6345:function(e,t,a){a.r(t),a.d(t,{assets:function(){return d},contentTitle:function(){return s},default:function(){return c},frontMatter:function(){return l},metadata:function(){return p},toc:function(){return u}});var n=a(7462),r=a(3366),i=(a(7294),a(3905)),o=["components"],l={id:"externaldata",title:"External Data"},s=void 0,p={unversionedId:"externaldata",id:"version-v3.10.x/externaldata",title:"External Data",description:"Feature State: Gatekeeper version v3.7+ (alpha)",source:"@site/versioned_docs/version-v3.10.x/externaldata.md",sourceDirName:".",slug:"/externaldata",permalink:"/gatekeeper/website/docs/externaldata",draft:!1,editUrl:"https://github.com/open-policy-agent/gatekeeper/edit/master/website/versioned_docs/version-v3.10.x/externaldata.md",tags:[],version:"v3.10.x",frontMatter:{id:"externaldata",title:"External Data"},sidebar:"docs",previous:{title:"Constraint Templates",permalink:"/gatekeeper/website/docs/constrainttemplates"},next:{title:"Validation of Workload Resources",permalink:"/gatekeeper/website/docs/expansion"}},d={},u=[{value:"Motivation",id:"motivation",level:2},{value:"Enabling external data support",id:"enabling-external-data-support",level:2},{value:"YAML",id:"yaml",level:3},{value:"Helm",id:"helm",level:3},{value:"Dev/Test",id:"devtest",level:3},{value:"Providers",id:"providers",level:2},{value:"Providers maintained by the community",id:"providers-maintained-by-the-community",level:3},{value:"Sample providers",id:"sample-providers",level:3},{value:"API (v1alpha1)",id:"api-v1alpha1",level:3},{value:"<code>Provider</code>",id:"provider",level:4},{value:"<code>ProviderRequest</code>",id:"providerrequest",level:4},{value:"<code>ProviderResponse</code>",id:"providerresponse",level:4},{value:"Implementation",id:"implementation",level:3},{value:"External data for Gatekeeper validating webhook",id:"external-data-for-gatekeeper-validating-webhook",level:2},{value:"External data for Gatekeeper mutating webhook",id:"external-data-for-gatekeeper-mutating-webhook",level:2},{value:"API",id:"api",level:3},{value:"<code>AssignMetadata</code>",id:"assignmetadata",level:3},{value:"<code>Assign</code>",id:"assign",level:3},{value:"Limitations",id:"limitations",level:3},{value:"TLS and mutual TLS support",id:"tls-and-mutual-tls-support",level:2},{value:"Prerequisites",id:"prerequisites",level:3},{value:"(Optional) How to generate a self-signed CA and a keypair for the external data provider",id:"optional-how-to-generate-a-self-signed-ca-and-a-keypair-for-the-external-data-provider",level:3},{value:"How Gatekeeper trusts the external data provider (TLS)",id:"how-gatekeeper-trusts-the-external-data-provider-tls",level:3},{value:"How the external data provider trusts Gatekeeper (mTLS)",id:"how-the-external-data-provider-trusts-gatekeeper-mtls",level:3}],m={toc:u};function c(e){var t=e.components,a=(0,r.Z)(e,o);return(0,i.kt)("wrapper",(0,n.Z)({},m,a,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,(0,i.kt)("inlineCode",{parentName:"p"},"Feature State"),": Gatekeeper version v3.7+ (alpha)"),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"\u2757 This feature is still in alpha stage, so the final form can still change (feedback is welcome!).")),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"\u2705  Mutation is supported with external data starting from v3.8.0.")),(0,i.kt)("h2",{id:"motivation"},"Motivation"),(0,i.kt)("p",null,"Gatekeeper provides various means to mutate and validate Kubernetes resources. However, in many of these scenarios this data is either built-in, static or user defined. With external data feature, we are enabling Gatekeeper to interface with various external data sources, such as image registries, using a provider-based model."),(0,i.kt)("p",null,"A similar way to connect with an external data source can be done today using OPA's built-in ",(0,i.kt)("inlineCode",{parentName:"p"},"http.send")," functionality. However, there are limitations to this approach."),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Gatekeeper does not support Rego policies for mutation, which cannot use the OPA ",(0,i.kt)("inlineCode",{parentName:"li"},"http.send")," built-in function."),(0,i.kt)("li",{parentName:"ul"},"Security concerns due to:",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"if template authors are not trusted, it will potentially give template authors access to the in-cluster network."),(0,i.kt)("li",{parentName:"ul"},"if template authors are trusted, authors will need to be careful on how rego is written to avoid injection attacks.")))),(0,i.kt)("p",null,"Key benefits provided by the external data solution:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Addresses security concerns by:",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"Restricting which hosts a user can access."),(0,i.kt)("li",{parentName:"ul"},"Providing an interface for making requests, which allows Gatekeeper to better handle things like escaping strings."))),(0,i.kt)("li",{parentName:"ul"},"Addresses common patterns with a single provider, e.g. image tag-to-digest mutation, which can be leveraged by multiple scenarios (e.g. validating image signatures or vulnerabilities)."),(0,i.kt)("li",{parentName:"ul"},"Provider model creates a common interface for extending Gatekeeper with external data.",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"It allows for separation of concerns between the implementation that allows access to external data and the actual policy being evaluated."),(0,i.kt)("li",{parentName:"ul"},"Developers and consumers of data sources can rely on that common protocol to ease authoring of both constraint templates and data sources."),(0,i.kt)("li",{parentName:"ul"},'Makes change management easier as users of an external data provider should be able to tell whether upgrading it will break existing constraint templates. (once external data API is stable, our goal is to have that answer always be "no")'))),(0,i.kt)("li",{parentName:"ul"},"Performance benefits as Gatekeeper can now directly control caching and which values are significant for caching, which increases the likelihood of cache hits.",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"For mutation, we can batch requests via lazy evaluation."),(0,i.kt)("li",{parentName:"ul"},"For validation, we make batching easier via ",(0,i.kt)("a",{parentName:"li",href:"#external-data-for-Gatekeeper-validating-webhook"},(0,i.kt)("inlineCode",{parentName:"a"},"external_data"))," Rego function design.")))),(0,i.kt)("h2",{id:"enabling-external-data-support"},"Enabling external data support"),(0,i.kt)("h3",{id:"yaml"},"YAML"),(0,i.kt)("p",null,"You can enable external data support by adding ",(0,i.kt)("inlineCode",{parentName:"p"},"--enable-external-data")," in gatekeeper audit and controller-manager deployment arguments."),(0,i.kt)("h3",{id:"helm"},"Helm"),(0,i.kt)("p",null,"You can also enable external data by installing or upgrading Helm chart by setting ",(0,i.kt)("inlineCode",{parentName:"p"},"enableExternalData=true"),":"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-sh"},"helm install gatekeeper/gatekeeper --name-template=gatekeeper --namespace gatekeeper-system --create-namespace \\\n    --set enableExternalData=true\n")),(0,i.kt)("h3",{id:"devtest"},"Dev/Test"),(0,i.kt)("p",null,"For dev/test deployments, use ",(0,i.kt)("inlineCode",{parentName:"p"},"make deploy ENABLE_EXTERNAL_DATA=true")),(0,i.kt)("h2",{id:"providers"},"Providers"),(0,i.kt)("p",null,"Providers are designed to be in-cluster components that can communicate with external data sources (such as image registries, Active Directory/LDAP directories, etc) and return data in a format that can be processed by Gatekeeper."),(0,i.kt)("p",null,"Example provider ",(0,i.kt)("em",{parentName:"p"},"template")," can be found at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/open-policy-agent/gatekeeper-external-data-provider"},"https://github.com/open-policy-agent/gatekeeper-external-data-provider")),(0,i.kt)("h3",{id:"providers-maintained-by-the-community"},"Providers maintained by the community"),(0,i.kt)("p",null,"If you have built an external data provider and would like to add it to this list, please submit a PR to update this page."),(0,i.kt)("p",null,"If you have any issues with a specific provider, please open an issue in the applicable provider's repository."),(0,i.kt)("p",null,"The following external data providers are maintained by the community:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://github.com/deislabs/ratify"},"ratify")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://github.com/sigstore/cosign-gatekeeper-provider"},"cosign-gatekeeper-provider"))),(0,i.kt)("h3",{id:"sample-providers"},"Sample providers"),(0,i.kt)("p",null,"The following external data providers are samples and are not supported/maintained by the community:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://github.com/sozercan/trivy-provider"},"trivy-provider")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://github.com/sozercan/tagToDigest-provider"},"tag-to-digest-provider")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://github.com/sozercan/aad-provider"},"aad-provider"))),(0,i.kt)("h3",{id:"api-v1alpha1"},"API (v1alpha1)"),(0,i.kt)("h4",{id:"provider"},(0,i.kt)("inlineCode",{parentName:"h4"},"Provider")),(0,i.kt)("p",null,"Provider resource defines the provider and the configuration for it."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},"apiVersion: externaldata.gatekeeper.sh/v1alpha1\nkind: Provider\nmetadata:\n  name: my-provider\nspec:\n  url: http://<service-name>.<namespace>:<port>/<endpoint> # URL to the external data source (e.g., http://my-provider.my-namespace:8090/validate)\n  timeout: <timeout> # timeout value in seconds (e.g., 1). this is the timeout on the Provider custom resource, not the provider implementation.\n  insecureTLSSkipVerify: true # need to enable this if the provider uses HTTP so that Gatekeeper can skip TLS verification.\n")),(0,i.kt)("h4",{id:"providerrequest"},(0,i.kt)("inlineCode",{parentName:"h4"},"ProviderRequest")),(0,i.kt)("p",null,(0,i.kt)("inlineCode",{parentName:"p"},"ProviderRequest")," is the API request that is sent to the external data provider."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-go"},'// ProviderRequest is the API request for the external data provider.\ntype ProviderRequest struct {\n    // APIVersion is the API version of the external data provider.\n    APIVersion string `json:"apiVersion,omitempty"`\n    // Kind is kind of the external data provider API call. This can be "ProviderRequest" or "ProviderResponse".\n    Kind ProviderKind `json:"kind,omitempty"`\n    // Request contains the request for the external data provider.\n    Request Request `json:"request,omitempty"`\n}\n\n// Request is the struct that contains the keys to query.\ntype Request struct {\n    // Keys is the list of keys to send to the external data provider.\n    Keys []string `json:"keys,omitempty"`\n}\n')),(0,i.kt)("h4",{id:"providerresponse"},(0,i.kt)("inlineCode",{parentName:"h4"},"ProviderResponse")),(0,i.kt)("p",null,(0,i.kt)("inlineCode",{parentName:"p"},"ProviderResponse")," is the API response that a provider must return."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-go"},'// ProviderResponse is the API response from a provider.\ntype ProviderResponse struct {\n    // APIVersion is the API version of the external data provider.\n    APIVersion string `json:"apiVersion,omitempty"`\n    // Kind is kind of the external data provider API call. This can be "ProviderRequest" or "ProviderResponse".\n    Kind ProviderKind `json:"kind,omitempty"`\n    // Response contains the response from the provider.\n    Response Response `json:"response,omitempty"`\n}\n\n// Response is the struct that holds the response from a provider.\ntype Response struct {\n    // Idempotent indicates that the responses from the provider are idempotent.\n    // Applies to mutation only and must be true for mutation.\n    Idempotent bool `json:"idempotent,omitempty"`\n    // Items contains the key, value and error from the provider.\n    Items []Item `json:"items,omitempty"`\n    // SystemError is the system error of the response.\n    SystemError string `json:"systemError,omitempty"`\n}\n\n// Items is the struct that contains the key, value or error from a provider response.\ntype Item struct {\n    // Key is the request from the provider.\n    Key string `json:"key,omitempty"`\n    // Value is the response from the provider.\n    Value interface{} `json:"value,omitempty"`\n    // Error is the error from the provider.\n    Error string `json:"error,omitempty"`\n}\n')),(0,i.kt)("h3",{id:"implementation"},"Implementation"),(0,i.kt)("p",null,"Provider is an HTTP server that listens on a port and responds to ",(0,i.kt)("a",{parentName:"p",href:"#providerrequest"},(0,i.kt)("inlineCode",{parentName:"a"},"ProviderRequest"))," with ",(0,i.kt)("a",{parentName:"p",href:"#providerresponse"},(0,i.kt)("inlineCode",{parentName:"a"},"ProviderResponse")),"."),(0,i.kt)("p",null,"As part of ",(0,i.kt)("a",{parentName:"p",href:"#providerresponse"},(0,i.kt)("inlineCode",{parentName:"a"},"ProviderResponse")),", the provider can return a list of items. Each item is a JSON object with the following fields:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"Key"),": the key that was sent to the provider"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"Value"),": the value that was returned from the provider for that key"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"Error"),": an error message if the provider returned an error for that key")),(0,i.kt)("p",null,"If there is a system error, the provider should return the system error message in the ",(0,i.kt)("inlineCode",{parentName:"p"},"SystemError")," field."),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"\ud83d\udcce Recommendation is for provider implementations to keep a timeout such as maximum of 1-2 seconds for the provider to respond.")),(0,i.kt)("p",null,"Example provider implementation: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/open-policy-agent/gatekeeper/blob/master/test/externaldata/dummy-provider/provider.go"},"https://github.com/open-policy-agent/gatekeeper/blob/master/test/externaldata/dummy-provider/provider.go")),(0,i.kt)("h2",{id:"external-data-for-gatekeeper-validating-webhook"},"External data for Gatekeeper validating webhook"),(0,i.kt)("p",null,"External data adds a ",(0,i.kt)("a",{parentName:"p",href:"https://www.openpolicyagent.org/docs/latest/extensions/#custom-built-in-functions-in-go"},"custom OPA built-in function")," called ",(0,i.kt)("inlineCode",{parentName:"p"},"external_data")," to Rego. This function is used to query external data providers."),(0,i.kt)("p",null,(0,i.kt)("inlineCode",{parentName:"p"},"external_data")," is a function that takes a request and returns a response. The request is a JSON object with the following fields:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"provider"),": the name of the provider to query"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"keys"),": the list of keys to send to the provider")),(0,i.kt)("p",null,"e.g.,"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-rego"},'  # build a list of keys containing images for batching\n  my_list := [img | img = input.review.object.spec.template.spec.containers[_].image]\n\n  # send external data request\n  response := external_data({"provider": "my-provider", "keys": my_list})\n')),(0,i.kt)("p",null,"Response example: [","[",(0,i.kt)("inlineCode",{parentName:"p"},'"my-key"'),", ",(0,i.kt)("inlineCode",{parentName:"p"},'"my-value"'),", ",(0,i.kt)("inlineCode",{parentName:"p"},'""'),"]",", ","[",(0,i.kt)("inlineCode",{parentName:"p"},'"another-key"'),", ",(0,i.kt)("inlineCode",{parentName:"p"},"42"),", ",(0,i.kt)("inlineCode",{parentName:"p"},'""'),"]",", ","[",(0,i.kt)("inlineCode",{parentName:"p"},'"bad-key"'),", ",(0,i.kt)("inlineCode",{parentName:"p"},'""'),", ",(0,i.kt)("inlineCode",{parentName:"p"},'"error message"'),"]","]"),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"\ud83d\udcce To avoid multiple calls to the same provider, recommendation is to batch the keys list to send a single request.")),(0,i.kt)("p",null,"Example template:\n",(0,i.kt)("a",{parentName:"p",href:"https://github.com/open-policy-agent/gatekeeper/blob/master/test/externaldata/dummy-provider/policy/template.yaml"},"https://github.com/open-policy-agent/gatekeeper/blob/master/test/externaldata/dummy-provider/policy/template.yaml")),(0,i.kt)("h2",{id:"external-data-for-gatekeeper-mutating-webhook"},"External data for Gatekeeper mutating webhook"),(0,i.kt)("p",null,"External data can be used in conjunction with ",(0,i.kt)("a",{parentName:"p",href:"/gatekeeper/website/docs/mutation"},"Gatekeeper mutating webhook"),"."),(0,i.kt)("h3",{id:"api"},"API"),(0,i.kt)("p",null,"You can specify the details of the external data provider in the ",(0,i.kt)("inlineCode",{parentName:"p"},"spec.parameters.assign.externalData")," field of ",(0,i.kt)("inlineCode",{parentName:"p"},"AssignMetadata")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"Assign"),"."),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"Note: ",(0,i.kt)("inlineCode",{parentName:"p"},"spec.parameters.assign.externalData"),", ",(0,i.kt)("inlineCode",{parentName:"p"},"spec.parameters.assign.value")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"spec.parameters.assign.fromMetadata")," are mutually exclusive.")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Field"),(0,i.kt)("th",{parentName:"tr",align:null},"Description"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("inlineCode",{parentName:"td"},"provider"),(0,i.kt)("br",null),"String"),(0,i.kt)("td",{parentName:"tr",align:null},"The name of the external data provider.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("inlineCode",{parentName:"td"},"dataSource"),(0,i.kt)("br",null),"DataSource"),(0,i.kt)("td",{parentName:"tr",align:null},"Specifies where to extract the data that will be sent to the external data provider.",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"ValueAtLocation")," (default): extracts an array of values from the path that will be modified. See ",(0,i.kt)("a",{parentName:"td",href:"/gatekeeper/website/docs/mutation#intent"},"mutation intent")," for more details.",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"Username"),": The name of the Kubernetes user who initiated the admission request.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("inlineCode",{parentName:"td"},"failurePolicy"),(0,i.kt)("br",null),"FailurePolicy"),(0,i.kt)("td",{parentName:"tr",align:null},"The policy to apply when the external data provider returns an error.",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"UseDefault"),": use the default value specified in ",(0,i.kt)("inlineCode",{parentName:"td"},"spec.parameters.assign.externalData.default"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"Ignore"),": ignore the error and do not perform any mutations.",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"Fail")," (default): do not perform any mutations and return the error to the user.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("inlineCode",{parentName:"td"},"default"),(0,i.kt)("br",null),"String"),(0,i.kt)("td",{parentName:"tr",align:null},"The default value to use when the external data provider returns an error and the failure policy is set to ",(0,i.kt)("inlineCode",{parentName:"td"},"UseDefault"),".")))),(0,i.kt)("h3",{id:"assignmetadata"},(0,i.kt)("inlineCode",{parentName:"h3"},"AssignMetadata")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: mutations.gatekeeper.sh/v1beta1\nkind: AssignMetadata\nmetadata:\n  name: annotate-owner\nspec:\n  match:\n    scope: Namespaced\n    kinds:\n    - apiGroups: ["*"]\n      kinds: ["Pod"]\n  location: "metadata.annotations.owner"\n  parameters:\n    assign:\n      externalData:\n        provider: my-provider\n        dataSource: Username\n')),(0,i.kt)("details",null,(0,i.kt)("summary",null,"Provider response"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-json"},'{\n  "apiVersion": "externaldata.gatekeeper.sh/v1alpha1",\n  "kind": "ProviderResponse",\n  "response": {\n    "idempotent": true,\n    "items": [\n      {\n        "key": "kubernetes-admin",\n        "value": "admin@example.com"\n      }\n    ]\n  }\n}\n'))),(0,i.kt)("details",null,(0,i.kt)("summary",null,"Mutated object"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},"...\nmetadata:\n  annotations:\n    owner: admin@example.com\n...\n"))),(0,i.kt)("h3",{id:"assign"},(0,i.kt)("inlineCode",{parentName:"h3"},"Assign")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'apiVersion: mutations.gatekeeper.sh/v1beta1\nkind: Assign\nmetadata:\n  name: mutate-images\nspec:\n  applyTo:\n  - groups: [""]\n    kinds: ["Pod"]\n    versions: ["v1"]\n  match:\n    scope: Namespaced\n  location: "spec.containers[name:*].image"\n  parameters:\n    assign:\n      externalData:\n        provider: my-provider\n        dataSource: ValueAtLocation\n        failurePolicy: UseDefault\n        default: busybox:latest\n')),(0,i.kt)("details",null,(0,i.kt)("summary",null,"Provider response"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-json"},'{\n  "apiVersion": "externaldata.gatekeeper.sh/v1alpha1",\n  "kind": "ProviderResponse",\n  "response": {\n    "idempotent": true,\n    "items": [\n      {\n        "key": "nginx",\n        "value": "nginx:v1.2.3"\n      }\n    ]\n  }\n}\n'))),(0,i.kt)("details",null,(0,i.kt)("summary",null,"Mutated object"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},"...\nspec:\n  containers:\n    - name: nginx\n      image: nginx:v1.2.3\n...\n"))),(0,i.kt)("h3",{id:"limitations"},"Limitations"),(0,i.kt)("p",null,"There are several limitations when using external data with the mutating webhook:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Only supports mutation of ",(0,i.kt)("inlineCode",{parentName:"li"},"string")," fields (e.g. ",(0,i.kt)("inlineCode",{parentName:"li"},".spec.containers[name:*].image"),")."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"AssignMetadata")," only supports ",(0,i.kt)("inlineCode",{parentName:"li"},"dataSource: Username")," because ",(0,i.kt)("inlineCode",{parentName:"li"},"AssignMetadata")," only supports creation of ",(0,i.kt)("inlineCode",{parentName:"li"},"metadata.annotations")," and ",(0,i.kt)("inlineCode",{parentName:"li"},"metadata.labels"),". ",(0,i.kt)("inlineCode",{parentName:"li"},"dataSource: ValueAtLocation")," will not return any data."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"ModifySet")," does not support external data."),(0,i.kt)("li",{parentName:"ul"},"Multiple mutations to the same object are applied alphabetically based on the name of the mutation CRDs. If you have an external data mutation and a non-external data mutation with the same ",(0,i.kt)("inlineCode",{parentName:"li"},"spec.location"),", the final result might not be what you expected. Currently, there is no way to enforce custom ordering of mutations but the issue is being tracked ",(0,i.kt)("a",{parentName:"li",href:"https://github.com/open-policy-agent/gatekeeper/issues/1133"},"here"),".")),(0,i.kt)("h2",{id:"tls-and-mutual-tls-support"},"TLS and mutual TLS support"),(0,i.kt)("p",null,"Since external data providers are in-cluster HTTP servers backed by Kubernetes services, communication is not encrypted by default. This can potentially lead to security issues such as request eavesdropping, tampering, and man-in-the-middle attack."),(0,i.kt)("p",null,"To further harden the security posture of the external data feature, starting from Gatekeeper v3.9.0, TLS and mutual TLS (mTLS) via HTTPS protocol are supported between Gatekeeper and external data providers. In this section, we will describe the steps required to configure them."),(0,i.kt)("h3",{id:"prerequisites"},"Prerequisites"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"A Gatekeeper deployment ",(0,i.kt)("strong",{parentName:"li"},"v3.9.0+"),"."),(0,i.kt)("li",{parentName:"ul"},"The certificate of your certificate authority (CA) in PEM format."),(0,i.kt)("li",{parentName:"ul"},"The certificate of your external data provider in PEM format, signed by the CA above."),(0,i.kt)("li",{parentName:"ul"},"The private key of the external data provider in PEM format.")),(0,i.kt)("h3",{id:"optional-how-to-generate-a-self-signed-ca-and-a-keypair-for-the-external-data-provider"},"(Optional) How to generate a self-signed CA and a keypair for the external data provider"),(0,i.kt)("p",null,"In this section, we will describe how to generate a self-signed CA and a keypair using ",(0,i.kt)("inlineCode",{parentName:"p"},"openssl"),"."),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"Generate a private key for your CA:")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"openssl genrsa -out ca.key 2048\n")),(0,i.kt)("ol",{start:2},(0,i.kt)("li",{parentName:"ol"},"Generate a self-signed certificate for your CA:")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'openssl req -new -x509 -days 365 -key ca.key -subj "/O=My Org/CN=External Data Provider CA" -out ca.crt\n')),(0,i.kt)("ol",{start:3},(0,i.kt)("li",{parentName:"ol"},"Generate a private key for your external data provider:")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"}," openssl genrsa -out server.key 2048\n")),(0,i.kt)("ol",{start:4},(0,i.kt)("li",{parentName:"ol"},"Generate a certificate signing request (CSR) for your external data provider:")),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"Replace ",(0,i.kt)("inlineCode",{parentName:"p"},"<service name>")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"<service namespace>")," with the correct values.")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/CN=<service name>.<service namespace>" -out server.csr\n')),(0,i.kt)("ol",{start:5},(0,i.kt)("li",{parentName:"ol"},"Generate a certificate for your external data provider:")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'openssl x509 -req -extfile <(printf "subjectAltName=DNS:<service name>.<service namespace>") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt\n')),(0,i.kt)("h3",{id:"how-gatekeeper-trusts-the-external-data-provider-tls"},"How Gatekeeper trusts the external data provider (TLS)"),(0,i.kt)("p",null,"To enable one-way TLS, your external data provider should enable any TLS-related configurations for their HTTP server. For example, for Go's built-in ",(0,i.kt)("a",{parentName:"p",href:"https://pkg.go.dev/net/http#Server"},(0,i.kt)("inlineCode",{parentName:"a"},"HTTP server"))," implementation, you can use ",(0,i.kt)("a",{parentName:"p",href:"https://pkg.go.dev/net/http#ListenAndServeTLS"},(0,i.kt)("inlineCode",{parentName:"a"},"ListenAndServeTLS")),":"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-go"},'server.ListenAndServeTLS("/etc/ssl/certs/server.crt", "/etc/ssl/certs/server.key")\n')),(0,i.kt)("p",null,"In addition, the provider is also responsible for supplying the certificate authority (CA) certificate as part of the Provider spec so that Gatekeeper can verify the authenticity of the external data provider's certificate."),(0,i.kt)("p",null,"The CA certificate must be encoded as a base64 string when defining the Provider spec. Run the following command to perform base64 encoding:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"cat ca.crt | base64 | tr -d '\\n'\n")),(0,i.kt)("p",null,"With the encoded CA certificate, you can define the Provider spec as follows:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},"apiVersion: externaldata.gatekeeper.sh/v1alpha1\nkind: Provider\nmetadata:\n  name: my-provider\nspec:\n  url: https://<service-name>.<namespace>:<port>/<endpoint> # URL to the external data source (e.g., https://my-provider.my-namespace:8090/validate)\n  timeout: <timeout> # timeout value in seconds (e.g., 1). this is the timeout on the Provider custom resource, not the provider implementation.\n  caBundle: <encoded-ca-certificate> # base64 encoded CA certificate.\n")),(0,i.kt)("h3",{id:"how-the-external-data-provider-trusts-gatekeeper-mtls"},"How the external data provider trusts Gatekeeper (mTLS)"),(0,i.kt)("p",null,"Gatekeeper attaches its certificate as part of the HTTPS request to the external data provider. To verify the authenticity of the Gatekeeper certificate, the external data provider must have access to Gatekeeper's CA certificate. There are several ways to do this:"),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"Deploy your external data provider to the same namespace as your Gatekeeper deployment. By default, ",(0,i.kt)("a",{parentName:"li",href:"https://github.com/open-policy-agent/cert-controller"},(0,i.kt)("inlineCode",{parentName:"a"},"cert-controller"))," is used to generate and rotate Gatekeeper's webhook certificate. The content of the certificate is stored as a Kubernetes secret called ",(0,i.kt)("inlineCode",{parentName:"li"},"gatekeeper-webhook-server-cert")," in the Gatekeeper namespace e.g. ",(0,i.kt)("inlineCode",{parentName:"li"},"gatekeeper-system"),". In your external provider deployment, you can access Gatekeeper's certificate by adding the following ",(0,i.kt)("inlineCode",{parentName:"li"},"volume")," and ",(0,i.kt)("inlineCode",{parentName:"li"},"volumeMount")," to the provider deployment so that your server can trust Gatekeeper's CA certificate:")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},"volumeMounts:\n  - name: gatekeeper-ca-cert\n    mountPath: /tmp/gatekeeper\n    readOnly: true\nvolumes:\n  - name: gatekeeper-ca-cert\n    secret:\n      secretName: gatekeeper-webhook-server-cert\n      items:\n        - key: ca.crt\n          path: ca.crt\n")),(0,i.kt)("p",null,"After that, you can attach Gatekeeper's CA certificate in your TLS config and enable any client authentication-related settings. For example:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-go"},'caCert, err := ioutil.ReadFile("/tmp/gatekeeper/ca.crt")\nif err != nil {\n    panic(err)\n}\n\nclientCAs := x509.NewCertPool()\nclientCAs.AppendCertsFromPEM(caCert)\n\nserver := &http.Server{\n    Addr:    ":8090",\n    TLSConfig: &tls.Config{\n        ClientAuth: tls.RequireAndVerifyClientCert,\n        ClientCAs:  clientCAs,\n        MinVersion: tls.VersionTLS13,\n    },\n}\n')),(0,i.kt)("ol",{start:2},(0,i.kt)("li",{parentName:"ol"},"If ",(0,i.kt)("inlineCode",{parentName:"li"},"cert-controller")," is disabled via the ",(0,i.kt)("inlineCode",{parentName:"li"},"--disable-cert-rotation")," flag, you can use a cluster-wide, well-known CA certificate for Gatekeeper so that your external data provider can trust it without being deployed to the ",(0,i.kt)("inlineCode",{parentName:"li"},"gatekeeper-system")," namespace.")))}c.isMDXComponent=!0}}]);