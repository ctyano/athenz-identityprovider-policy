package identityprovider

import data.mock.instance.input as mock_input
import data.invalid.instance.input as invalid_input
#import data.mock.pem.public as mock_public_key
import data.mock.jwks_url as mock_jwks_url
import data.mock.jwks as mock_jwks
import data.mock.jwt_api_node as mock_jwt_api_node
import data.mock.api_node_url as mock_api_node_url
import data.mock.pods as mock_pods
import data.invalid.pods as invalid_pods
import data.config.constraints.kubernetes.serviceaccount.token.issuer as service_account_token_issuer
import data.config.constraints.kubernetes.serviceaccount.token.audience as service_account_token_audience
import data.config.constraints.cert.expiry.maxminutes as cert_expiry_time_max
import data.config.constraints.cert.expiry.defaultminutes as cert_expiry_time_default
import data.config.constraints.cert.refresh as cert_refresh_default
import data.config.constraints.debug

# with empty athenz domain in config to associate kubernetes namespace as athenz domain
# with retrieving jwks from https://httpbin.org/base64/<base64 encoded jwks string>
test_instance01 {
    instance == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": cert_expiry_time_default,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with data.config.constraints.keys.jwks.url as mock_jwks_url
    with data.kubernetes.pods as mock_pods
}

# with empty athenz domain in config to associate kubernetes namespace as athenz domain
# with retrieving jwks in each nodes from https://httpbin.org/base64/<base64 encoded jwks string>
test_instance02 {
    instance == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": cert_expiry_time_default,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with input.attestationData as mock_jwt_api_node
    with data.config.constraints.keys.jwks.url as ""
    with data.config.constraints.keys.jwks.apinodes.url as mock_api_node_url
    with data.kubernetes.pods as mock_pods
}

# with empty athenz domain in config to associate kubernetes namespace as athenz domain
test_instance03 {
    instance == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": cert_expiry_time_default,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with specific athenz domain in config
test_instance04 {
    instance == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": cert_expiry_time_default,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with data.config.constraints.keys.static as mock_jwks
    with data.config.constraints.athenz.domain.name as "athenz"
    with data.kubernetes.pods as mock_pods
}

# with specific constraints kubernetes namespaces in config
test_instance05 {
    instance == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": cert_expiry_time_default,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
    with data.config.constraints.kubernetes.namespaces as ["athenz"]
}

# with specific constraints kubernetes serviceaccounts in config
test_instance06 {
    instance == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": cert_expiry_time_default,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
    with data.config.constraints.kubernetes.serviceaccount.names as ["client"]
}

# with shortened input.attributes.certExpiryTime
test_instance07 {
    instance == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": 21600,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
    with data.config.constraints.cert.expiry.maxminutes as 21600
}

# with empty input.attributes.certExpiryTime
test_instance08 {
    instance == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": cert_expiry_time_default,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with input.attributes as object.remove(mock_input.attributes, ["certExpiryTime"])
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with empty input
test_instance09 {
    instance == {
        "allow": false,
        "status": {
            "reason": "empty input"
        },
    }
    with input as false
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with empty input.attestationData
test_instance10 {
    instance == {
        "allow": false,
        "status": {
            "reason": "empty input: empty attestation data"
        },
    }
    with input as mock_input
    with input.attestationData as ""
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with invalid input.attestationData
test_instance11 {
    instance == {
        "allow": false,
        "status": {
            "reason": sprintf("invalid jwt: failed to verify the service account token signature, or failed to attest jwt claims: claims[%v], constraints[%v]", [
                io.jwt.decode(invalid_input.attestationData)[1],
                {
                    "iss": service_account_token_issuer,
                    "aud": service_account_token_audience,
                    "cert": mock_jwks,
                }
            ])
        },
    }
    with input as invalid_input
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with invalid provider athenz service
test_instance12 {
    instance == {
        "allow": false,
        "status": {
            "reason": sprintf("invalid input: input athenz provider service mismatched: input[%v], configuration[%v]",
                ["", "athenz.identityprovider"])
        },
    }
    with input as json.patch(mock_input, [{"op": "replace", "path": "/provider", "value": ""}])
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with invalid athenz domain
test_instance13 {
    instance == {
        "allow": false,
        "status": {
            "reason": sprintf("invalid input: input athenz domain mismatched: input[%v], configuration[%v]",
                ["", "athenz"])
        },
    }
    with input as json.patch(mock_input, [{"op": "replace", "path": "/domain", "value": ""}])
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with invalid athenz service
test_instance14 {
    print(io.jwt.decode(invalid_input.attestationData)[1])
    instance == {
        "allow": false,
        "status": {
            "reason": sprintf("invalid input: input athenz service mismatched: input[%v], token_claims[%v]",
                [
                    "",
                    io.jwt.decode(invalid_input.attestationData)[1]["kubernetes.io"],
                ])
        },
    }
    with input as json.patch(mock_input, [{"op": "replace", "path": "/service", "value": ""}])
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with empty kubernetes.io claim
test_instance15 {
    instance == {
        "allow": false,
        "status": {
            "reason": sprintf("invalid input: input attributes mismatched: input[%v], kube-apiserver[%v]", [object.get(input, "attributes", ""), false])
        },
    }
    with input as mock_input
    with data.config.constraints.keys.static as mock_jwks
    with verified_jwt as []
    with data.kubernetes.pods as mock_pods
}
# with empty data.kubernetes.pods
test_instance11 {
    attestated_pod == false
    with input as mock_input
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as invalid_pods
}

# with invalid input.attributes.sanDNS with empty constraints
test_instance17 {
    instance == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": cert_expiry_time_default,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with input.attributes.sanDNS as "athenz.invalid"
    with data.config.constraints.cert.sandns as []
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with invalid input.attributes.sanDNS for "<instance id>.instanceid.zts.athenz.cloud" pattern
test_instance18 {
    instance == {
        "allow": false,
        "status": {
            "reason": "no matching validations found",
        },
    }
    with input as mock_input
    with input.attributes.sanDNS as "client.athenz.svc.cluster.local,0e71e3f6-171a-45b7-a05c-caafd799c7cc.instanceid.athenz.cloud"
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with invalid input.attributes.sanDNS for "<service account>.<namespace>.<provider dns suffix>" pattern
test_instance19 {
    instance == {
        "allow": false,
        "status": {
            "reason": "no matching validations found",
        },
    }
    with input as mock_input
    with input.attributes.sanDNS as "client.athenz.pod.cluster.local,0e71e3f6-171a-45b7-a05c-caafd799c7cc.instanceid.zts.athenz.cloud"
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with empty athenz domain in config to associate kubernetes namespace as athenz domain
test_refresh {
    refresh == {
        "domain": mock_input.domain,
        "service": mock_input.service,
        "provider": mock_input.provider,
        "attributes": {
            "instanceId": mock_input.attributes.instanceId,
            "sanIP": mock_input.attributes.sanIP,
            "clientIP": mock_input.attributes.clientIP,
            "sanURI": mock_input.attributes.sanURI,
            "sanDNS": mock_input.attributes.sanDNS,
            "certExpiryTime": cert_expiry_time_default,
            "certRefresh": cert_refresh_default
        }
    }
    with input as mock_input
    with data.config.constraints.keys.static as mock_jwks
    with data.kubernetes.pods as mock_pods
}

# with debug enabled
test_debug1 {
    log("key", "value")
    with data.config.debug as true
}

# with debug disabled
test_debug2 {
    log("key", "value")
    with data.config.debug as false
}
