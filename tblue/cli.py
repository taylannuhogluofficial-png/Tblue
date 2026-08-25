"""
Tblue CLI — entry point and argument parsing.
"""

import sys
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from typing import List, Dict
from urllib.parse import urlparse

from tblue import __version__
from tblue.constants import DEFAULT_DEPTH, DEFAULT_USER_AGENT, DEFAULT_TIMEOUT, DEFAULT_RETRIES
from tblue.config import load as load_config, apply as apply_config
from tblue.scanner.xss             import XSSScanner
from tblue.scanner.headers         import HeaderScanner
from tblue.scanner.cookies         import CookieScanner
from tblue.scanner.ssl             import SSLScanner
from tblue.scanner.dom             import DOMScanner
from tblue.scanner.csp             import CSPScanner
from tblue.scanner.mixed_content   import MixedContentScanner
from tblue.scanner.info_disclosure import InfoDisclosureScanner
from tblue.scanner.login_security  import LoginSecurityScanner
from tblue.scanner.email_security  import EmailSecurityScanner
from tblue.scanner.access_control  import AccessControlScanner
from tblue.scanner.graphql         import GraphQLScanner
from tblue.scanner.http_methods    import HTTPMethodsScanner
from tblue.scanner.ports           import PortScanner
from tblue.scanner.cors            import CORSScanner
from tblue.scanner.security_txt    import SecurityTxtScanner
from tblue.scanner.error_pages     import ErrorPageScanner
from tblue.scanner.exposure        import ExposureScanner
from tblue.scanner.rate_limit      import RateLimitScanner
from tblue.scanner.jwt_security    import JWTScanner
from tblue.scanner.waf             import WAFScanner
from tblue.scanner.dns_security      import DNSSecurityScanner
from tblue.scanner.js_libraries      import JSLibraryScanner
from tblue.scanner.sensitive_params  import SensitiveParamScanner
from tblue.scanner.tls_deep          import TLSDeepScanner
from tblue.scanner.email_advanced    import EmailAdvancedScanner
from tblue.scanner.js_secrets        import JSSecretsScanner
from tblue.scanner.supply_chain      import SupplyChainScanner
from tblue.scanner.form_security     import FormSecurityScanner
from tblue.scanner.crt_sh            import CRTShScanner
from tblue.scanner.subdomain_takeover import SubdomainTakeoverScanner
from tblue.scanner.typosquatting     import TyposquattingScanner
from tblue.scanner.sca               import SCAScanner
from tblue.scanner.cloud_storage     import CloudStorageScanner
from tblue.scanner.cms_detection     import CMSDetectionScanner
from tblue.scanner.infra             import InfraScanner
from tblue.scanner.dns_advanced      import DNSAdvancedScanner
from tblue.scanner.admin_exposure    import AdminExposureScanner
from tblue.scanner.html_comments     import HTMLCommentsScanner
from tblue.scanner.cookie_advanced   import CookieAdvancedScanner
from tblue.scanner.redirect_chain    import RedirectChainScanner
from tblue.scanner.robots_txt        import RobotsSecurityScanner
from tblue.scanner.csp_advanced      import CSPAdvancedScanner
from tblue.scanner.sri_advanced      import SRIAdvancedScanner
from tblue.scanner.response_headers  import ResponseHeadersScanner
from tblue.scanner.host_header       import HostHeaderScanner
from tblue.scanner.open_redirect     import OpenRedirectScanner
from tblue.scanner.permissions_policy import PermissionsPolicyScanner
from tblue.scanner.gdpr_privacy      import GDPRPrivacyScanner
from tblue.scanner.threat_intel      import ThreatIntelScanner
from tblue.scanner.api_surface       import APISurfaceScanner
from tblue.scanner.directory_listing import DirectoryListingScanner
from tblue.scanner.ssrf_params       import SSRFParamScanner
from tblue.scanner.oauth             import OAuthScanner
from tblue.scanner.cache_poisoning   import CachePoisoningScanner
from tblue.scanner.request_smuggling  import RequestSmugglingScanner
from tblue.scanner.websocket          import WebSocketScanner
from tblue.scanner.saml              import SAMLScanner
from tblue.scanner.prototype_pollution import PrototypePollutionScanner
from tblue.scanner.xml_xxe           import XXEScanner
from tblue.scanner.spring_actuator   import SpringActuatorScanner
from tblue.scanner.deserialization   import DeserializationScanner
from tblue.scanner.ssti              import SSTIScanner
from tblue.scanner.file_upload       import FileUploadScanner
from tblue.scanner.path_traversal    import PathTraversalScanner
from tblue.scanner.scim              import SCIMScanner
from tblue.scanner.grpc              import GRPCScanner
from tblue.scanner.cloud_metadata    import CloudMetadataScanner
from tblue.scanner.nosql_injection   import NoSQLInjectionScanner
from tblue.scanner.web_cache_deception import WebCacheDeceptionScanner
from tblue.scanner.session_security  import SessionSecurityScanner
from tblue.scanner.k8s_exposure      import K8sExposureScanner
from tblue.scanner.http2_security    import HTTP2SecurityScanner
from tblue.scanner.graphql_advanced  import GraphQLAdvancedScanner
from tblue.scanner.jwt_advanced      import JWTAdvancedScanner
from tblue.scanner.cors_advanced     import CORSAdvancedScanner
from tblue.scanner.business_logic    import BusinessLogicScanner
from tblue.scanner.graphql_depth     import GraphQLDepthScanner
from tblue.scanner.ssrf_advanced     import SSRFAdvancedScanner
from tblue.scanner.rate_limiting     import RateLimitingScanner
from tblue.scanner.api_security_headers import APISecurityHeadersScanner
from tblue.scanner.oauth_advanced    import OAuthAdvancedScanner
from tblue.scanner.crlf_injection    import CRLFInjectionScanner
from tblue.scanner.http_parameter_pollution import HTTPParameterPollutionScanner
from tblue.scanner.weak_crypto       import WeakCryptoScanner
from tblue.scanner.clickjacking      import ClickjackingScanner
from tblue.scanner.account_enumeration import AccountEnumerationScanner
from tblue.scanner.open_api_exposure import OpenAPIExposureScanner
from tblue.scanner.dependency_confusion import DependencyConfusionScanner
from tblue.scanner.mass_assignment   import MassAssignmentScanner
from tblue.scanner.log_injection     import LogInjectionScanner
from tblue.scanner.file_inclusion    import FileInclusionScanner
from tblue.scanner.ldap_injection    import LDAPinjectionScanner
from tblue.scanner.command_injection import CommandInjectionScanner
from tblue.scanner.xxe_injection     import XXEInjectionScanner
from tblue.scanner.ssrf_detection    import SSRFDetectionScanner
from tblue.scanner.http_verb_tampering   import HTTPVerbTamperingScanner
from tblue.scanner.service_worker_security import ServiceWorkerSecurityScanner
from tblue.scanner.idor_detection    import IDORDetectionScanner
from tblue.scanner.sensitive_data_exposure import SensitiveDataExposureScanner
from tblue.scanner.api_auth_security import APIAuthSecurityScanner
from tblue.scanner.content_injection import ContentInjectionScanner
from tblue.scanner.cicd_exposure     import CICDExposureScanner
from tblue.scanner.webauthn_security import WebAuthnSecurityScanner
from tblue.scanner.api_versioning    import APIVersioningScanner
from tblue.scanner.password_reset    import PasswordResetScanner
from tblue.scanner.race_condition    import RaceConditionScanner
from tblue.scanner.json_injection    import JSONInjectionScanner
from tblue.scanner.el_injection      import ELInjectionScanner
from tblue.scanner.client_storage    import ClientStorageScanner
from tblue.scanner.csti              import CSTIScanner
from tblue.scanner.fetch_metadata    import FetchMetadataScanner
from tblue.scanner.path_confusion    import PathConfusionScanner
from tblue.scanner.csv_injection     import CSVInjectionScanner
from tblue.scanner.reflected_file_download import ReflectedFileDownloadScanner
from tblue.scanner.source_map         import SourceMapScanner
from tblue.scanner.dev_artifact       import DevArtifactScanner
from tblue.scanner.link_security      import LinkSecurityScanner
from tblue.scanner.api_collection     import APICollectionScanner
from tblue.scanner.framework_config   import FrameworkConfigScanner
from tblue.scanner.xssi              import XSSIScanner
from tblue.scanner.server_timing     import ServerTimingScanner
from tblue.scanner.crossdomain_policy import CrossDomainPolicyScanner
from tblue.scanner.ai_api_exposure   import AIAPIExposureScanner
from tblue.scanner.graphql_field_suggestion import GraphQLFieldSuggestionScanner
from tblue.scanner.js_file_analysis      import JSFileAnalysisScanner
from tblue.scanner.version_cve           import VersionCVEScanner
from tblue.scanner.llm_prompt_injection  import LLMPromptInjectionScanner
from tblue.scanner.xsleak               import XSLeakScanner
from tblue.scanner.graphql_batching     import GraphQLBatchingScanner
from tblue.scanner.css_injection        import CSSInjectionScanner
from tblue.scanner.prssi               import PRSSIScanner
from tblue.scanner.referrer_policy     import ReferrerPolicyScanner
from tblue.scanner.hsts_preload        import HSTSPreloadScanner
from tblue.scanner.oauth_token_leak    import OAuthTokenLeakScanner
from tblue.scanner.dom_clobbering      import DOMClobberingScanner
from tblue.scanner.trojan_source       import TrojanSourceScanner
from tblue.scanner.dangling_markup     import DanglingMarkupScanner
from tblue.scanner.csp_reporting       import CSPReportingScanner
from tblue.scanner.live_cve            import LiveCVEScanner
from tblue.scanner.csp_nonce           import CSPNonceAnalyzer
from tblue.scanner.wasm_security       import WASMSecurityScanner
from tblue.scanner.timing_oracle       import TimingOracleScanner
from tblue.scanner.open_graph_exposure import OpenGraphExposureScanner
from tblue.scanner.cache_control_security import CacheControlSecurityScanner
from tblue.scanner.http3_quic          import HTTP3QUICScanner
from tblue.scanner.etag_fingerprinting import ETagFingerprintingScanner
from tblue.scanner.sse_security        import SSESecurityScanner
from tblue.scanner.security_txt_deep   import SecurityTxtDeepScanner
from tblue.scanner.supply_chain_lockfile import SupplyChainLockfileScanner
from tblue.scanner.mutation_xss        import MutationXSSScanner
from tblue.scanner.cookie_prefix_security import CookiePrefixSecurityScanner
from tblue.scanner.postmessage_security   import PostMessageSecurityScanner
from tblue.scanner.web_manifest_security  import WebManifestSecurityScanner
from tblue.scanner.http_observatory       import HTTPObservatoryScanner
from tblue.scanner.api_schema_exposure    import APISchemaExposureScanner
from tblue.scanner.header_injection_sink  import HeaderInjectionSinkScanner
from tblue.scanner.content_type_confusion import ContentTypeConfusionScanner
from tblue.scanner.oauth_pkce             import OAuthPKCEScanner
from tblue.scanner.dns_caa                import DNSCAAScanner
from tblue.scanner.dom_xss_sources        import DOMXSSSourcesScanner
from tblue.scanner.path_parameter_pollution import PathParameterPollutionScanner
from tblue.scanner.js_framework_detection import JSFrameworkDetectionScanner
from tblue.scanner.link_preview_exposure   import LinkPreviewExposureScanner
from tblue.scanner.websocket_security_deep import WebSocketSecurityDeepScanner
from tblue.scanner.tls_certificate_deep    import TLSCertificateDeepScanner
from tblue.scanner.graphql_subscription    import GraphQLSubscriptionScanner
from tblue.scanner.shadow_dom_security     import ShadowDOMSecurityScanner
from tblue.scanner.account_lockout         import AccountLockoutScanner
from tblue.scanner.cors_misconfiguration_deep import CORSMisconfigurationDeepScanner
from tblue.scanner.csp_violation_report    import CSPViolationReportScanner
from tblue.scanner.http_security_baseline  import HTTPSecurityBaselineScanner
from tblue.scanner.client_hints_security   import ClientHintsSecurityScanner
from tblue.scanner.api_error_disclosure    import APIErrorDisclosureScanner
from tblue.scanner.jwks_exposure           import JWKSExposureScanner
from tblue.scanner.open_redirect_deep      import OpenRedirectDeepScanner
from tblue.scanner.http_method_override    import HTTPMethodOverrideScanner
from tblue.scanner.third_party_exposure    import ThirdPartyExposureScanner
from tblue.scanner.session_fixation        import SessionFixationScanner
from tblue.scanner.introspection_disclosure import IntrospectionDisclosureScanner
from tblue.scanner.clickjacking_deep       import ClickjackingDeepScanner
from tblue.scanner.tls_protocol_version    import TLSProtocolVersionScanner
from tblue.scanner.http_response_splitting import HTTPResponseSplittingScanner
from tblue.scanner.dns_rebinding           import DNSRebindingScanner
from tblue.scanner.content_negotiation     import ContentNegotiationScanner
from tblue.scanner.webrtc_exposure         import WebRTCExposureScanner
from tblue.scanner.cdn_misconfiguration    import CDNMisconfigurationScanner
from tblue.scanner.password_policy         import PasswordPolicyScanner
from tblue.scanner.feature_flag_exposure   import FeatureFlagExposureScanner
from tblue.scanner.account_recovery        import AccountRecoveryScanner
from tblue.scanner.social_login_security   import SocialLoginSecurityScanner
from tblue.scanner.iframe_sandbox_security import IframeSandboxSecurityScanner
from tblue.scanner.broadcast_channel_security import BroadcastChannelSecurityScanner
from tblue.scanner.api_gateway_security    import APIGatewaySecurityScanner
from tblue.scanner.link_header_injection   import LinkHeaderInjectionScanner
from tblue.scanner.graphql_persisted_queries import GraphQLPersistedQueriesScanner
from tblue.scanner.serverless_exposure     import ServerlessExposureScanner
from tblue.scanner.http2_push_security     import HTTP2PushSecurityScanner
from tblue.scanner.mime_type_security      import MIMETypeSecurityScanner
from tblue.scanner.certificate_transparency import CertificateTransparencyScanner
from tblue.scanner.web_worker_security     import WebWorkerSecurityScanner
from tblue.scanner.cookie_samesite_deep    import CookieSameSiteDeepScanner
from tblue.scanner.form_action_security    import FormActionSecurityScanner
from tblue.scanner.open_graph_security     import OpenGraphSecurityScanner
from tblue.scanner.deep_link_security      import DeepLinkSecurityScanner
from tblue.scanner.http_caching_security   import HTTPCachingSecurityScanner
from tblue.scanner.waf_bypass_detection    import WAFBypassDetectionScanner
from tblue.scanner.api_rate_limit_deep     import APIRateLimitDeepScanner
from tblue.scanner.jwt_claim_analysis      import JWTClaimAnalysisScanner
from tblue.scanner.cors_deep_analysis      import CORSDeepAnalysisScanner
from tblue.scanner.hsts_deep_analysis      import HSTSDeepAnalysisScanner
from tblue.scanner.referrer_policy_deep    import ReferrerPolicyDeepScanner
from tblue.scanner.cross_origin_policy_deep import CrossOriginPolicyDeepScanner
from tblue.scanner.credential_exposure     import CredentialExposureScanner
from tblue.scanner.server_info_deep        import ServerInfoDeepScanner
from tblue.scanner.cache_poisoning_passive import CachePoisoningPassiveScanner
from tblue.scanner.session_fixation_passive import SessionFixationPassiveScanner
from tblue.scanner.sourcemap_exposure      import SourceMapExposureScanner
from tblue.scanner.mfa_detection           import MFADetectionScanner
from tblue.scanner.api_key_in_js           import APIKeyInJSScanner
from tblue.scanner.email_header_injection  import EmailHeaderInjectionScanner
from tblue.scanner.csp_nonce_reuse         import CSPNonceReuseScanner
from tblue.scanner.cors_max_age_deep       import CORSMaxAgeDeepScanner
from tblue.scanner.tls_downgrade_passive   import TLSDowngradePassiveScanner
from tblue.scanner.graphql_batch_abuse     import GraphQLBatchAbuseScanner
from tblue.scanner.sql_error_passive       import SQLErrorPassiveScanner
from tblue.scanner.nginx_alias_traversal   import NginxAliasTravesalScanner
from tblue.scanner.apache_status_exposure  import ApacheStatusExposureScanner
from tblue.scanner.debug_mode_detection    import DebugModeDetectionScanner
from tblue.scanner.security_misconfiguration import SecurityMisconfigurationScanner
from tblue.scanner.http_desync_passive     import HTTPDesyncPassiveScanner
from tblue.scanner.token_exposure_passive  import TokenExposurePassiveScanner
from tblue.scanner.cors_wildcard_api       import CORSWildcardAPIScanner
from tblue.scanner.javascript_prototype_pollution_deep import JavaScriptPrototypePollutionDeepScanner
from tblue.scanner.api_pagination_security import APIPaginationSecurityScanner
from tblue.scanner.subresource_integrity_deep import SubresourceIntegrityDeepScanner
from tblue.scanner.open_s3_bucket          import OpenS3BucketScanner
from tblue.scanner.websocket_origin_check  import WebSocketOriginCheckScanner
from tblue.scanner.spa_hash_routing_security import SPAHashRoutingSecurityScanner
from tblue.scanner.http_strict_transport_upgrade import HTTPStrictTransportUpgradeScanner
from tblue.scanner.sensitive_endpoint_exposure import SensitiveEndpointExposureScanner
from tblue.scanner.xml_security_passive import XMLSecurityPassiveScanner
from tblue.scanner.email_config_exposure import EmailConfigExposureScanner
from tblue.scanner.graphql_info_disclosure import GraphQLInfoDisclosureScanner
from tblue.scanner.path_normalization_security import PathNormalizationSecurityScanner
from tblue.scanner.server_timing_disclosure import ServerTimingDisclosureScanner
from tblue.scanner.iframe_security_deep import IframeSecurityDeepScanner
from tblue.scanner.secret_in_error_page import SecretInErrorPageScanner
from tblue.scanner.insecure_deserialization_passive import InsecureDeserializationPassiveScanner
from tblue.scanner.xxe_probe import XXEProbeScanner
from tblue.scanner.ssrf_passive import SSRFPassiveScanner
from tblue.scanner.host_header_injection import HostHeaderInjectionScanner
from tblue.scanner.clickjacking_advanced import ClickjackingAdvancedScanner
from tblue.scanner.business_logic_exposure import BusinessLogicExposureScanner
from tblue.scanner.api_versioning_security import APIVersioningSecurityScanner
from tblue.scanner.csrf_token_strength import CSRFTokenStrengthScanner
from tblue.scanner.cors_preflight_deep import CORSPreflightDeepScanner
from tblue.scanner.rate_limiting_detection import RateLimitingDetectionScanner
from tblue.scanner.jwt_algorithm_confusion import JWTAlgorithmConfusionScanner
from tblue.scanner.oauth_redirect_uri_validation import OAuthRedirectURIValidationScanner
from tblue.scanner.saml_passive import SAMLPassiveScanner
from tblue.scanner.file_upload_security import FileUploadSecurityScanner
from tblue.scanner.subdomain_takeover_passive import SubdomainTakeoverPassiveScanner
from tblue.scanner.dns_rebinding_passive import DNSRebindingPassiveScanner
from tblue.scanner.log_injection_probe import LogInjectionProbeScanner
from tblue.scanner.parameter_pollution import ParameterPollutionScanner
from tblue.scanner.feature_policy_security import FeaturePolicySecurityScanner
from tblue.scanner.docker_exposure     import DockerExposureScanner
from tblue.scanner.graphql_batch_attack import GraphQLBatchAttackScanner
from tblue.scanner.api_key_rotation    import APIKeyRotationScanner
from tblue.scanner.subdomain_enum_passive import SubdomainEnumPassiveScanner
from tblue.scanner.redos_passive       import ReDoSPassiveScanner
from tblue.scanner.http2_rapid_reset   import HTTP2RapidResetScanner
from tblue.scanner.payment_page_security import PaymentPageSecurityScanner
from tblue.scanner.health_endpoint_exposure import HealthEndpointExposureScanner
from tblue.scanner.log4shell_passive    import Log4ShellPassiveScanner
from tblue.scanner.cors_expose_headers  import CORSExposeHeadersScanner
from tblue.scanner.cross_origin_isolation import CrossOriginIsolationScanner
from tblue.scanner.trusted_types_policy import TrustedTypesPolicyScanner
from tblue.scanner.nel_reporting        import NELReportingScanner
from tblue.scanner.speculation_rules_security import SpeculationRulesSecurityScanner
from tblue.scanner.origin_trial_exposure import OriginTrialExposureScanner
from tblue.scanner.link_resource_hints_security import LinkResourceHintsSecurityScanner
from tblue.scanner.webhook_security     import WebhookSecurityScanner
from tblue.scanner.http_range_security  import HTTPRangeSecurityScanner
from tblue.scanner.content_disposition_security import ContentDispositionSecurityScanner
from tblue.scanner.cookies_partitioned_security import CookiesPartitionedSecurityScanner
from tblue.scanner.privacy_sandbox_apis import PrivacySandboxAPIsScanner
from tblue.scanner.document_policy_security import DocumentPolicySecurityScanner
from tblue.scanner.cors_null_origin        import CORSNullOriginScanner
from tblue.scanner.compression_oracle      import CompressionOracleScanner
from tblue.scanner.form_action_hijacking   import FormActionHijackingScanner
from tblue.scanner.js_dangerous_patterns   import JSDangerousPatternsScanner
from tblue.scanner.importmap_security      import ImportMapSecurityScanner
from tblue.scanner.permissions_policy_deep import PermissionsPolicyDeepScanner
from tblue.scanner.base_uri_injection      import BaseURIInjectionScanner
from tblue.scanner.js_supply_chain_integrity import JSSupplyChainIntegrityScanner
from tblue.scanner.svg_security            import SVGSecurityScanner
from tblue.scanner.css_exfiltration        import CSSExfiltrationScanner
from tblue.scanner.local_storage_sensitive import LocalStorageSensitiveScanner
from tblue.scanner.relative_path_overwrite import RelativePathOverwriteScanner
from tblue.scanner.url_parser_differential import URLParserDifferentialScanner
from tblue.scanner.exposed_backup_files    import ExposedBackupFilesScanner
from tblue.scanner.client_side_redirect    import ClientSideRedirectScanner
from tblue.scanner.protocol_confusion      import ProtocolConfusionScanner
from tblue.scanner.iframe_allow_security   import IframeAllowSecurityScanner
from tblue.scanner.package_manifest_exposure import PackageManifestExposureScanner
from tblue.scanner.canvas_fingerprinting   import CanvasFingerprintingScanner
from tblue.scanner.hardcoded_credentials   import HardcodedCredentialsScanner
from tblue.scanner.private_network_access  import PrivateNetworkAccessScanner
from tblue.scanner.jsonp_endpoint          import JSONPEndpointScanner
from tblue.scanner.http_security_consistency import HTTPSecurityConsistencyScanner
from tblue.scanner.api_authentication_exposure import APIAuthenticationExposureScanner
# Phase 124: Tabnabbing, EXIF metadata, GraphQL CSRF, PHI exposure
from tblue.scanner.tabnabbing             import TabnabbingScanner
from tblue.scanner.exif_metadata_exposure import EXIFMetadataExposureScanner
from tblue.scanner.graphql_csrf           import GraphQLCSRFScanner
from tblue.scanner.phi_exposure           import PHIExposureScanner
# Phase 125: HTTP method tampering, CSRF double-submit, XPath injection passive, session token exposure
from tblue.scanner.http_method_tampering  import HTTPMethodTamperingScanner
from tblue.scanner.csrf_double_submit     import CSRFDoubleSubmitScanner
from tblue.scanner.xpath_injection_passive import XPathInjectionPassiveScanner
from tblue.scanner.session_token_exposure import SessionTokenExposureScanner
# Phase 126: API pagination abuse, content security framing, OAuth implicit flow, web worker deep
from tblue.scanner.api_pagination_abuse    import APIPaginationAbuseScanner
from tblue.scanner.content_security_framing import ContentSecurityFramingScanner
from tblue.scanner.oauth_implicit_flow     import OAuthImplicitFlowScanner
from tblue.scanner.web_worker_security_deep import WebWorkerSecurityDeepScanner
# Phase 127: JS template literal injection, CORS origin reflection, JWT token exposure, HTTP headers deep
from tblue.scanner.javascript_template_literal import JavaScriptTemplateLiteralScanner
from tblue.scanner.cors_origin_reflection  import CORSOriginReflectionScanner
from tblue.scanner.jwt_token_exposure      import JWTTokenExposureScanner
from tblue.scanner.http_security_headers_deep import HTTPSecurityHeadersDeepScanner
# Phase 128: srcdoc injection, WebCrypto weaknesses, autocomplete security, API doc exposure
from tblue.scanner.srcdoc_injection       import SrcdocInjectionScanner
from tblue.scanner.web_crypto_weaknesses  import WebCryptoWeaknessesScanner
from tblue.scanner.autocomplete_security  import AutocompleteSecurityScanner
from tblue.scanner.api_documentation_exposure import APIDocumentationExposureScanner
# Phase 129: SSE security, path traversal deep, WASM security deep, content-type sniffing
from tblue.scanner.server_sent_events_security import ServerSentEventsSecurityScanner
from tblue.scanner.path_traversal_deep    import PathTraversalDeepScanner
from tblue.scanner.wasm_security_deep     import WASMSecurityDeepScanner
from tblue.scanner.content_type_sniffing  import ContentTypeSniffingScanner
# Phase 130: Service worker deep, Trusted Types CSP, Early Hints security, Reporting API security
from tblue.scanner.service_worker_security_deep import ServiceWorkerSecurityDeepScanner
from tblue.scanner.trusted_types_csp      import TrustedTypesCspScanner
from tblue.scanner.http_early_hints_security import HTTPEarlyHintsSecurityScanner
from tblue.scanner.reporting_api_security import ReportingAPISecurityScanner
# Phase 131: Idle Detection API, Network Information API, Cache API, Credential Management API
from tblue.scanner.idle_detection_api_security import IdleDetectionAPISecurityScanner
from tblue.scanner.network_information_security import NetworkInformationSecurityScanner
from tblue.scanner.cache_api_security     import CacheAPISecurityScanner
from tblue.scanner.credential_management_security import CredentialManagementSecurityScanner
# Phase 132: Permissions API, Web Locks API, Payment Request API, File System Access API
from tblue.scanner.permissions_api_security import PermissionsAPISecurityScanner
from tblue.scanner.lock_api_security      import LockAPISecurityScanner
from tblue.scanner.payment_request_security import PaymentRequestSecurityScanner
from tblue.scanner.file_system_access_security import FileSystemAccessSecurityScanner
# Phase 133: WebUSB, Web Bluetooth, Web Serial, Screen Capture security
from tblue.scanner.web_usb_security       import WebUSBSecurityScanner
from tblue.scanner.web_bluetooth_security import WebBluetoothSecurityScanner
from tblue.scanner.web_serial_security    import WebSerialSecurityScanner
from tblue.scanner.screen_capture_security import ScreenCaptureSecurityScanner
# Phase 134: Geolocation API, PerformanceObserver, IntersectionObserver, MSE security
from tblue.scanner.geolocation_api_security import GeolocationAPISecurityScanner
from tblue.scanner.performance_observer_security import PerformanceObserverSecurityScanner
from tblue.scanner.intersection_observer_security import IntersectionObserverSecurityScanner
from tblue.scanner.media_source_extension_security import MediaSourceExtensionSecurityScanner
# Phase 135: WebCodecs API, EyeDropper API, ResizeObserver, Compression Streams security
from tblue.scanner.webcodecs_security         import WebCodecsSecurityScanner
from tblue.scanner.eyedropper_api_security    import EyeDropperAPISecurityScanner
from tblue.scanner.resize_observer_security   import ResizeObserverSecurityScanner
from tblue.scanner.compression_streams_security import CompressionStreamsSecurityScanner
# Phase 136: Web NFC, Ambient Light Sensor, Device Motion, Vibration API security
from tblue.scanner.web_nfc_security       import WebNFCSecurityScanner
from tblue.scanner.ambient_light_security import AmbientLightSecurityScanner
from tblue.scanner.device_motion_security import DeviceMotionSecurityScanner
from tblue.scanner.vibration_api_security import VibrationAPISecurityScanner
# Phase 137: Generic Sensor, User Timing, Background Sync, Push API security
from tblue.scanner.generic_sensor_security  import GenericSensorSecurityScanner
from tblue.scanner.user_timing_security     import UserTimingSecurityScanner
from tblue.scanner.background_sync_security import BackgroundSyncSecurityScanner
from tblue.scanner.push_api_security        import PushAPISecurityScanner
# Phase 138: Window Management, Document PiP, Notification API, Screen Wake Lock security
from tblue.scanner.window_management_security import WindowManagementSecurityScanner
from tblue.scanner.document_pip_security      import DocumentPIPSecurityScanner
from tblue.scanner.notification_api_security  import NotificationAPISecurityScanner
from tblue.scanner.screen_wake_lock_security  import ScreenWakeLockSecurityScanner
# Phase 139: Web OTP, Contact Picker, Clipboard API, WebXR security
from tblue.scanner.web_otp_security        import WebOTPSecurityScanner
from tblue.scanner.contact_picker_security import ContactPickerSecurityScanner
from tblue.scanner.clipboard_api_security  import ClipboardAPISecurityScanner
from tblue.scanner.webxr_security          import WebXRSecurityScanner
# Phase 140: Web Audio, MIDI API, Battery Status, WebHID security
from tblue.scanner.web_audio_security      import WebAudioSecurityScanner
from tblue.scanner.midi_api_security       import MIDIAPISecurityScanner
from tblue.scanner.battery_status_security import BatteryStatusSecurityScanner
from tblue.scanner.hid_api_security        import HIDAPISecurityScanner
# Phase 141: Navigation API, Sanitizer API, Portals security
from tblue.scanner.navigation_api_security import NavigationAPISecurityScanner
from tblue.scanner.sanitizer_api_security  import SanitizerAPISecurityScanner
from tblue.scanner.portals_security        import PortalsSecurityScanner
# Phase 142: Trusted Types bypass, Font Loading, BFCache, Scheduler API security
from tblue.scanner.trusted_types_security      import TrustedTypesSecurityScanner
from tblue.scanner.font_loading_security       import FontLoadingSecurityScanner
from tblue.scanner.back_forward_cache_security import BackForwardCacheSecurityScanner
from tblue.scanner.scheduler_api_security      import SchedulerAPISecurityScanner
# Phase 143: MessageChannel, SharedWorker, StorageManager, Periodic Background Sync security
from tblue.scanner.message_channel_security          import MessageChannelSecurityScanner
from tblue.scanner.shared_worker_security            import SharedWorkerSecurityScanner
from tblue.scanner.storage_manager_security          import StorageManagerSecurityScanner
from tblue.scanner.periodic_background_sync_security import PeriodicBackgroundSyncSecurityScanner
# Phase 144: CSS Paint API, CSS Custom Highlight, URL Protocol Handler, Launch Handler security
from tblue.scanner.css_paint_api_security        import CSSPaintAPISecurityScanner
from tblue.scanner.css_custom_highlight_security import CSSCustomHighlightSecurityScanner
from tblue.scanner.url_protocol_handler_security import URLProtocolHandlerSecurityScanner
from tblue.scanner.launch_handler_security       import LaunchHandlerSecurityScanner
# Phase 145: Element Timing, Document Visibility, Screen Details, Long Task Observer security
from tblue.scanner.element_timing_security        import ElementTimingSecurityScanner
from tblue.scanner.document_visibility_security   import DocumentVisibilitySecurityScanner
from tblue.scanner.screen_details_security        import ScreenDetailsSecurityScanner
from tblue.scanner.longtask_observer_security     import LongTaskObserverSecurityScanner
# Phase 146: View Transition, Document PiP API, Cookie Store, Web Locks security
from tblue.scanner.view_transition_security   import ViewTransitionSecurityScanner
from tblue.scanner.document_pip_api_security  import DocumentPIPApiSecurityScanner
from tblue.scanner.cookie_store_security      import CookieStoreSecurityScanner
from tblue.scanner.web_locks_security         import WebLocksSecurityScanner
# Phase 147: Shape Detection, Media Session, Badging API, Content Index security
from tblue.scanner.shape_detection_security import ShapeDetectionSecurityScanner
from tblue.scanner.media_session_security   import MediaSessionSecurityScanner
from tblue.scanner.badging_api_security     import BadgingAPISecurityScanner
from tblue.scanner.content_index_security   import ContentIndexSecurityScanner
# Phase 148: PWA Manifest, BeforeInstallPrompt, Ink API, OPFS security
from tblue.scanner.pwa_manifest_security          import PWAManifestSecurityScanner
from tblue.scanner.before_install_prompt_security import BeforeInstallPromptSecurityScanner
from tblue.scanner.ink_api_security               import InkAPISecurityScanner
from tblue.scanner.opfs_security                  import OPFSSecurityScanner
# Phase 149
from tblue.scanner.webtransport_security    import WebTransportSecurityScanner
from tblue.scanner.webgpu_security          import WebGPUSecurityScanner
from tblue.scanner.compute_pressure_security import ComputePressureSecurityScanner
from tblue.scanner.background_fetch_security import BackgroundFetchSecurityScanner
# Phase 150
from tblue.scanner.fedcm_security          import FedCMSecurityScanner
from tblue.scanner.shared_storage_security import SharedStorageSecurityScanner
from tblue.scanner.fenced_frame_security   import FencedFrameSecurityScanner
from tblue.scanner.text_fragment_security  import TextFragmentSecurityScanner
# Phase 151
from tblue.scanner.attribution_reporting_security import AttributionReportingSecurityScanner
from tblue.scanner.storage_bucket_security        import StorageBucketSecurityScanner
from tblue.scanner.payment_handler_security       import PaymentHandlerSecurityScanner
from tblue.scanner.interest_group_security        import InterestGroupSecurityScanner
# Phase 152
from tblue.scanner.topics_api_security         import TopicsAPISecurityScanner
from tblue.scanner.private_aggregation_security import PrivateAggregationSecurityScanner
from tblue.scanner.custom_elements_security    import CustomElementsSecurityScanner
from tblue.scanner.dynamic_import_security     import DynamicImportSecurityScanner
# Phase 153
from tblue.scanner.mutation_observer_security import MutationObserverSecurityScanner
from tblue.scanner.eventsource_security       import EventSourceSecurityScanner
from tblue.scanner.login_status_api_security  import LoginStatusAPISecurityScanner
from tblue.scanner.reporting_observer_security import ReportingObserverSecurityScanner
# Phase 154
from tblue.scanner.beacon_api_security         import BeaconAPISecurityScanner
from tblue.scanner.pointer_lock_security       import PointerLockSecurityScanner
from tblue.scanner.history_api_security        import HistoryAPISecurityScanner
from tblue.scanner.credentialless_iframe_security import CredentiallessIframeSecurityScanner
# Phase 155
from tblue.scanner.drag_drop_security      import DragDropSecurityScanner
from tblue.scanner.form_data_security      import FormDataSecurityScanner
from tblue.scanner.readable_stream_security import ReadableStreamSecurityScanner
from tblue.scanner.structured_clone_security import StructuredCloneSecurityScanner
# Phase 156
from tblue.scanner.webgl_security              import WebGLSecurityScanner
from tblue.scanner.speech_recognition_security import SpeechRecognitionSecurityScanner
from tblue.scanner.speech_synthesis_security   import SpeechSynthesisSecurityScanner
from tblue.scanner.media_recorder_security     import MediaRecorderSecurityScanner
# Phase 157
from tblue.scanner.gamepad_security              import GamepadSecurityScanner
from tblue.scanner.proximity_sensor_security     import ProximitySensorSecurityScanner
from tblue.scanner.picture_in_picture_security   import PictureInPictureSecurityScanner
from tblue.scanner.keyboard_lock_security        import KeyboardLockSecurityScanner
# Phase 158
from tblue.scanner.resource_timing_security      import ResourceTimingSecurityScanner
from tblue.scanner.permission_policy_security    import PermissionPolicySecurityScanner
from tblue.scanner.long_animation_frame_security import LongAnimationFrameSecurityScanner
from tblue.scanner.scroll_timeline_security      import ScrollTimelineSecurityScanner
# Phase 159
from tblue.scanner.anchor_positioning_security    import AnchorPositioningSecurityScanner
from tblue.scanner.css_cascade_layers_security    import CSSCascadeLayersSecurityScanner
from tblue.scanner.css_houdini_security           import CSSHoudiniSecurityScanner
from tblue.scanner.css_custom_properties_security import CSSCustomPropertiesSecurityScanner
# Phase 160
from tblue.scanner.coop_security        import COOPSecurityScanner
from tblue.scanner.coep_security        import COEPSecurityScanner
from tblue.scanner.corp_security        import CORPSecurityScanner
from tblue.scanner.trust_token_security import TrustTokenSecurityScanner
# Phase 161
from tblue.scanner.css_container_query_security import CSSContainerQuerySecurityScanner
from tblue.scanner.import_assertions_security   import ImportAssertionsSecurityScanner
from tblue.scanner.fetch_priority_security      import FetchPrioritySecurityScanner
from tblue.scanner.prerendering_security        import PrerenderingSecurityScanner
# Phase 162
from tblue.scanner.storage_access_api_security  import StorageAccessAPISecurityScanner
from tblue.scanner.document_domain_security     import DocumentDomainSecurityScanner
from tblue.scanner.identity_credential_security import IdentityCredentialSecurityScanner
from tblue.scanner.css_scope_security           import CSSScopeSecurityScanner
# Phase 163
from tblue.scanner.css_nesting_security         import CSSNestingSecurityScanner
from tblue.scanner.css_font_palette_security    import CSSFontPaletteSecurityScanner
from tblue.scanner.object_url_security          import ObjectURLSecurityScanner
from tblue.scanner.worker_module_security       import WorkerModuleSecurityScanner
# Phase 164
from tblue.scanner.abort_controller_security    import AbortControllerSecurityScanner
from tblue.scanner.observable_api_security      import ObservableAPISecurityScanner
from tblue.scanner.css_masonry_security         import CSSMasonrySecurityScanner
from tblue.scanner.css_math_security            import CSSMathSecurityScanner
# Phase 165
from tblue.scanner.video_decoder_security       import VideoDecoderSecurityScanner
from tblue.scanner.audio_worklet_security       import AudioWorkletSecurityScanner
from tblue.scanner.media_capabilities_security  import MediaCapabilitiesSecurityScanner
from tblue.scanner.web_hid_security             import WebHIDSecurityScanner
from tblue.scanner.virtual_keyboard_security    import VirtualKeyboardSecurityScanner
from tblue.scanner.rtc_encoded_transform_security import RTCEncodedTransformSecurityScanner
from tblue.scanner.page_lifecycle_security      import PageLifecycleSecurityScanner
# Phase 166
from tblue.scanner.document_picture_in_picture_security import DocumentPictureInPictureSecurityScanner
from tblue.scanner.image_decoder_security       import ImageDecoderSecurityScanner
from tblue.scanner.audio_decoder_security       import AudioDecoderSecurityScanner
from tblue.scanner.highlight_api_security       import HighlightAPISecurityScanner
# Phase 167
from tblue.scanner.element_internals_security        import ElementInternalsSecurityScanner
from tblue.scanner.declarative_shadow_dom_security   import DeclarativeShadowDOMSecurityScanner
from tblue.scanner.animation_worklet_security        import AnimationWorkletSecurityScanner
from tblue.scanner.fullscreen_security               import FullscreenSecurityScanner
# Phase 168
from tblue.scanner.handwriting_recognition_security import HandwritingRecognitionSecurityScanner
from tblue.scanner.presentation_api_security        import PresentationAPISecurityScanner
from tblue.scanner.css_typed_om_security            import CSSTypedOMSecurityScanner
from tblue.scanner.popover_api_security             import PopoverAPISecurityScanner
# Phase 169
from tblue.scanner.remote_playback_security   import RemotePlaybackSecurityScanner
from tblue.scanner.layout_worklet_security    import LayoutWorkletSecurityScanner
from tblue.scanner.dialog_element_security    import DialogElementSecurityScanner
from tblue.scanner.font_access_security       import FontAccessSecurityScanner
# Phase 170
from tblue.scanner.content_visibility_security import ContentVisibilitySecurityScanner
from tblue.scanner.inert_security              import InertSecurityScanner
from tblue.scanner.scroll_snap_security        import ScrollSnapSecurityScanner
from tblue.scanner.color_scheme_security       import ColorSchemeSecurityScanner
# Phase 171
from tblue.scanner.focus_management_security      import FocusManagementSecurityScanner
from tblue.scanner.css_counter_security           import CSSCounterSecurityScanner
from tblue.scanner.form_data_api_security         import FormDataAPISecurityScanner
from tblue.scanner.custom_element_registry_security import CustomElementRegistrySecurityScanner
# Phase 172
from tblue.scanner.css_grid_security              import CSSGridSecurityScanner
from tblue.scanner.document_fragment_security     import DocumentFragmentSecurityScanner
from tblue.scanner.pointer_events_security        import PointerEventsSecurityScanner
from tblue.scanner.input_event_security           import InputEventSecurityScanner
# Phase 173
from tblue.scanner.tree_walker_security           import TreeWalkerSecurityScanner
from tblue.scanner.dom_parser_security            import DOMParserSecurityScanner
from tblue.scanner.channel_messaging_security     import ChannelMessagingSecurityScanner
from tblue.scanner.css_transitions_security       import CSSTransitionsSecurityScanner
# Phase 174
from tblue.scanner.typed_array_security           import TypedArraySecurityScanner
from tblue.scanner.array_buffer_security          import ArrayBufferSecurityScanner
from tblue.scanner.event_target_security          import EventTargetSecurityScanner
from tblue.scanner.proxy_reflect_security         import ProxyReflectSecurityScanner
# Phase 175
from tblue.scanner.promise_security               import PromiseSecurityScanner
from tblue.scanner.generator_security             import GeneratorSecurityScanner
from tblue.scanner.symbol_security                import SymbolSecurityScanner
from tblue.scanner.weakmap_security               import WeakMapSecurityScanner
# Phase 176
from tblue.scanner.json_security                  import JSONSecurityScanner
from tblue.scanner.error_event_security           import ErrorEventSecurityScanner
from tblue.scanner.define_property_security       import DefinePropertySecurityScanner
from tblue.scanner.storage_event_security         import StorageEventSecurityScanner
# Phase 177
from tblue.scanner.regex_security                 import RegexSecurityScanner
from tblue.scanner.date_security                  import DateSecurityScanner
from tblue.scanner.intl_security                  import IntlSecurityScanner
from tblue.scanner.object_spread_security         import ObjectSpreadSecurityScanner
# Phase 178
from tblue.scanner.map_set_security               import MapSetSecurityScanner
from tblue.scanner.iterator_protocol_security     import IteratorProtocolSecurityScanner
from tblue.scanner.function_constructor_security  import FunctionConstructorSecurityScanner
from tblue.scanner.web_components_security        import WebComponentsSecurityScanner
# Phase 179
from tblue.scanner.geolocation_security           import GeolocationSecurityScanner
# Phase 180
from tblue.scanner.media_devices_security         import MediaDevicesSecurityScanner
from tblue.scanner.clipboard_advanced_security    import ClipboardAdvancedSecurityScanner
from tblue.scanner.device_orientation_security    import DeviceOrientationSecurityScanner
from tblue.scanner.vibration_security             import VibrationSecurityScanner
# Phase 181
from tblue.scanner.broadcast_channel_advanced_security import BroadcastChannelAdvancedSecurityScanner
from tblue.scanner.web_share_security             import WebShareSecurityScanner
from tblue.scanner.idle_detection_security        import IdleDetectionSecurityScanner
from tblue.scanner.notification_security          import NotificationSecurityScanner
# Phase 182
from tblue.scanner.web_authentication_security    import WebAuthenticationSecurityScanner
from tblue.scanner.credential_api_advanced        import CredentialApiAdvancedScanner
from tblue.scanner.federated_identity_security    import FederatedIdentitySecurityScanner
from tblue.scanner.magic_link_security            import MagicLinkSecurityScanner
# Phase 183
from tblue.scanner.session_fixation_security      import SessionFixationSecurityScanner
from tblue.scanner.account_enumeration_security   import AccountEnumerationSecurityScanner
from tblue.scanner.same_site_cookie_security      import SameSiteCookieSecurityScanner
from tblue.scanner.jwt_advanced_security          import JwtAdvancedSecurityScanner
# Phase 184
from tblue.scanner.cors_credential_security       import CORSCredentialSecurityScanner
from tblue.scanner.token_refresh_security         import TokenRefreshSecurityScanner
from tblue.scanner.sql_injection_client_security  import SQLInjectionClientSecurityScanner
from tblue.scanner.xpath_injection_security       import XPathInjectionSecurityScanner
# Phase 185
from tblue.scanner.auth_bypass_pattern_security   import AuthBypassPatternSecurityScanner
from tblue.scanner.rate_limit_bypass_security     import RateLimitBypassSecurityScanner
from tblue.scanner.ldap_injection_security        import LDAPInjectionSecurityScanner
from tblue.scanner.template_injection_client_security import TemplateInjectionClientSecurityScanner
# Phase 186
from tblue.scanner.prototype_pollution_advanced   import PrototypePollutionAdvancedScanner
from tblue.scanner.mass_assignment_security       import MassAssignmentSecurityScanner
from tblue.scanner.insecure_direct_object_reference import InsecureDirectObjectReferenceScanner
from tblue.scanner.command_injection_client_security import CommandInjectionClientSecurityScanner
# Phase 187
from tblue.scanner.dependency_hijacking           import DependencyHijackingScanner
from tblue.scanner.file_inclusion_security        import FileInclusionSecurityScanner
from tblue.scanner.server_side_template_passive   import ServerSideTemplatePassiveScanner
from tblue.scanner.http_request_smuggling         import HTTPRequestSmugglingScanner
# Phase 188
from tblue.scanner.api_rate_limit_headers         import APIRateLimitHeadersScanner
from tblue.scanner.cors_policy_advanced           import CORSPolicyAdvancedScanner
from tblue.scanner.content_sniffing_bypass        import ContentSniffingBypassScanner
from tblue.scanner.javascript_prototype_chain     import JavaScriptPrototypeChainScanner
# Phase 189
from tblue.scanner.xml_external_entity_advanced   import XMLExternalEntityAdvancedScanner
from tblue.scanner.broken_object_level_auth       import BrokenObjectLevelAuthScanner
from tblue.scanner.insecure_data_exposure         import InsecureDataExposureScanner
from tblue.scanner.graphql_introspection_security import GraphQLIntrospectionSecurityScanner
# Phase 190
from tblue.scanner.latex_injection_passive        import LaTeXInjectionPassiveScanner
from tblue.scanner.css_injection_passive          import CSSInjectionPassiveScanner
from tblue.scanner.deserialization_gadget_passive import DeserializationGadgetPassiveScanner
from tblue.scanner.race_condition_passive         import RaceConditionPassiveScanner
# Phase 191
from tblue.scanner.link_injection_passive         import LinkInjectionPassiveScanner
from tblue.scanner.parameter_pollution_passive    import ParameterPollutionPassiveScanner
from tblue.scanner.timing_attack_passive          import TimingAttackPassiveScanner
from tblue.scanner.cryptographic_weakness_passive import CryptographicWeaknessPassiveScanner
# Phase 192
from tblue.scanner.nosql_injection_advanced       import NoSQLInjectionAdvancedScanner
from tblue.scanner.ldap_injection_passive         import LDAPInjectionPassiveScanner
from tblue.scanner.oauth_misconfiguration_passive import OAuthMisconfigurationPassiveScanner
from tblue.scanner.saml_security_passive          import SAMLSecurityPassiveScanner
# Phase 193
from tblue.scanner.actuator_endpoint_exposure     import ActuatorEndpointExposureScanner
from tblue.scanner.tabnapping_passive             import TabnappingPassiveScanner
from tblue.scanner.zip_slip_passive               import ZipSlipPassiveScanner
from tblue.scanner.integer_overflow_passive       import IntegerOverflowPassiveScanner
# Phase 194
from tblue.scanner.debug_endpoint_exposure        import DebugEndpointExposureScanner
from tblue.scanner.sensitive_cache_control        import SensitiveCacheControlScanner
from tblue.scanner.client_side_validation_only    import ClientSideValidationOnlyScanner
from tblue.scanner.session_entropy_passive        import SessionEntropyPassiveScanner
from tblue.scanner.browser_dom_xss     import BrowserDOMXSSScanner
from tblue.scanner.browser_spa_scan    import BrowserSPAScanner
from tblue.scanner.browser_storage     import BrowserStorageScanner
from tblue.scanner.pci_dss_compliance   import PCIDSSComplianceScanner
from tblue.scanner.hipaa_compliance     import HIPAAComplianceScanner
from tblue.scanner.soc2_compliance      import SOC2ComplianceScanner
from tblue.scanner.nist_csf_compliance  import NISTCSFComplianceScanner
from tblue.scanner.iso27001_compliance  import ISO27001ComplianceScanner
from tblue.scanner.sbom_scanner         import SBOMScanner
from tblue.scanner.polyfill_supply_chain import PolyfillSupplyChainScanner
from tblue.scanner.active_cors_origin_fuzz  import ActiveCORSOriginFuzzScanner
from tblue.scanner.active_http_verb_probe   import ActiveHTTPVerbProbeScanner
from tblue.scanner.active_port_probe        import ActivePortProbeScanner
from tblue.scanner.active_subdomain_enum    import ActiveSubdomainEnumScanner
from tblue.scanner.active_tls_cipher_probe  import ActiveTLSCipherProbeScanner
from tblue.scanner.elasticsearch_exposure   import ElasticsearchExposureScanner
from tblue.scanner.redis_exposure           import RedisExposureScanner
from tblue.scanner.mongodb_exposure         import MongoDBExposureScanner
from tblue.scanner.account_takeover_passive import AccountTakeoverPassiveScanner
from tblue.scanner.graphql_authorization    import GraphQLAuthorizationScanner
from tblue.scanner.oauth_device_flow        import OAuthDeviceFlowScanner
from tblue.cache                      import ResponseCache
from tblue.dashboard                  import DashboardServer
from tblue.report import stride as stride_report
from tblue.report import poc as poc_report
from tblue.compliance                 import generate_report as compliance_report
from tblue.notify                     import send as notify_send, parse_target as notify_parse
from tblue.soar                       import send as soar_send, parse_target as soar_parse
from tblue.report import terminal as term
from tblue.report import html as html_report
from tblue.report import json as json_report
from tblue.report import sarif as sarif_report
from tblue.report import siem as siem_report
from tblue.report import sigma as sigma_report
from tblue.report import splunk_spl as splunk_report
from tblue.report import kql as sentinel_report
from tblue.remediation import generate_playbooks, format_terminal as fmt_playbook_term, format_markdown as fmt_playbook_md
from tblue.scoring import score_results
from tblue.history import save_snapshot, load_previous_snapshot, compute_diff, load_score_history
from tblue.logger import get_logger, set_level, log_head, log_warn
from tblue.ai_analysis import analyze_with_ai, format_ai_analysis_terminal

logger = get_logger(__name__)

ALL_MODULES: List[str] = [
    "ssl", "headers", "cookies", "csp",
    "info", "mixed_content", "login", "xss", "dom",
    "email", "access", "graphql", "methods", "ports",
    "cors", "security_txt", "error_pages",
    "exposure", "rate_limit", "jwt", "waf",
    "dns", "js_libs", "sensitive_params",
    # Phase 5
    "tls_deep", "email_adv", "js_secrets",
    "supply_chain", "form_security",
    "crt_sh", "subdomain_takeover", "typosquatting",
    "sca", "cloud_storage", "cms", "infra",
    # Phase 6
    "dns_adv", "admin_exposure", "html_comments",
    "cookie_adv", "redirects", "robots",
    "csp_adv", "sri_adv", "resp_headers",
    "host_header", "open_redirect", "permissions_policy", "gdpr",
    # Phase 10
    "threat_intel",
    # Phase 11
    "api_surface", "dir_listing", "ssrf_params",
    "oauth", "cache_poisoning", "req_smuggling",
    # Phase 12
    "websocket", "saml", "proto_pollution",
    # Phase 13
    "xml_xxe", "spring_actuator", "deserialization",
    "ssti", "file_upload", "path_traversal",
    # Phase 15
    "scim", "grpc", "cloud_metadata",
    "nosql_injection", "web_cache_deception", "session_security",
    "k8s_exposure",
    # Phase 16
    "http2_security", "graphql_advanced", "jwt_advanced", "cors_advanced",
    # Phase 18
    "business_logic", "graphql_depth", "ssrf_advanced", "rate_limiting",
    "api_security_headers",
    "oauth_advanced", "crlf_injection",
    "http_parameter_pollution", "weak_crypto",
    "clickjacking", "account_enumeration",
    "open_api_exposure", "dependency_confusion",
    "mass_assignment", "log_injection", "file_inclusion",
    "ldap_injection", "command_injection",
    "xxe_injection", "ssrf_detection",
    "http_verb_tampering", "service_worker_security",
    "idor_detection", "sensitive_data_exposure",
    "api_auth_security", "content_injection",
    "cicd_exposure", "webauthn_security", "api_versioning", "password_reset",
    "race_condition", "json_injection", "el_injection",
    "client_storage", "csti", "fetch_metadata", "path_confusion",
    "csv_injection", "reflected_file_download", "source_map",
    "dev_artifact", "link_security", "api_collection", "framework_config",
    "xssi", "server_timing", "crossdomain_policy", "ai_api_exposure",
    "graphql_field_suggestion",
    # Phase 50-54: Gap-closing
    "js_file_analysis", "version_cve",
    "llm_prompt_injection", "xsleak",
    # Phase 55: New attack surface scanners
    "graphql_batching", "css_injection", "prssi",
    "referrer_policy", "hsts_preload",
    "oauth_token_leak", "dom_clobbering",
    # Phase 56: Supply chain + injection surface
    "trojan_source", "dangling_markup", "csp_reporting",
    # Phase 57: Browser runtime (Playwright)
    "browser_dom_xss", "browser_spa_scan", "browser_storage",
    # Phase 58: Live CVE feed
    "live_cve",
    # Phase 60: Deep-tech scanners
    "csp_nonce", "wasm_security", "timing_oracle",
    # Phase 61: Privacy, caching, and protocol scanners
    "open_graph_exposure", "cache_control_security", "http3_quic",
    # Phase 62: ETag fingerprinting, SSE security, security.txt deep
    "etag_fingerprinting", "sse_security", "security_txt_deep",
    # Phase 63: Supply chain lockfile exposure + Mutation XSS
    "supply_chain_lockfile", "mutation_xss",
    # Phase 64: Cookie prefix security, postMessage security, Web Manifest security
    "cookie_prefix_security", "postmessage_security", "web_manifest_security",
    # Phase 65: HTTP Observatory, API schema exposure, header injection sinks
    "http_observatory", "api_schema_exposure", "header_injection_sink",
    # Phase 66: Content-Type confusion, OAuth PKCE
    "content_type_confusion", "oauth_pkce",
    # Phase 67: DNS CAA records, DOM XSS source-to-sink analysis
    "dns_caa", "dom_xss_sources",
    # Phase 68: Path parameter pollution, JS framework version detection
    "path_parameter_pollution", "js_framework_detection",
    # Phase 69: Link preview SSRF exposure, WebSocket security deep audit
    "link_preview_exposure", "websocket_security_deep",
    # Phase 70: TLS certificate deep, GraphQL subscriptions, Shadow DOM security
    "tls_certificate_deep", "graphql_subscription", "shadow_dom_security",
    # Phase 71: Account lockout detection, deep CORS, CSP violation reporting
    "account_lockout", "cors_misconfiguration_deep", "csp_violation_report",
    # Phase 72: HTTP security baseline scorecard, client hints, API error disclosure
    "http_security_baseline", "client_hints_security", "api_error_disclosure",
    # Phase 73: JWKS key exposure, deep open redirect bypass detection
    "jwks_exposure", "open_redirect_deep",
    # Phase 74: HTTP method override bypass, third-party resource exposure
    "http_method_override", "third_party_exposure",
    # Phase 75: Session fixation indicators, introspection / debug mode disclosure
    "session_fixation", "introspection_disclosure",
    # Phase 76: Deep clickjacking analysis (ALLOW-FROM, frame-busting JS bypass)
    "clickjacking_deep",
    # Phase 77: TLS protocol version compliance (TLS 1.0/1.1 deprecation, weak ciphers)
    "tls_protocol_version",
    # Phase 78: HTTP response splitting / deep CRLF injection with encoding bypass variants
    "http_response_splitting",
    # Phase 79: DNS rebinding risk factors (private IP, low TTL, Host header validation)
    "dns_rebinding",
    # Phase 80: Content negotiation security (Accept reflection, JSON-as-HTML, JSONP)
    "content_negotiation",
    # Phase 82: WebRTC exposure, CDN misconfiguration, password policy, feature flags, account recovery
    "webrtc_exposure", "cdn_misconfiguration", "password_policy",
    "feature_flag_exposure", "account_recovery",
    # Phase 83: Social login OAuth security, iframe sandbox, BroadcastChannel, API gateway headers
    "social_login_security", "iframe_sandbox_security",
    "broadcast_channel_security", "api_gateway_security",
    # Phase 84: Link header injection, GraphQL persisted queries, serverless exposure
    "link_header_injection", "graphql_persisted_queries", "serverless_exposure",
    # Phase 85: HTTP/2 push security, MIME type security, certificate transparency
    "http2_push_security", "mime_type_security", "certificate_transparency",
    # Phase 86: Web worker security, cookie SameSite deep analysis
    "web_worker_security", "cookie_samesite_deep",
    # Phase 87: Form action security, Open Graph / JSON-LD security
    "form_action_security", "open_graph_security",
    # Phase 88: Deep link / Universal Link security, HTTP caching security
    "deep_link_security", "http_caching_security",
    # Phase 89: WAF bypass detection, API rate limit deep analysis
    "waf_bypass_detection", "api_rate_limit_deep",
    # Phase 90: JWT claim analysis, CORS deep analysis, HSTS deep analysis
    "jwt_claim_analysis", "cors_deep_analysis", "hsts_deep_analysis",
    # Phase 91: Referrer policy deep, cross-origin policy (COOP/COEP/CORP), credential exposure
    "referrer_policy_deep", "cross_origin_policy_deep", "credential_exposure",
    # Phase 92: Server info deep, cache poisoning passive, session fixation passive
    "server_info_deep", "cache_poisoning_passive", "session_fixation_passive",
    # Phase 93: Source map exposure, MFA detection, API keys in JS, email header injection
    "sourcemap_exposure", "mfa_detection", "api_key_in_js", "email_header_injection",
    # Phase 94: CSP nonce reuse, CORS max-age, TLS downgrade passive, GraphQL batch abuse
    "csp_nonce_reuse", "cors_max_age_deep", "tls_downgrade_passive", "graphql_batch_abuse",
    # Phase 96: SQL error passive, Nginx alias traversal, Apache status, debug mode
    "sql_error_passive", "nginx_alias_traversal", "apache_status_exposure", "debug_mode_detection",
    # Phase 97: Security misconfiguration, HTTP desync passive, token exposure, CORS wildcard API
    "security_misconfiguration", "http_desync_passive", "token_exposure_passive", "cors_wildcard_api",
    # Phase 98: JS prototype pollution deep, API pagination, SRI deep, open S3 bucket
    "javascript_prototype_pollution_deep", "api_pagination_security",
    "subresource_integrity_deep", "open_s3_bucket",
    # Phase 99: WebSocket origin check, SPA hash routing, HTTPS upgrade chain, sensitive endpoints
    "websocket_origin_check", "spa_hash_routing_security",
    "http_strict_transport_upgrade", "sensitive_endpoint_exposure",
    # Phase 100: XML security, email config exposure, GraphQL info disclosure, path normalization
    "xml_security_passive", "email_config_exposure",
    "graphql_info_disclosure", "path_normalization_security",
    # Phase 101: TLS cert deep, server-timing, dependency confusion, iframe security
    "tls_certificate_deep", "server_timing_disclosure",
    "dependency_confusion", "iframe_security_deep",
    # Phase 102: HTTP method override, content-type confusion, cache poisoning passive, secret in error page
    "http_method_override", "content_type_confusion",
    "cache_poisoning_passive", "secret_in_error_page",
    # Phase 103: Open redirect deep, insecure deserialization passive, XXE passive, SSRF passive
    "open_redirect_deep", "insecure_deserialization_passive",
    "xxe_probe", "ssrf_passive",
    # Phase 104: Host header injection, clickjacking advanced, business logic, API versioning
    "host_header_injection", "clickjacking_advanced",
    "business_logic_exposure", "api_versioning_security",
    # Phase 105: CSRF token strength, CORS preflight deep, rate limiting, JWT algorithm confusion
    "csrf_token_strength", "cors_preflight_deep",
    "rate_limiting_detection", "jwt_algorithm_confusion",
    # Phase 106: OAuth redirect URI, SAML passive, file upload security
    "oauth_redirect_uri_validation", "saml_passive", "file_upload_security",
    # Phase 107-108: Subdomain takeover, DNS rebinding, log injection, parameter pollution
    "subdomain_takeover_passive", "dns_rebinding_passive",
    "log_injection_probe", "parameter_pollution",
    # Phase 109 (final): WebSocket security deep, source map exposure, feature/permissions policy
    "websocket_security_deep", "sourcemap_exposure", "feature_policy_security",
    # Phase 81: Previously-implemented scanners now activated (reach 210 total)
    "access_control", "cms_detection", "cookie_advanced", "csp_advanced",
    "directory_listing", "dns_advanced", "dns_security",
    "email_advanced", "email_security", "gdpr_privacy", "http_methods",
    "info_disclosure", "js_libraries", "jwt_security", "login_security",
    "mixed_content", "prototype_pollution", "redirect_chain",
    "request_smuggling", "response_headers", "robots_txt", "sri_advanced",
    # Phase 110: Docker/container exposure, GraphQL batch attacks, API key rotation
    "docker_exposure", "graphql_batch_attack", "api_key_rotation",
    # Phase 111: Passive subdomain enumeration, ReDoS, HTTP/2 Rapid Reset
    "subdomain_enum_passive", "redos_passive", "http2_rapid_reset",
    # Phase 112: Payment page security (PCI DSS), health endpoint exposure
    "payment_page_security", "health_endpoint_exposure",
    # Phase 113: Log4Shell passive, CORS expose-headers
    "log4shell_passive", "cors_expose_headers",
    # Phase 114: Cross-origin isolation, Trusted Types, NEL/Reporting API, Speculation Rules
    "cross_origin_isolation", "trusted_types_policy",
    "nel_reporting", "speculation_rules_security",
    # Phase 115: Origin Trial exposure, Link resource hints, Webhook security, HTTP range security
    "origin_trial_exposure", "link_resource_hints_security",
    "webhook_security", "http_range_security",
    # Phase 116: Content-Disposition, CHIPS cookies, Privacy Sandbox APIs, Document-Policy
    "content_disposition_security", "cookies_partitioned_security",
    "privacy_sandbox_apis", "document_policy_security",
    # Phase 117: CORS null origin, compression oracle, form action hijacking, JS dangerous patterns
    "cors_null_origin", "compression_oracle",
    "form_action_hijacking", "js_dangerous_patterns",
    # Phase 118: Import map security, Permissions-Policy deep, Base URI injection, JS supply chain
    "importmap_security", "permissions_policy_deep",
    "base_uri_injection", "js_supply_chain_integrity",
    # Phase 119: SVG security, CSS exfiltration, localStorage sensitive data, RPO
    "svg_security", "css_exfiltration",
    "local_storage_sensitive", "relative_path_overwrite",
    # Phase 120: URL parser differentials, exposed backup files, client-side redirect, protocol confusion
    "url_parser_differential", "exposed_backup_files",
    "client_side_redirect", "protocol_confusion",
    # Phase 121: Iframe allow security, package manifest exposure, canvas fingerprinting, hardcoded credentials
    "iframe_allow_security", "package_manifest_exposure",
    "canvas_fingerprinting", "hardcoded_credentials",
    # Phase 122: Private network access, JSONP endpoints, security header consistency, API auth exposure
    "private_network_access", "jsonp_endpoint",
    "http_security_consistency", "api_authentication_exposure",
    # Phase 124: Tabnabbing, EXIF metadata exposure, GraphQL CSRF, PHI exposure
    "tabnabbing", "exif_metadata_exposure",
    "graphql_csrf", "phi_exposure",
    # Phase 125: HTTP method tampering, CSRF double-submit, XPath injection passive, session token exposure
    "http_method_tampering", "csrf_double_submit",
    "xpath_injection_passive", "session_token_exposure",
    # Phase 126: API pagination abuse, content security framing, OAuth implicit flow, web worker deep
    "api_pagination_abuse", "content_security_framing",
    "oauth_implicit_flow", "web_worker_security_deep",
    # Phase 127: JS template literal injection, CORS origin reflection, JWT exposure, HTTP headers deep
    "javascript_template_literal", "cors_origin_reflection",
    "jwt_token_exposure", "http_security_headers_deep",
    # Phase 128: srcdoc injection, WebCrypto weaknesses, autocomplete security, API doc exposure
    "srcdoc_injection", "web_crypto_weaknesses",
    "autocomplete_security", "api_documentation_exposure",
    # Phase 129: SSE security, path traversal deep, WASM security deep, content-type sniffing
    "server_sent_events_security", "path_traversal_deep",
    "wasm_security_deep", "content_type_sniffing",
    # Phase 130: Service worker deep, Trusted Types CSP, Early Hints security, Reporting API
    "service_worker_security_deep", "trusted_types_csp",
    "http_early_hints_security", "reporting_api_security",
    # Phase 131: Idle Detection API, Network Information API, Cache API, Credential Management API
    "idle_detection_api_security", "network_information_security",
    "cache_api_security", "credential_management_security",
    # Phase 132: Permissions API, Web Locks API, Payment Request API, File System Access API
    "permissions_api_security", "lock_api_security",
    "payment_request_security", "file_system_access_security",
    # Phase 133: WebUSB, Web Bluetooth, Web Serial, Screen Capture security
    "web_usb_security", "web_bluetooth_security",
    "web_serial_security", "screen_capture_security",
    # Phase 134: Geolocation API, PerformanceObserver, IntersectionObserver, MSE security
    "geolocation_api_security", "performance_observer_security",
    "intersection_observer_security", "media_source_extension_security",
    # Phase 135: WebCodecs API, EyeDropper API, ResizeObserver, Compression Streams security
    "webcodecs_security", "eyedropper_api_security",
    "resize_observer_security", "compression_streams_security",
    # Phase 136: Web NFC, Ambient Light Sensor, Device Motion, Vibration API security
    "web_nfc_security", "ambient_light_security",
    "device_motion_security", "vibration_api_security",
    # Phase 137: Generic Sensor, User Timing, Background Sync, Push API security
    "generic_sensor_security", "user_timing_security",
    "background_sync_security", "push_api_security",
    # Phase 138: Window Management, Document PiP, Notification API, Screen Wake Lock security
    "window_management_security", "document_pip_security",
    "notification_api_security", "screen_wake_lock_security",
    # Phase 139: Web OTP, Contact Picker, Clipboard API, WebXR security
    "web_otp_security", "contact_picker_security",
    "clipboard_api_security", "webxr_security",
    # Phase 140: Web Audio, MIDI API, Battery Status, WebHID security
    "web_audio_security", "midi_api_security",
    "battery_status_security", "hid_api_security",
    # Phase 141: Import Map, Navigation API, Sanitizer API, Portals security
    "navigation_api_security",
    "sanitizer_api_security", "portals_security",
    # Phase 142: Trusted Types bypass, Font Loading, BFCache, Scheduler API security
    "trusted_types_security", "font_loading_security",
    "back_forward_cache_security", "scheduler_api_security",
    # Phase 143: MessageChannel, SharedWorker, StorageManager, Periodic Background Sync security
    "message_channel_security", "shared_worker_security",
    "storage_manager_security", "periodic_background_sync_security",
    # Phase 144: CSS Paint API, CSS Custom Highlight, URL Protocol Handler, Launch Handler security
    "css_paint_api_security", "css_custom_highlight_security",
    "url_protocol_handler_security", "launch_handler_security",
    # Phase 145: Element Timing, Document Visibility, Screen Details, Long Task Observer security
    "element_timing_security", "document_visibility_security",
    "screen_details_security", "longtask_observer_security",
    # Phase 146: View Transition, Document PiP API, Cookie Store, Web Locks security
    "view_transition_security", "document_pip_api_security",
    "cookie_store_security", "web_locks_security",
    # Phase 147: Shape Detection, Media Session, Badging API, Content Index security
    "shape_detection_security", "media_session_security",
    "badging_api_security", "content_index_security",
    # Phase 148: PWA Manifest, BeforeInstallPrompt, Ink API, OPFS security
    "pwa_manifest_security", "before_install_prompt_security",
    "ink_api_security", "opfs_security",
    # Phase 149: WebTransport, WebGPU, Compute Pressure, Background Fetch security
    "webtransport_security", "webgpu_security",
    "compute_pressure_security", "background_fetch_security",
    # Phase 150: FedCM, Shared Storage, Fenced Frame, Text Fragment security
    "fedcm_security", "shared_storage_security",
    "fenced_frame_security", "text_fragment_security",
    # Phase 151: Attribution Reporting, Storage Bucket, Payment Handler, Interest Group security
    "attribution_reporting_security", "storage_bucket_security",
    "payment_handler_security", "interest_group_security",
    # Phase 152: Topics API, Private Aggregation, Custom Elements, Dynamic Import security
    "topics_api_security", "private_aggregation_security",
    "custom_elements_security", "dynamic_import_security",
    # Phase 153: MutationObserver, EventSource, Login Status API, ReportingObserver security
    "mutation_observer_security", "eventsource_security",
    "login_status_api_security", "reporting_observer_security",
    # Phase 154: Beacon API, Pointer Lock, History API, Credentialless iframe security
    "beacon_api_security", "pointer_lock_security",
    "history_api_security", "credentialless_iframe_security",
    # Phase 155: Drag Drop, FormData, Readable Stream, Structured Clone security
    "drag_drop_security", "form_data_security",
    "readable_stream_security", "structured_clone_security",
    # Phase 156: WebGL, Speech Recognition, Speech Synthesis, MediaRecorder security
    "webgl_security", "speech_recognition_security",
    "speech_synthesis_security", "media_recorder_security",
    # Phase 157: Gamepad, Proximity Sensor, Picture-in-Picture, Keyboard Lock security
    "gamepad_security", "proximity_sensor_security",
    "picture_in_picture_security", "keyboard_lock_security",
    # Phase 158: Resource Timing, Permission Policy, Long Animation Frame, Scroll Timeline
    "resource_timing_security", "permission_policy_security",
    "long_animation_frame_security", "scroll_timeline_security",
    # Phase 159: Anchor Positioning, CSS Cascade Layers, CSS Houdini, CSS Custom Properties
    "anchor_positioning_security", "css_cascade_layers_security",
    "css_houdini_security", "css_custom_properties_security",
    # Phase 160: COOP, COEP, CORP, Trust Token security
    "coop_security", "coep_security", "corp_security", "trust_token_security",
    # Phase 161: CSS Container Queries, Import Assertions, Fetch Priority, Prerendering
    "css_container_query_security", "import_assertions_security",
    "fetch_priority_security", "prerendering_security",
    # Phase 162: Storage Access API, document.domain, Identity Credential, CSS @scope
    "storage_access_api_security", "document_domain_security",
    "identity_credential_security", "css_scope_security",
    # Phase 163: CSS Nesting, CSS Font Palette, Object URL, Worker Module
    "css_nesting_security", "css_font_palette_security",
    "object_url_security", "worker_module_security",
    # Phase 164: AbortController, Observable API, CSS Masonry, CSS Math
    "abort_controller_security", "observable_api_security",
    "css_masonry_security", "css_math_security",
    # Phase 165: VideoDecoder, AudioWorklet, MediaCapabilities, WebHID, VirtualKeyboard, RTCEncodedTransform, PageLifecycle
    "video_decoder_security", "audio_worklet_security",
    "media_capabilities_security", "web_hid_security",
    "virtual_keyboard_security", "rtc_encoded_transform_security",
    "page_lifecycle_security",
    # Phase 166: Document PiP, ImageDecoder, AudioDecoder, Highlight API
    "document_picture_in_picture_security", "image_decoder_security",
    "audio_decoder_security", "highlight_api_security",
    # Phase 167: ElementInternals, Declarative Shadow DOM, Animation Worklet, Fullscreen
    "element_internals_security", "declarative_shadow_dom_security",
    "animation_worklet_security", "fullscreen_security",
    # Phase 168: Handwriting Recognition, Presentation API, CSS Typed OM, Popover API
    "handwriting_recognition_security", "presentation_api_security",
    "css_typed_om_security", "popover_api_security",
    # Phase 169: Remote Playback, Layout Worklet, Dialog Element, Font Access
    "remote_playback_security", "layout_worklet_security",
    "dialog_element_security", "font_access_security",
    # Phase 170: Content Visibility, Inert, Scroll Snap, Color Scheme
    "content_visibility_security", "inert_security",
    "scroll_snap_security", "color_scheme_security",
    # Phase 171: Focus Management, CSS Counter, FormData API, Custom Element Registry
    "focus_management_security", "css_counter_security",
    "form_data_api_security", "custom_element_registry_security",
    # Phase 172: CSS Grid, Document Fragment, Pointer Events, Input Event
    "css_grid_security", "document_fragment_security",
    "pointer_events_security", "input_event_security",
    # Phase 173: Tree Walker, DOM Parser, Channel Messaging, CSS Transitions
    "tree_walker_security", "dom_parser_security",
    "channel_messaging_security", "css_transitions_security",
    # Phase 174: Typed Array, ArrayBuffer, EventTarget, Proxy/Reflect
    "typed_array_security", "array_buffer_security",
    "event_target_security", "proxy_reflect_security",
    # Phase 175: Promise, Generator, Symbol, WeakMap
    "promise_security", "generator_security",
    "symbol_security", "weakmap_security",
    # Phase 176: JSON, Error Event, defineProperty, Storage Event
    "json_security", "error_event_security",
    "define_property_security", "storage_event_security",
    # Phase 177: Regex, Date, Intl, Object Spread
    "regex_security", "date_security",
    "intl_security", "object_spread_security",
    # Phase 178: Map/Set, Iterator Protocol, Function Constructor, Web Components
    "map_set_security", "iterator_protocol_security",
    "function_constructor_security", "web_components_security",
    # Phase 179: Geolocation
    "geolocation_security",
    # Phase 180: Media Devices, Clipboard Advanced, Device Orientation, Vibration
    "media_devices_security", "clipboard_advanced_security",
    "device_orientation_security", "vibration_security",
    # Phase 181: Broadcast Channel Advanced, Web Share, Idle Detection, Notification
    "broadcast_channel_advanced_security", "web_share_security",
    "idle_detection_security", "notification_security",
    # Phase 182: WebAuthn, Credential API Advanced, Federated Identity, Magic Link
    "web_authentication_security", "credential_api_advanced",
    "federated_identity_security", "magic_link_security",
    # Phase 183: Session Fixation, Account Enumeration, SameSite Cookie, JWT Advanced
    "session_fixation_security", "account_enumeration_security",
    "same_site_cookie_security", "jwt_advanced_security",
    # Phase 184: CORS Credential, Token Refresh, SQL Client, XPath Injection
    "cors_credential_security", "token_refresh_security",
    "sql_injection_client_security", "xpath_injection_security",
    # Phase 185: Auth Bypass, Rate Limit Bypass, LDAP Injection, Template Injection Client
    "auth_bypass_pattern_security", "rate_limit_bypass_security",
    "ldap_injection_security", "template_injection_client_security",
    # Phase 186: Prototype Pollution Advanced, Mass Assignment, IDOR, Command Injection Client
    "prototype_pollution_advanced", "mass_assignment_security",
    "insecure_direct_object_reference", "command_injection_client_security",
    # Phase 187: Dependency Hijacking, File Inclusion, Server-Side Template Passive, HTTP Request Smuggling
    "dependency_hijacking", "file_inclusion_security",
    "server_side_template_passive", "http_request_smuggling",
    # Phase 188: API Rate Limit Headers, CORS Policy Advanced, Content Sniffing Bypass, JS Prototype Chain
    "api_rate_limit_headers", "cors_policy_advanced",
    "content_sniffing_bypass", "javascript_prototype_chain",
    # Phase 189: XXE Advanced, BOLA, Insecure Data Exposure, GraphQL Introspection
    "xml_external_entity_advanced", "broken_object_level_auth",
    "insecure_data_exposure", "graphql_introspection_security",
    # Phase 190: LaTeX Injection, CSS Injection, Deserialization Gadget, Race Condition
    "latex_injection_passive", "css_injection_passive",
    "deserialization_gadget_passive", "race_condition_passive",
    # Phase 191: Link Injection, Parameter Pollution, Timing Attack, Cryptographic Weakness
    "link_injection_passive", "parameter_pollution_passive",
    "timing_attack_passive", "cryptographic_weakness_passive",
    # Phase 192: NoSQL Injection Advanced, LDAP Injection, OAuth Misconfiguration, SAML Security
    "nosql_injection_advanced", "ldap_injection_passive",
    "oauth_misconfiguration_passive", "saml_security_passive",
    # Phase 193: Actuator Endpoint Exposure, Tabnapping, Zip Slip, Integer Overflow
    "actuator_endpoint_exposure", "tabnapping_passive",
    "zip_slip_passive", "integer_overflow_passive",
    # Phase 194: Debug Endpoint, Sensitive Cache Control, Client-Side Validation, Session Entropy
    "debug_endpoint_exposure", "sensitive_cache_control",
    "client_side_validation_only", "session_entropy_passive",
    # Phase 195: Missing passive scanners wired up
    "xss", "dom", "sensitive_params", "subdomain_takeover",
    # Phase 196: Compliance frameworks
    "pci_dss_compliance", "hipaa_compliance", "soc2_compliance",
    "nist_csf_compliance", "iso27001_compliance",
    # Phase 197: SBOM + Supply chain
    "sbom", "polyfill_supply_chain",
    # Phase 198: Active scanners (opt-in via --active flag)
    "active_cors_fuzz", "active_http_verb", "active_port_probe",
    "active_subdomain_enum", "active_tls_cipher",
    # Phase 199: Database exposure + ATO + GraphQL auth + OAuth device flow
    "elasticsearch_exposure", "redis_exposure", "mongodb_exposure",
    "account_takeover_passive", "graphql_authorization", "oauth_device_flow",
]

_SCANNER_REGISTRY: List[tuple] = [
    ("ssl", SSLScanner, "Checking SSL..."),
    ("headers", HeaderScanner, "Checking security headers..."),
    ("cookies", CookieScanner, "Checking cookie flags..."),
    ("csp", CSPScanner, "Analyzing Content-Security-Policy..."),
    ("info", InfoDisclosureScanner, "Checking information disclosure..."),
    ("login", LoginSecurityScanner, "Checking login page security..."),
    ("email", EmailSecurityScanner, "Checking email security (SPF/DKIM/DMARC/CAA)..."),
    ("access", AccessControlScanner, "Checking admin page exposure and access control..."),
    ("graphql", GraphQLScanner, "Probing for GraphQL endpoints..."),
    ("methods", HTTPMethodsScanner, "Enumerating HTTP methods..."),
    ("ports", PortScanner, "Scanning for exposed ports..."),
    ("cors", CORSScanner, "Checking CORS configuration..."),
    ("security_txt", SecurityTxtScanner, "Checking for security.txt (RFC 9116)..."),
    ("error_pages", ErrorPageScanner, "Checking error page information disclosure..."),
    ("exposure", ExposureScanner, "Scanning for exposed specs, manifests, and CI/CD configs..."),
    ("rate_limit", RateLimitScanner, "Checking rate limiting on auth endpoints..."),
    ("jwt", JWTScanner, "Inspecting JWT security..."),
    ("waf", WAFScanner, "Detecting WAF/CDN..."),
    ("dns", DNSSecurityScanner, "Checking DNSSEC and subdomain surface..."),
    ("js_libs", JSLibraryScanner, "Scanning for outdated JavaScript libraries..."),
    ("tls_deep", TLSDeepScanner, "Deep TLS/certificate analysis..."),
    ("email_adv", EmailAdvancedScanner, "Advanced email security (MTA-STS, BIMI, DANE, SPF depth)..."),
    ("js_secrets", JSSecretsScanner, "Scanning JavaScript files for hardcoded secrets..."),
    ("supply_chain", SupplyChainScanner, "Checking supply chain (SRI, Permissions-Policy, COOP/COEP, trackers)..."),
    ("form_security", FormSecurityScanner, "Checking form and authentication security..."),
    ("crt_sh", CRTShScanner, "Querying Certificate Transparency logs (crt.sh)..."),
    ("typosquatting", TyposquattingScanner, "Checking for typosquatting / lookalike domains..."),
    ("sca", SCAScanner, "Running SCA against exposed manifests (OSV.dev)..."),
    ("cloud_storage", CloudStorageScanner, "Checking for public cloud storage buckets..."),
    ("cms", CMSDetectionScanner, "Detecting CMS/framework and checking for CVEs..."),
    ("infra", InfraScanner, "Checking infrastructure hardening (directory listing, artifacts, referrer)..."),
    ("dns_adv", DNSAdvancedScanner, "Checking advanced DNS security (CAA, DNSSEC, NS diversity)..."),
    ("admin_exposure", AdminExposureScanner, "Probing for exposed admin panels and debug interfaces..."),
    ("html_comments", HTMLCommentsScanner, "Scanning HTML comments for leaked credentials and internal data..."),
    ("cookie_adv", CookieAdvancedScanner, "Checking advanced cookie security (__Secure-/__Host- prefixes, SameSite=None)..."),
    ("redirects", RedirectChainScanner, "Tracing redirect chain for HTTP downgrade and mixed-protocol issues..."),
    ("robots", RobotsSecurityScanner, "Auditing robots.txt for sensitive path disclosure..."),
    ("csp_adv", CSPAdvancedScanner, "Deep CSP analysis (report-uri, frame-ancestors, base-uri, Trusted Types)..."),
    ("sri_adv", SRIAdvancedScanner, "Advanced SRI coverage and hash strength analysis..."),
    ("resp_headers", ResponseHeadersScanner, "Auditing response headers for version disclosure and deprecated headers..."),
    ("host_header", HostHeaderScanner, "Testing host header injection (X-Forwarded-Host reflection)..."),
    ("open_redirect", OpenRedirectScanner, "Detecting open redirect parameters in page links and forms..."),
    ("permissions_policy", PermissionsPolicyScanner, "Deep Permissions-Policy feature audit (camera, mic, geolocation, payment)..."),
    ("gdpr", GDPRPrivacyScanner, "GDPR/privacy compliance check (consent banner, privacy policy, tracking scripts)..."),
    ("threat_intel", ThreatIntelScanner, "Querying threat intelligence feeds (AbuseIPDB, AlienVault OTX, VirusTotal)..."),
    ("api_surface", APISurfaceScanner, "Scanning for exposed API documentation (OpenAPI/Swagger)..."),
    ("dir_listing", DirectoryListingScanner, "Probing common directories for public listings..."),
    ("ssrf_params", SSRFParamScanner, "Detecting SSRF-prone parameters in forms and URLs..."),
    ("oauth", OAuthScanner, "Checking OAuth/OIDC misconfiguration..."),
    ("cache_poisoning", CachePoisoningScanner, "Checking for web cache poisoning vectors..."),
    ("req_smuggling", RequestSmugglingScanner, "Checking for HTTP request smuggling indicators..."),
    ("websocket", WebSocketScanner, "Scanning for WebSocket endpoints and WSS enforcement..."),
    ("saml", SAMLScanner, "Checking SAML/SSO misconfiguration..."),
    ("proto_pollution", PrototypePollutionScanner, "Scanning JS bundles for prototype pollution patterns..."),
    ("xml_xxe", XXEScanner, "Checking for XML/XXE-prone endpoints..."),
    ("spring_actuator", SpringActuatorScanner, "Probing for exposed framework admin endpoints..."),
    ("deserialization", DeserializationScanner, "Checking for insecure deserialization indicators..."),
    ("ssti", SSTIScanner, "Scanning for Server-Side Template Injection indicators..."),
    ("file_upload", FileUploadScanner, "Auditing file upload endpoint security..."),
    ("path_traversal", PathTraversalScanner, "Scanning for path traversal / LFI parameter indicators..."),
    ("scim", SCIMScanner, "Scanning for exposed SCIM/IdM identity endpoints..."),
    ("grpc", GRPCScanner, "Detecting gRPC endpoints and reflection API exposure..."),
    ("cloud_metadata", CloudMetadataScanner, "Checking for cloud metadata SSRF exposure..."),
    ("nosql_injection", NoSQLInjectionScanner, "Scanning for NoSQL injection indicators..."),
    ("web_cache_deception", WebCacheDeceptionScanner, "Checking for web cache deception vulnerabilities..."),
    ("session_security", SessionSecurityScanner, "Auditing session management security..."),
    ("k8s_exposure", K8sExposureScanner, "Checking for exposed Kubernetes API endpoints..."),
    ("http2_security", HTTP2SecurityScanner, "Checking HTTP/2 security (CVE-2023-44487 rapid reset indicators)..."),
    ("graphql_advanced", GraphQLAdvancedScanner, "Running advanced GraphQL security checks..."),
    ("jwt_advanced", JWTAdvancedScanner, "Running advanced JWT security analysis..."),
    ("cors_advanced", CORSAdvancedScanner, "Running advanced CORS origin validation tests..."),
    ("business_logic", BusinessLogicScanner, "Running business logic vulnerability checks..."),
    ("graphql_depth", GraphQLDepthScanner, "Running GraphQL depth & complexity limit checks..."),
    ("ssrf_advanced", SSRFAdvancedScanner, "Running advanced SSRF parameter and endpoint detection..."),
    ("rate_limiting", RateLimitingScanner, "Running rate limiting and DoS protection checks..."),
    ("api_security_headers", APISecurityHeadersScanner, "Running API security header and response quality checks..."),
    ("oauth_advanced", OAuthAdvancedScanner, "Running advanced OAuth 2.0/OIDC security checks..."),
    ("crlf_injection", CRLFInjectionScanner, "Running CRLF injection / HTTP response splitting checks..."),
    ("http_parameter_pollution", HTTPParameterPollutionScanner, "Running HTTP Parameter Pollution (HPP) checks..."),
    ("weak_crypto", WeakCryptoScanner, "Running weak cryptographic primitive checks..."),
    ("clickjacking", ClickjackingScanner, "Running clickjacking defense checks..."),
    ("account_enumeration", AccountEnumerationScanner, "Running account enumeration checks..."),
    ("open_api_exposure", OpenAPIExposureScanner, "Running OpenAPI/Swagger documentation exposure checks..."),
    ("mass_assignment", MassAssignmentScanner, "Running mass assignment vulnerability checks..."),
    ("log_injection", LogInjectionScanner, "Running log injection / log forging checks..."),
    ("file_inclusion", FileInclusionScanner, "Running local/remote file inclusion checks..."),
    ("ldap_injection", LDAPinjectionScanner, "Running LDAP injection / filter bypass checks..."),
    ("command_injection", CommandInjectionScanner, "Running OS command injection checks..."),
    ("xxe_injection", XXEInjectionScanner, "Running XXE / XML external entity injection checks..."),
    ("ssrf_detection", SSRFDetectionScanner, "Running SSRF / server-side request forgery checks..."),
    ("http_verb_tampering", HTTPVerbTamperingScanner, "Running HTTP verb tampering / method override checks..."),
    ("service_worker_security", ServiceWorkerSecurityScanner, "Running service worker and PWA manifest security checks..."),
    ("idor_detection", IDORDetectionScanner, "Running IDOR / broken object-level authorization checks..."),
    ("sensitive_data_exposure", SensitiveDataExposureScanner, "Running sensitive data exposure checks..."),
    ("api_auth_security", APIAuthSecurityScanner, "Running API authentication security checks..."),
    ("content_injection", ContentInjectionScanner, "Running HTML/CSS content injection checks..."),
    ("cicd_exposure", CICDExposureScanner, "Checking for exposed CI/CD pipeline configuration files..."),
    ("webauthn_security", WebAuthnSecurityScanner, "Checking WebAuthn/FIDO2 security configuration..."),
    ("api_versioning", APIVersioningScanner, "Checking for deprecated API versions with weaker security..."),
    ("password_reset", PasswordResetScanner, "Checking password reset flow security..."),
    ("race_condition", RaceConditionScanner, "Checking for race condition / TOCTOU vulnerable endpoints..."),
    ("json_injection", JSONInjectionScanner, "Checking for JSON injection vulnerabilities..."),
    ("el_injection", ELInjectionScanner, "Checking for Expression Language (SpEL/OGNL/EL) injection..."),
    ("client_storage", ClientStorageScanner, "Checking for sensitive data in client-side storage (localStorage/sessionStorage)..."),
    ("csti", CSTIScanner, "Checking for Client-Side Template Injection (AngularJS, Vue, React, Handlebars)..."),
    ("fetch_metadata", FetchMetadataScanner, "Checking Fetch Metadata policy (COOP/COEP/CORP headers)..."),
    ("path_confusion", PathConfusionScanner, "Checking for URL normalization / path confusion access control bypass..."),
    ("csv_injection", CSVInjectionScanner, "Checking for CSV/formula injection in export endpoints..."),
    ("reflected_file_download", ReflectedFileDownloadScanner, "Checking for Reflected File Download (RFD) vulnerabilities..."),
    ("source_map", SourceMapScanner, "Checking for exposed JavaScript source maps and webpack stats.json..."),
    ("dev_artifact", DevArtifactScanner, "Probing for exposed developer artifacts (HAR, Terraform state, .npmrc, SSH keys, kubeconfig, AWS credentials)..."),
    ("link_security", LinkSecurityScanner, "Checking links for reverse tabnabbing, opener hijacking, and iframe sandbox security..."),
    ("api_collection", APICollectionScanner, "Probing for exposed Postman/Insomnia/Hoppscotch API collection files..."),
    ("framework_config", FrameworkConfigScanner, "Probing for exposed framework config and log files (Spring Boot, Rails, Django, ASP.NET, Laravel)..."),
    ("xssi", XSSIScanner, "Checking for Cross-Site Script Inclusion (XSSI) — JSON array responses without anti-XSSI prefixes..."),
    ("server_timing", ServerTimingScanner, "Checking Server-Timing header for internal service/IP/datacenter disclosure..."),
    ("crossdomain_policy", CrossDomainPolicyScanner, "Checking crossdomain.xml, clientaccesspolicy.xml, AASA, and assetlinks.json for misconfigurations..."),
    ("ai_api_exposure", AIAPIExposureScanner, "Scanning for exposed AI/LLM API endpoints (Ollama, LM Studio, HF TGI, vLLM, FlowiseAI)..."),
    ("graphql_field_suggestion", GraphQLFieldSuggestionScanner, "Checking GraphQL endpoints for schema leak via field suggestions and error messages..."),
    ("js_file_analysis", JSFileAnalysisScanner, "Analysing external JavaScript files for DOM sinks and security patterns..."),
    ("version_cve", VersionCVEScanner, "Correlating detected server versions against known CVEs..."),
    ("llm_prompt_injection", LLMPromptInjectionScanner, "Scanning for AI/LLM prompt injection attack surfaces..."),
    ("xsleak", XSLeakScanner, "Checking cross-site leak (XSLeak) mitigations..."),
    ("graphql_batching", GraphQLBatchingScanner, "Checking GraphQL batching and alias abuse attack surface..."),
    ("css_injection", CSSInjectionScanner, "Checking CSS injection attack surface..."),
    ("prssi", PRSSIScanner, "Checking for Path-Relative StyleSheet Import (PRSSI) vulnerabilities..."),
    ("referrer_policy", ReferrerPolicyScanner, "Checking Referrer-Policy header security..."),
    ("hsts_preload", HSTSPreloadScanner, "Checking HSTS preload eligibility and configuration..."),
    ("oauth_token_leak", OAuthTokenLeakScanner, "Checking for OAuth token and client secret leakage in URLs..."),
    ("dom_clobbering", DOMClobberingScanner, "Checking for DOM clobbering attack surface..."),
    ("trojan_source", TrojanSourceScanner, "Checking for Trojan Source / Unicode BIDI characters in scripts..."),
    ("dangling_markup", DanglingMarkupScanner, "Checking for dangling markup injection contexts..."),
    ("csp_reporting", CSPReportingScanner, "Checking CSP violation reporting configuration..."),
    ("live_cve", LiveCVEScanner, "Querying live CVE feed (NVD + OSV)..."),
    ("csp_nonce", CSPNonceAnalyzer, "Analyzing CSP nonce entropy and uniqueness..."),
    ("wasm_security", WASMSecurityScanner, "Scanning WebAssembly files for secrets and misconfigs..."),
    ("timing_oracle", TimingOracleScanner, "Checking for timing-based information leakage..."),
    ("open_graph_exposure", OpenGraphExposureScanner, "Scanning Open Graph / social metadata for information disclosure..."),
    ("cache_control_security", CacheControlSecurityScanner, "Auditing Cache-Control headers on sensitive endpoints..."),
    ("http3_quic", HTTP3QUICScanner, "Checking HTTP/3 and QUIC Alt-Svc advertisement..."),
    ("etag_fingerprinting", ETagFingerprintingScanner, "Analyzing ETag headers for fingerprinting and information disclosure..."),
    ("sse_security", SSESecurityScanner, "Scanning Server-Sent Events endpoints for security misconfigurations..."),
    ("security_txt_deep", SecurityTxtDeepScanner, "Deep RFC 9116 security.txt compliance analysis..."),
    ("supply_chain_lockfile", SupplyChainLockfileScanner, "Scanning for exposed dependency lockfiles..."),
    ("mutation_xss", MutationXSSScanner, "Scanning JavaScript for mutation XSS patterns..."),
    ("cookie_prefix_security", CookiePrefixSecurityScanner, "Auditing __Host- and __Secure- cookie prefix compliance..."),
    ("postmessage_security", PostMessageSecurityScanner, "Scanning JavaScript for unsafe postMessage patterns..."),
    ("web_manifest_security", WebManifestSecurityScanner, "Auditing Web App Manifest (PWA) security..."),
    ("http_observatory", HTTPObservatoryScanner, "HTTP security header cross-cutting analysis (Observatory)..."),
    ("api_schema_exposure", APISchemaExposureScanner, "Scanning for exposed OpenAPI/Swagger/AsyncAPI schemas..."),
    ("header_injection_sink", HeaderInjectionSinkScanner, "Probing for HTTP response header injection sinks..."),
    ("oauth_pkce", OAuthPKCEScanner, "Auditing OAuth 2.0 PKCE enforcement and authorization security..."),
    ("dns_caa", DNSCAAScanner, "Checking DNS CAA records for certificate authority authorization..."),
    ("dom_xss_sources", DOMXSSSourcesScanner, "Scanning for DOM XSS source-to-sink patterns in JavaScript..."),
    ("path_parameter_pollution", PathParameterPollutionScanner, "Testing for path parameter pollution and matrix parameter injection..."),
    ("js_framework_detection", JSFrameworkDetectionScanner, "Detecting JavaScript frameworks and vulnerable versions..."),
    ("link_preview_exposure", LinkPreviewExposureScanner, "Probing for link preview and URL fetch endpoints (SSRF risk)..."),
    ("graphql_subscription", GraphQLSubscriptionScanner, "Auditing GraphQL subscription security..."),
    ("shadow_dom_security", ShadowDOMSecurityScanner, "Scanning for unsafe Shadow DOM patterns in JavaScript..."),
    ("account_lockout", AccountLockoutScanner, "Checking brute force / account lockout protection on login endpoints..."),
    ("cors_misconfiguration_deep", CORSMisconfigurationDeepScanner, "Deep CORS misconfiguration analysis (null origin, bypass variants, Vary header)..."),
    ("csp_violation_report", CSPViolationReportScanner, "Checking CSP violation reporting configuration..."),
    ("http_security_baseline", HTTPSecurityBaselineScanner, "HTTP security baseline scorecard (8 fundamental controls)..."),
    ("client_hints_security", ClientHintsSecurityScanner, "Client Hints security — Accept-CH fingerprinting and delegation..."),
    ("api_error_disclosure", APIErrorDisclosureScanner, "API error disclosure — stack traces, SQL errors, internal paths in responses..."),
    ("jwks_exposure", JWKSExposureScanner, "JWKS endpoint security — key types, sizes, algorithm confusion risks..."),
    ("third_party_exposure", ThirdPartyExposureScanner, "Third-party resource exposure — tracking domains, missing SRI, sandbox-less iframes..."),
    ("session_fixation", SessionFixationScanner, "Session fixation indicators — pre-login cookie, URL session params, SameSite..."),
    ("introspection_disclosure", IntrospectionDisclosureScanner, "Introspection / debug mode disclosure — Werkzeug, PHPInfo, pprof, Prometheus metrics..."),
    ("clickjacking_deep", ClickjackingDeepScanner, "Deep clickjacking analysis — ALLOW-FROM bypass, frame-ancestors, JS frame-busting..."),
    ("tls_protocol_version", TLSProtocolVersionScanner, "TLS protocol version compliance — checking TLS 1.0/1.1 acceptance and weak ciphers..."),
    ("http_response_splitting", HTTPResponseSplittingScanner, "HTTP response splitting — CRLF injection with encoding bypass variants..."),
    ("dns_rebinding", DNSRebindingScanner, "DNS rebinding risk — private IP in DNS, low TTL, Host header validation..."),
    ("content_negotiation", ContentNegotiationScanner, "Content negotiation security — Accept reflection, JSON-as-HTML, JSONP..."),
    ("deep_link_security", DeepLinkSecurityScanner, "Deep link security — AASA wildcard paths, assetlinks.json, custom URL schemes..."),
    ("http_caching_security", HTTPCachingSecurityScanner, "HTTP caching security — no-store missing, public on auth, Pragma-only, long max-age..."),
    ("waf_bypass_detection", WAFBypassDetectionScanner, "WAF bypass detection — WAF presence, detect-only mode, origin IP disclosure..."),
    ("api_rate_limit_deep", APIRateLimitDeepScanner, "API rate limit deep — missing on auth endpoints, IP-only scope, X-Forwarded-For bypass..."),
    ("jwt_claim_analysis", JWTClaimAnalysisScanner, "JWT claim analysis — alg:none, weak HMAC, missing exp, sensitive payload data..."),
    ("cors_deep_analysis", CORSDeepAnalysisScanner, "CORS deep analysis — origin reflection, null origin, wildcard+credentials, Vary header..."),
    ("hsts_deep_analysis", HSTSDeepAnalysisScanner, "HSTS deep analysis — max-age length, includeSubDomains, preload readiness..."),
    ("referrer_policy_deep", ReferrerPolicyDeepScanner, "Referrer policy deep — unsafe-url, downgrade policy, meta tag mismatch..."),
    ("cross_origin_policy_deep", CrossOriginPolicyDeepScanner, "Cross-origin policy deep — COOP/COEP/CORP presence and misconfiguration..."),
    ("credential_exposure", CredentialExposureScanner, "Credential exposure — .env, .git/config, wp-config backups, phpinfo, .htpasswd..."),
    ("server_info_deep", ServerInfoDeepScanner, "Server info deep — version headers, internal hostnames, stack traces in errors..."),
    ("session_fixation_passive", SessionFixationPassiveScanner, "Session fixation passive — session ID in URL, weak IDs, long-lived session cookies..."),
    ("sourcemap_exposure", SourceMapExposureScanner, "Source map exposure — .map files accessible, inline source maps in JS bundles..."),
    ("mfa_detection", MFADetectionScanner, "MFA detection — login forms without 2FA/TOTP/WebAuthn indicators..."),
    ("api_key_in_js", APIKeyInJSScanner, "API key in JS — hardcoded AWS keys, Stripe secrets, PEM keys in JS bundles..."),
    ("email_header_injection", EmailHeaderInjectionScanner, "Email header injection — SMTP headers exposed, unvalidated email form fields..."),
    ("csp_nonce_reuse", CSPNonceReuseScanner, "CSP nonce reuse — static nonce across requests, short entropy, unsafe-inline coexistence..."),
    ("cors_max_age_deep", CORSMaxAgeDeepScanner, "CORS max-age deep — excessive preflight cache duration, dangerous method caching..."),
    ("tls_downgrade_passive", TLSDowngradePassiveScanner, "TLS downgrade passive — HTTP endpoint accessible, missing upgrade-insecure-requests..."),
    ("graphql_batch_abuse", GraphQLBatchAbuseScanner, "GraphQL batch abuse — array batching, alias batching enabling rate limit bypass..."),
    ("sql_error_passive", SQLErrorPassiveScanner, "SQL error passive — MySQL/PostgreSQL/MSSQL/Oracle error strings in responses..."),
    ("nginx_alias_traversal", NginxAliasTravesalScanner, "Nginx alias traversal — off-by-slash misconfiguration, autoindex exposure..."),
    ("apache_status_exposure", ApacheStatusExposureScanner, "Apache status exposure — mod_status, mod_info, .htaccess, .htpasswd..."),
    ("debug_mode_detection", DebugModeDetectionScanner, "Debug mode detection — Django, Laravel, Rails, Werkzeug, PHP error pages..."),
    ("security_misconfiguration", SecurityMisconfigurationScanner, "Security misconfiguration — backup files, HTML comment leakage, internal IP disclosure..."),
    ("http_desync_passive", HTTPDesyncPassiveScanner, "HTTP desync passive — TE+CL response headers, multi-hop proxy chains, mixed stacks..."),
    ("token_exposure_passive", TokenExposurePassiveScanner, "Token exposure passive — access tokens in URLs, JWTs in URLs, token response headers..."),
    ("cors_wildcard_api", CORSWildcardAPIScanner, "CORS wildcard API — wildcard/reflected origin on /api endpoints with credentials..."),
    ("javascript_prototype_pollution_deep", JavaScriptPrototypePollutionDeepScanner, "JS prototype pollution deep — __proto__ access, constructor.prototype, lodash merge gadgets..."),
    ("api_pagination_security", APIPaginationSecurityScanner, "API pagination security — missing limits, excessive data exposure, limit bypass..."),
    ("subresource_integrity_deep", SubresourceIntegrityDeepScanner, "SRI deep — external scripts/CSS without integrity, sha1 hashes, missing crossorigin..."),
    ("open_s3_bucket", OpenS3BucketScanner, "Open S3/GCS/Azure bucket — publicly listable cloud storage buckets from domain name..."),
    ("websocket_origin_check", WebSocketOriginCheckScanner, "WebSocket origin check — ws:// on HTTPS, wildcard CORS on upgrade, origin validation..."),
    ("spa_hash_routing_security", SPAHashRoutingSecurityScanner, "SPA hash routing — fragment XSS sinks, open redirect via hash, hash router detection..."),
    ("http_strict_transport_upgrade", HTTPStrictTransportUpgradeScanner, "HTTPS upgrade chain — HTTP no-redirect, HSTS on HTTP, mixed scheme links and forms..."),
    ("sensitive_endpoint_exposure", SensitiveEndpointExposureScanner, "Sensitive endpoint exposure — /metrics, /actuator, /debug/pprof, /swagger-ui, admin..."),
    ("xml_security_passive", XMLSecurityPassiveScanner, "XML security passive — DTD declarations, ENTITY SYSTEM, SOAP endpoint enumeration, WSDL exposure..."),
    ("email_config_exposure", EmailConfigExposureScanner, "Email config exposure — SMTP credentials in JS, SMTP host leak, MailHog/MailCatcher UI, x-mailer header..."),
    ("graphql_info_disclosure", GraphQLInfoDisclosureScanner, "GraphQL info disclosure — field suggestions, stack trace in errors, __typename without auth..."),
    ("path_normalization_security", PathNormalizationSecurityScanner, "Path normalization — URL-encoded dot bypass, double-slash admin bypass, semicolon injection..."),
    ("tls_certificate_deep", TLSCertificateDeepScanner, "TLS certificate deep — cipher weakness, expired cert, HSTS max-age too short, no SAN..."),
    ("server_timing_disclosure", ServerTimingDisclosureScanner, "Server-Timing disclosure — internal component names, DB/auth timing leaks, slow operation sidechannel..."),
    ("dependency_confusion", DependencyConfusionScanner, "Dependency confusion — internal scoped npm packages in client JS that could be hijacked on npmjs.com..."),
    ("iframe_security_deep", IframeSecurityDeepScanner, "Iframe security deep — missing X-Frame-Options/CSP frame-ancestors, external iframes without sandbox, bypass combo..."),
    ("http_method_override", HTTPMethodOverrideScanner, "HTTP method override — X-HTTP-Method-Override abuse, form _method tunneling, dangerous Allow header..."),
    ("content_type_confusion", ContentTypeConfusionScanner, "Content-Type confusion — MIME sniffing, JSON-as-HTML, SVG+script XSS, JS-as-text/plain, X-Content-Type-Options..."),
    ("cache_poisoning_passive", CachePoisoningPassiveScanner, "Cache poisoning passive — X-Forwarded-Host reflection, sensitive Vary headers, Age without Cache-Control..."),
    ("secret_in_error_page", SecretInErrorPageScanner, "Secret in error page — stack traces, DB connection strings, internal paths, API keys in 404/500 responses..."),
    ("open_redirect_deep", OpenRedirectDeepScanner, "Open redirect deep — URL param redirect, meta-refresh external, JS location external assignment..."),
    ("insecure_deserialization_passive", InsecureDeserializationPassiveScanner, "Insecure deserialization passive — Java rO0AB, PHP O:, .NET ViewState without MAC, serialized cookies..."),
    ("xxe_probe", XXEProbeScanner, "XXE passive — ENTITY SYSTEM in XML response, DOCTYPE exposure, entity value reflection in API..."),
    ("ssrf_passive", SSRFPassiveScanner, "SSRF passive — metadata IP in response, SSRF-prone URL params, URL-fetching endpoints (/proxy, /fetch, /render)..."),
    ("host_header_injection", HostHeaderInjectionScanner, "Host header injection — X-Forwarded-Host reflection, password reset link poisoning, Location header probe..."),
    ("clickjacking_advanced", ClickjackingAdvancedScanner, "Clickjacking advanced — missing X-Frame-Options/CSP frame-ancestors, ALLOW-FROM deprecated, JS framebuster, sensitive page frameable..."),
    ("business_logic_exposure", BusinessLogicExposureScanner, "Business logic exposure — client-side price calc, mass assignment fields (is_admin/role), admin API without auth..."),
    ("api_versioning_security", APIVersioningSecurityScanner, "API versioning security — deprecated API versions accessible, unversioned endpoints, version downgrade via header..."),
    ("csrf_token_strength", CSRFTokenStrengthScanner, "CSRF token strength — missing token on POST forms, token too short, low entropy, SameSite=None without Secure..."),
    ("cors_preflight_deep", CORSPreflightDeepScanner, "CORS preflight deep — reflected origin with credentials, wildcard+credentials, missing Vary: Origin, dangerous methods..."),
    ("rate_limiting_detection", RateLimitingDetectionScanner, "Rate limiting detection — missing X-RateLimit headers, auth endpoint accepts rapid requests without 429..."),
    ("jwt_algorithm_confusion", JWTAlgorithmConfusionScanner, "JWT algorithm confusion — alg=none, HS256 symmetric, kid path traversal, missing alg field..."),
    ("oauth_redirect_uri_validation", OAuthRedirectURIValidationScanner, "OAuth redirect_uri — missing state param (CSRF), open redirect via redirect_uri, reflected URI..."),
    ("saml_passive", SAMLPassiveScanner, "SAML passive — SAMLResponse in forms, comment injection risk, SHA-1 signature algorithm, endpoint enumeration..."),
    ("file_upload_security", FileUploadSecurityScanner, "File upload security — no accept restriction, dangerous types (.php/.asp/.svg), exposed /upload endpoint..."),
    ("subdomain_takeover_passive", SubdomainTakeoverPassiveScanner, "Subdomain takeover passive — GitHub Pages, Heroku, S3, Azure, Netlify, Zendesk unclaimed resource pages..."),
    ("dns_rebinding_passive", DNSRebindingPassiveScanner, "DNS rebinding passive — private IP in response, localhost references, arbitrary Host header accepted..."),
    ("log_injection_probe", LogInjectionProbeScanner, "Log injection passive — CRLF injection via URL (%0d%0a), injected header in response, User-Agent CRLF..."),
    ("parameter_pollution", ParameterPollutionScanner, "HTTP parameter pollution — both duplicate values reflected, last-wins override, array-style parameter injection..."),
    ("websocket_security_deep", WebSocketSecurityDeepScanner, "WebSocket security deep — plain ws:// scheme, auth token in URL, Socket.IO endpoint exposure..."),
    ("sourcemap_exposure", SourceMapExposureScanner, "Source map exposure — sourceMappingURL comment, .js.map file downloadable, webpack server paths revealed..."),
    ("feature_policy_security", FeaturePolicySecurityScanner, "Feature/Permissions Policy — missing header, camera/mic/geo wildcard allowlist, overly permissive features..."),
    ("form_action_security", FormActionSecurityScanner, "Form action security — HTTP actions, external domains, CSRF tokens, JS pseudo-URLs..."),
    ("open_graph_security", OpenGraphSecurityScanner, "Open Graph security — mixed content in OG tags, domain mismatch, JSON-LD external context..."),
    ("web_worker_security", WebWorkerSecurityScanner, "Web worker security — SharedWorker origin, cross-origin importScripts, blob workers..."),
    ("cookie_samesite_deep", CookieSameSiteDeepScanner, "Cookie SameSite deep — None without Secure, missing on session, Lax risks..."),
    ("http2_push_security", HTTP2PushSecurityScanner, "HTTP/2 push security — cross-origin push, h2c cleartext, trailer headers..."),
    ("mime_type_security", MIMETypeSecurityScanner, "MIME type security — XCTO nosniff, JSON-as-HTML, SVG, UTF-7 charset..."),
    ("certificate_transparency", CertificateTransparencyScanner, "Certificate transparency — wildcard certs, multi-CA issuance via crt.sh..."),
    ("link_header_injection", LinkHeaderInjectionScanner, "Link header injection — resource hint reflection, cross-origin preload..."),
    ("graphql_persisted_queries", GraphQLPersistedQueriesScanner, "GraphQL persisted queries — APQ support, GET execution, introspection bypass..."),
    ("serverless_exposure", ServerlessExposureScanner, "Serverless exposure — platform headers, config files, env variable leakage..."),
    ("social_login_security", SocialLoginSecurityScanner, "Social login security — OAuth state, implicit flow, redirect_uri..."),
    ("iframe_sandbox_security", IframeSandboxSecurityScanner, "Iframe sandbox — escape via allow-same-origin+scripts, top-navigation..."),
    ("broadcast_channel_security", BroadcastChannelSecurityScanner, "BroadcastChannel security — auth channels, sensitive payloads..."),
    ("api_gateway_security", APIGatewaySecurityScanner, "API gateway security — vendor headers, upstream disclosure, CORS Vary..."),
    ("webrtc_exposure", WebRTCExposureScanner, "WebRTC exposure — STUN/TURN server disclosure, hardcoded credentials..."),
    ("cdn_misconfiguration", CDNMisconfigurationScanner, "CDN misconfiguration — cache headers, SWR abuse, CORS wildcard injection..."),
    ("password_policy", PasswordPolicyScanner, "Password policy — minlength, maxlength truncation, autocomplete, rotation..."),
    ("feature_flag_exposure", FeatureFlagExposureScanner, "Feature flag exposure — LaunchDarkly, Split.io, Unleash SDK keys in JS..."),
    ("account_recovery", AccountRecoveryScanner, "Account recovery — security questions, token expiry, username enumeration..."),
    ("access_control", AccessControlScanner, "Access control — broken access control patterns, forced browsing..."),
    ("cms_detection", CMSDetectionScanner, "CMS detection — WordPress, Drupal, Joomla, Magento fingerprinting..."),
    ("cookie_advanced", CookieAdvancedScanner, "Cookie advanced — SameSite, Secure, HttpOnly, Prefix deep analysis..."),
    ("csp_advanced", CSPAdvancedScanner, "CSP advanced — unsafe-inline, base-uri, object-src, bypass gadgets..."),
    ("directory_listing", DirectoryListingScanner, "Directory listing — open indexes exposing file trees..."),
    ("dns_advanced", DNSAdvancedScanner, "DNS advanced — zone transfer, wildcard, SPF/DKIM/DMARC alignment..."),
    ("dns_security", DNSSecurityScanner, "DNS security — DNSSEC, open resolver, dangling CNAME checks..."),
    ("email_advanced", EmailAdvancedScanner, "Email advanced — SPF/DKIM/DMARC deep policy checks..."),
    ("email_security", EmailSecurityScanner, "Email security — MX records, STARTTLS, spoofing surface..."),
    ("gdpr_privacy", GDPRPrivacyScanner, "GDPR privacy — consent banners, privacy policy, data retention signals..."),
    ("http_methods", HTTPMethodsScanner, "HTTP methods — dangerous verbs, OPTIONS disclosure, TRACE..."),
    ("info_disclosure", InfoDisclosureScanner, "Info disclosure — server banners, debug headers, version strings..."),
    ("js_libraries", JSLibraryScanner, "JS libraries — outdated jQuery, Angular, React, lodash versions..."),
    ("jwt_security", JWTScanner, "JWT security — alg:none, weak secret, kid injection..."),
    ("login_security", LoginSecurityScanner, "Login security — autocomplete, HTTPS enforcement, credential exposure..."),
    ("mixed_content", MixedContentScanner, "Mixed content — HTTP resources loaded on HTTPS pages..."),
    ("prototype_pollution", PrototypePollutionScanner, "Prototype pollution — __proto__, constructor.prototype gadgets in params..."),
    ("redirect_chain", RedirectChainScanner, "Redirect chain — open redirect chains, HTTPS downgrade hops..."),
    ("request_smuggling", RequestSmugglingScanner, "Request smuggling — CL.TE / TE.CL desync indicators..."),
    ("response_headers", ResponseHeadersScanner, "Response headers — missing / misconfigured security headers audit..."),
    ("robots_txt", RobotsSecurityScanner, "Robots.txt — disallowed paths, sensitive endpoint disclosure..."),
    ("sri_advanced", SRIAdvancedScanner, "SRI advanced — missing integrity attributes, weak hash algorithms..."),
    # Phase 110
    ("docker_exposure", DockerExposureScanner, "Docker/container exposure — daemon API, registry auth, Portainer UI, container runtime fingerprints..."),
    ("graphql_batch_attack", GraphQLBatchAttackScanner, "GraphQL batch attacks — query batching bypass, alias flooding DoS, IDE exposure, GET CSRF, introspection..."),
    ("api_key_rotation", APIKeyRotationScanner, "API key rotation — long-lived JWTs, AWS/GCP/Azure keys in responses, Basic auth in JS, session cookie max-age..."),
    # Phase 111
    ("subdomain_enum_passive", SubdomainEnumPassiveScanner, "Subdomain enumeration passive — crt.sh CT logs, HackerTarget passive DNS, wildcard certs, high-value subdomains..."),
    ("redos_passive", ReDoSPassiveScanner, "ReDoS passive — nested quantifier patterns in JS bundles, dynamic RegExp from input, regex timeout error messages..."),
    ("http2_rapid_reset", HTTP2RapidResetScanner, "HTTP/2 Rapid Reset (CVE-2023-44487) — H2 support via alt-svc/Via, affected server versions, gRPC exposure..."),
    # Phase 112
    ("payment_page_security", PaymentPageSecurityScanner, "Payment page security — PCI DSS checks: HTTP checkout, missing CSP, inline scripts, CVV autocomplete, unknown payment iframes..."),
    ("health_endpoint_exposure", HealthEndpointExposureScanner, "Health endpoint exposure — /healthz, /metrics, /actuator/health, /debug/pprof publicly accessible without auth..."),
    # Phase 113
    ("log4shell_passive", Log4ShellPassiveScanner, "Log4Shell passive (CVE-2021-44228) — Log4j version in headers, JNDI pattern in body, exposed log4j config files..."),
    ("cors_expose_headers", CORSExposeHeadersScanner, "CORS expose-headers — sensitive headers (Authorization, X-API-Key) in ACEH, wildcard expose, missing Vary: Origin..."),
    ("cross_origin_isolation", CrossOriginIsolationScanner, "Cross-origin isolation — COOP/COEP/CORP headers for process isolation and Spectre mitigation..."),
    ("trusted_types_policy", TrustedTypesPolicyScanner, "Trusted Types enforcement — require-trusted-types-for 'script' in CSP; DOM XSS sink protection..."),
    ("nel_reporting", NELReportingScanner, "NEL/Reporting API security — internal collector URL exposure in NEL, Report-To, Reporting-Endpoints headers..."),
    ("speculation_rules_security", SpeculationRulesSecurityScanner, "Speculation Rules security — wildcard prefetch, sensitive URL prerender, eager prerender, No-Vary-Search cache confusion..."),
    ("origin_trial_exposure", OriginTrialExposureScanner, "Chrome Origin Trial exposure — dangerous experimental API tokens (DirectSockets, SharedStorage), third-party OT, feature fingerprinting..."),
    ("link_resource_hints_security", LinkResourceHintsSecurityScanner, "Link resource hints security — preload/prefetch/dns-prefetch to internal IPs/hostnames, sensitive path prefetch, CDN modulepreload without SRI..."),
    ("webhook_security", WebhookSecurityScanner, "Webhook security — endpoint accessible via GET, payload echo, ngrok/debug interface exposure, HTTP webhook URL..."),
    ("http_range_security", HTTPRangeSecurityScanner, "HTTP Range request security — Accept-Ranges on API/auth endpoints, Content-Range size disclosure, multipart byteranges on application paths..."),
    ("content_disposition_security", ContentDispositionSecurityScanner, "Content-Disposition security — inline SVG/HTML on upload paths, missing attachment, filename path traversal, RTL override, dangerous extensions..."),
    ("cookies_partitioned_security", CookiesPartitionedSecurityScanner, "CHIPS / Partitioned cookie security — SameSite=None without Partitioned, Partitioned without Secure, __Host- prefix conflict..."),
    ("privacy_sandbox_apis", PrivacySandboxAPIsScanner, "Privacy Sandbox APIs — Topics API observation, Attribution Reporting source/trigger, Shared Storage write, Private State Tokens, Protected Audience FLEDGE..."),
    ("document_policy_security", DocumentPolicySecurityScanner, "Document-Policy security — report-only only, js-profiling feature, missing Require-Document-Policy for iframe enforcement..."),
    ("cors_null_origin", CORSNullOriginScanner, "CORS null origin — Origin: null bypass; sandboxed iframe ACAO: null with credentials exfiltrates cross-origin data..."),
    ("compression_oracle", CompressionOracleScanner, "Compression oracle (BREACH/CRIME) — gzip/br on HTTPS pages containing CSRF tokens or session identifiers enables oracle attack..."),
    ("form_action_hijacking", FormActionHijackingScanner, "Form action hijacking — external domain actions, javascript:/data: URIs, HTTP action on HTTPS, sensitive field exfiltration..."),
    ("js_dangerous_patterns", JSDangerousPatternsScanner, "JS dangerous patterns — eval(location.*), innerHTML=location.*, new Function(), setTimeout string, postMessage no origin check, dynamic script no SRI..."),
    ("importmap_security", ImportMapSecurityScanner, "Import map security — external module URLs without SRI, HTTP sources, data:/javascript: specifiers, global scope override, multiple import maps..."),
    ("permissions_policy_deep", PermissionsPolicyDeepScanner, "Permissions-Policy deep audit — camera/microphone/geolocation/payment/USB/serial/bluetooth wildcard; idle-detection, Topics, display-capture, XR unrestricted..."),
    ("base_uri_injection", BaseURIInjectionScanner, "Base URI injection — CSP missing base-uri with script-src, base-uri wildcard, <base href> to external/HTTP origin, multiple base tags..."),
    ("js_supply_chain_integrity", JSSupplyChainIntegrityScanner, "JS supply chain integrity — external scripts without SRI, SRI without crossorigin, dynamic import() of external URLs, mixed SRI posture, module preload without integrity..."),
    ("svg_security", SVGSecurityScanner, "SVG security — embedded scripts, event handler attributes, <foreignObject>, external <use> hrefs, SMIL animation handlers, upload-path SVGs without attachment disposition..."),
    ("css_exfiltration", CSSExfiltrationScanner, "CSS data exfiltration — attribute selector + URL() in style blocks, @import of external URLs, no style-src CSP with CSRF tokens, external stylesheets without SRI..."),
    ("local_storage_sensitive", LocalStorageSensitiveScanner, "LocalStorage sensitive data — JWT/tokens/passwords/API keys in localStorage or sessionStorage, storage event listeners without origin validation..."),
    ("relative_path_overwrite", RelativePathOverwriteScanner, "Relative Path Overwrite (RPO) — relative CSS/JS on ambiguous paths, missing X-Content-Type-Options nosniff, server path/path/ ambiguity enabling CSS injection..."),
    ("url_parser_differential", URLParserDifferentialScanner, "URL parser differential — user@host auth confusion, backslash normalization, null bytes, double-slash redirect, JavaScript URI in redirect params..."),
    ("exposed_backup_files", ExposedBackupFilesScanner, "Exposed backup files — .bak/.orig/.old/~ editor backups, SQL dumps, .git/config, wp-config.php.bak, .env.bak, VCS repositories, source archives..."),
    ("client_side_redirect", ClientSideRedirectScanner, "Client-side open redirect — location.href from URL param/hash/referrer, postMessage redirect, eval+location, meta refresh to external, prefix-only validation bypass..."),
    ("protocol_confusion", ProtocolConfusionScanner, "Protocol confusion — HTTP 200 without HTTPS redirect, HTTP→HTTP redirect chain, HTTP→HTTPS without HSTS, CSP without upgrade-insecure-requests..."),
    ("iframe_allow_security", IframeAllowSecurityScanner, "Iframe allow security — allow='*', camera/microphone/payment/USB delegated to cross-origin iframes, broken sandbox (allow-scripts+allow-same-origin), no sandbox on cross-origin iframes..."),
    ("package_manifest_exposure", PackageManifestExposureScanner, "Package manifest exposure — package.json/.npmrc/composer.json/requirements.txt/Gemfile/go.mod accessible, .npmrc with auth tokens, embedded secrets..."),
    ("canvas_fingerprinting", CanvasFingerprintingScanner, "Canvas fingerprinting — canvas.toDataURL()+fillText, WebGL RENDERER/debug_renderer_info, AudioContext oscillator+getChannelData, battery/hardwareConcurrency/deviceMemory fingerprinting..."),
    ("hardcoded_credentials", HardcodedCredentialsScanner, "Hardcoded credentials — AWS access keys, Stripe/GitHub/Slack tokens, OAuth client secrets, JWT secrets, MongoDB/Postgres connection strings, private key PEM in page JS..."),
    ("private_network_access", PrivateNetworkAccessScanner, "Private network access (PNA) — private IP with ACAO: *, cross-origin access to localhost/RFC1918, API endpoints with wildcard CORS on authenticated resources..."),
    ("jsonp_endpoint", JSONPEndpointScanner, "JSONP endpoint detection — callback parameter reflected as function wrapper, pre-existing JSONP responses bypassing CORS, authenticated JSONP data exfiltration..."),
    ("http_security_consistency", HTTPSecurityConsistencyScanner, "Security header consistency — CSP/X-Frame-Options/HSTS/XCTO absent on API/login/error paths while present on main page, inconsistent security posture..."),
    ("api_authentication_exposure", APIAuthenticationExposureScanner, "API authentication exposure — /api/users /api/admin accessible without auth, Swagger/OpenAPI docs exposed, sensitive JSON fields returned unauthenticated..."),
    ("tabnabbing", TabnabbingScanner, "Tabnabbing — target=_blank links without rel=noopener/noreferrer, window.open() missing noopener, window.opener property accessed without nulling..."),
    ("exif_metadata_exposure", EXIFMetadataExposureScanner, "EXIF metadata exposure — images served with embedded GPS coordinates, camera model, software version, or author data in EXIF APP1 segment..."),
    ("graphql_csrf", GraphQLCSRFScanner, "GraphQL CSRF — mutations accepted via GET request, application/x-www-form-urlencoded accepted bypassing CORS preflight, no CSRF header enforcement..."),
    ("phi_exposure", PHIExposureScanner, "PHI exposure — Protected Health Information detected in API responses: SSN patterns, DOB, diagnosis/medication fields, MRN, insurance IDs, FHIR resources..."),
    ("http_method_tampering", HTTPMethodTamperingScanner, "HTTP method tampering — X-HTTP-Method-Override header tunnels DELETE via GET, _method param bypasses verb restrictions, CSRF-triggerable destructive operations..."),
    ("csrf_double_submit", CSRFDoubleSubmitScanner, "CSRF double-submit cookie — forms without CSRF token, double-submit cookie pattern bypass, static/hardcoded CSRF token values, login form CSRF risk..."),
    ("xpath_injection_passive", XPathInjectionPassiveScanner, "XPath injection passive — XPathException/LDAP error messages in responses to probe inputs, tainted XPath evaluate in JS, XQuery error disclosure..."),
    ("session_token_exposure", SessionTokenExposureScanner, "Session token exposure — tokens in URL query params (logged by proxies), tokens in HTML links (Referer leakage), Bearer/JWT in response body, token in API JSON..."),
    ("api_pagination_abuse", APIPaginationAbuseScanner, "API pagination abuse — large default page returning 50+ records, total count disclosure (1000+ items), limit=99999 bypass returning bulk data unauthenticated..."),
    ("content_security_framing", ContentSecurityFramingScanner, "Content security framing — frame-ancestors wildcard, XFO ALLOW-FROM without CSP fallback, XFO/CSP inconsistency, <object>/<embed>/<applet> tag usage..."),
    ("oauth_implicit_flow", OAuthImplicitFlowScanner, "OAuth implicit flow — response_type=token in discovery or page, access_token in redirect fragment, implicit grant advertised without PKCE alternative..."),
    ("web_worker_security_deep", WebWorkerSecurityDeepScanner, "Web Worker security deep — SharedArrayBuffer without COOP+COEP isolation, external importScripts(), postMessage wildcard, worker URL from user param, blob eval..."),
    ("javascript_template_literal", JavaScriptTemplateLiteralScanner, "JS template literal injection — eval/innerHTML/document.write with interpolated template literals, location redirect from tainted source, script.src from template..."),
    ("cors_origin_reflection", CORSOriginReflectionScanner, "CORS origin reflection — server mirrors probe Origin header in ACAO, reflected with ACAC: true enabling credentialed cross-origin reads, null origin accepted..."),
    ("jwt_token_exposure", JWTTokenExposureScanner, "JWT token exposure — alg:none JWT in page, HMAC JWT in response body, JWT in URL parameter, JWT stored in localStorage, API endpoints returning raw tokens..."),
    ("http_security_headers_deep", HTTPSecurityHeadersDeepScanner, "HTTP security headers deep — HSTS max-age too short (<6 months), missing includeSubDomains, XCTO missing/wrong value, referrer-policy too permissive..."),
    ("srcdoc_injection", SrcdocInjectionScanner, "srcdoc injection — iframe srcdoc with embedded script, javascript: iframe src, data:text/html iframe, srcdoc assigned from URL params, blob URL iframes..."),
    ("web_crypto_weaknesses", WebCryptoWeaknessesScanner, "WebCrypto weaknesses — Math.random() for crypto secrets, AES-ECB mode, static/hardcoded IV, weak key params, SHA-1/MD5 hash, timestamp as entropy source..."),
    ("autocomplete_security", AutocompleteSecurityScanner, "Autocomplete security — password fields without autocomplete=new-password/off, credit card inputs with autocomplete enabled, API key fields with browser autofill..."),
    ("api_documentation_exposure", APIDocumentationExposureScanner, "API documentation exposure — Swagger UI/OpenAPI spec/Redoc/Postman collection accessible without authentication, sensitive admin/internal endpoints enumerated..."),
    ("server_sent_events_security", ServerSentEventsSecurityScanner, "SSE security — CORS wildcard on event streams, SSE endpoint without cache-control no-store, sensitive PII/tokens in SSE data events, unauthenticated stream access..."),
    ("path_traversal_deep", PathTraversalDeepScanner, "Path traversal deep — file/path/dir parameter probing with encoded traversal sequences, /etc/passwd content in response, Windows hosts file read, PHP source disclosure, error path leakage..."),
    ("wasm_security_deep", WASMSecurityDeepScanner, "WASM security deep — WebAssembly URL from URL parameter, WASM fetched over HTTP (MITM risk), WASM compiled from base64 string, eval() with WASM, wrong WASM Content-Type..."),
    ("content_type_sniffing", ContentTypeSniffingScanner, "Content-type sniffing — missing X-Content-Type-Options: nosniff on risky MIME types, upload endpoints without nosniff, JSON responses with HTML tags lacking nosniff..."),
    ("service_worker_security_deep", ServiceWorkerSecurityDeepScanner, "Service worker deep — skipWaiting with fetch intercept, message handler without origin check, caching auth tokens, eval/HTTP importScripts in SW, overly wide scope..."),
    ("trusted_types_csp", TrustedTypesCspScanner, "Trusted Types CSP — missing require-trusted-types-for on pages with DOM XSS sinks, Trusted Types API used without CSP enforcement, trusted-types allowlist missing..."),
    ("http_early_hints_security", HTTPEarlyHintsSecurityScanner, "HTTP Early Hints security — Link preload headers exposing sensitive internal paths, external preload enabling third-party tracking, credentials embedded in preload URLs..."),
    ("reporting_api_security", ReportingAPISecurityScanner, "Reporting API security — Report-To header with external endpoints leaking CSP violations, NEL include_subdomains risk, high success_fraction, overly long max_age..."),
    ("idle_detection_api_security", IdleDetectionAPISecurityScanner, "Idle Detection API security — device presence data transmitted to server, short threshold, no privacy notice before requestPermission, state surveillance..."),
    ("network_information_security", NetworkInformationSecurityScanner, "Network Information API security — connection type fingerprinting sent to analytics, adaptive payload based on effectiveType enabling attack variation, third-party tracking..."),
    ("cache_api_security", CacheAPISecurityScanner, "Cache API security — auth headers cached in Cache Storage, sensitive API endpoints cached, security-sensitive cache names, no cache clear on logout..."),
    ("credential_management_security", CredentialManagementSecurityScanner, "Credential Management API security — hardcoded password in PasswordCredential, silent mediation without checks, credentials.store without preventSilentAccess..."),
    ("permissions_api_security", PermissionsAPISecurityScanner, "Permissions API security — bulk permission state enumeration for fingerprinting, permission state transmitted to server, sensitive permission without user context..."),
    ("lock_api_security", LockAPISecurityScanner, "Web Locks API security — locks without abort signal (DoS), steal:true breaking concurrent ops, lock name from URL input, lock state transmitted to server..."),
    ("payment_request_security", PaymentRequestSecurityScanner, "Payment Request API security — Payment Request over HTTP, basic-card deprecated method with raw card exposure, payment response logged to console, no HSTS on payment page..."),
    ("file_system_access_security", FileSystemAccessSecurityScanner, "File System Access API security — showDirectoryPicker broad scope, recursive delete, FileHandle persisted in localStorage (XSS accessible), file path transmitted to server..."),
    ("web_usb_security", WebUSBSecurityScanner, "WebUSB security — empty device filters, all paired device enumeration, hardware fingerprinting via serialNumber, device info transmitted to server, firmware write patterns..."),
    ("web_bluetooth_security", WebBluetoothSecurityScanner, "Web Bluetooth security — acceptAllDevices fingerprinting, paired device enumeration, health GATT data (PHI), device name transmitted, advertisement scanning, characteristic write..."),
    ("web_serial_security", WebSerialSecurityScanner, "Web Serial API security — port enumeration fingerprinting, serial data from URL params (injection to physical device), port info transmitted, no vendor/product filters..."),
    ("screen_capture_security", ScreenCaptureSecurityScanner, "Screen Capture API security — auto-start getDisplayMedia without user gesture, full monitor capture scope, screen stream transmitted to server, canvas screenshot exfiltration..."),
    ("geolocation_api_security", GeolocationAPISecurityScanner, "Geolocation API security — enableHighAccuracy GPS tracking, watchPosition without clearWatch, location shared with analytics (GDPR), continuous tracking without consent..."),
    ("performance_observer_security", PerformanceObserverSecurityScanner, "PerformanceObserver security — resource timing side-channels, timing data shared with analytics, fine-grained performance.now() timing oracle, navigation timing leakage..."),
    ("intersection_observer_security", IntersectionObserverSecurityScanner, "IntersectionObserver security — invisible pixel tracking pattern, element visibility data transmitted, scroll depth shared with analytics, sensitive form element observation..."),
    ("media_source_extension_security", MediaSourceExtensionSecurityScanner, "MSE security — video source URL from URL param (codec injection), addSourceBuffer MIME from URL param, ClearKey DRM (no protection), cleartext media fetch..."),
    # Phase 135
    ("webcodecs_security", WebCodecsSecurityScanner, "WebCodecs API security — encoded data transmitted, decode input from URL params, timing side-channel via decode measurement, SharedArrayBuffer Spectre risk, missing error handler..."),
    ("eyedropper_api_security", EyeDropperAPISecurityScanner, "EyeDropper API security — auto-trigger on page load, rapid loop sampling, color value transmitted to remote, screen color shared with analytics, no consent notice..."),
    ("resize_observer_security", ResizeObserverSecurityScanner, "ResizeObserver security — element dimensions transmitted (layout fingerprinting), bulk observe across collection, cross-origin iframe dimension probing, no disconnect() call..."),
    ("compression_streams_security", CompressionStreamsSecurityScanner, "Compression Streams security — BREACH-like secret mixed with user data before compression, size oracle side-channel, decompressing untrusted URL input (zip bomb), no size limit..."),
    # Phase 136
    ("web_nfc_security", WebNFCSecurityScanner, "Web NFC security — auto-scan without gesture, write from URL param (attacker payload), contactless data exfiltration, sensitive types in NFC records, missing permission denial handling..."),
    ("ambient_light_security", AmbientLightSecurityScanner, "Ambient Light Sensor security — high-freq screen content inference, illuminance data to analytics (cross-site tracking), high sample frequency config, missing permission error handling..."),
    ("device_motion_security", DeviceMotionSecurityScanner, "Device Motion security — keypress/motion correlation (keylogging), inertial navigation position reconstruction, accelerometer data to analytics, missing iOS requestPermission()..."),
    ("vibration_api_security", VibrationAPISecurityScanner, "Vibration API security — vibration from URL param (attacker pattern), rapid loop harassment, excessive duration DoS, long pattern array, covert haptic channel encoding session data..."),
    # Phase 137
    ("generic_sensor_security", GenericSensorSecurityScanner, "Generic Sensor API security — Gyroscope/Magnetometer data to analytics (fingerprinting), high sample frequency, magnetic heading for indoor positioning, missing permission handling..."),
    ("user_timing_security", UserTimingSecurityScanner, "User Timing API security — sensitive mark names leaking user flow, duration transmitted to analytics, cross-origin resource timing probe (XS-Leak), performance data to third party..."),
    ("background_sync_security", BackgroundSyncSecurityScanner, "Background Sync security — sensitive data in sync tags, deferred exfiltration on reconnect, periodic sync background collection, very short sync interval, tag enumeration..."),
    ("push_api_security", PushAPISecurityScanner, "Push API security — silent push (userVisibleOnly:false), missing VAPID key, subscription endpoint to analytics, push payload logged, push-to-server amplification, subscription in localStorage..."),
    # Phase 138
    ("window_management_security", WindowManagementSecurityScanner, "Window Management API security — multi-screen fingerprinting via getScreenDetails(), screen layout to analytics, auto window placement on non-visible screens, missing permission handling..."),
    ("document_pip_security", DocumentPIPSecurityScanner, "Document PiP security — auto-open without gesture, sensitive DOM (password/token) in floating window, PiP window accessing parent, data transmitted from PiP context..."),
    ("notification_api_security", NotificationAPISecurityScanner, "Notification API security — auto permission request on load, sensitive data in notification body (lock screen visible), notification from URL param, click handler open redirect..."),
    ("screen_wake_lock_security", ScreenWakeLockSecurityScanner, "Screen Wake Lock security — auto-acquire on load, loop re-acquisition, never released (battery drain), missing visibilitychange handler, wake lock state to analytics..."),
    # Phase 139
    ("web_otp_security", WebOTPSecurityScanner, "Web OTP API security — OTP code sent to third-party analytics, stored in localStorage, no AbortController, auto-read on load, single-use OTP forwarded externally..."),
    ("contact_picker_security", ContactPickerSecurityScanner, "Contact Picker API security — all properties requested (mass grab), multiple:true full phonebook, contact data to remote server, analytics receiving PII, data in localStorage..."),
    ("clipboard_api_security", ClipboardAPISecurityScanner, "Clipboard API security — auto read on load, paste event sniffing to server, clipboard content to analytics, clipboard poisoning via writeText(javascript:...), content transmitted..."),
    ("webxr_security", WebXRSecurityScanner, "WebXR security — auto XR session on load, immersive-AR camera capture, depth sensing room mapping, pose/position transmitted, spatial data to analytics, session never ended..."),
    # Phase 140
    ("web_audio_security", WebAudioSecurityScanner, "Web Audio API security — AudioContext hardware fingerprinting, mic stream to AnalyserNode, frequency data transmitted, raw AudioBuffer exfiltration, audio steganography pattern..."),
    ("midi_api_security", MIDIAPISecurityScanner, "Web MIDI API security — sysex:true firmware injection, SysEx from URL param, all inputs/outputs device enumeration, device name/manufacturer to analytics, MIDI data exfiltration..."),
    ("battery_status_security", BatteryStatusSecurityScanner, "Battery Status API security — battery level/charging fingerprinting, cross-site tracking via localStorage, charging state to analytics, chargingTime high-resolution timing..."),
    ("hid_api_security", HIDAPISecurityScanner, "WebHID API security — empty device filters (any HID), getDevices() enumeration fingerprinting, HID write from URL param (injection), device productId/vendorId transmitted, input report exfiltration..."),
    # Phase 141
    ("importmap_security", ImportMapSecurityScanner, "Import Map security — external URL specifiers (CDN confusion), overriding well-known packages to attacker URL, dynamic importmap injection via innerHTML, scopes to external origins..."),
    ("navigation_api_security", NavigationAPISecurityScanner, "Navigation API security — all navigations intercepted (suppressing back-button), destination URL to analytics, URL param redirect (open redirect), URL bar spoofing via transitionWhile..."),
    ("sanitizer_api_security", SanitizerAPISecurityScanner, "Sanitizer API security — allowElements includes 'script', allowAttributes includes on* event handlers, setHTML from URL param, setHTML without config, href/src without protocol filter..."),
    ("portals_security", PortalsSecurityScanner, "Portals API security — portal src from URL param (SSRF), sensitive internal pages embedded, activate() with auth/session data, auto-activate on load, message handler without origin check..."),
    # Phase 142
    ("trusted_types_security", TrustedTypesSecurityScanner, "Trusted Types bypass — default policy override (global TT bypass), createHTML/createScript passthrough policy (no sanitization), innerHTML from URL without TrustedHTML, eval alongside TT..."),
    ("font_loading_security", FontLoadingSecurityScanner, "Font Loading API security — FontFace src from URL param (SSRF), font load timing oracle (fingerprinting), font availability exfiltrated to analytics, data: URI font, @font-face SSRF probe..."),
    ("back_forward_cache_security", BackForwardCacheSecurityScanner, "BFCache security — auth token restored on pageshow persisted, stale auth state on login/logout page, form values restored from bfcache, sensitive vars not cleared on pagehide, back-button tracking..."),
    ("scheduler_api_security", SchedulerAPISecurityScanner, "Scheduler API security — postTask data exfiltration (localStorage/cookies to remote), sensitive credentials in task payload, timing oracle via performance.now, TaskController abort from URL param..."),
    # Phase 143
    ("message_channel_security", MessageChannelSecurityScanner, "MessageChannel security — port transferred with wildcard targetOrigin, sensitive data via port.postMessage, port to URL-param-controlled target, no origin check on port.onmessage..."),
    ("shared_worker_security", SharedWorkerSecurityScanner, "SharedWorker security — worker URL from URL param (arbitrary script), sensitive global state shared across tabs, broadcasts auth tokens to all connected ports, no origin validation on connect..."),
    ("storage_manager_security", StorageManagerSecurityScanner, "StorageManager security — storage quota/usage estimate exfiltrated (fingerprinting), storage probe for site-visit detection, auto-persist on load, quota side-channel, quota disclosed to console..."),
    ("periodic_background_sync_security", PeriodicBackgroundSyncSecurityScanner, "Periodic Background Sync security — sync tag from URL param, recurring data exfil from localStorage/cookies, very short minInterval (continuous access), location beacon, remote data injection..."),
    # Phase 144
    ("css_paint_api_security", CSSPaintAPISecurityScanner, "CSS Paint API (Houdini) security — paint worklet module from URL param, CSS custom property injected from URL param, inputProperties exfiltrated, paint timing oracle, DOM access attempt in worklet..."),
    ("css_custom_highlight_security", CSSCustomHighlightSecurityScanner, "CSS Custom Highlight API security — highlight range from URL param (content highlighting aid), selection tracking, highlighted text exfiltrated to analytics, dynamic server-controlled highlights..."),
    ("url_protocol_handler_security", URLProtocolHandlerSecurityScanner, "Protocol handler security — handler URL from URL param, attempting to override http/https, registering sensitive protocol (mailto/tel) handler, auto-registered on load, %s placeholder injection..."),
    ("launch_handler_security", LaunchHandlerSecurityScanner, "Launch Handler API security — targetURL open redirect (attacker crafts launch URL), targetURL to innerHTML/XSS sink, script load from launch URL, launch URL exfiltrated to analytics..."),
    # Phase 145
    ("element_timing_security", ElementTimingSecurityScanner, "Element Timing API security — render/load time exfiltrated (layout fingerprinting), auth oracle via element timing, content inference, PerformanceObserver 'element' entries transmitted to remote..."),
    ("document_visibility_security", DocumentVisibilitySecurityScanner, "Document Visibility API security — tab visibility state transmitted to analytics, focus duration tracked, payment flow detection via visibility, away-time exfiltration, sensitive data cleared on hide..."),
    ("screen_details_security", ScreenDetailsSecurityScanner, "Screen Details API security — multi-monitor data exfiltrated (display fingerprint), screen label/ID transmitted, monitor count disclosed, resolution/colorDepth exfiltrated, auto-permission request on load..."),
    ("longtask_observer_security", LongTaskObserverSecurityScanner, "Long Task Observer security — task duration/startTime exfiltrated (CPU timing side-channel), attribution disclosed cross-origin, crypto timing oracle (brute-force aid), CPU fingerprinting via task duration..."),
    # Phase 146
    ("view_transition_security", ViewTransitionSecurityScanner, "View Transition API security — sensitive content in transition snapshot, transition name from URL param (element capture), snapshot exfiltrated via toDataURL/fetch, cross-document transition leak..."),
    ("document_pip_api_security", DocumentPIPApiSecurityScanner, "Document PiP API security — PiP content URL from URL param, sensitive content in PiP window, PiP accesses parent DOM via opener, auth data via postMessage from PiP, auto-opens on load..."),
    ("cookie_store_security", CookieStoreSecurityScanner, "Cookie Store API security — cookieStore.set() value from URL param, getAll() result exfiltrated (full cookie jar), change event exfiltration (new cookies auto-sent), set without Secure flag, sensitive cookie logged..."),
    ("web_locks_security", WebLocksSecurityScanner, "Web Locks API security — lock name from URL param (lock hijacking), lock contention timing oracle, locks.query() exfiltrated (cross-tab state), lock never released (DoS), sensitive data exfil inside lock callback..."),
    # Phase 147
    ("shape_detection_security", ShapeDetectionSecurityScanner, "Shape Detection API security — FaceDetector biometric data exfiltrated, BarcodeDetector QR/barcode rawValue transmitted, TextDetector OCR exfiltrated, detection on live camera stream, continuous scan loop..."),
    ("media_session_security", MediaSessionSecurityScanner, "Media Session API security — metadata (title/artist) transmitted to analytics (consumption tracking), playback position tracked, MediaMetadata from URL param, artwork SSRF, action handler exfiltration..."),
    ("badging_api_security", BadgingAPISecurityScanner, "Web Badging API security — badge count from URL param, badge reflects sensitive counts (auth/payment), auto-set on load, badge count exfiltrated to analytics, badge controlled by server response..."),
    ("content_index_security", ContentIndexSecurityScanner, "Content Index API security — index entry from URL param, sensitive pages indexed (auth/payment), getAll() exfiltrated (full content inventory), indexed URLs transmitted, cross-origin content indexed..."),
    # Phase 148
    ("pwa_manifest_security", PWAManifestSecurityScanner, "PWA Manifest security — external start_url (launched to attacker page), overly broad scope '/'), shortcut with auth params, dangerous permissions requested, handle_links 'preferred' intercepts all links..."),
    ("before_install_prompt_security", BeforeInstallPromptSecurityScanner, "BeforeInstallPrompt security — install prompt on page load (auto-install), prompt from URL param (forced install dialog), repeated prompt loop, deceptive UI labels (download/security), userChoice exfiltrated..."),
    ("ink_api_security", InkAPISecurityScanner, "Ink API security — stroke/path data exfiltrated (handwriting surveillance), stylus pressure/tilt biometric exfiltrated, presenter target from URL param, continuous pointermove recording, ink data stored to localStorage..."),
    ("opfs_security", OPFSSecurityScanner, "OPFS security — file written from URL param (arbitrary content injection), credentials/tokens written to OPFS, file content exfiltrated, directory listing transmitted, FileSystemSyncAccessHandle in main thread..."),
    # Phase 149
    ("webtransport_security", WebTransportSecurityScanner, "WebTransport security — QUIC URL from URL param (SSRF), sensitive credential stream exfiltration, external endpoint connection, data relayed to WebSocket/fetch (proxy pattern)..."),
    ("webgpu_security", WebGPUSecurityScanner, "WebGPU security — adapter name/vendor/limits fingerprinting transmitted, GPU compute timing oracle, buffer data from URL param (injection), compute pipeline results exfiltrated (covert channel)..."),
    ("compute_pressure_security", ComputePressureSecurityScanner, "Compute Pressure API security — CPU state/factor exfiltrated, serious/critical pressure tied to auth/payment flow (activity inference), continuous monitoring via interval/rAF (CPU surveillance)..."),
    ("background_fetch_security", BackgroundFetchSecurityScanner, "Background Fetch API security — fetch URL from URL param (SSRF), sensitive credential upload, auth token POST/PUT via background channel, large file/blob exfiltration pattern..."),
    # Phase 150
    ("fedcm_security", FedCMSecurityScanner, "FedCM security — attacker-controlled configURL (IdP injection), IdentityCredential token exfiltrated, silent/optional auto sign-in without user gesture, nonce from URL param (replay risk)..."),
    ("shared_storage_security", SharedStorageSecurityScanner, "Shared Storage API security — PII/credentials written to shared storage, selectURL result exfiltrated (cross-site profiling), value from URL param (injection), cross-site data read and transmitted..."),
    ("fenced_frame_security", FencedFrameSecurityScanner, "Fenced Frame security — URL from URL param (attacker-controlled frame), reportEvent leaks PII, parent postMessage communication attempt (isolation bypass), cookie/localStorage access attempt in fenced context..."),
    ("text_fragment_security", TextFragmentSecurityScanner, "Text Fragment security — scroll oracle via IntersectionObserver/timing, :~:text= URL from URL param (highlight injection), highlighted text content exfiltrated, timing-based text presence detection..."),
    # Phase 151
    ("attribution_reporting_security", AttributionReportingSecurityScanner, "Attribution Reporting API security — PII in source registration (email/userId), cross-origin destination sends data to third party, filterData contains PII (user identification in ad attribution)..."),
    ("storage_bucket_security", StorageBucketSecurityScanner, "Storage Bucket API security — credentials stored in isolated bucket, bucket name from URL param (attacker-controlled access), bucket keys enumerated and exfiltrated, persisted bucket with sensitive data..."),
    ("payment_handler_security", PaymentHandlerSecurityScanner, "Payment Handler API security — excessive delegation (all PII fields), instrument key/details exfiltrated, card credential harvesting in payment event, payment total from URL param (price tampering)..."),
    ("interest_group_security", InterestGroupSecurityScanner, "Protected Audience/FLEDGE security — PII in interest group membership, group name from URL param (attacker ad targeting), biddingLogicURL from URL param (script injection), auction result exfiltrated..."),
    # Phase 152
    ("topics_api_security", TopicsAPISecurityScanner, "Topics API security — browsing topics transmitted to remote (user interest profile exfil), topics stored in localStorage/cookie (persistent profile), topics combined with PII (identity linkage)..."),
    ("private_aggregation_security", PrivateAggregationSecurityScanner, "Private Aggregation API security — PII in histogram bucket key (user identification), enableDebugMode in production (bypass noise), bucket key from URL param (attacker-controlled histogram)..."),
    ("custom_elements_security", CustomElementsSecurityScanner, "Custom Elements security — prototype modified from URL param (prototype pollution), customElements.define() name from URL param (attacker registration), Shadow DOM transmits credentials (data exfil)..."),
    ("dynamic_import_security", DynamicImportSecurityScanner, "Dynamic import() security — specifier from URL param (script injection), external URL import (unverified third-party code), concatenated URL import (injection), import.meta data exfiltrated..."),
    # Phase 153
    ("mutation_observer_security", MutationObserverSecurityScanner, "MutationObserver security — input/textarea value transmitted (DOM keylogger), password/token field watched and exfiltrated (credential surveillance), full document observation with subtree:true, addedNodes data exfiltrated..."),
    ("eventsource_security", EventSourceSecurityScanner, "EventSource (SSE) security — SSE URL from URL param (SSRF), external SSE URL connection, message data with auth/token exfiltrated (credential relay), auth token received via SSE stream..."),
    ("login_status_api_security", LoginStatusAPISecurityScanner, "Login Status API security — login state transmitted to remote (surveillance), setStatus('logged-in') on page load (false state injection), login status from URL param (attacker-controlled state)..."),
    ("reporting_observer_security", ReportingObserverSecurityScanner, "ReportingObserver security — browser reports transmitted externally (surveillance), feature-policy-violation reports transmitted (policy probing), deprecation reports transmitted (browser fingerprinting)..."),
    # Phase 154
    ("beacon_api_security", BeaconAPISecurityScanner, "Beacon API security — sendBeacon transmits credentials/tokens (covert exfil), beacon to external URL, beacon URL from URL param (SSRF), PII transmitted via beacon without consent..."),
    ("pointer_lock_security", PointerLockSecurityScanner, "Pointer Lock API security — movementX/Y transmitted to remote (mouse surveillance), auto-requested on page load, continuous mousemove tracking via pointer lock (behavioral biometric)..."),
    ("history_api_security", HistoryAPISecurityScanner, "History API security — pushState URL from URL param (URL spoofing), external URL pushed to history (address bar phishing), sensitive state object (token/auth in history stack)..."),
    ("credentialless_iframe_security", CredentiallessIframeSecurityScanner, "Credentialless iframe security — storage access from anonymous frame (isolation bypass), postMessage exfiltrates auth/token from credentialless frame, fetch with credentials:include in credentialless context..."),
    # Phase 155
    ("drag_drop_security", DragDropSecurityScanner, "Drag and Drop security — dataTransfer.getData() transmitted externally (data exfil), sensitive credentials set as drag data, dropped files uploaded to remote (file exfil)..."),
    ("form_data_security", FormDataSecurityScanner, "FormData API security — sensitive credentials appended as form fields, field value from URL param (attacker-controlled submission), file/blob uploaded via FormData to external endpoint..."),
    ("readable_stream_security", ReadableStreamSecurityScanner, "Readable Stream API security — stream with credentials piped to external destination, stream piped to external URL/fetch, stream data from URL param, response tee'd and second copy exfiltrated..."),
    ("structured_clone_security", StructuredCloneSecurityScanner, "Structured Clone security — structuredClone() copies credentials/tokens for exfil, cloned data posted to worker, DOM/localStorage cloned, postMessage sends credentials to wildcard origin..."),
    # Phase 156
    ("webgl_security", WebGLSecurityScanner, "WebGL security — shader source from URL param (GLSL injection), readPixels/toDataURL GPU data exfiltrated, WebGL extension list transmitted (browser fingerprinting), cross-origin texture loading..."),
    ("speech_recognition_security", SpeechRecognitionSecurityScanner, "Speech Recognition API security — auto-started on page load (microphone without gesture), transcript transmitted to remote (audio surveillance), continuous recognition mode (extended mic capture)..."),
    ("speech_synthesis_security", SpeechSynthesisSecurityScanner, "Speech Synthesis API security — voice list transmitted (TTS fingerprinting), utterance text from URL param (audio phishing), social engineering text spoken (password/verify/authorize), TTS audio data exfil..."),
    ("media_recorder_security", MediaRecorderSecurityScanner, "MediaRecorder API security — auto-started on page load (silent recording), recorded Blob transmitted to remote (media exfil), continuous chunked upload pattern via timeslice+fetch..."),
    # Phase 157
    ("gamepad_security", GamepadSecurityScanner, "Gamepad API security — getGamepads() input state transmitted to remote (controller surveillance), continuous button/axes polling via rAF (persistent input monitoring), GamepadEvent id/mapping fingerprinting, input correlated with password fields..."),
    ("proximity_sensor_security", ProximitySensorSecurityScanner, "Proximity Sensor API security — ProximitySensor near/distance readings exfiltrated, proximity correlated with auth/payment events (activity inference), continuous proximity polling and data upload..."),
    ("picture_in_picture_security", PictureInPictureSecurityScanner, "Picture-in-Picture API security — requestPictureInPicture() auto-triggered on page load (unsolicited PiP), PiP enter/leave events transmitted (media behaviour surveillance), PiP window dimensions for fingerprinting, URL param controls PiP target..."),
    ("keyboard_lock_security", KeyboardLockSecurityScanner, "Keyboard Lock API security — keyboard.lock([]) captures all system keys, KeyboardLayoutMap transmitted for fingerprinting, system keys (Escape/Meta/F-keys) locked preventing user exit, keyboard.lock() auto-triggered on fullscreen load..."),
    # Phase 158
    ("resource_timing_security", ResourceTimingSecurityScanner, "Resource Timing API security — PerformanceResourceTiming duration/size exfiltrated (network side-channel), timing correlated with auth endpoints (timing oracle), full resource list enumerated and transmitted, continuous timing collection..."),
    ("permission_policy_security", PermissionPolicySecurityScanner, "Permissions Policy security — wildcard (*) grants to camera/microphone/geolocation/payment, iframe over-permissive allow= attribute, allowedFeatures results transmitted (policy disclosure), serial/USB/Bluetooth wildcard policy bypass..."),
    ("long_animation_frame_security", LongAnimationFrameSecurityScanner, "Long Animation Frame (LoAF) security — LoAF timing data exfiltrated (performance side-channel), timing correlated with keydown/input (keystroke inference), script attribution URLs transmitted (internal disclosure), continuous buffered collection..."),
    ("scroll_timeline_security", ScrollTimelineSecurityScanner, "Scroll Timeline API security — ScrollTimeline currentTime/progress exfiltrated (scroll position surveillance), scroll state correlated with auth/login, ViewTimeline offset data exfiltrated, scroll timeline configured from URL parameter..."),
    # Phase 159
    ("anchor_positioning_security", AnchorPositioningSecurityScanner, "CSS Anchor Positioning security — anchor-name/position-anchor from URL param (layout injection), anchor() positions overlay near password fields (phishing), anchor CSS injected via setAttribute, anchor-name sourced from localStorage/cookies..."),
    ("css_cascade_layers_security", CSSCascadeLayersSecurityScanner, "CSS Cascade Layers security — @layer name/content from URL param (cascade injection), @layer injected via insertRule/innerHTML, !important in layer near auth elements (priority bypass), layer order manipulated from URL parameter..."),
    ("css_houdini_security", CSSHoudiniSecurityScanner, "CSS Houdini security — paintWorklet URL from URL param (worklet code injection), external domain worklet loaded (3rd-party CSS execution), CSS.registerProperty from URL param (property injection), registerPaint worklet contains fetch (exfil from CSS context)..."),
    ("css_custom_properties_security", CSSCustomPropertiesSecurityScanner, "CSS Custom Properties security — CSS variable value set from URL param (variable injection), var() inside external url() (CSS-based exfil request), sensitive CSS var read and transmitted (variable data exfil), CSS var injected via style attribute from URL..."),
    # Phase 160
    ("coop_security", COOPSecurityScanner, "Cross-Origin Opener Policy (COOP) security — window.opener data exfiltrated, opener DOM/storage access without COOP isolation, cross-origin popup controlled via opener reference, COOP set to weak same-origin-allow-popups..."),
    ("coep_security", COEPSecurityScanner, "Cross-Origin Embedder Policy (COEP) security — SharedArrayBuffer transferred without COEP isolation, Atomics.wait/notify with network calls (timing oracle), crossOriginIsolated=false with SAB usage, credentialless embedding accesses localStorage/cookies..."),
    ("corp_security", CORPSecurityScanner, "Cross-Origin Resource Policy (CORP) security — CORP header set to cross-origin (Spectre risk), no-cors mode on auth/session endpoints (opaque read bypass), SharedArrayBuffer/Atomics in cross-origin context (Spectre timing gadget)..."),
    ("trust_token_security", TrustTokenSecurityScanner, "Private State Token (Trust Token) security — token redemption result transmitted to remote (tracking), token issuer from URL param (issuer manipulation), hasPrivateToken() result sent to analytics (presence tracking), forced redemption on page load..."),
    # Phase 161
    ("css_container_query_security", CSSContainerQuerySecurityScanner, "CSS Container Queries security — container-name/@container from URL param (injection), @container injected via insertRule, @container applies url() to external domain (CSS exfil), container size breakpoint triggers analytics (fingerprinting)..."),
    ("import_assertions_security", ImportAssertionsSecurityScanner, "Import Assertions / Module Attributes security — dynamic import() URL from param with type assertion (module injection), importmap injected via innerHTML (specifier hijacking), JSON module from sensitive path, importmap maps to external URL (3rd-party substitution)..."),
    ("fetch_priority_security", FetchPrioritySecurityScanner, "Fetch Priority API security — fetchpriority/importance from URL param (priority injection), priority+performance.now creates timing oracle, priority correlated with auth/session (covert channel), fetchpriority injected via setAttribute..."),
    ("prerendering_security", PrerenderingSecurityScanner, "Prerendering security — network/storage access during document.prerendering=true (premature data exposure), prerender URL from URL param (attacker-controlled prerender target), prerenderingchange event transmits data, ActivationStart timing fingerprinting..."),
    # Phase 162
    ("storage_access_api_security", StorageAccessAPISecurityScanner, "Storage Access API security — requestStorageAccess() result used for cross-site cookie/storage exfil, auto-requested on load without user gesture, hasStorageAccess() presence transmitted (tracking signal), requestStorageAccessFor from URL param..."),
    ("document_domain_security", DocumentDomainSecurityScanner, "document.domain security — domain set from URL param (attacker-controlled relaxation), document.domain relaxation weakens same-origin isolation, domain changed then data exfiltrated, Origin-Agent-Cluster disabled allowing domain mutation..."),
    ("identity_credential_security", IdentityCredentialSecurityScanner, "Digital Identity Credential API security — IdentityCredential token/claims exfiltrated, digital credential provider from URL param (attacker-controlled IdP), silent credential presentation without user awareness, PII fields (name/email/DOB) transmitted to remote..."),
    ("css_scope_security", CSSScopeSecurityScanner, "CSS @scope security — @scope selector from URL param (scope injection), @scope injected via insertRule/innerHTML, adoptedStyleSheets state transmitted (surveillance), CSSStyleSheet.replace() content from URL param (constructable sheet injection)..."),
    # Phase 163
    ("css_nesting_security", CSSNestingSecurityScanner, "CSS Nesting security — @nest/& selector from URL param (nested injection), @nest injected via insertRule, nested rule uses url() on external domain (exfil), CSSNestingRule selector from URL param..."),
    ("css_font_palette_security", CSSFontPaletteSecurityScanner, "CSS Font Palette security — FontFace from URL param (font injection), FontFace loaded from external domain (3rd-party tracking), document.fonts enumerated for fingerprinting, @font-palette-values injected via insertRule..."),
    ("object_url_security", ObjectURLSecurityScanner, "Object URL / Blob URL security — createObjectURL() encodes credentials in blob (sensitive blob creation), blob content from URL param (blob injection), createObjectURL used to inject Worker code (dynamic code execution), sensitive data in blob without revocation..."),
    ("worker_module_security", WorkerModuleSecurityScanner, "Worker Module security — Worker/SharedWorker URL from URL param (worker code injection), worker loaded from external domain (3rd-party worker), importScripts() URL from URL param (script injection into worker), worker.postMessage sends credentials (sensitive data to worker)..."),
    # Phase 164
    ("abort_controller_security", AbortControllerSecurityScanner, "AbortController/AbortSignal security — AbortController state from URL param (attacker-controlled request cancellation), AbortSignal.timeout timing oracle, abort signal on auth/session requests, controller.abort() race condition pattern..."),
    ("observable_api_security", ObservableAPISecurityScanner, "Observable API security — Observable streams credentials to remote (data exfil), Observable source from URL param (attacker-controlled stream), ObservableEventTarget events transmitted (DOM surveillance), unbounded keydown/mouse/scroll Observable with network calls (covert input stream)..."),
    ("css_masonry_security", CSSMasonrySecurityScanner, "CSS Masonry Layout security — masonry property from URL param (layout injection), masonry rule injected via insertRule/innerHTML, masonryAutoFlow state transmitted to analytics (layout surveillance)..."),
    ("css_math_security", CSSMathSecurityScanner, "CSS Math Functions security — calc/clamp/min/max from URL param (math injection), env(safe-area) transmitted for device fingerprinting, calc() injected via insertRule/innerHTML, var() in calc() where var is URL-param-controlled..."),
    # Phase 165
    ("video_decoder_security", VideoDecoderSecurityScanner, "VideoDecoder/VideoEncoder API security — decode timing oracle (codec latency transmitted for hardware profiling), VideoFrame pixel data exfiltrated to remote, codec configured from URL param (attacker-controlled decode), cross-origin EncodedVideoChunk loaded without CORP..."),
    ("audio_worklet_security", AudioWorkletSecurityScanner, "AudioWorklet security — AudioContext characteristics transmitted for fingerprinting, AudioWorkletNode connected to mic with network exfil, audioWorklet.addModule() URL from URL param (attacker-controlled worklet), AudioContext timing covert channel (currentTime/outputLatency transmitted)..."),
    ("media_capabilities_security", MediaCapabilitiesSecurityScanner, "MediaCapabilities API security — decodingInfo/encodingInfo results transmitted for device fingerprinting, batch codec probes (systematic hardware enumeration), media query from URL param (attacker-controlled probe), smooth/powerEfficient flags transmitted as covert channel..."),
    ("web_hid_security", WebHIDSecurityScanner, "WebHID API security — hid.getDevices() auto-connect on page load (silent device re-connection), HID input report data exfiltrated to remote, requestDevice() filter from URL param (attacker-controlled HID targeting), HID input report used for keystroke inference..."),
    ("virtual_keyboard_security", VirtualKeyboardSecurityScanner, "VirtualKeyboard API security — keyboard bounding rect geometry transmitted for fingerprinting, overlaysContent=true near auth form (overlay phishing), API controlled from URL param (attacker-controlled keyboard), keyboard inset dimensions used for device type profiling..."),
    ("rtc_encoded_transform_security", RTCEncodedTransformSecurityScanner, "RTCInsertableStreams/Encoded Transform security — RTCEncodedVideoFrame/AudioFrame exfiltrated to remote (WebRTC media interception), SFrameTransform key from URL param, Math.random/xor used instead of SubtleCrypto (weak DIY encryption), passthrough tap (readable.pipeTo(writable) without transform)..."),
    ("page_lifecycle_security", PageLifecycleSecurityScanner, "Page Lifecycle API security — data exfiltrated on freeze event (sendBeacon in freeze handler), visibilitychange events transmitted to analytics (tab attention surveillance), wasDiscarded flag transmitted (session fingerprinting), keydown captured while document.hidden (background keyboard surveillance)..."),
    # Phase 166
    ("document_picture_in_picture_security", DocumentPictureInPictureSecurityScanner, "Document PiP security — requestWindow() triggered automatically on page load (unprompted floating window), PiP window used with auth/login/payment content (phishing overlay), PiP configuration from URL param (attacker-controlled floating window), data exfiltrated on enterpictureinpicture event..."),
    ("image_decoder_security", ImageDecoderSecurityScanner, "ImageDecoder (WebCodecs) security — decoded frame pixel data exfiltrated to remote, ImageDecoder data source from URL param (attacker-controlled image data), decode timing measured and transmitted (hardware timing oracle), cross-origin image data decoded without CORP..."),
    ("audio_decoder_security", AudioDecoderSecurityScanner, "AudioDecoder/AudioEncoder (WebCodecs) security — AudioData frame content exfiltrated to remote, decoder configured from URL param (attacker-controlled codec), decode timing oracle (latency transmitted), AudioEncoder connected to mic with network exfil (mic audio encoded and sent)..."),
    ("highlight_api_security", HighlightAPISecurityScanner, "CSS Custom Highlight API security — highlight range from URL param (attacker-controlled text selection), highlight state transmitted to remote (covert exfil channel), highlight applied to password/token/SSN content (sensitive text targeting), highlight registry combined with innerHTML (DOM injection)..."),
    # Phase 167
    ("element_internals_security", ElementInternalsSecurityScanner, "ElementInternals API security — setFormValue() from URL param (attacker-controlled submission), sensitive form data exfil via custom element, setValidity({}) empty bypass (all validation skipped), internals.form.action dynamically redirected (form hijacking)..."),
    ("declarative_shadow_dom_security", DeclarativeShadowDOMSecurityScanner, "Declarative Shadow DOM security — setHTMLUnsafe/shadowrootmode from URL param (shadow root injection), script/eval/innerHTML inside open shadow root (code execution in shadow), shadow DOM credential exfiltration, setHTMLUnsafe() with innerHTML/userInput (unsafe HTML parsing without sanitization)..."),
    ("animation_worklet_security", AnimationWorkletSecurityScanner, "Animation Worklet (Houdini) security — animationWorklet.addModule() URL from URL param (attacker-controlled worklet code), external module loaded from 3rd-party URL, WorkletAnimation timing values transmitted (timeline covert channel), registerAnimator timing data exfiltrated..."),
    ("fullscreen_security", FullscreenSecurityScanner, "Fullscreen API security — requestFullscreen() auto-triggered on page load (no user gesture), fullscreen combined with auth/login/payment form (phishing overlay), keyboard.lock with fullscreen (navigation trap), data exfiltrated on fullscreenchange event..."),
    # Phase 168
    ("handwriting_recognition_security", HandwritingRecognitionSecurityScanner, "Handwriting Recognition API security — stroke/drawing data exfiltrated to remote (handwriting surveillance), recognizer language/hints transmitted for fingerprinting, createHandwritingRecognizer() from URL param (attacker-controlled recognizer), continuous stroke capture with network exfil..."),
    ("presentation_api_security", PresentationAPISecurityScanner, "Presentation API security — PresentationRequest URL from URL param (attacker-controlled cast target), PresentationConnection.send() exfiltrates session/cookie/token, auth/credential content cast to external screen, presentationRequest.start() auto-triggered on page load..."),
    ("css_typed_om_security", CSSTypedOMSecurityScanner, "CSS Typed Object Model security — CSS.px/em/percent value from URL param (typed CSS injection), computedStyleMap() result transmitted to remote (computed style surveillance), typed CSS values used for DPI/platform fingerprinting, attributeStyleMap.set() with innerHTML/userInput..."),
    ("popover_api_security", PopoverAPISecurityScanner, "Popover API security — searchParams flows into showPopover() (content from URL param), popover opened with auth/login/payment form (phishing overlay), innerHTML/insertAdjacentHTML before showPopover() (unsanitized DOM injection), showPopover() auto-triggered on page load..."),
    # Phase 169
    ("remote_playback_security", RemotePlaybackSecurityScanner, "Remote Playback API security — remote.state transmitted to analytics (cast state surveillance), watchAvailability() result exfiltrated (home network topology inference), remote.prompt() controlled by URL param (attacker-controlled cast), remote.prompt() auto-triggered without user gesture..."),
    ("layout_worklet_security", LayoutWorkletSecurityScanner, "CSS Layout Worklet (Houdini) security — layoutWorklet.addModule() URL from URL param (attacker-controlled worklet code), external module loaded from 3rd party, layout timing values transmitted (covert timing channel), display:layout() worklet name from URL param..."),
    ("dialog_element_security", DialogElementSecurityScanner, "Dialog element security — searchParams/location flows into showModal() (attacker-controlled dialog), showModal() with auth/login/payment form (phishing modal), innerHTML before showModal() (unsanitized dialog injection), dialog.returnValue transmitted to remote (form result exfiltrated)..."),
    ("font_access_security", FontAccessSecurityScanner, "Font Access API security — local font list transmitted for fingerprinting (persistent device identifier), queryLocalFonts() with no filter (complete font inventory), FontData list exfiltrated to remote, queryLocalFonts() filter from URL param (targeted font detection)..."),
    # Phase 170
    ("content_visibility_security", ContentVisibilitySecurityScanner, "Content Visibility API security — contentvisibilityautostatechange + performance.now timing oracle (rendering state reveals cross-origin timing), content-visibility from URL param (attacker-controlled rendering skip), contentVisibility skip/hidden state transmitted, contain-intrinsic-size fingerprinting..."),
    ("inert_security", InertSecurityScanner, "Inert attribute security — inert set on auth/form/button elements (UI interaction disabled), inert combined with iframe/overlay (clickjacking variant), inert attribute controlled by URL param (attacker-controlled UI disable), removeAttribute('inert') triggered via URL param (attacker re-enables hidden elements)..."),
    ("scroll_snap_security", ScrollSnapSecurityScanner, "CSS Scroll Snap security — scrollY/scrollTop position transmitted to analytics (scroll behaviour surveillance), scrollIntoView() used on password/auth/token element (sensitive field revealed to viewport), scroll-snap injected via insertRule/innerHTML, scroll-snap-type controlled by URL param..."),
    ("color_scheme_security", ColorSchemeSecurityScanner, "Color Scheme / Media Preference fingerprinting — prefers-color-scheme matchMedia result transmitted (dark mode as device fingerprint), prefers-reduced-motion/contrast/forced-colors batch probe transmitted, forced-colors accessibility state exfiltrated for user profiling, color-scheme controlled via URL param..."),
    # Phase 171
    ("focus_management_security", FocusManagementSecurityScanner, "Focus Management security — programmatic focus() on password/auth/card/SSN field (auto-focus phishing), tabIndex=-1/0 combined with iframe/overlay/modal (focus trapping clickjacking), document.activeElement exfiltrated to remote (interaction surveillance), tabIndex value from URL parameter (attacker-controlled keyboard navigation)..."),
    ("css_counter_security", CSSCounterSecurityScanner, "CSS Counter security — counter() value used in url() CSS exfiltration (counter-based data leakage), counter-reset/increment value from URL param (attacker-controlled counter), counter injected via insertRule/innerHTML (dynamic counter manipulation), counter reset/increment naming password/token/auth elements (sensitive element enumeration)..."),
    ("form_data_api_security", FormDataAPISecurityScanner, "FormData API security — FormData containing password/token/credential sent via fetch/sendBeacon (credential exfiltration), FormData submitted to third-party external URL (form data harvesting), FormData values sourced from URL params (attacker-controlled fields), new FormData(form) all fields harvested and transmitted (complete form exfiltration)..."),
    ("custom_element_registry_security", CustomElementRegistrySecurityScanner, "Custom Element Registry security — customElements.define() tag name from URL param (attacker-controlled element registration), customElements.define() registers builtin elements like input/form/button (builtin override attack), connectedCallback() exfiltrates document/shadowRoot/innerHTML (lifecycle exfiltration), attributeChangedCallback() processes searchParams/innerHTML/eval (attacker-controlled attribute injection)..."),
    # Phase 172
    ("css_grid_security", CSSGridSecurityScanner, "CSS Grid security — grid-template-areas/columns/rows from URL param (attacker-controlled layout injection), CSS grid injected via insertRule/innerHTML/setAttribute, performance.now timing around grid layout and fetch (timing oracle), grid-area value from URL param (attacker-controlled placement)..."),
    ("document_fragment_security", DocumentFragmentSecurityScanner, "Document Fragment / Range API security — createContextualFragment() parses HTML from URL parameter (Range API XSS injection), range.insertNode() inserts URL parameter content (attacker-controlled DOM insertion), range.extractContents() transmitted via fetch (DOM exfiltration), range.cloneContents() sent to analytics (DOM surveillance)..."),
    ("pointer_events_security", PointerEventsSecurityScanner, "Pointer Events security — pointermove events transmitted to analytics (coordinate stream surveillance), pointer hardware attributes (pressure/tilt/type) fingerprinted and transmitted, setPointerCapture() followed by remote data exfil, PointerEvent configuration from URL param (attacker-controlled event simulation)..."),
    ("input_event_security", InputEventSecurityScanner, "Input Event security — event.key/code/data transmitted via fetch/sendBeacon (JavaScript keylogger), keystroke sequence with password/auth context exfiltrated (sensitive field keylogging), beforeinput preventDefault intercepts and suppresses input, InputEvent configuration from URL param (attacker-controlled event simulation)..."),
    # Phase 173
    ("tree_walker_security", TreeWalkerSecurityScanner, "TreeWalker / NodeIterator security — createTreeWalker() filtering for password/auth nodes (sensitive DOM harvesting), TreeWalker nextNode() result transmitted via fetch (text node exfiltration), full document walk with NodeFilter.SHOW_ALL (entire DOM surveillance), createTreeWalker parameters from URL param (attacker-controlled traversal)..."),
    ("dom_parser_security", DOMParserSecurityScanner, "DOMParser security — parseFromString() parses HTML from URL parameter (DOMParser XSS injection), parseFromString() result passed to eval()/Function() (parsed DOM executed as code), XMLSerializer.serializeToString() transmitted via fetch (DOM serialization exfil), parseFromString() processing <script>/event-handler HTML (script injection pattern)..."),
    ("channel_messaging_security", ChannelMessagingSecurityScanner, "MessageChannel / Channel Messaging security — port.postMessage() sends password/token/secret (sensitive payload over message port), port.onmessage handler passes data to eval()/innerHTML (injection via message port), MessageChannel port data transmitted via fetch (port data exfiltration), MessageChannel configuration from URL param (attacker-controlled channel)..."),
    ("css_transitions_security", CSSTransitionsSecurityScanner, "CSS Transitions / Animations security — transitionend/transitionstart event timing transmitted via fetch (CSS timing oracle), transition-duration value from URL parameter (attacker-controlled animation timing), CSS transition/animation injected via insertRule/innerHTML (dynamic injection), @keyframes content from URL param (attacker-controlled animation sequence)..."),
    # Phase 174
    ("typed_array_security", TypedArraySecurityScanner, "Typed Array security — Uint8Array containing password/token transmitted via fetch (binary credential exfil), TypedArray initialized from URL parameter (attacker-controlled buffer content), TypedArray memory layout transmitted (binary fingerprinting), WebAssembly.Memory wrapped in Uint8Array and exfiltrated (WASM memory dump)..."),
    ("array_buffer_security", ArrayBufferSecurityScanner, "ArrayBuffer / DataView security — ArrayBuffer containing token/credential transmitted (binary sensitive data exfil), ArrayBuffer/DataView from URL parameter (attacker-controlled buffer), DataView.getUint8/getFloat64 results transmitted (binary memory value exfil), SharedArrayBuffer with Atomics.store/load (shared memory timing attack for Spectre)..."),
    ("event_target_security", EventTargetSecurityScanner, "EventTarget / CustomEvent security — new CustomEvent() carries password/token/secret (sensitive data in DOM event), CustomEvent dispatched with URL parameter payload (attacker-controlled event injection), addEventListener handler transmits credentials via fetch (event listener exfiltration), window.addEventListener for message/storage/focus/blur events transmitted to remote (global event surveillance)..."),
    ("proxy_reflect_security", ProxyReflectSecurityScanner, "Proxy / Reflect security — Proxy handler.get trap transmits property reads to analytics (property read surveillance), Proxy handler.set trap exfiltrates property write values via sendBeacon (Proxy-based keylogger), new Proxy() wraps password/credential/cookie object (sensitive object interception), Proxy target from URL parameter (attacker-controlled proxy target)..."),
    # Phase 175
    ("promise_security", PromiseSecurityScanner, "Promise security — Promise.resolve()/new Promise() resolves with password/token/credential (sensitive data in promise chain), .then() handler transmits credentials via fetch/sendBeacon (promise resolution triggers exfil), unhandledrejection event transmitted to remote (rejection reason/stack trace exfil), Promise created from URL parameter (attacker-controlled resolve value)..."),
    ("generator_security", GeneratorSecurityScanner, "Generator / Iterator security — yield expression triggers fetch/sendBeacon (generator streams data to remote), yield produces password/token/credential/cookie (sensitive data streamed via generator), while(true) generator with fetch (infinite loop continuous exfiltration), generator function sourced from URL parameter (attacker-controlled sequence injection)..."),
    ("symbol_security", SymbolSecurityScanner, "Symbol / Well-Known Symbol security — [Symbol.toPrimitive] trap transmits via fetch (type coercion triggers exfil), Object.getOwnPropertySymbols() results transmitted (hidden property enumeration exfil), [Symbol.toStringTag] from URL param (attacker-controlled type tag spoofing), Symbol.keyFor() results transmitted (global registry probe for library detection fingerprinting)..."),
    ("weakmap_security", WeakMapSecurityScanner, "WeakMap / WeakSet / WeakRef / FinalizationRegistry security — WeakMap.set() stores password/token/credential (sensitive data cached in WeakMap), WeakRef.deref() result transmitted via fetch (dereferenced value exfiltrated), FinalizationRegistry callback transmits to remote (GC lifecycle data exfil), new WeakMap() from URL parameter (attacker-controlled initial entries)..."),
    # Phase 176
    ("json_security", JSONSecurityScanner, "JSON security — JSON.parse() parses content from URL parameter/localStorage (attacker-controlled JSON injection), JSON.stringify() serializes password/token/credential for fetch exfil, JSON.parse() result passed to eval()/Function() (JSON-based code injection), JSON.parse() reviver from URL param (attacker-controlled deserialization)..."),
    ("error_event_security", ErrorEventSecurityScanner, "Error Event security — error.stack transmitted via fetch/sendBeacon (stack trace exfil reveals file paths/function names), window.onerror handler transmits all uncaught errors to remote, new Error()/throw includes password/token in message (sensitive data in error), error.message transmitted to analytics (internal error details leaked)..."),
    ("define_property_security", DefinePropertySecurityScanner, "Object.defineProperty security — defineProperty() getter transmits to fetch/analytics (property read surveillance), defineProperty() setter exfiltrates property write values (Proxy-like keylogger via setter), Object.freeze() on auth/permissions object (verify freeze is effective), defineProperty target from URL parameter (attacker-controlled property injection)..."),
    ("storage_event_security", StorageEventSecurityScanner, "Storage Event security — localStorage/sessionStorage.getItem() transmitted via fetch (stored data exfiltration), localStorage.setItem() stores password/token/credential (sensitive data in plaintext browser storage), storage event listener transmits cross-tab changes to remote (cross-tab surveillance), localStorage.setItem() value from URL param (attacker-controlled persistent storage injection)..."),
    # Phase 177
    ("regex_security", RegexSecurityScanner, "Regex security — new RegExp() constructed from URL parameter (attacker-controlled regex enables ReDoS or injection), RegExp with nested quantifiers (.*)+/(\\w+)+/(.+)+ (catastrophic backtracking ReDoS vulnerability), .exec()/.match()/.test() results transmitted via fetch/sendBeacon (regex match results exfiltrated), new RegExp() result passed to eval()/Function() (regex injection to code execution)..."),
    ("date_security", DateSecurityScanner, "Date / Time security — getTimezoneOffset() transmitted to remote (timezone offset for cross-site fingerprinting/geolocation), toLocaleString()/Intl.DateTimeFormat locale transmitted (locale/language for user fingerprinting), new Date() from URL parameter (attacker-controlled date manipulation), Date.now()/performance.now() timing around auth fetch (timing oracle enables credential enumeration)..."),
    ("intl_security", IntlSecurityScanner, "Intl / Internationalization security — navigator.languages/language transmitted to remote (browser locale reveals geographic/language preferences for fingerprinting), Intl.Collator result transmitted to analytics (locale-specific sort behavior for cross-site fingerprinting), Intl.NumberFormat result transmitted (locale-specific number formatting reveals user locale), Intl API locale from URL parameter (attacker-controlled locale injection changes formatting behavior)..."),
    ("object_spread_security", ObjectSpreadSecurityScanner, "Object Spread / Assign security — Object.assign() merges URL parameter/JSON.parse() content (attacker-controlled properties merged enabling prototype pollution), object spread {...params} includes URL parameter content (attacker-controlled property injection), Object.entries() result transmitted via fetch/sendBeacon (all key-value pairs exfiltrated), Object.assign() targets Object.prototype/__proto__ (direct prototype pollution)..."),
    # Phase 178
    ("map_set_security", MapSetSecurityScanner, "Map / Set security — new Map() initialized with password/token/credential (sensitive data in Map object), .entries() result transmitted via fetch/sendBeacon (complete Map contents exfiltrated), new Map()/Set() from URL parameter/JSON.parse() (attacker-controlled initial entries), .set() stores credential then transmits via fetch (Map-based credential collection/exfil mechanism)..."),
    ("iterator_protocol_security", IteratorProtocolSecurityScanner, "Iterator Protocol security — [Symbol.iterator]/Array.from() result transmitted via fetch (iterable contents exfiltrated), Array.from() from URL parameter (attacker-controlled sequence injection), iterator over credential-containing object (sensitive values exposed to iteration), .next() result transmitted via fetch (iterator values incrementally exfiltrated)..."),
    ("function_constructor_security", FunctionConstructorSecurityScanner, "Function Constructor security — new Function() from URL parameter/innerHTML (attacker-controlled code execution, CSP bypass), new Function() body contains password/token/credential (sensitive data in dynamic function), eval() receives URL parameter/innerHTML (classic DOM XSS via eval), setTimeout() with string argument containing URL param (implicit eval via string-based setTimeout)..."),
    ("web_components_security", WebComponentsSecurityScanner, "Web Components security — shadowRoot.innerHTML/insertAdjacentHTML set from URL parameter (shadow DOM XSS), .content.cloneNode() with URL parameter content (attacker-controlled template cloning), .assignedNodes() result transmitted via fetch/sendBeacon (slotted DOM content exfiltrated), attachShadow({mode:'open'}) near password/credential (open shadow DOM accessible to external scripts enabling credential theft)..."),
    # Phase 179
    ("geolocation_security", GeolocationSecurityScanner, "Geolocation security — coords.latitude/longitude transmitted via fetch/sendBeacon (GPS coordinates exfiltrated without evident consent), .watchPosition() callback transmits (continuous covert location tracking), getCurrentPosition/watchPosition options from URL param (attacker-controlled accuracy/timeout), enableHighAccuracy:true with network transmission (maximum precision GPS exfiltration)..."),
    # Phase 180
    ("media_devices_security", MediaDevicesSecurityScanner, "Media Devices security — getUserMedia() stream sent via RTCPeerConnection/WebSocket (camera/mic captured and transmitted covertly), enumerateDevices() result transmitted to analytics (hardware list for fingerprinting), getUserMedia() constraints from URL param (attacker-controlled capture config), MediaStreamTrack.label/deviceId transmitted (persistent cross-site device tracking)..."),
    ("clipboard_advanced_security", ClipboardAdvancedSecurityScanner, "Clipboard Advanced security — clipboard.readText() result transmitted via fetch/sendBeacon (clipboard contents including passwords silently exfiltrated), paste event clipboardData.getData() transmitted (pasted passwords stolen), clipboard.writeText() from URL param (clipboard hijacking for phishing), clipboard.writeText() contains password/token (sensitive data written to shared clipboard)..."),
    ("device_orientation_security", DeviceOrientationSecurityScanner, "Device Orientation security — event.alpha/beta/gamma transmitted (compass/tilt for location fingerprinting), event.acceleration/rotationRate transmitted (accelerometer/gyroscope for gait analysis and keystroke inference), DeviceOrientationEvent config from URL param (attacker-controlled sensor access), alpha/acceleration correlated with password/keydown (side-channel credential theft via motion sensor)..."),
    ("vibration_security", VibrationSecurityScanner, "Vibration API security — navigator.vibrate() pattern from URL param/JSON.parse() (attacker-controlled pattern DoS or covert channel), navigator.vibrate() near password/token/credential (vibration pattern encodes sensitive data as covert side-channel), navigator.vibrate() inside setInterval/loop (repeated pattern for data encoding or DoS), complex vibration array with long durations (timing-based information encoding)..."),
    # Phase 181
    ("broadcast_channel_advanced_security", BroadcastChannelAdvancedSecurityScanner, "Broadcast Channel Advanced security — BroadcastChannel postMessage contains password/token/credential (sensitive data broadcast to all same-origin tabs), .onmessage handler transmits to fetch/sendBeacon (cross-tab message relay to remote), new BroadcastChannel() name from URL param (attacker-controlled channel subscription), BroadcastChannel named 'auth'/'login'/'token' (predictable channel enables eavesdropping)..."),
    ("web_share_security", WebShareSecurityScanner, "Web Share API security — navigator.share() includes password/token/credential (sensitive data shared via native share sheet to any app), navigator.share() content from URL param (attacker-controlled share enables phishing), navigator.share() includes files/Blob (private documents shared via share sheet), share url field from URL param (open redirect via native share UI)..."),
    ("idle_detection_security", IdleDetectionSecurityScanner, "Idle Detection security — userState/screenState transmitted via fetch/sendBeacon (user presence/screen status exfiltrated — covert surveillance), IdleDetector result to remote (continuous presence monitoring), IdleDetector.start() threshold from URL param (attacker-controlled idle detection config), 'change' event listener transmits (every active↔idle transition exfiltrated)..."),
    ("notification_security", NotificationSecurityScanner, "Notification security — new Notification() body contains password/token/credential (sensitive data visible on OS lock screen/notification center), Notification content from URL param (notification phishing via crafted URL), notificationclick event transmits via fetch (notification interaction tracking), showNotification() includes credential in service worker notification..."),
    # Phase 182
    ("web_authentication_security", WebAuthenticationSecurityScanner, "WebAuthn security — authenticatorData transmitted to non-server endpoint (attestation data to unauthorized endpoint), clientDataJSON transmitted via fetch (auth state leakage), credentials.create()/get() options from URL param (attacker-controlled rpId/challenge enables credential confusion), credentials.get() with password/federated fallback (WebAuthn downgrade path)..."),
    ("credential_api_advanced", CredentialApiAdvancedScanner, "Credential API Advanced security — credentials.store() with explicit password field (plaintext password written to browser store), mediation:'silent' with network request (silent credential auto-fill for headless auth), credentials.store() data from URL param (attacker-controlled credential stored in browser), PasswordCredential/FederatedCredential object transmitted via fetch/sendBeacon (credential object exfil)..."),
    ("federated_identity_security", FederatedIdentitySecurityScanner, "Federated Identity (FedCM) security — IdentityCredential transmitted via fetch/sendBeacon (token forwarding attack to unauthorized endpoint), FedCM configURL from URL param (attacker-controlled identity provider), FedCM clientId from URL param (client impersonation), static short nonce in identity request (replay attack via nonce reuse)..."),
    ("magic_link_security", MagicLinkSecurityScanner, "Magic Link / Passwordless security — magic/email token logged via console.log/error (auth token visible to extensions/devtools), magic/verification token transmitted to analytics/third-party (token forwarding), magic link/login token appears to be short static string (guessable token, insufficient entropy), verification token from URL parameter without apparent server validation..."),
    # Phase 183
    ("session_fixation_security", SessionFixationSecurityScanner, "Session Fixation security — sessionId/sessionToken read from URL parameter (classic session fixation: attacker pre-sets session), document.cookie set from URL param (session cookie injection), sessionStorage/localStorage session value from URL param (storage-based fixation), sessionToken transmitted via fetch/sendBeacon (active session token exfil enabling hijacking)..."),
    ("account_enumeration_security", AccountEnumerationSecurityScanner, "Account Enumeration security — different error messages for 'user not found' vs 'wrong password' (username enumeration via error differentiation), 'user not found' near timing measurement (timing-based enumeration oracle), checkEmail()/checkUsername() fetch endpoint (real-time account existence oracle), registration form reveals 'email already in use' (registration-based enumeration)..."),
    ("same_site_cookie_security", SameSiteCookieSecurityScanner, "SameSite Cookie security — SameSite=None without Secure flag (browsers reject; insecure transmission), auth/session cookie with SameSite=Lax (top-level GET allows cookie → CSRF risk for GET-based state changes), document.cookie set from URL param (cookie injection/session fixation), session/auth cookie without explicit SameSite attribute (implicit Lax may not be secure enough)..."),
    ("jwt_advanced_security", JwtAdvancedSecurityScanner, "JWT Advanced security — JWT with alg:'none' (signature verification disabled → any unsigned token accepted), JWT/Bearer token from URL parameter (token in URL logged in access logs/history), decoded JWT payload logged to console (claims visible to extensions/devtools), JWT payload transmitted to analytics (claims exfiltrated), JWT signing with short/common secret (offline brute-force to forge tokens)..."),
    # Phase 184
    ("cors_credential_security", CORSCredentialSecurityScanner, "CORS Credential security — credentials:'include' with wildcard origin '*' (browser blocks; code intent to bypass CORS), fetch to external domain with credentials:'include' (session/cookie forwarding cross-origin), fetch with credentials to URL from URL param (CSRF-like cross-origin request), XHR withCredentials=true to analytics/CDN (unintended session sharing to third-party)..."),
    ("token_refresh_security", TokenRefreshSecurityScanner, "Token Refresh security — refresh token from URL parameter (tokens in URLs logged in access logs/history), refresh/access token stored in localStorage/sessionStorage (accessible to XSS), refresh token transmitted via fetch/sendBeacon to remote (persistent account takeover), refresh/access token logged to console (visible to extensions/devtools)..."),
    ("sql_injection_client_security", SQLInjectionClientSecurityScanner, "SQL Injection Client-side security — SQL query constructed with URL parameter/innerHTML (client-side SQL injection into Web SQL/IndexedDB), SQL query built via string concat with userInput/searchTerm (classic injection via string building), openDatabase() from URL param (attacker-controlled database name), executeSql result transmitted via fetch/sendBeacon (database contents exfiltrated)..."),
    ("xpath_injection_security", XPathInjectionSecurityScanner, "XPath Injection security — XPath expression from URL parameter/innerHTML (attacker-controlled XPath enables auth bypass or data extraction), XPath built via string concat with user input (classic XPath injection), XPathResult transmitted via fetch/sendBeacon (XML document query results exfiltrated), boolean injection patterns (and/or with string literal, 1=1, nested predicates) in XPath expression..."),
    # Phase 185
    ("auth_bypass_pattern_security", AuthBypassPatternSecurityScanner, "Auth Bypass Pattern security — isAdmin/role/permission from URL parameter (authorization decision from attacker-controlled input, client-side auth bypass), isAuthenticated set from localStorage/sessionStorage/cookie (client-side-only auth bypassed by clearing storage), isAdmin||true boolean short-circuit (always-true condition completely bypasses auth check), hardcoded password/secret/token string comparison (trivial credential bypass if string known)..."),
    ("rate_limit_bypass_security", RateLimitBypassSecurityScanner, "Rate Limit Bypass security — X-Forwarded-For/X-Real-IP header from URL parameter (spoofed IP header bypasses IP-based rate limiting), loginAttempts/maxAttempts counter in localStorage/sessionStorage (client-side counter cleared to reset limit), X-Forwarded-For header set from URL param in fetch (client injects own IP header to bypass server rate limit), rateLimit/throttle/maxAttempts from URL param (attacker-controlled rate limit threshold)..."),
    ("ldap_injection_security", LDAPInjectionSecurityScanner, "LDAP Injection security — ldap.search/ldapFilter from URL parameter/user input (LDAP injection enables auth bypass or directory enumeration), cn=/ou= attribute built via string concatenation with username/email (classic LDAP injection, unsanitized DN/filter), LDAP filter with wildcard (*) or boolean operators (|, !) (metacharacter injection pattern), LDAP search result exfiltrated via fetch/sendBeacon (directory user attributes sent to remote)..."),
    ("template_injection_client_security", TemplateInjectionClientSecurityScanner, "Template Injection Client-side security — Handlebars.compile()/ejs.render() template string from URL parameter (SSTI via attacker-controlled template expression), render context from URL parameter/JSON.parse() (attacker-controlled context variables inject data or access prototype), {{__proto__}}/{{constructor}} in template expression (prototype chain access enables sandbox escape and RCE), template render includes password/token/credential in context (sensitive data accessible via SSTI)..."),
    # Phase 186
    ("prototype_pollution_advanced", PrototypePollutionAdvancedScanner, "Prototype Pollution Advanced — __proto__/Object.setPrototypeOf() from URL parameter/JSON.parse (attacker-controlled prototype chain mutation poisons all objects), Object.assign() merges URL parameter data enabling __proto__ key injection, Object.defineProperty() target from URL parameter (attacker-controlled property override), prototype[userInput] bracket notation (direct prototype write from user-controlled key)..."),
    ("mass_assignment_security", MassAssignmentSecurityScanner, "Mass Assignment security — ...spread of URL parameter/JSON.parse (all user-supplied properties assigned without allowlist), Object.assign(this/model, req.body/searchParams) (entire user-controlled object merged into model without field filtering), for...in over req.body assigns to this[key] (unrestricted property iteration), role/isAdmin/permissions from req.body/searchParams (privilege escalation via mass assignment)..."),
    ("insecure_direct_object_reference", InsecureDirectObjectReferenceScanner, "IDOR — userId/accountId/recordId from URL parameter (attacker changes ID to access other users' data), sequential numeric ID from parseInt/Number(searchParams) (enumeration by incrementing), direct API fetch with ID in template literal without visible Authorization header (object fetched by ID without confirmed auth), userId/accountId exfiltrated via sendBeacon/analytics (internal object IDs sent to third-party)..."),
    ("command_injection_client_security", CommandInjectionClientSecurityScanner, "Command Injection Client-side — exec()/spawn()/execSync() with URL parameter/userInput (OS command injection in client-side Node.js/Electron apps), shell command built via string concat with userInput/filename (classic metacharacter injection via ; | &&), spawn/exec with shell:true and user-controlled input (shell metacharacter interpretation enabled), shell command result via fetch/sendBeacon (OS command output exfiltrated to remote)..."),
    # Phase 187
    ("dependency_hijacking", DependencyHijackingScanner, "Dependency Hijacking — CDN package URL built from URL parameter (attacker controls which unpkg/jsdelivr package version is loaded), dynamic require() path from URL parameter (attacker-controlled module path loads malicious local/network modules), dynamic import() from URL parameter (open redirect + dynamic import = remote module loading), external <script> without SRI integrity attribute (CDN compromise runs attacker script with full page privileges)..."),
    ("file_inclusion_security", FileInclusionSecurityScanner, "File Inclusion Security — readFile/fs.readFile with URL parameter (local file disclosure from attacker-controlled path), path built by string concat with userInput/searchParams (path traversal via ../ sequences), require() with user-controlled relative path (arbitrary local file load as module), ../../../ traversal pattern in JavaScript string (attacker navigating out of web root to system files)..."),
    ("server_side_template_passive", ServerSideTemplatePassiveScanner, "Server-Side Template Passive — reflected template expression with math/config/self (7*7 or config.items() in response body indicates SSTI probe result or unescaped template variable), template engine error class in response (TemplateSyntaxError/Twig_Error reveals engine type/version/file structure), server header fingerprints template engine (Werkzeug/Flask/Django in Server header enables targeted SSTI payload selection)..."),
    ("http_request_smuggling", HTTPRequestSmugglingScanner, "HTTP Request Smuggling — Transfer-Encoding and Content-Length both present (TE/CL desync; front-end uses CL, back-end uses TE or vice versa), obfuscated Transfer-Encoding header (chunked in unusual format bypasses front-end TE parsing), proxy + TE conflict (chunked body after Forwarded/Via header indicates proxy desync path), duplicate Content-Length headers (CL/CL desync where front-end takes first, back-end takes last value)..."),
    # Phase 188
    ("api_rate_limit_headers", APIRateLimitHeadersScanner, "API Rate Limit Headers — API endpoint with no RateLimit/X-RateLimit response headers (brute-force and enumeration attacks are unsignalled to clients), RateLimit-Limit value of 0 (advertises unlimited requests, effectively disables throttling), Retry-After: 0 (tells clients to retry immediately with no backoff delay), conflicting X-RateLimit and X-Rate-Limit header namespaces (proxy/origin disagreement causes unpredictable throttling)..."),
    ("cors_policy_advanced", CORSPolicyAdvancedScanner, "CORS Policy Advanced — Access-Control-Allow-Origin: * with credentials: true (browsers block this but misconfigured clients may still send cookies), ACAO: null (sandbox iframes send Origin: null enabling credentialed attacker cross-origin requests), reflected origin with credentials: true (attacker.com reflected in ACAO grants full credentialed cross-origin access), Allow-Methods includes PUT+DELETE (cross-origin destructive operations), Allow-Headers exposes Authorization/X-Api-Key (credential theft via cross-origin header access)..."),
    ("content_sniffing_bypass", ContentSniffingBypassScanner, "Content Sniffing Bypass — HTML/JS content-type without X-Content-Type-Options: nosniff (legacy browsers execute attacker files as scripts via MIME sniffing), HTML/script content with application/octet-stream type (polyglot file executed by MIME-sniffing browsers), uploaded executable-extension filename reflected without nosniff (served file executed as sniffed type), SVG without nosniff (inline SVG scripts bypass CSP script-src restrictions)..."),
    ("javascript_prototype_chain", JavaScriptPrototypeChainScanner, "JavaScript Prototype Chain — __proto__ assignment or bracket access (attacker-controlled values poison all objects inheriting from Object.prototype), Object.prototype.property = value (prototype extension propagates to all runtime objects), prototype[searchParams/userInput] bracket notation (direct prototype write from URL parameter), Object.setPrototypeOf with JSON.parse/URL param (attacker controls prototype chain target), hasOwnProperty override (property guards bypassed, inherited attacker properties pass checks), Object.defineProperty(Object.prototype) (getter/setter gadget enabling code execution on innocent property access)..."),
    # Phase 189
    ("xml_external_entity_advanced", XMLExternalEntityAdvancedScanner, "XXE Advanced — DOCTYPE with SYSTEM entity referencing file:// or http:// (XML parser resolves local files or triggers SSRF), parameter entity % name SYSTEM (blind XXE out-of-band data exfiltration via DNS/HTTP), DOCTYPE with internal subset [ without external entity (billion laughs exponential expansion DoS), XML parser error message in response (SAXParseException/XMLSyntaxError reveals parser type enabling targeted payloads), SSI directives in response (<!--#include exec--> alongside XML contexts), DOMParser.parseFromString with URL parameter (client-side XML injection)..."),
    ("broken_object_level_auth", BrokenObjectLevelAuthScanner, "BOLA/IDOR — numeric object ID in API path without Authorization header observed (changing ID grants access to other users' objects), sensitive field in API JSON response without per-object authorization (password/token/SSN exposed to any requester), total/count field with 3+ digit value alongside object-ID path (listing endpoint may return all records without ownership filtering), user_id/owner_id in response body (substitutable in request path for BOLA bypass)..."),
    ("insecure_data_exposure", InsecureDataExposureScanner, "Insecure Data Exposure — PEM private key header in response body (complete private key material; signing/decryption impersonation), AWS access key ID AKIA prefix in response (direct cloud infrastructure access if paired with secret), sensitive JSON field with non-masked value (password/api_key/access_token in API response; direct credential theft), credit card number pattern in response (PCI-DSS violation; card numbers must never appear in API responses), SSN pattern in response (PII breach under GLBA/state law), JWT token in response body (logged by proxies; XSS token theft), internal RFC-1918 IP in JSON (internal topology disclosure enabling SSRF targeting)..."),
    ("graphql_introspection_security", GraphQLIntrospectionSecurityScanner, "GraphQL Introspection — __schema.types in response (full schema exposed; attackers map all queries/mutations/fields), mutationType exposed (write operations discoverable including names and argument types; state-changing operations directly targeted), extensions.stacktrace in error response (full stack trace reveals framework/file paths/function names), verbose error message in errors array (schema structure/field names exposed even without introspection), GraphQL IDE in production response (GraphiQL/Playground enables interactive schema exploration for attackers), field suggestions in error (Cannot query field + Did you mean enables field enumeration with introspection disabled)..."),
    # Phase 190
    ("latex_injection_passive", LaTeXInjectionPassiveScanner, r"LaTeX Injection Passive — \write18/\immediate\write18 command (shell escape in pdflatex --shell-escape executes OS commands; full RCE), \input{/etc/...} path traversal (LaTeX reads local files from filesystem; exfiltrate /etc/passwd or private keys via generated PDF), LaTeX command with URL parameter (\input/\include/\def containing searchParams; attacker-controlled file inclusion), LaTeX error message disclosure (engine type/version/paths revealed enabling targeted payload selection)..."),
    ("css_injection_passive", CSSInjectionPassiveScanner, "CSS Injection Passive — expression()/behavior: directive (IE CSS expressions execute arbitrary JavaScript; behavior: loads HTC script files), url('javascript:') in CSS (javascript: scheme in url() executes in some browser/Electron contexts), @import url() from URL parameter (attacker-controlled external stylesheet; CSS exfil via attribute selectors), style= attribute from URL parameter (attacker-controlled inline CSS; UI redressing, data exfiltration via background-image requests, phishing overlays), attribute selector exfil gadget (input[value^=X]{background:url(attacker.com)} leaks form values character by character)..."),
    ("deserialization_gadget_passive", DeserializationGadgetPassiveScanner, r'Deserialization Gadget Passive — PHP serialized object O:N:"Class" in response (if returned to client and re-submitted, enables PHP object injection via magic method chains), Java serialized stream aced0005/rO0AB in response (Apache Commons Collections or similar gadget chain enables RCE via ObjectInputStream), pickle.loads with user input (Python pickle executes arbitrary code via __reduce__), unserialize($_GET/$_POST) (PHP object injection from HTTP parameter; magic methods __destruct/__wakeup triggered), ObjectInputStream from request body (classpath gadget chains exploitable without allowlist filtering), yaml.load() unsafe (PyYAML unsafe load executes !!python/object/apply; use safe_load()), gadget class in error (Apache Commons Collections in error confirms exploitable chain on classpath)...'),
    ("race_condition_passive", RaceConditionPassiveScanner, "Race Condition Passive — financial operation endpoint (transfer/withdraw/purchase/checkout) without Idempotency-Key header (concurrent duplicate requests execute multiple times; double-spend or double-withdrawal), balance/stock/credit counter response without ETag/Last-Modified (no optimistic locking; concurrent updates cause lost update anomaly), TOCTOU pattern if(balance>0){deduct()} without atomic operation (race window between check and update), coupon/voucher redemption without idempotency (same promo code applied multiple times via simultaneous parallel requests)..."),
    # Phase 191
    ("link_injection_passive", LinkInjectionPassiveScanner, "Link Injection Passive — <a href> containing URL parameter reference (attacker injects javascript:/data: URL for XSS links or external URL for phishing), document.write() with URL parameter (writes attacker-controlled HTML; bypasses innerHTML script-tag filters), Location/Refresh/Link header with URL parameter (CRLF header injection enables arbitrary header injection and response splitting), window.location from URL parameter (open redirect after legitimate action), <base href> pointing to external domain (all relative links redirect to attacker-controlled domain)..."),
    ("parameter_pollution_passive", ParameterPollutionPassiveScanner, "Parameter Pollution Passive — code takes only [0] from multi-value parameter (front-end security check reads first value but back-end uses second; attacker's malicious second value bypasses check), PHP $_GET['x'][0] double-bracket (PHP accepts param[] as array; attacker sends param[0]=safe&param[1]=malicious to bypass string-level checks), _method/X-HTTP-Method-Override in URL (HTTP method tunneling; WAF sees GET/POST but back-end processes DELETE/PUT), backend splits parameter on delimiter (attacker injects delimiter to inject key=value pairs into back-end request)..."),
    ("timing_attack_passive", TimingAttackPassiveScanner, "Timing Attack Passive — direct === equality comparison on token/password/secret (string comparison short-circuits; timing difference reveals character matches enabling char-by-char brute force), .equals()/strcmp() on token/hash (not constant-time; network-measurable timing differences enable offline oracle attacks), early return on credential mismatch (function exits faster on wrong credentials; reveals whether prefix matched), X-Response-Time/X-Runtime header (per-request timing data enables statistical timing oracle; attackers average many requests to detect microsecond credential validation differences)..."),
    ("cryptographic_weakness_passive", CryptographicWeaknessPassiveScanner, "Cryptographic Weakness Passive — MD5/SHA-1 hash (cryptographically broken; MD5 has known collision attacks; SHA-1 has SHAttered chosen-prefix collisions; use SHA-256+ or bcrypt/argon2 for passwords), DES/3DES/RC4/Blowfish cipher (DES is 56-bit brute-forceable; RC4 biases exploited in BEAST/POODLE; 3DES vulnerable to Sweet32; use AES-256-GCM), AES-ECB mode (deterministic; identical plaintext blocks produce identical ciphertext; pattern-preserving; 'ECB penguin'), Math.random() for token/secret/key (52-bit PRNG state; predictable from output; forge CSRF tokens/session IDs), hardcoded IV (fixed IV breaks AES-CBC/GCM security), 512/1024-bit RSA (512-bit factored in 1999; nation-state risk for 1024-bit; use 2048+ or ECC), time-based PRNG seed (predictable from timestamp; enumerate all states)..."),
    # Phase 192
    ("nosql_injection_advanced", NoSQLInjectionAdvancedScanner, "NoSQL Injection Advanced — MongoDB $where operator from req.body/URL parameter (evaluates attacker-controlled JavaScript server-side; authorization bypass), MongoDB query operators ($gt/$lt/$ne/$in/$regex) sourced from req.body (attacker sends {password:{$ne:null}} to bypass auth; {$regex:'.*'} returns all documents), .find() receiving raw req.body as query selector (entire attacker-supplied object used as MongoDB filter; no sanitization), .aggregate() pipeline from URL parameter (attacker adds $lookup to join sensitive collections; $out to write new collections), mapReduce() with user input (JavaScript execution in MongoDB context), MongoDB/Redis error disclosure (library version/schema/field names revealed)..."),
    ("ldap_injection_passive", LDAPInjectionPassiveScanner, "LDAP Injection Passive — LDAP search filter constructed from URL parameter/req.body (attacker injects * | & ! to modify filter logic; (&(uid=admin)(pass=*))(|(uid=*)) bypasses auth), LDAP filter built by string concatenation '(uid=' + username (direct metacharacter injection; no parameterized LDAP API), .bind() with user-controlled credential (attacker injects empty string or foreign DN for anonymous/impersonated bind), LDAP error disclosure (LDAPException/Invalid DN syntax reveals library/server type/directory structure), DN in response body (internal directory OU hierarchy/domain components exposed)..."),
    ("oauth_misconfiguration_passive", OAuthMisconfigurationPassiveScanner, "OAuth Misconfiguration Passive — access_token in URL query string (tokens logged by web servers/proxies/browser history; Referer header leaks; must be in Authorization header), client_secret returned in API response (anyone with secret can impersonate the app and obtain tokens for any user), implicit flow response_type=token (deprecated in OAuth 2.1; tokens in URL fragment exposed to browser history/Referer/same-origin JavaScript; use authorization code + PKCE), scope wildcard * (compromised token grants full access to all resources; violates least privilege)..."),
    ("saml_security_passive", SAMLSecurityPassiveScanner, "SAML Security Passive — multiple Assertion elements with different IDs (XML Signature Wrapping attack; attacker moves signed assertion/inserts malicious unsigned one; signature validates while SP processes attacker's content), RSA-SHA1 signature algorithm (deprecated; SHAttered collision enables XML signature forgery; use RSA-SHA256 minimum), SAML library error in response (SAMLException/org.opensaml reveals library version/parsing errors; enables targeted CVE exploitation), unspecified NameID format (arbitrary NameID values including other users' IDs; account impersonation in some SP implementations)..."),
    # Phase 193
    ("actuator_endpoint_exposure", ActuatorEndpointExposureScanner, "Actuator Endpoint Exposure — Spring Boot Actuator _links exposed (full actuator map reveals all management endpoints; no auth), /env returning systemProperties/systemEnvironment (database passwords, API keys, cloud credentials in plaintext), /heapdump accessible (full JVM heap snapshot; all in-memory secrets, session tokens, decrypted credentials extractable), Prometheus metrics exposed (request rates, error rates, latency percentiles, connection pool state without auth), Jolokia JMX-over-HTTP (read/write MBean attributes, invoke JVM operations including classloading and thread management), detailed /health with db/redis/diskSpace status (internal infrastructure topology for attacker reconnaissance)..."),
    ("tabnapping_passive", TabnappingPassiveScanner, "Tabnapping Passive — <a target=_blank> without rel=noopener noreferrer (opened tab retains window.opener reference; malicious site redirects opener/parent to phishing page while user is in new tab), window.opener.location redirect in child (explicitly redirects opener to attacker URL; credential-harvest attack), window.opener.postMessage() without origin check (attacker sends crafted messages to opener; bypasses same-origin if no origin validation), window.open() without nulling opener (programmatic tab creation leaving opener reference intact), missing Referrer-Policy header (Referer leaks full URL including path/query tokens to opened tabs/external resources)..."),
    ("zip_slip_passive", ZipSlipPassiveScanner, "Zip Slip Passive — extractall() without path normalization check (Python zipfile.extractall writes files to arbitrary paths; attacker-crafted ../../etc/cron.d/backdoor in zip), iteration without path validation (member.name used directly in file writes without realpath/canonicalPath check), ../  traversal sequence in archive member filename (../../var/www/html/shell.php path detected in archive; direct path traversal payload), ZipInputStream without canonicalPath (Java zip extraction without canonical path validation; traversal to server root), upload+extract without sanitization (file upload then immediate extraction without member path validation), os.path.join with archive member name (path join with untrusted name; on Unix os.path.join ignores earlier components if name starts with /)..."),
    ("integer_overflow_passive", IntegerOverflowPassiveScanner, "Integer Overflow Passive — price × parseInt(req.body) without bounds check (attacker sends negative quantity; price becomes negative; credit to attacker account), balance -= parseInt(req.body.amount) without validation (negative withdrawal adds to balance; financial manipulation), parseInt(searchParams) without min/max validation (URL parameter used as integer without range check; overflow/underflow in calculations), price×quantity without Math.abs (signed arithmetic; negative values produce credit instead of debit), large integer constant near Number.MAX_SAFE_INTEGER (precision loss above 2^53; integer identity checks fail; exploit path depends on context)..."),
    # Phase 194
    ("debug_endpoint_exposure", DebugEndpointExposureScanner, "Debug Endpoint Exposure — Django DEBUG=True error page (full stack trace, settings, SECRET_KEY, DATABASES, SQL queries), Werkzeug Interactive Debugger (browser Python REPL; arbitrary OS command execution without auth), Django Debug Toolbar in production (SQL query log with parameter values, template timeline, cache stats), Laravel Debugbar/Telescope/Ignition/Whoops (Ignition executes arbitrary PHP; Telescope logs all requests/queries/exceptions), full Python stack trace in response (file paths, library versions, function arguments, source excerpts), debug response headers (X-Debug-Token, X-Powered-By: PHP/version)..."),
    ("sensitive_cache_control", SensitiveCacheControlScanner, "Sensitive Cache Control — login/payment/password form missing Cache-Control: no-store (browsers and proxies cache response including form values; cached credentials readable by subsequent users on shared devices or via browser history), sensitive page missing Cache-Control: private (shared proxy/CDN caches serve page to other users; user-specific data visible to other clients hitting same cache node), sensitive URL with no Cache-Control header at all (browser applies RFC 7234 heuristic caching; Last-Modified-based expiry caches sensitive responses for hours)..."),
    ("client_side_validation_only", ClientSideValidationOnlyScanner, "Client-Side Validation Only — HTML5 required attribute without server-side validation (browser enforcement bypassed by removing attribute in DevTools or sending raw HTTP request; required fields submitted empty), minlength constraint without server-side length check (direct POST ignores minlength; single-character passwords and empty usernames accepted), pattern= regex without server-side validation (format constraints on email/phone/ZIP bypassed in direct requests), novalidate on form (explicitly disables all HTML5 validation; all constraints absent if server-side validation also missing)..."),
    ("session_entropy_passive", SessionEntropyPassiveScanner, "Session Entropy Passive — session ID ≤15 characters (NIST SP 800-63B requires ≥64 bits entropy; short tokens brute-forceable by online enumeration), purely numeric session ID (10^N entropy; 10-digit ID has ~33 bits; sequential enumeration exposes all active sessions), short/sequential identifier in response (IDOR via enumeration; increment ID to access other users' sessions or accounts), session/auth token in URL query string (logged by web servers, proxies, CDNs, browser history; appears in Referer headers sent to external resources), predictable token pattern (username+number, timestamp-seeded, non-cryptographic UUID)..."),
    # Phase 195 — previously unregistered passive scanners
    ("xss",               XSSScanner,               "XSS reflection — form/URL/header reflection using harmless text markers (no JS payloads)..."),
    ("dom",               DOMScanner,                "DOM risk patterns — eval/innerHTML sinks, unsafe postMessage, open redirect, prototype pollution in page JS..."),
    ("sensitive_params",  SensitiveParamScanner,     "Sensitive URL params — tokens/passwords/API keys in query strings (logged by servers, CDNs, browser history)..."),
    ("subdomain_takeover",SubdomainTakeoverScanner,  "Subdomain takeover — CNAME chain analysis against 30+ fingerprints (GitHub Pages, Heroku, S3, Azure, Netlify)..."),
    # Phase 196 — Compliance framework scanners
    ("pci_dss_compliance",  PCIDSSComplianceScanner,  "PCI-DSS v4.0 compliance — TLS enforcement, CSP, SRI, card number exposure, CVV autocomplete, HSTS, frame protection..."),
    ("hipaa_compliance",    HIPAAComplianceScanner,   "HIPAA Security Rule — §164.312 technical safeguards: TLS, HSTS, PHI field exposure, audit endpoint, XCTO, CSP..."),
    ("soc2_compliance",     SOC2ComplianceScanner,    "SOC 2 TSC — CC6/CC7/CC8/A1: TLS, HSTS, CSP, frame protection, error disclosure, version disclosure, CORS..."),
    ("nist_csf_compliance", NISTCSFComplianceScanner, "NIST CSF v2.0 — GV/ID/PR/DE/RS functions: TLS, HSTS, CSP, credential exposure, internal IP, error disclosure..."),
    ("iso27001_compliance", ISO27001ComplianceScanner,"ISO 27001:2022 Annex A — A.5.14/A.8.3/A.8.9/A.8.12/A.8.20/A.8.23/A.8.24: TLS, HSTS, CSP, secrets, mixed content..."),
    # Phase 197 — SBOM + Polyfill supply chain
    ("sbom",               SBOMScanner,               "SBOM inventory — exposed package.json/requirements.txt/go.mod; component count, deprecated packages, CycloneDX summary..."),
    ("polyfill_supply_chain", PolyfillSupplyChainScanner, "Polyfill.io supply chain — June 2024 cdn.polyfill.io/bootcss.com compromise; script src + CSP allowlist detection..."),
    # Phase 198 — Active scanners (only run with --active flag)
    ("active_cors_fuzz",    ActiveCORSOriginFuzzScanner,  "Active CORS fuzz — crafted Origin headers (null, evil.com, sub-domain variants) to map reflected ACAO..."),
    ("active_http_verb",    ActiveHTTPVerbProbeScanner,   "Active HTTP verb probe — OPTIONS + method-by-method requests to enumerate allowed verbs..."),
    ("active_port_probe",   ActivePortProbeScanner,       "Active port probe — TCP connect scan of 30+ dangerous ports (SSH, RDP, DB, Docker, K8s)..."),
    ("active_subdomain_enum", ActiveSubdomainEnumScanner, "Active subdomain enum — DNS brute-force of common subdomains (dev, staging, api, admin, vpn)..."),
    ("active_tls_cipher",   ActiveTLSCipherProbeScanner,  "Active TLS cipher probe — negotiation attempt for weak/deprecated cipher suites and protocol versions..."),
    # Phase 199 — Database exposure, ATO, GraphQL auth, OAuth device flow
    ("elasticsearch_exposure", ElasticsearchExposureScanner, "Elasticsearch/OpenSearch exposure — unauthenticated /_cat/indices, /_cluster/health, cluster_name on ports 9200/9201/28017..."),
    ("redis_exposure",       RedisExposureScanner,        "Redis/Memcached exposure — PING→PONG without auth on port 6379, INFO server, Memcached stats on port 11211..."),
    ("mongodb_exposure",     MongoDBExposureScanner,      "MongoDB/CouchDB/Firebase exposure — CouchDB /_all_dbs, MongoDB HTTP interface, Firebase .json public read, connection string in JS..."),
    ("account_takeover_passive", AccountTakeoverPassiveScanner, "Account takeover passive — reset link poisoning, username enumeration via reset, no rate limit on reset, token in URL, weak numeric token..."),
    ("graphql_authorization", GraphQLAuthorizationScanner, "GraphQL authorization — introspection without auth, sensitive mutations in schema, sensitive field names, CORS wildcard on GQL endpoint..."),
    ("oauth_device_flow",    OAuthDeviceFlowScanner,      "OAuth device flow (RFC 8628) — long-lived device codes, fast polling interval, low-entropy user codes, sensitive state in verification_uri..."),
]

# Deduplicate registry — if the same scanner class was registered under two keys,
# keep only the first occurrence so each scanner runs exactly once per scan.
_seen_cls: set = set()
_SCANNER_REGISTRY = [
    entry for entry in _SCANNER_REGISTRY
    if entry[1] not in _seen_cls and not _seen_cls.add(entry[1])
]
del _seen_cls

# Modules that send traffic the target did not invite. These are NOT passive
# and never run unless the user passes --active.
#
# The third group was determined empirically, not by name: every scanner was
# run against an instrumented server and any that issued POST/PUT/PATCH/DELETE
# or sent traversal / XXE / CRLF / injection payloads is listed here. Several
# are named "passive" but are not. tests/test_passive_by_default.py reproduces
# that measurement and fails if a default scanner starts sending traffic.
# ── Scan tiers ────────────────────────────────────────────────────────────────
# Tblue splits scanners by what they send, not by what they are named. The
# assignment below was produced by measurement: every scanner was run against
# an instrumented server and classified by its observed traffic.
#
#   default    read-only. GET/HEAD plus a CORS preflight. Safe on production.
#   --probe    also sends crafted but side-effect-free requests: GraphQL
#              introspection, CORS origin reflection, TLS cipher negotiation,
#              DNS enumeration. Nothing is modified, no credentials submitted.
#   --active   also sends intrusive traffic: authentication attempts, password
#              reset and registration submissions, injection payloads, port
#              scans. These can lock accounts out, email real users, create
#              records and trip WAFs. Own the target before using this.

# Crafted requests with no side effects.
PROBE_MODULES: set = {
    "graphql",
    "graphql_advanced",
    "graphql_batch_abuse",
    "graphql_batching",
    "graphql_depth",
    "graphql_field_suggestion",
    "graphql_info_disclosure",
    "graphql_persisted_queries",
    "graphql_subscription",
    "active_cors_fuzz",
    "active_tls_cipher",
    "active_subdomain_enum",
}

# Traffic with real consequences for the target or its users.
INTRUSIVE_MODULES: set = {
    # Authentication: repeated failed logins can lock accounts; reset probes
    # can email real people; mass_assignment attempts to create records.
    "account_enumeration",
    "account_lockout",
    "password_reset",
    "rate_limit",
    "timing_oracle",
    "mass_assignment",
    "xss",
    "ldap_injection",
    "llm_prompt_injection",
    # Attack payloads: traversal, XXE, CRLF, response splitting.
    "xxe_probe",
    "xxe_injection",
    "log_injection_probe",
    "path_traversal_deep",
    "http_response_splitting",
    "api_error_disclosure",
    # Non-idempotent HTTP verbs against live endpoints.
    "active_http_verb",
    "http_verb_tampering",
    # Network-level: port scans and database wire protocols.
    "ports",
    "active_port_probe",
    "redis_exposure",
}

# Everything held out of the default run. --active implies --probe.
ACTIVE_MODULES: set = PROBE_MODULES | INTRUSIVE_MODULES

# Split the registry: passive entries feed the default worker pool, active
# entries are reachable only via --active.
_ACTIVE_REGISTRY  = [e for e in _SCANNER_REGISTRY if e[0]     in ACTIVE_MODULES]
_TIER_OF = {**{k: "probe" for k in PROBE_MODULES},
            **{k: "intrusive" for k in INTRUSIVE_MODULES}}
_SCANNER_REGISTRY = [e for e in _SCANNER_REGISTRY if e[0] not in ACTIVE_MODULES]

# Rebuild ALL_MODULES: keep only keys that exist in the deduplicated registry,
# and remove any duplicate string entries, preserving first-seen order.
_registry_keys: set = {entry[0] for entry in _SCANNER_REGISTRY}
_seen_mod: set = set()
ALL_MODULES = [
    m for m in ALL_MODULES
    if m in _registry_keys and m not in _seen_mod and not _seen_mod.add(m)
]
del _registry_keys, _seen_mod

EXIT_OK               = 0
EXIT_BELOW_THRESHOLD  = 1
EXIT_ERROR            = 2


def build_session(args=None) -> requests.Session:
    """Build a requests.Session, optionally applying authentication from CLI args."""
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    if args is None:
        return session

    # Session cookies: "name=value; name2=value2"
    if getattr(args, "cookie", None):
        for part in args.cookie.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                session.cookies.set(name.strip(), value.strip())

    # Arbitrary headers: "X-API-Key: secret"
    for h in getattr(args, "extra_headers", None) or []:
        if ":" in h:
            name, _, value = h.partition(":")
            session.headers[name.strip()] = value.strip()

    # Bearer token: Authorization: Bearer <token>
    if getattr(args, "bearer", None):
        session.headers["Authorization"] = f"Bearer {args.bearer}"

    # HTTP Basic auth: "user:pass"
    if getattr(args, "auth_basic", None) and ":" in args.auth_basic:
        user, _, pwd = args.auth_basic.partition(":")
        session.auth = (user, pwd)

    return session


def gated_selection(only: str) -> Dict[str, List[str]]:
    """Names in --only that exist but sit behind --probe / --active.

    Without this the CLI silently scanned nothing: `--only xss` resolved to an
    empty module list and produced a clean, empty report. A security tool must
    never report "no findings" when it in fact ran no checks.
    """
    named = {m.strip() for m in (only or "").split(",") if m.strip()}
    return {
        "probe":     sorted(named & PROBE_MODULES),
        "intrusive": sorted(named & INTRUSIVE_MODULES),
        "unknown":   sorted(n for n in named
                            if n not in ALL_MODULES and n not in ACTIVE_MODULES),
    }


def resolve_modules(only: str, skip: str) -> List[str]:
    if only:
        return [m.strip() for m in only.split(",") if m.strip() in ALL_MODULES]
    if skip:
        excluded = {m.strip() for m in skip.split(",")}
        return [m for m in ALL_MODULES if m not in excluded]
    return ALL_MODULES


def count_results(all_results: Dict[str, List], status: str) -> int:
    return sum(
        1 for v in all_results.values()
        for r in v
        if r.get("status") == status
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tblue — Passive blue-team security scanner for your own websites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  ssl           — HTTPS check and HTTP redirect verification
  headers       — Security headers with value analysis and grading
  cookies       — Cookie flag checker (HttpOnly, Secure, SameSite, GDPR consent)
  csp           — Deep Content-Security-Policy analysis
  info          — Information disclosure (headers, PII, API keys, sensitive files)
  mixed         — Mixed content (HTTP resources on HTTPS pages)
  login         — Login page security checks
  xss           — XSS reflection in forms and URL parameters
  dom           — Risky JavaScript pattern detection
  email         — Email security: SPF, DKIM, DMARC, DNS CAA records
  access        — Admin page discovery and robots.txt leakage
  graphql       — GraphQL introspection, playground, and batch query checks
  methods       — HTTP method enumeration (TRACE, PUT, DELETE on non-API paths)
  ports         — Open port scan (databases, Redis, Docker API, RDP, etc.)
  cors          — CORS misconfiguration (reflected origin, null origin, wildcard)
  security_txt  — RFC 9116 security.txt file presence and field validation
  error_pages   — Error page leakage (stack traces, framework versions, paths)
  exposure      — Exposed API specs, dependency files, and CI/CD configs
  rate_limit    — Rate limiting detection on login/auth endpoints
  jwt           — JWT security (alg:none, weak algorithms, missing expiry)
  waf           — WAF/CDN detection (Cloudflare, AWS, Akamai, Imperva, etc.)
  dns           — DNSSEC and subdomain surface scan
  js_libs       — Outdated JavaScript library detection (jQuery, Bootstrap, etc.)
  sensitive_params — Sensitive data in URL parameters (tokens, passwords, keys)

Exit codes:
  0 — passed (or no --fail-below)
  1 — score below threshold (--fail-below)
  2 — scan error

Config file: place .tblue.toml in the current directory to persist defaults.
  url        = "https://example.com"
  fail_below = 80
  skip       = "xss,dom"
  output     = "report.html"

Examples:
  python -m tblue -u https://yoursite.com
  python -m tblue -u https://yoursite.com --fail-below 80
  python -m tblue -u https://yoursite.com --sarif -o report.html
  python -m tblue -u https://yoursite.com --only headers,ssl,csp
  python -m tblue -u https://yoursite.com --skip xss,dom
  python -m tblue --config /path/to/.tblue.toml
        """
    )

    parser.add_argument("-u", "--url",          default=None,                       help="Target URL (your own site only)")
    parser.add_argument("-d", "--depth",        type=int, default=DEFAULT_DEPTH,    help=f"Crawl depth (default: {DEFAULT_DEPTH})")
    parser.add_argument("-o", "--output",       default="tblue_report.html",   help="HTML report output path")
    parser.add_argument("--json",               action="store_true",                help="Also export JSON report")
    parser.add_argument("--sarif",              action="store_true",                help="Also export SARIF report (GitHub Security tab)")
    parser.add_argument("--sigma",              action="store_true",                help="Also export Sigma detection rules (.yaml) for SIEM ingestion")
    parser.add_argument("--splunk",             action="store_true",                help="Also export Splunk SPL correlation searches (.spl)")
    parser.add_argument("--sentinel",           action="store_true",                help="Also export Microsoft Sentinel KQL analytics rules (.json)")
    parser.add_argument("--playbook",           default=None, metavar="FORMAT",
                        help="Print remediation playbook: terminal | markdown")
    parser.add_argument("--siem",               default=None, metavar="FORMAT",
                        help="Export SIEM-native findings: cef (ArcSight), leef (QRadar), elastic (Elastic SIEM), sentinel (Azure Sentinel)")
    # ── Authenticated scanning ────────────────────────────────────────────
    parser.add_argument("--cookie",
                        default=None, metavar="COOKIES",
                        help="Session cookie(s) to inject: 'sessionid=abc; csrftoken=xyz'")
    parser.add_argument("--header",
                        action="append", dest="extra_headers", metavar="HEADER",
                        help="Custom HTTP header, repeatable: 'X-API-Key: secret'")
    parser.add_argument("--bearer",
                        default=None, metavar="TOKEN",
                        help="Bearer token: sets Authorization: Bearer <TOKEN>")
    parser.add_argument("--auth",
                        dest="auth_basic", default=None, metavar="USER:PASS",
                        help="HTTP Basic auth credentials: 'username:password'")
    # ── Multi-target scanning ─────────────────────────────────────────────
    parser.add_argument("--targets",
                        default=None, metavar="FILE",
                        help="File with one target URL per line (runs full scan on each)")
    # ── Notifications ─────────────────────────────────────────────────────
    parser.add_argument("--notify",
                        action="append", dest="notify_targets", metavar="FORMAT:URL",
                        help="Send scan summary to webhook, repeatable: "
                             "slack:https://... | teams:https://... | discord:https://... | webhook:https://...")
    parser.add_argument("--soar",
                        action="append", dest="soar_targets", metavar="FORMAT:URL",
                        help="Send scan to SOAR/incident platform, repeatable: "
                             "jira:https://company.atlassian.net/PROJECT | "
                             "pagerduty:https://events.pagerduty.com/... | "
                             "thehive:https://thehive.company.com | "
                             "servicenow:https://company.service-now.com")
    parser.add_argument("--skip",               default="",                         help="Modules to skip (comma-separated)")
    parser.add_argument("--only",               default="",                         help="Run only these modules (comma-separated)")
    parser.add_argument("--timeout",            type=int, default=DEFAULT_TIMEOUT,  help=f"Request timeout seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--retries",            type=int, default=DEFAULT_RETRIES,  help=f"Retry attempts (default: {DEFAULT_RETRIES})")
    parser.add_argument("--verbose",            action="store_true",                help="Enable debug logging")
    parser.add_argument("--no-history",         action="store_true",                help="Skip saving/comparing scan history")
    parser.add_argument("--fail-below",         type=int, default=None, metavar="N",
                        help="Exit code 1 if score < N (CI/CD gate). Range: 0-100.")
    parser.add_argument("--config",             default=None, metavar="PATH",
                        help="Path to .tblue.toml config file (default: .tblue.toml in cwd)")
    parser.add_argument("--ai-key",             default=None, metavar="KEY",
                        help="Anthropic API key for AI-powered attack chain analysis (or set ANTHROPIC_API_KEY env var)")
    parser.add_argument("--ai-model",           default="claude-sonnet-4-6", metavar="MODEL",
                        help="Claude model for AI analysis (default: claude-sonnet-4-6)")
    parser.add_argument("--ai",                 action="store_true",
                        help="Send findings to Anthropic for AI attack-chain analysis. "
                             "Opt-in: nothing is transmitted without this flag (or --ai-key).")
    parser.add_argument("--no-ai",              action="store_true",
                        help="Disable AI analysis even if ANTHROPIC_API_KEY is set")
    parser.add_argument("--stride",             action="store_true",
                        help="Generate STRIDE threat model (JSON + Markdown) from scan findings")
    parser.add_argument("--poc",                action="store_true",
                        help="Generate Proof-of-Concept curl commands for all FAIL/WARN findings (JSON + Markdown)")
    parser.add_argument("--probe",              action="store_true",
                        help="Also run side-effect-free probes: GraphQL introspection, "
                             "CORS origin reflection, TLS cipher negotiation, DNS enumeration. "
                             "Sends crafted requests but modifies nothing.")
    parser.add_argument("--active",             action="store_true",
                        help="Run every probe INCLUDING intrusive ones: authentication attempts, password-reset and registration submissions, injection payloads and port scans. These can lock accounts out, email real users and trip WAFs. Implies --probe. Own the target before using this.")
    parser.add_argument("--dashboard",          action="store_true",
                        help="Open a live browser dashboard that streams scan results in real time")
    parser.add_argument("--browser",            action="store_true",
                        help="Enable Playwright browser-based scanning (DOM XSS, SPA routes, storage audit). Requires: pip install playwright && playwright install chromium")
    parser.add_argument("--monitor",            action="store_true",
                        help="Continuous monitoring mode: scan on a schedule and alert only on new findings")
    parser.add_argument("--interval",           default="6h", metavar="INTERVAL",
                        help="Monitoring interval (e.g. 30m, 6h, 1d). Default: 6h. Requires --monitor")
    parser.add_argument("--workers",            type=int, default=50, metavar="N",
                        help="Parallel scanner workers (default: 50). Set to 1 for sequential.")
    parser.add_argument("--version",            action="version",                   version=f"Tblue {__version__}")

    args = parser.parse_args()

    # ── Load and apply config file (CLI args override) ─────────────────────
    config = load_config(args.config)
    apply_config(config, args)

    # Allow --url to be absent when --targets is provided
    if not args.url and not args.targets:
        parser.error("one of --url / --targets is required")

    # ── Validate --notify specs early ─────────────────────────────────────
    for spec in (args.notify_targets or []):
        try:
            notify_parse(spec)
        except ValueError as e:
            parser.error(str(e))

    # ── Validate --soar specs early ────────────────────────────────────────
    for spec in (args.soar_targets or []):
        try:
            soar_parse(spec)
        except ValueError as e:
            parser.error(str(e))

    # ── Multi-target mode ─────────────────────────────────────────────────
    if args.targets:
        import os
        if not os.path.isfile(args.targets):
            parser.error(f"--targets: file not found: {args.targets!r}")
        with open(args.targets) as fh:
            raw_targets = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        if not raw_targets:
            parser.error(f"--targets: no URLs found in {args.targets!r}")
        # If --url also provided, prepend it
        if args.url:
            raw_targets.insert(0, args.url if args.url.startswith("http") else "https://" + args.url)
        all_targets = [t if t.startswith("http") else "https://" + t for t in raw_targets]
    else:
        all_targets = [args.url if args.url.startswith("http") else "https://" + args.url]

    # ── Monitor mode ───────────────────────────────────────────────────────
    if getattr(args, "monitor", False):
        from tblue.monitor import MonitorSession, parse_interval

        try:
            interval_secs = parse_interval(args.interval)
        except (ValueError, TypeError):
            parser.error(f"--interval: invalid value {args.interval!r}. Use e.g. 30m, 6h, 1d")

        # Build a notification function from --notify specs (sends text message)
        notify_specs = args.notify_targets or []
        def _notify_fn(message: str) -> None:
            import urllib.request
            import json as _json
            for spec in notify_specs:
                try:
                    from tblue.notify import parse_target as _np
                    fmt, url = _np(spec)
                    if fmt == "slack":
                        body = _json.dumps({"text": message}).encode()
                    elif fmt == "discord":
                        body = _json.dumps({"content": message}).encode()
                    elif fmt in ("teams", "webhook"):
                        body = _json.dumps({"text": message}).encode()
                    else:
                        body = _json.dumps({"text": message}).encode()
                    req = urllib.request.Request(url, data=body,
                                                 headers={"Content-Type": "application/json"})
                    urllib.request.urlopen(req, timeout=10)
                except Exception as e:
                    logger.warning(f"Monitor notify failed for {spec}: {e}")

        notify_fn = _notify_fn if notify_specs else None

        # Use only the first target for monitor mode
        monitor_target = all_targets[0]
        if len(all_targets) > 1:
            logger.warning("Monitor mode: only the first target will be monitored")

        class _Score:
            def __init__(self, score, grade):
                self.score = score
                self.grade = grade

        def _monitor_scan_fn(t: str) -> dict:
            previous = load_previous_snapshot(t)
            try:
                _run_scan(parser, args, t)
            except SystemExit:
                pass  # --fail-below exit code must not kill the monitor loop
            current_snap = load_previous_snapshot(t)
            if not current_snap:
                return {}
            return {
                "all_results": current_snap.get("results", {}),
                "scan_score": _Score(current_snap.get("score", 0), current_snap.get("grade", "?")),
                "previous_snapshot": previous,
            }

        session_obj = MonitorSession(
            target=monitor_target,
            interval_seconds=interval_secs,
            scan_fn=_monitor_scan_fn,
            notify_fn=notify_fn,
            alert_on_new_only=True,
            alert_on_clear=False,
        )
        sys.exit(session_obj.run())

    # ── Run scan for each target (multi-target iterates this block) ───────
    for target_idx, target in enumerate(all_targets):
        if len(all_targets) > 1:
            log_head(logger, f"[{target_idx + 1}/{len(all_targets)}] Scanning {target}")
        _run_scan(parser, args, target)

    if len(all_targets) > 1:
        log_head(logger, f"Multi-target scan complete: {len(all_targets)} target(s)")
    sys.exit(EXIT_OK)


def _run_scan(parser, args, target: str) -> None:
    """Execute the full scan for a single target URL."""
    active = resolve_modules(args.only, args.skip)

    # --only may name a module that exists but is gated behind --probe/--active.
    # Say so loudly: silently scanning nothing and reporting no findings is the
    # worst failure mode a security tool has.
    if args.only:
        gated = gated_selection(args.only)
        needs_probe  = gated["probe"]  and not (args.probe or args.active)
        needs_active = gated["intrusive"] and not args.active
        if needs_probe:
            log_warn(logger, f"--only names probe-tier modules that will not run "
                             f"without --probe: {', '.join(gated['probe'])}")
        if needs_active:
            log_warn(logger, f"--only names intrusive modules that will not run "
                             f"without --active: {', '.join(gated['intrusive'])}")
        if gated["unknown"]:
            log_warn(logger, f"--only names unknown modules: "
                             f"{', '.join(gated['unknown'])}")
        would_run = bool(active) or (gated["probe"] and (args.probe or args.active)) \
                    or (gated["intrusive"] and args.active)
        if not would_run:
            parser.error(
                "--only selected no runnable modules, so nothing would be scanned. "
                + ("Add --active to run: " + ", ".join(gated["intrusive"]) + ". "
                   if gated["intrusive"] else "")
                + ("Add --probe to run: " + ", ".join(gated["probe"]) + ". "
                   if gated["probe"] else "")
                + ("Unknown module(s): " + ", ".join(gated["unknown"]) + ". "
                   if gated["unknown"] else ""))

    if args.fail_below is not None and not (0 <= args.fail_below <= 100):
        parser.error("--fail-below must be between 0 and 100")

    set_level(args.verbose)
    term.print_banner(target, args.depth, args.output, active)

    # ── Load previous scan for trend comparison ────────────────────────────
    previous_snapshot = None
    if not args.no_history:
        previous_snapshot = load_previous_snapshot(target)

    session: requests.Session    = build_session(args)
    # Include the gated tiers: --probe/--active write their results here too,
    # and a missing key raised KeyError that the dispatch loop swallowed as
    # "active scanner error", silently dropping every active finding.
    all_results: Dict[str, List] = {m: [] for m in ALL_MODULES}
    all_results.update({m: [] for m in ACTIVE_MODULES})
    start: float                 = time.time()

    # ── Shared response cache — eliminates redundant fetches ───────────────
    shared_cache = ResponseCache(max_entries=2000, ttl=300.0)

    # Credentials supplied for the target must never be sent anywhere else.
    # HTTPClient uses allowed_host to route off-target requests (crt.sh, OSV,
    # OTX, ...) through a session with no auth, cookies or custom headers.
    _target_host = (urlparse(target).hostname or "").lower()
    scanner_kwargs = {"timeout": args.timeout, "retries": args.retries,
                      "cache": shared_cache, "allowed_host": _target_host}

    # Pre-fetch the target URL into cache so all scanners get it instantly
    try:
        _prefetch_resp = session.get(target, timeout=args.timeout, allow_redirects=True)
        from tblue.cache import _Entry
        _key = target
        with shared_cache._lock:
            shared_cache._store[_key] = _Entry(_prefetch_resp)
    except Exception:
        pass  # cache miss is fine; scanners will fetch on demand

    # ── Parallel scanner execution ─────────────────────────────────────────
    workers = getattr(args, "workers", 50)
    # Auto-scale: no point spawning more threads than tasks
    _active_tasks = [(mod, cls, msg) for (mod, cls, msg) in _SCANNER_REGISTRY if mod in active]
    workers = min(workers, max(1, len(_active_tasks)))
    _results_lock = threading.Lock()

    # ── Live dashboard (optional) ──────────────────────────────────────────
    dashboard: DashboardServer | None = None
    if getattr(args, "dashboard", False):
        dashboard = DashboardServer(target=target, total_scanners=len(_active_tasks))
        dashboard.start(open_browser=True)

    def _run_one(entry):
        mod_name, cls, msg = entry
        thread_session = build_session(args)
        try:
            log_head(logger, msg)
            scan_results = cls(thread_session, **scanner_kwargs).scan(target)
            with _results_lock:
                all_results[mod_name].extend(scan_results)
            if dashboard:
                dashboard.push_scanner_done(mod_name, scan_results)
        except Exception as exc:
            logger.warning(f"[{mod_name}] scanner error: {exc}")
            if dashboard:
                dashboard.push_scanner_done(mod_name, [])
        finally:
            thread_session.close()

    with ThreadPoolExecutor(max_workers=workers) as _executor:
        futures = {_executor.submit(_run_one, entry): entry[0] for entry in _active_tasks}
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as exc:
                logger.warning(f"[{futures[fut]}] unhandled future error: {exc}")

    # ── Browser-Based Scanning (Playwright) ───────────────────────────────
    if getattr(args, "browser", False):
        if "browser_dom_xss" in active:
            log_head(logger, "Browser DOM XSS scan (Playwright + Chromium)...")
            all_results["browser_dom_xss"].extend(
                BrowserDOMXSSScanner(session, **scanner_kwargs).scan(target))

        if "browser_spa_scan" in active:
            log_head(logger, "Browser SPA route discovery + scan (Playwright)...")
            all_results["browser_spa_scan"].extend(
                BrowserSPAScanner(session, **scanner_kwargs).scan(target))

        if "browser_storage" in active:
            log_head(logger, "Browser storage audit (localStorage/sessionStorage/cookies post-JS)...")
            all_results["browser_storage"].extend(
                BrowserStorageScanner(session, **scanner_kwargs).scan(target))

    # ── Active Scanning (opt-in via --active) ─────────────────────────────
    if getattr(args, "active", False) or getattr(args, "probe", False):
        _active_map = {
            "active_cors_fuzz":     (ActiveCORSOriginFuzzScanner,  "Active CORS origin fuzzing..."),
            "active_http_verb":     (ActiveHTTPVerbProbeScanner,   "Active HTTP verb probing..."),
            "active_port_probe":    (ActivePortProbeScanner,       "Active TCP port scanning..."),
            "active_subdomain_enum":(ActiveSubdomainEnumScanner,   "Active subdomain DNS enumeration..."),
            "active_tls_cipher":    (ActiveTLSCipherProbeScanner,  "Active TLS cipher suite probing..."),
        }
        for _k, _cls, _msg in _ACTIVE_REGISTRY:
            _active_map.setdefault(_k, (_cls, _msg))
        # --active implies --probe; --probe alone stops short of intrusive.
        _tier = PROBE_MODULES | INTRUSIVE_MODULES if getattr(args, "active", False) else PROBE_MODULES
        _only_raw = {m.strip() for m in (getattr(args, "only", "") or "").split(",") if m.strip()}
        _skip_raw = {m.strip() for m in (getattr(args, "skip", "") or "").split(",") if m.strip()}
        _selected = (_only_raw & _tier) if _only_raw else (_tier - _skip_raw)
        for mod_name, (cls, msg) in _active_map.items():
            if mod_name in _selected:
                log_head(logger, msg)
                try:
                    all_results[mod_name].extend(cls(session, **scanner_kwargs).scan(target))
                except Exception as exc:
                    logger.warning(f"[{mod_name}] active scanner error: {exc}")

    # ── AI-Powered Analysis ────────────────────────────────────────────────
    import os
    ai_analysis = None
    # AI analysis sends findings to a third party, so it is opt-in. Merely
    # having ANTHROPIC_API_KEY in the environment must not transmit results.
    _ai_requested = bool(getattr(args, "ai", False) or getattr(args, "ai_key", None))
    if _ai_requested and not getattr(args, "no_ai", False):
        ai_key = getattr(args, "ai_key", None) or os.environ.get("ANTHROPIC_API_KEY")
        ai_model = getattr(args, "ai_model", "claude-sonnet-4-6")
        if ai_key:
            log_head(logger, "Running AI attack chain analysis...")
            ai_analysis = analyze_with_ai(all_results, target, api_key=ai_key, model=ai_model)
            if ai_analysis:
                print(format_ai_analysis_terminal(ai_analysis))

    # ── Scoring & Compliance ───────────────────────────────────────────────
    scan_score      = score_results(all_results)
    flat_results    = [r for v in all_results.values() for r in v]
    compliance_data = compliance_report(flat_results)

    # ── Trend tracking ─────────────────────────────────────────────────────
    scan_diff = None
    if not args.no_history:
        scan_diff = compute_diff(all_results, scan_score, previous_snapshot)
        try:
            saved_path = save_snapshot(target, all_results, scan_score)
            logger.info(f"Scan history saved: {saved_path}")
        except Exception as e:
            logger.warning(f"Could not save scan history: {e}")

    # ── Summary ────────────────────────────────────────────────────────────
    elapsed = round(time.time() - start, 1)
    passed  = count_results(all_results, "PASS")
    warned  = count_results(all_results, "WARN")
    failed  = count_results(all_results, "FAIL")
    term.print_summary(passed, warned, failed, elapsed)
    term.print_score(scan_score)

    # ── Dashboard final events ─────────────────────────────────────────────
    if dashboard:
        dashboard.push_score(scan_score.score)
        dashboard.push_complete(
            score=scan_score.score,
            grade=scan_score.grade,
            passed=passed,
            warned=warned,
            failed=failed,
            breakdown=dict(scan_score.breakdown),
        )

    if scan_diff is not None:
        term.print_trend(scan_diff)

    # ── CI/CD gate ─────────────────────────────────────────────────────────
    exit_code = EXIT_OK
    if args.fail_below is not None:
        term.print_ci_gate(scan_score, args.fail_below)
        if scan_score.score < args.fail_below:
            exit_code = EXIT_BELOW_THRESHOLD

    # ── Reports ────────────────────────────────────────────────────────────
    score_history = []
    if not args.no_history:
        try:
            score_history = load_score_history(target)
        except Exception:
            score_history = []

    html_report.generate(
        target, all_results, args.output,
        scan_score=scan_score, scan_diff=scan_diff,
        compliance=compliance_data,
        score_history=score_history,
        ai_analysis=ai_analysis,
    )
    logger.info(f"HTML report saved: {args.output}")

    if args.json:
        json_path = args.output.replace(".html", ".json")
        json_report.generate(target, all_results, json_path, scan_score=scan_score)
        logger.info(f"JSON report saved: {json_path}")

    if args.sarif:
        sarif_path = args.output.replace(".html", ".sarif")
        sarif_report.generate(target, all_results, sarif_path, scan_score=scan_score)
        logger.info(f"SARIF report saved: {sarif_path}")

    if args.siem:
        _SIEM_EXT = {"cef": "cef", "leef": "leef", "elastic": "ndjson", "sentinel": "json"}
        fmt = args.siem.lower().strip()
        if fmt not in _SIEM_EXT:
            parser.error(f"--siem: unknown format {fmt!r}. Choose: cef, leef, elastic, sentinel")
        siem_path = args.output.replace(".html", f"_siem.{_SIEM_EXT[fmt]}")
        siem_report.generate(target, all_results, siem_path, fmt=fmt, scan_score=scan_score)
        logger.info(f"SIEM report ({fmt.upper()}) saved: {siem_path}")

    if args.sigma:
        sigma_path = args.output.replace(".html", "_sigma.yaml")
        sigma_report.generate(target, all_results, sigma_path, scan_score=scan_score)
        logger.info(f"Sigma rules saved: {sigma_path}")

    if args.splunk:
        splunk_path = args.output.replace(".html", "_splunk.spl")
        splunk_report.generate(target, all_results, splunk_path, scan_score=scan_score)
        logger.info(f"Splunk SPL searches saved: {splunk_path}")

    if args.sentinel:
        sentinel_path = args.output.replace(".html", "_sentinel.json")
        sentinel_report.generate(target, all_results, sentinel_path, scan_score=scan_score)
        logger.info(f"Sentinel KQL rules saved: {sentinel_path}")

    if args.playbook:
        pb_fmt = args.playbook.lower().strip()
        if pb_fmt not in ("terminal", "markdown"):
            parser.error(f"--playbook: unknown format {pb_fmt!r}. Choose: terminal, markdown")
        playbooks = generate_playbooks(all_results)
        if pb_fmt == "terminal":
            print(fmt_playbook_term(playbooks))
        else:
            md_path = args.output.replace(".html", "_playbook.md")
            with open(md_path, "w") as f:
                f.write(fmt_playbook_md(playbooks, target))
            logger.info(f"Remediation playbook saved: {md_path}")

    if getattr(args, "stride", False):
        stride_path = args.output.replace(".html", "_stride.json")
        stride_report.generate(target, all_results, stride_path, scan_score=scan_score)
        logger.info(f"STRIDE threat model saved: {stride_path} (+ .md)")

    if getattr(args, "poc", False):
        poc_path = args.output.replace(".html", "_poc.json")
        poc_report.generate(target, all_results, poc_path, scan_score=scan_score)
        logger.info(f"PoC report saved: {poc_path} (+ .md)")

    # ── Notifications ──────────────────────────────────────────────────────
    for spec in (args.notify_targets or []):
        notify_send(spec, target, scan_score, all_results, scan_diff)

    # ── SOAR dispatch ──────────────────────────────────────────────────────
    for spec in (args.soar_targets or []):
        soar_send(spec, target, scan_score, all_results, scan_diff)

    if exit_code != EXIT_OK:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
