#!/usr/bin/env python3
"""
Generate SCANNERS.md — full educational reference for every Tblue scanner.

Run:
    python generate_scanner_docs.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

# Pull the THREAT_INTEL dict without running the dashboard generator
import importlib.util, types

spec = importlib.util.spec_from_file_location("gd", "generate_dashboard.py")
mod = types.ModuleType("gd")
spec.loader.exec_module(mod)   # type: ignore[attr-defined]
THREAT_INTEL = mod.THREAT_INTEL

# ── Category mapping ──────────────────────────────────────────────────────────
CATEGORIES = {
    "Critical Injection & RCE": [
        "command_injection", "ssti", "xxe_injection", "xxe_passive",
        "deserialization", "deserialization_gadget_passive", "insecure_deserialization_passive",
        "log4shell_passive", "latex_injection_passive", "el_injection",
        "csti", "server_side_template_passive", "nosql_injection_advanced",
        "ldap_injection_passive", "xml_external_entity_advanced",
        "xpath_injection_passive", "xpath_injection_security",
        "ldap_injection_security", "sql_injection_client_security",
        "template_injection_client_security", "command_injection_client_security",
        "zip_slip_passive",
    ],
    "SSRF & Request Forgery": [
        "ssrf_detection", "ssrf_advanced", "ssrf_passive",
        "cloud_metadata", "dns_rebinding", "dns_rebinding_passive",
        "http_request_smuggling", "http_desync_passive",
    ],
    "Cross-Site Scripting (XSS)": [
        "xss", "dom_xss_sources", "mutation_xss", "css_injection",
        "css_injection_passive", "srcdoc_injection", "dangling_markup",
        "svg_security", "trojan_source", "javascript_template_literal",
        "trusted_types_policy", "trusted_types_csp", "trusted_types_security",
        "sanitizer_api_security", "dom_clobbering", "dom_parser_security",
    ],
    "Authentication & Session": [
        "session_security", "session_fixation", "session_fixation_passive",
        "session_fixation_security", "session_token_exposure", "session_entropy_passive",
        "jwt_security", "jwt_advanced", "jwt_algorithm_confusion",
        "jwt_advanced_security", "jwt_token_exposure", "jwt_claim_analysis",
        "jwt_advanced_security", "credential_exposure", "hardcoded_credentials",
        "account_lockout", "account_recovery", "account_enumeration",
        "account_enumeration_security", "magic_link_security",
        "mfa_detection", "password_policy", "password_reset",
        "social_login_security", "web_authentication_security",
        "credential_api_advanced", "credential_management_security",
        "auth_bypass_pattern_security", "login_security",
    ],
    "Authorization & Access Control": [
        "access_control", "admin_exposure", "idor_detection",
        "insecure_direct_object_reference", "broken_object_level_auth",
        "mass_assignment", "mass_assignment_security",
        "business_logic", "business_logic_exposure",
        "path_traversal", "path_traversal_deep", "path_normalization_security",
        "directory_listing", "exposed_backup_files",
        "api_versioning", "api_versioning_security",
        "rate_limit", "rate_limiting", "rate_limiting_detection",
        "rate_limit_bypass_security", "api_rate_limit_headers",
        "api_rate_limit_deep", "api_pagination_abuse", "api_pagination_security",
    ],
    "OAuth, SAML & Identity": [
        "oauth", "oauth_advanced", "oauth_implicit_flow",
        "oauth_redirect_uri_validation", "oauth_token_leak",
        "oauth_pkce", "oauth_misconfiguration_passive",
        "saml", "saml_passive", "saml_security_passive",
        "federated_identity_security", "identity_credential_security",
        "fedcm_security", "login_status_api_security",
        "trust_token_security",
    ],
    "CSRF & Clickjacking": [
        "csrf_token_strength", "csrf_double_submit",
        "clickjacking", "clickjacking_advanced", "clickjacking_deep",
        "content_security_framing", "x_frame_options",
        "tabnabbing", "tabnapping_passive",
        "form_action_hijacking",
    ],
    "HTTP Headers & Transport": [
        "headers", "http_security_headers_deep", "http_security_baseline",
        "http_security_consistency", "response_headers",
        "hsts_deep_analysis", "hsts_preload", "http_strict_transport_upgrade",
        "mixed_content", "csp", "csp_advanced", "csp_nonce",
        "csp_nonce_reuse", "csp_reporting", "csp_violation_report",
        "permissions_policy", "permissions_policy_deep", "permission_policy_security",
        "feature_policy_security", "referrer_policy", "referrer_policy_deep",
        "cors", "cors_advanced", "cors_deep_analysis", "cors_misconfiguration_deep",
        "cors_preflight_deep", "cors_credential_security", "cors_expose_headers",
        "cors_max_age_deep", "cors_null_origin", "cors_origin_reflection",
        "cors_wildcard_api", "cors_policy_advanced",
        "fetch_metadata", "nel_reporting", "reporting_api_security",
        "cache_control_security", "sensitive_cache_control",
        "host_header", "host_header_injection",
        "http_method_override", "http_method_tampering", "http_verb_tampering",
        "http_methods", "http_range_security",
        "content_type_confusion", "content_type_sniffing", "content_sniffing_bypass",
        "content_disposition_security",
    ],
    "Cookies": [
        "cookies", "cookie_advanced", "cookie_prefix_security",
        "cookie_samesite_deep", "same_site_cookie_security",
        "cookies_partitioned_security", "cookie_store_security",
        "autocomplete_security",
    ],
    "TLS & Cryptography": [
        "ssl", "tls_deep", "tls_certificate_deep", "tls_protocol_version",
        "tls_downgrade_passive", "weak_crypto", "web_crypto_weaknesses",
        "cryptographic_weakness_passive", "compression_oracle",
        "certificate_transparency", "crt_sh",
    ],
    "Supply Chain & Dependencies": [
        "dependency_confusion", "dependency_hijacking",
        "js_supply_chain_integrity", "subresource_integrity_deep",
        "sri_advanced", "supply_chain", "supply_chain_lockfile",
        "sca", "js_libraries", "js_file_analysis",
        "js_framework_detection", "import_map_security", "importmap_security",
        "import_assertions_security", "dynamic_import_security",
    ],
    "Secrets & Information Disclosure": [
        "info_disclosure", "error_pages", "html_comments",
        "js_secrets", "api_key_in_js", "api_key_rotation",
        "hardcoded_credentials", "credential_exposure",
        "secret_in_error_page", "server_timing", "server_timing_disclosure",
        "server_info_deep", "etag_fingerprinting", "dev_artifact",
        "framework_config", "source_map", "source_map_exposure",
        "sourcemap_exposure", "package_manifest_exposure",
        "open_api_exposure", "api_schema_exposure", "api_documentation_exposure",
        "api_error_disclosure", "security_txt", "security_txt_deep",
        "version_cve", "live_cve", "insecure_data_exposure",
        "debug_mode_detection", "debug_endpoint_exposure",
        "actuator_endpoint_exposure", "spring_actuator", "health_endpoint_exposure",
    ],
    "GraphQL": [
        "graphql", "graphql_advanced", "graphql_depth", "graphql_batch_abuse",
        "graphql_batch_attack", "graphql_batching", "graphql_csrf",
        "graphql_field_suggestion", "graphql_info_disclosure",
        "graphql_introspection_security", "graphql_persisted_queries",
        "graphql_subscription", "introspection_disclosure",
    ],
    "API Security": [
        "api_auth_security", "api_authentication_exposure",
        "api_collection", "api_gateway_security", "api_security_headers",
        "api_surface", "grpc", "scim", "webhook_security",
        "json_injection", "json_security", "jsonp_endpoint",
        "open_graph_exposure", "open_graph_security",
    ],
    "Cloud & Infrastructure": [
        "cloud_storage", "open_s3_bucket", "k8s_exposure", "docker_exposure",
        "cicd_exposure", "serverless_exposure", "infra", "ports",
        "apache_status_exposure", "nginx_alias_traversal",
        "security_misconfiguration",
    ],
    "DNS & Network": [
        "dns_security", "dns_advanced", "dns_caa",
        "subdomain_takeover", "subdomain_takeover_passive",
        "subdomain_enum_passive", "typosquatting",
        "certificate_transparency", "redirect_chain",
        "private_network_access", "protocol_confusion",
        "network_information_security",
    ],
    "Injection (Other)": [
        "parameter_pollution", "parameter_pollution_passive",
        "path_parameter_pollution", "http_parameter_pollution",
        "log_injection", "log_injection_passive",
        "crlf_injection", "csv_injection", "content_injection",
        "content_negotiation", "link_injection_passive",
        "link_header_injection", "header_injection_sink",
        "email_header_injection", "json_injection",
        "open_redirect", "open_redirect_deep", "client_side_redirect",
        "prssi", "relative_path_overwrite",
        "integer_overflow_passive",
    ],
    "WebSockets & Real-Time": [
        "websocket", "websocket_security_deep", "websocket_origin_check",
        "sse_security", "eventsource_security", "server_sent_events_security",
        "webtransport_security", "push_api_security",
        "broadcast_channel_security", "broadcast_channel_advanced_security",
        "message_channel_security", "channel_messaging_security",
        "postmessage_security",
    ],
    "Browser APIs & Web Platform": [
        "web_usb_security", "web_bluetooth_security", "web_serial_security",
        "web_nfc_security", "hid_api_security", "midi_api_security",
        "web_hid_security", "gamepad_security",
        "geolocation_api_security", "geolocation_security",
        "device_motion_security", "device_orientation_security",
        "ambient_light_security", "generic_sensor_security",
        "proximity_sensor_security", "battery_status_security",
        "screen_capture_security", "screen_wake_lock_security",
        "screen_details_security",
        "contact_picker_security", "eyedropper_api_security",
        "clipboard_api_security", "clipboard_advanced_security",
        "vibration_api_security", "vibration_security",
        "window_management_security", "fullscreen_security",
        "pointer_lock_security", "keyboard_lock_security",
        "virtual_keyboard_security",
        "file_system_access_security", "storage_manager_security",
        "storage_bucket_security", "storage_access_api_security",
        "opfs_security", "cache_api_security", "lock_api_security",
        "web_locks_security",
        "notification_api_security", "notification_security",
        "web_otp_security", "web_share_security",
        "badging_api_security", "web_audio_security",
        "speech_recognition_security", "speech_synthesis_security",
        "media_recorder_security", "media_capabilities_security",
        "media_devices_security", "media_session_security",
        "media_source_extension_security", "remote_playback_security",
        "presentation_api_security", "picture_in_picture_security",
        "document_pip_security", "document_pip_api_security",
        "document_picture_in_picture_security",
        "payment_request_security", "payment_handler_security",
        "payment_page_security",
        "geolocation_security", "deep_link_security",
        "launch_handler_security", "pwa_manifest_security",
        "before_install_prompt_security", "content_index_security",
        "background_fetch_security", "background_sync_security",
        "periodic_background_sync_security",
        "idle_detection_api_security", "idle_detection_security",
        "compute_pressure_security", "web_authentication_security",
        "webxr_security", "webgpu_security", "webgl_security",
        "webcodecs_security", "video_decoder_security",
        "audio_decoder_security", "image_decoder_security",
        "wasm_security", "wasm_security_deep",
    ],
    "Service Workers & Caching": [
        "service_worker_security", "service_worker_security_deep",
        "shared_worker_security", "web_worker_security",
        "web_worker_security_deep", "worker_module_security",
        "back_forward_cache_security", "prerendering_security",
        "speculation_rules_security", "http_caching_security",
        "cache_poisoning", "cache_poisoning_passive",
        "web_cache_deception",
    ],
    "JavaScript & Prototype": [
        "prototype_pollution", "prototype_pollution_advanced",
        "javascript_prototype_chain", "javascript_prototype_pollution_deep",
        "dom_clobbering", "js_dangerous_patterns",
        "function_constructor_security", "define_property_security",
        "object_spread_security", "proxy_reflect_security",
        "promise_security", "generator_security", "symbol_security",
        "weakmap_security", "typed_array_security", "array_buffer_security",
        "structured_clone_security", "iterator_protocol_security",
        "map_set_security", "date_security", "intl_security",
        "json_security", "regex_security", "redos_passive",
        "abort_controller_security", "observable_api_security",
        "readable_stream_security",
    ],
    "CSS & UI Security": [
        "css_exfiltration", "css_injection", "css_injection_passive",
        "css_houdini_security", "css_paint_api_security",
        "css_typed_om_security", "css_custom_properties_security",
        "css_custom_highlight_security", "css_cascade_layers_security",
        "css_container_query_security", "css_nesting_security",
        "css_scope_security", "css_grid_security", "css_math_security",
        "css_masonry_security", "css_font_palette_security",
        "css_counter_security", "css_transitions_security",
        "color_scheme_security", "canvas_fingerprinting",
        "highlight_api_security",
    ],
    "DOM & Web Components": [
        "dom", "shadow_dom_security", "declarative_shadow_dom_security",
        "custom_elements_security", "custom_element_registry_security",
        "web_components_security", "element_internals_security",
        "popover_api_security", "dialog_element_security",
        "inert_security", "focus_management_security",
        "scroll_snap_security", "scroll_timeline_security",
        "anchor_positioning_security", "view_transition_security",
        "content_visibility_security", "drag_drop_security",
        "pointer_events_security", "input_event_security",
        "event_target_security", "error_event_security",
        "mutation_observer_security", "resize_observer_security",
        "intersection_observer_security", "performance_observer_security",
        "reporting_observer_security", "longtask_observer_security",
        "long_animation_frame_security", "element_timing_security",
        "user_timing_security", "resource_timing_security",
        "document_visibility_security", "document_domain_security",
        "document_fragment_security", "tree_walker_security",
        "history_api_security", "navigation_api_security",
        "text_fragment_security", "font_access_security",
        "font_loading_security", "shape_detection_security",
        "scheduler_api_security",
    ],
    "Privacy & Fingerprinting": [
        "privacy_sandbox_apis", "topics_api_security",
        "attribution_reporting_security", "private_aggregation_security",
        "interest_group_security", "shared_storage_security",
        "fenced_frame_security", "portals_security",
        "canvas_fingerprinting", "exif_metadata_exposure",
        "phi_exposure", "gdpr_privacy", "sensitive_data_exposure",
        "local_storage_sensitive", "client_storage",
        "open_graph_exposure", "open_graph_security",
    ],
    "Iframe & Cross-Origin": [
        "iframe_security_deep", "iframe_allow_security",
        "iframe_sandbox_security", "credentialless_iframe_security",
        "cross_origin_policy_deep", "cross_origin_isolation",
        "coop_security", "coep_security", "corp_security",
        "document_policy_security", "url_parser_differential",
        "cors_null_origin",
    ],
    "Email & Miscellaneous": [
        "email_security", "email_advanced", "email_config_exposure",
        "email_header_injection", "sensitive_params",
        "http2_security", "http2_rapid_reset", "http2_push_security",
        "http3_quic", "grpc", "path_confusion",
        "sensitive_endpoint_exposure", "open_graph_exposure",
        "form_security", "form_data_security", "form_data_api_security",
        "form_action_security",
        "file_upload", "file_upload_security", "file_inclusion",
        "file_inclusion_security",
        "client_side_validation_only",
        "link_preview_exposure", "third_party_exposure",
        "origin_trial_exposure", "feature_flag_exposure",
        "ai_api_exposure", "llm_prompt_injection",
        "robots_txt", "crossdomain_policy",
        "timing_oracle", "timing_attack_passive",
        "race_condition", "race_condition_passive",
        "http_observatory", "waf", "waf_bypass_detection",
        "cms_detection", "js_framework_detection",
        "api_surface", "api_collection",
        "link_resource_hints_security", "http_early_hints_security",
        "fetch_priority_security",
    ],
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "ℹ️",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def severity_rank(s):
    try:
        return SEVERITY_ORDER.index(s)
    except ValueError:
        return 99


def format_entry(key, data, idx):
    sev = data.get("severity", "INFO")
    emoji = SEVERITY_EMOJI.get(sev, "ℹ️")
    short = data.get("short", key.replace("_", " ").title())
    desc = data.get("description", "")
    cwe = data.get("cwe", "")
    mitre = data.get("mitre", "")
    remediation = data.get("remediation", [])
    references = data.get("references", [])

    # Older entries use 'threats' instead of 'description'
    if not desc:
        threats = data.get("threats", [])
        if threats:
            desc = " ".join(threats)

    lines = [f"### {idx}. {short}"]
    lines.append(f"**Module:** `{key}` &nbsp;|&nbsp; **Severity:** {emoji} {sev}")
    if cwe or mitre:
        tags = []
        if cwe:
            tags.append(f"**{cwe}**")
        if mitre:
            tags.append(f"**MITRE:** {mitre}")
        lines.append(" &nbsp;|&nbsp; ".join(tags))
    lines.append("")

    if desc:
        lines.append(desc)
        lines.append("")

    if remediation:
        lines.append("**How to fix:**")
        for r in remediation:
            lines.append(f"- {r}")
        lines.append("")

    if references:
        lines.append("**References:** " + " · ".join(f"[↗]({r})" for r in references))
        lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def main():
    placed = set()
    sections = []

    for cat_name, keys in CATEGORIES.items():
        entries = []
        for key in keys:
            if key in THREAT_INTEL and key not in placed:
                entries.append((key, THREAT_INTEL[key]))
                placed.add(key)
        if not entries:
            continue
        entries.sort(key=lambda x: severity_rank(x[1].get("severity", "INFO")))
        sections.append((cat_name, entries))

    # Catch any THREAT_INTEL keys not yet in a category
    uncategorized = [(k, v) for k, v in THREAT_INTEL.items() if k not in placed]
    if uncategorized:
        uncategorized.sort(key=lambda x: severity_rank(x[1].get("severity", "INFO")))
        sections.append(("Other Scanners", uncategorized))

    total = sum(len(e) for _, e in sections)

    out = []
    out.append("# Tblue Scanner Reference")
    out.append("")
    try:
        from tblue.cli import _SCANNER_REGISTRY
        shipped = len(_SCANNER_REGISTRY)
    except Exception:
        shipped = None
    if shipped and shipped != total:
        out.append(
            f"In-depth reference for **{total} of the {shipped} passive blue-team scanners** "
            f"in Tblue. The remaining {shipped - total} ship and run, but do not yet have a "
            f"long-form entry here — see `tblue --help` for the full module list."
        )
    else:
        out.append(f"Complete educational reference for all **{total} passive blue-team scanners** in Tblue.")
    out.append("Each entry explains what the scanner detects, why it is dangerous, and how to fix it.")
    out.append("")
    out.append("> **Blue-team only.** Tblue is a passive detection tool — no active exploitation, no brute force,")
    out.append("> no destructive probing. Every scanner reads responses and reports findings without modifying state.")
    out.append("")
    out.append("## Severity Guide")
    out.append("")
    out.append("| Level | Meaning |")
    out.append("|---|---|")
    out.append("| 🔴 CRITICAL | Direct path to RCE, credential theft, or data breach. Fix immediately. |")
    out.append("| 🟠 HIGH | Significant security weakness; exploitable under common conditions. |")
    out.append("| 🟡 MEDIUM | Defence-in-depth gap; exploitable with additional preconditions. |")
    out.append("| 🟢 LOW | Best-practice deviation; low direct risk but hardens attack surface. |")
    out.append("| ℹ️ INFO | Informational — may leak context that assists an attacker during reconnaissance. |")
    out.append("")

    # Table of contents
    out.append("## Table of Contents")
    out.append("")
    for cat_name, entries in sections:
        anchor = cat_name.lower().replace(" ", "-").replace("(", "").replace(")", "").replace("&", "").replace("/", "").replace(",", "").replace("__", "_").strip("-")
        out.append(f"- [{cat_name} ({len(entries)} scanners)](#user-content-{anchor})")
    out.append("")
    out.append("---")
    out.append("")

    global_idx = 1
    for cat_name, entries in sections:
        anchor = cat_name.lower().replace(" ", "-").replace("(", "").replace(")", "").replace("&", "").replace("/", "").replace(",", "").replace("__", "_").strip("-")
        out.append(f"## {cat_name}")
        out.append("")
        out.append(f"*{len(entries)} scanner{'s' if len(entries) != 1 else ''} in this category.*")
        out.append("")
        for key, data in entries:
            out.append(format_entry(key, data, global_idx))
            global_idx += 1

    content = "\n".join(out)
    with open("SCANNERS.md", "w") as f:
        f.write(content)

    print(f"✓ SCANNERS.md generated — {total} scanners documented across {len(sections)} categories.")


if __name__ == "__main__":
    main()
