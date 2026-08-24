"""GraphQL Introspection Security scanner — passive detection of dangerous GraphQL exposure."""
import re
from .base import BaseScanner

_GQL_ANY_RE = re.compile(
    r'(?:__schema|__type|__typename|"data"\s*:\s*\{|'
    r'graphql|application/graphql|'
    r'"errors"\s*:\s*\[)',
    re.I,
)

_GQL_INTROSPECTION_ENABLED_RE = re.compile(
    r'"__schema"\s*:\s*\{[^}]{0,200}"types"',
    re.I,
)

_GQL_INTROSPECTION_MUTATION_RE = re.compile(
    r'"mutationType"\s*:\s*\{[^}]{0,200}"name"',
    re.I,
)

_GQL_ERROR_DISCLOSURE_RE = re.compile(
    r'"errors"\s*:\s*\[\s*\{[^}]{0,500}"message"\s*:\s*"[^"]{10,500}"',
    re.I,
)

_GQL_STACK_TRACE_RE = re.compile(
    r'"extensions"\s*:\s*\{[^}]{0,200}"stacktrace"\s*:\s*\[',
    re.I,
)

_GQL_PLAYGROUND_RE = re.compile(
    r'(?:GraphiQL|Apollo\s+Studio|GraphQL\s+Playground|'
    r'<title>GraphQL\s+Playground|Voyager)',
    re.I,
)

_GQL_FIELD_SUGGESTIONS_RE = re.compile(
    r'"message"\s*:\s*"[^"]*Cannot\s+query\s+field[^"]*Did\s+you\s+mean',
    re.I,
)


class GraphQLIntrospectionSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "graphql_introspection_not_used", "PASS")]

        body = resp.text
        if not _GQL_ANY_RE.search(body):
            return [self._result(url, "graphql_introspection_not_used", "PASS")]

        findings = []

        if _GQL_INTROSPECTION_ENABLED_RE.search(body):
            findings.append(self._result(
                url, "graphql_introspection_enabled", "WARN",
                detail="GraphQL introspection response with __schema.types present — full schema exposed to unauthenticated clients; attackers map all queries, mutations, types, and field names enabling precision attacks.",
            ))

        if _GQL_INTROSPECTION_MUTATION_RE.search(body):
            findings.append(self._result(
                url, "graphql_introspection_mutations_exposed", "FAIL",
                detail="GraphQL introspection reveals mutationType — write operations (mutations) are discoverable including names and argument types; attackers identify and target state-changing operations directly.",
            ))

        if _GQL_STACK_TRACE_RE.search(body):
            findings.append(self._result(
                url, "graphql_stack_trace_in_extensions", "FAIL",
                detail="GraphQL error response includes extensions.stacktrace — full server-side stack trace reveals framework versions, file paths, and internal function names enabling targeted exploitation.",
            ))

        if _GQL_ERROR_DISCLOSURE_RE.search(body):
            findings.append(self._result(
                url, "graphql_error_message_disclosure", "WARN",
                detail="GraphQL errors array with detailed message string — verbose error messages expose internal schema structure, field names, and argument types even when introspection is disabled.",
            ))

        if _GQL_PLAYGROUND_RE.search(body):
            findings.append(self._result(
                url, "graphql_ide_enabled", "WARN",
                detail="GraphQL IDE (GraphiQL, Apollo Studio, Playground, Voyager) accessible in response — interactive schema exploration enabled in production; attackers use IDE to browse and execute queries without writing code.",
            ))

        if _GQL_FIELD_SUGGESTIONS_RE.search(body):
            findings.append(self._result(
                url, "graphql_field_suggestion_disclosure", "WARN",
                detail="GraphQL error suggests valid field names ('Did you mean X?') — field name enumeration possible even with introspection disabled; attacker submits typos to discover all field names via suggestions.",
            ))

        return findings or [self._result(url, "graphql_introspection_safe", "PASS")]
