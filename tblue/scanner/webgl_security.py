"""WebGL security scanner — passive detection of shader injection and texture exfiltration."""
import re
from .base import BaseScanner

_WGL_ANY_RE = re.compile(
    r'(?:getContext\s*\(\s*["\']webgl|WebGLRenderingContext\b|WebGL2RenderingContext\b|gl\.createShader\b|gl\.texImage2D\b)',
    re.I,
)

_WGL_SHADER_FROM_PARAM_RE = re.compile(
    r'(?:gl\.shaderSource|createShader)[^;]{0,200}(?:searchParams|location\.hash|innerHTML)',
    re.I,
)

_WGL_TEXTURE_EXFIL_RE = re.compile(
    r'(?:gl\.readPixels|toDataURL)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_WGL_EXTENSION_FINGERPRINT_RE = re.compile(
    r'(?:getSupportedExtensions|getExtension)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I,
)

_WGL_CROSS_ORIGIN_TEXTURE_RE = re.compile(
    r'gl\.texImage2D[^;]{0,200}(?:crossOriginImage|crossorigin|https?://(?!localhost|127\.0\.0\.1))',
    re.I,
)


class WebGLSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "webgl_not_used", "PASS")]

        body = resp.text

        if not _WGL_ANY_RE.search(body):
            return [self._result(url, "webgl_not_used", "PASS")]

        findings = []

        if _WGL_SHADER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "webgl_shader_from_url_param", "FAIL",
                detail="WebGL shader source sourced from URL parameter or innerHTML — GLSL shader injection vector.",
            ))

        if _WGL_TEXTURE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "webgl_texture_exfiltrated", "FAIL",
                detail="WebGL readPixels/toDataURL result transmitted to remote — GPU framebuffer data exfiltration.",
            ))

        if _WGL_EXTENSION_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "webgl_extension_fingerprinting", "WARN",
                detail="WebGL supported extensions transmitted to analytics — GPU extension-based browser fingerprinting.",
            ))

        return findings or [self._result(url, "webgl_safe", "PASS")]
